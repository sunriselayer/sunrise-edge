//! DR-0187: the closed canonical Seal frames (SealIntent 0xD050, target
//! preimage 0xD051, request preimage 0xD052, accepted SealOutcome 0xD053)
//! and Seal pure/warranted verification.
//!
//! `Seal` is an OrderedOperationKind like `Freeze`/`DrainSet`: it carries no
//! outer signature of its own. Its authority is the signed-genesis
//! Freeze/DrainSet prerequisite plus a quorum-backed
//! `consensus::readiness::ReadinessCertificate` over the exact successor
//! set this candidate targets, never an additional signer on the intent
//! itself. `validate_seal_intent_structure`/pure authentication
//! (`super::policy`s `Seal` arm) decide everything that is provable from
//! the candidate own canonical bytes alone, with zero storage reads: the
//! predecessor pin, the created_checkpoint/cut history binding, the
//! readiness subject own internal consistency and the target/request
//! derivation. `require_seal_warrant` re-verifies, through durable storage
//! and the immutable certificate blob, exactly what cannot be decided
//! purely: that `DrainSet` has actually committed, that the referenced
//! certificate blob exists and matches its declared digest/length, that
//! its quorum is genuinely valid over the pinned successor set, and that
//! every named successor is still a currently eligible, committed bond.
//!
//! This module implements only the verification half DR-0187 calls private
//! acceptance-only business closure plus its warranted pre-vote check. The
//! durable Seal completion (the mandatory outgoing barrier and sealed
//! record, the OutgoingSealRepository contract) is a separate
//! storage-owning deliverable and is not implemented here: see
//! `super::engine`s `Seal` dispatch arm, which stops rather than inventing
//! a completion.
use super::*;
use crate::business_reconstruction::cut::business_cut_identity_digest;
use crate::business_reconstruction::cut::{BusinessCutIdentity, decode_business_cut_identity};
use crate::epoch_transition::{self, NextSetEligibilityError};
use crate::fast_path::records::FastPathValidatorEntry;
use canonical_encoding::{decode_digest32, encode_digest32};
use consensus::readiness::{
    MAX_READINESS_CERTIFICATE_BYTES, MAX_READINESS_SUBJECT_BYTES, ReadinessCertificate,
    ReadinessCertifier, ReadinessSubject, decode_readiness_certificate, decode_readiness_subject,
    encode_readiness_subject,
};
use execution::publication::PublicationContext;
use runtime::StructuredStateReader;
use runtime::portable::{
    MAX_PORTABLE_CHUNK_BYTES, PortableBlobChunkOutcome, PortableBlobChunkRequest,
    PortableBlobDescriptor,
};
use std::num::NonZeroUsize;

/// Canonical frame type of an encoded SealIntent (an OrderedCandidate intent
/// body for OrderedOperationKind::Seal).
pub const SEAL_INTENT_TYPE: u16 = 0xD050;
/// Canonical frame type of the target preimage DR-0187 derives target from.
pub const SEAL_TARGET_PREIMAGE_TYPE: u16 = 0xD051;
/// Canonical frame type of the request preimage DR-0187 derives the
/// candidate request_id from, before the explicit high-bit set.
pub const SEAL_REQUEST_PREIMAGE_TYPE: u16 = 0xD052;
/// Canonical frame type of an encoded SealOutcome.
pub const SEAL_OUTCOME_TYPE: u16 = 0xD053;
const ENCODING_VERSION: u16 = 1;

/// The sole supported predecessor: the original locally pinned signed
/// genesis. DR-0187: only predecessor tag 1, original genesis, is
/// supported; unknown tags stop, no legacy transition certificate is a
/// fallback. A future authenticated predecessor needs another reviewed tag
/// and producer; this verifier cannot repin to a peer epoch.
pub const SEAL_PREDECESSOR_TAG_GENESIS: u16 = 1;

/// SealIntent 40 KiB.
pub const MAX_SEAL_INTENT_BYTES: usize = 40 * 1024;
/// Each cut identity 16 KiB.
pub const MAX_SEAL_CUT_IDENTITY_BYTES: usize = 16 * 1024;
/// Accepted outcome 1 KiB.
pub const MAX_SEAL_OUTCOME_BYTES: usize = 1024;

fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

/// The candidate body for OrderedOperationKind::Seal. Carries bounded
/// references, not a saved-cut superframe: cut_identity_bytes is the exact
/// canonical BusinessCutIdentity frame this Seal targets, and the
/// certificate itself is staged separately (by digest/length only) rather
/// than embedded, so a 1 MiB quorum certificate never has to fit inside the
/// 40 KiB intent bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealIntent {
    /// Separate complete local hash-suite schedule, adjacent successor set
    /// and semantic cut this Seal is conditioned on readiness for.
    pub readiness_subject: ReadinessSubject,
    /// Exact canonical BusinessCutIdentity frame bytes this Seal targets.
    /// Opaque at this layer by design: only the business-reconstruction
    /// layer that owns BusinessCutIdentity interprets its fields.
    pub cut_identity_bytes: Vec<u8>,
    /// Predecessor kind; only SEAL_PREDECESSOR_TAG_GENESIS is supported.
    pub predecessor_tag: u16,
    /// Digest the predecessor tag names; for genesis, the pinned genesis
    /// manifest digest.
    pub predecessor_digest: Digest32,
    /// Digest of the staged immutable ReadinessCertificate blob.
    pub certificate_digest: Digest32,
    /// Exact byte length of the staged certificate, checked against the
    /// blob before it is trusted.
    pub certificate_length: u32,
}

fn validate_seal_intent_structure(intent: &SealIntent) -> Result<(), NodeCoreError> {
    if intent.cut_identity_bytes.is_empty()
        || intent.cut_identity_bytes.len() > MAX_SEAL_CUT_IDENTITY_BYTES
    {
        return Err(invalid("seal intent cut identity length"));
    }
    if intent.predecessor_tag != SEAL_PREDECESSOR_TAG_GENESIS {
        return Err(invalid("seal intent predecessor tag is unsupported"));
    }
    if intent.certificate_length == 0
        || (intent.certificate_length as usize) > MAX_READINESS_CERTIFICATE_BYTES
    {
        return Err(invalid("seal intent certificate length"));
    }
    Ok(())
}

/// Encodes frame 0xD050/v1.
pub fn encode_seal_intent(intent: &SealIntent) -> Result<Vec<u8>, NodeCoreError> {
    validate_seal_intent_structure(intent)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(SEAL_INTENT_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        encode_readiness_subject(&intent.readiness_subject)
            .map_err(|_| invalid("invalid seal intent readiness subject"))?,
    )?;
    frame.field_bytes(2, intent.cut_identity_bytes.clone())?;
    frame.field_u16(3, intent.predecessor_tag)?;
    frame.field_bytes(4, encode_digest32(&intent.predecessor_digest)?)?;
    frame.field_bytes(5, encode_digest32(&intent.certificate_digest)?)?;
    frame.field_u32(6, intent.certificate_length)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_SEAL_INTENT_BYTES {
        return Err(invalid("seal intent exceeds the candidate bound"));
    }
    Ok(bytes)
}

/// Strictly decodes frame 0xD050/v1.
pub fn decode_seal_intent(bytes: &[u8]) -> Result<SealIntent, NodeCoreError> {
    if bytes.len() > MAX_SEAL_INTENT_BYTES {
        return Err(invalid("seal intent exceeds the candidate bound"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(SEAL_INTENT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
    let readiness_subject_bytes: &[u8] = frame.required_field(1)?;
    if readiness_subject_bytes.is_empty()
        || readiness_subject_bytes.len() > MAX_READINESS_SUBJECT_BYTES
    {
        return Err(invalid("seal intent readiness subject length"));
    }
    let cut_identity_bytes: &[u8] = frame.required_field(2)?;
    if cut_identity_bytes.is_empty() || cut_identity_bytes.len() > MAX_SEAL_CUT_IDENTITY_BYTES {
        return Err(invalid("seal intent cut identity length"));
    }
    let intent: SealIntent = SealIntent {
        readiness_subject: decode_readiness_subject(readiness_subject_bytes)
            .map_err(|_| invalid("invalid seal intent readiness subject"))?,
        cut_identity_bytes: cut_identity_bytes.to_vec(),
        predecessor_tag: frame.required_u16(3)?,
        predecessor_digest: decode_digest32(frame.required_field(4)?)?,
        certificate_digest: decode_digest32(frame.required_field(5)?)?,
        certificate_length: frame.required_u32(6)?,
    };
    if encode_seal_intent(&intent)? != bytes {
        return Err(invalid("noncanonical seal intent"));
    }
    Ok(intent)
}

fn hashed_context(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    bytes: &[u8],
) -> Result<Digest32, NodeCoreError> {
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(invalid("seal hash context differs"));
    }
    resolver
        .hash_for_purpose(context.epoch(), HashPurpose::NodeEvent, bytes)
        .map_err(|_| invalid("seal committed hash suite unavailable"))
}

/// Derives target from frame 0xD051/v1: the fixed binding between the
/// readiness subject this Seal is conditioned on and the pinned predecessor,
/// independent of which certificate variant eventually proves readiness.
pub fn seal_target_digest(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    subject_identity: Digest32,
    predecessor_tag: u16,
    predecessor_digest: Digest32,
) -> Result<Digest32, NodeCoreError> {
    if predecessor_tag != SEAL_PREDECESSOR_TAG_GENESIS {
        return Err(invalid("seal target predecessor tag is unsupported"));
    }
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(SEAL_TARGET_PREIMAGE_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_digest32(&subject_identity)?)?;
    frame.field_u16(2, predecessor_tag)?;
    frame.field_bytes(3, encode_digest32(&predecessor_digest)?)?;
    hashed_context(resolver, context, &frame.finish()?)
}

/// Forces the explicit DR-0187 high-bit convention on a request preimage
/// digest: `request_id[0] |= 0x80`. Exposed separately from
/// seal_request_id so tests can exercise the exact byte-level postcondition
/// -- unchanged when the bit was already set, changed only in that one bit
/// otherwise -- without depending on any particular hash output.
pub(crate) fn force_request_high_bit(digest: Digest32) -> [u8; 32] {
    let mut request_id: [u8; 32] = digest.bytes();
    request_id[0] |= 0x80;
    request_id
}

/// Derives the candidate request_id from frame 0xD052/v1: hashes
/// (target, certificate_digest) at the outgoing epoch, then applies
/// force_request_high_bit exactly as DR-0187 specifies. Two Seal candidates
/// sharing one target but a different certificate variant therefore always
/// produce different request ids/candidates, never a conflicting overwrite
/// of one header.
pub fn seal_request_id(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    target: Digest32,
    certificate_digest: Digest32,
) -> Result<[u8; 32], NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(SEAL_REQUEST_PREIMAGE_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_digest32(&target)?)?;
    frame.field_bytes(2, encode_digest32(&certificate_digest)?)?;
    let digest: Digest32 = hashed_context(resolver, context, &frame.finish()?)?;
    Ok(force_request_high_bit(digest))
}

/// Exact digest of the staged immutable certificate blob, in the
/// HashPurpose::Certificate domain DR-0187 specifies ("The actual
/// certificate reference uses Certificate at outgoing epoch"). Deliberately
/// a different domain than the NodeEvent-purpose candidate/history digests
/// (see super::engine::candidate_digest) and than the target/request
/// preimages above, which DR-0187 pins to NodeEvent instead: reusing one
/// purpose for both would let a certificate blob and a target/request
/// preimage collide under the same domain separation tag.
pub fn seal_certificate_digest(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    certificate_bytes: &[u8],
) -> Result<Digest32, NodeCoreError> {
    resolver
        .hash_for_purpose(epoch, HashPurpose::Certificate, certificate_bytes)
        .map_err(|_| invalid("seal certificate hash suite unavailable"))
}

/// The accepted outcome DR-0187 0xD053 frame carries. Added for the closed
/// wire contract; the durable Seal completion that would actually construct
/// and retain one is a separate storage-owning deliverable (see the
/// module-level doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealOutcome {
    pub target: Digest32,
    pub request: [u8; 32],
    pub seal_block_height: u64,
    pub seal_block_digest: Digest32,
}

fn validate_seal_outcome_structure(outcome: &SealOutcome) -> Result<(), NodeCoreError> {
    if outcome.request == [0u8; 32] || outcome.request[0] & 0x80 == 0 {
        return Err(invalid("seal outcome request is not a sealed request id"));
    }
    if outcome.seal_block_height == 0 {
        return Err(invalid("seal outcome block height must not be zero"));
    }
    Ok(())
}

/// Encodes frame 0xD053/v1.
pub fn encode_seal_outcome(outcome: &SealOutcome) -> Result<Vec<u8>, NodeCoreError> {
    validate_seal_outcome_structure(outcome)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(SEAL_OUTCOME_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_digest32(&outcome.target)?)?;
    frame.field_bytes(2, outcome.request.to_vec())?;
    frame.field_u64(3, outcome.seal_block_height)?;
    frame.field_bytes(4, encode_digest32(&outcome.seal_block_digest)?)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_SEAL_OUTCOME_BYTES {
        return Err(invalid("seal outcome exceeds its frame bound"));
    }
    Ok(bytes)
}

/// Strictly decodes frame 0xD053/v1.
pub fn decode_seal_outcome(bytes: &[u8]) -> Result<SealOutcome, NodeCoreError> {
    if bytes.len() > MAX_SEAL_OUTCOME_BYTES {
        return Err(invalid("seal outcome exceeds its frame bound"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(SEAL_OUTCOME_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let request: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| invalid("seal outcome request length"))?;
    let outcome: SealOutcome = SealOutcome {
        target: decode_digest32(frame.required_field(1)?)?,
        request,
        seal_block_height: frame.required_u64(3)?,
        seal_block_digest: decode_digest32(frame.required_field(4)?)?,
    };
    if encode_seal_outcome(&outcome)? != bytes {
        return Err(invalid("noncanonical seal outcome"));
    }
    Ok(outcome)
}

/// Pure (storage-free) decode of candidate.intent embedded BusinessCutIdentity
/// bytes, shared by super::policy Seal authentication arm and tests.
/// Decoding is the only cross-module coupling this verification half takes
/// on business-reconstruction cut identity type: everything else about
/// SealIntent stays opaque to that layer, matching DR-0187 "bounded
/// references, not a saved-cut superframe."
pub(crate) fn decode_seal_cut_identity(
    intent: &SealIntent,
) -> Result<BusinessCutIdentity, NodeCoreError> {
    decode_business_cut_identity(&intent.cut_identity_bytes)
        .map_err(|_| invalid("invalid seal candidate cut identity"))
}

/// Exact semantic cut digest of a decoded cut identity, in the same domain
/// business-reconstruction itself uses, exposed here so pure Seal
/// authentication never needs its own separate import of
/// `business_reconstruction::cut`.
pub(crate) fn seal_cut_identity_digest(
    resolver: &HashSuiteResolver,
    identity: &BusinessCutIdentity,
) -> Result<Digest32, NodeCoreError> {
    business_cut_identity_digest(resolver, identity)
        .map_err(|_| invalid("seal candidate cut identity digest"))
}

/// Re-verifies, through durable storage and the staged immutable certificate
/// blob, every warrant pure authentication cannot decide purely:
///
/// * DrainSet has actually committed for this epoch (OrderedRefusal::NoFreeze
///   otherwise -- Seal cannot warrant before a complete post-drain cut
///   exists);
/// * the staged certificate blob exists, matches its declared digest and
///   length exactly, and decodes as a ReadinessCertificate over exactly the
///   candidate own readiness_subject;
/// * that certificate successor quorum is genuinely valid
///   (ReadinessCertifier::verify_certificate: every vote signature, every
///   signer registered in the certified successor set, and aggregate
///   voting power at or above that set own quorum threshold); and
/// * every member of the certified successor set is still a currently
///   committed, eligible bond (epoch_transition::check_next_set_eligibility,
///   derived from the same post-drain state, not the certificate own
///   supplied set alone).
///
/// Readiness is not serving permission, and this function grants none: it
/// only proves that honest proposal/vote exposure for this exact Seal
/// candidate is warranted.
pub(crate) fn require_seal_warrant<S: StructuredStateReader>(
    store: &S,
    context: &DurableOperationContext,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> Result<(), OrderedEconomicsError> {
    super::preflight::require_live_authority(store, context, env)?;
    let intent: SealIntent = decode_seal_intent(&candidate.intent)
        .map_err(|_| OrderedEconomicsError::Unauthenticated("invalid seal candidate intent"))?;
    let chain: &ChainId = env.policy.context().chain_id();
    let epoch: Epoch = env.policy.context().epoch();
    if super::drain_set::read_drain_set_record(store, context, env.policy.domain(), chain, epoch)?
        .is_none()
    {
        return Err(OrderedEconomicsError::Refused(OrderedRefusal::NoFreeze));
    }
    // DR-0187: bounded exact-range reads over the actual PortableBlobRepository
    // owner, never an unbounded whole-blob fetch. The descriptor length is
    // cross-checked before a single byte is read, so a corrupt or
    // adversarially oversized stored row cannot force an unbounded read.
    let composition = env
        .seal
        .as_ref()
        .ok_or(OrderedEconomicsError::Prerequisite(
            "ordered Seal warrant requires the live Seal composition",
        ))?;
    let descriptor: PortableBlobDescriptor = composition
        .blobs
        .read_portable_blob_descriptor(&intent.certificate_digest)
        .map_err(|_| {
            OrderedEconomicsError::Prerequisite("seal certificate descriptor read failed")
        })?
        .ok_or(OrderedEconomicsError::Prerequisite(
            "seal certificate blob is absent",
        ))?;
    if descriptor.digest() != intent.certificate_digest
        || descriptor.length() as u64 != u64::from(intent.certificate_length)
    {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal certificate length disagrees with the staged blob",
        ));
    }
    let mut certificate_bytes: Vec<u8> = Vec::with_capacity(descriptor.length());
    let mut offset: usize = 0;
    while offset < descriptor.length() {
        let remaining: usize = descriptor.length() - offset;
        let limit: NonZeroUsize = NonZeroUsize::new(remaining.min(MAX_PORTABLE_CHUNK_BYTES))
            .ok_or(OrderedEconomicsError::Prerequisite(
                "seal certificate chunk limit",
            ))?;
        let request: PortableBlobChunkRequest =
            PortableBlobChunkRequest::new(descriptor, offset, limit).map_err(|_| {
                OrderedEconomicsError::Prerequisite("seal certificate chunk request")
            })?;
        match composition.blobs.read_portable_blob_chunk(&request) {
            Ok(PortableBlobChunkOutcome::Chunk(chunk)) => {
                offset = offset.checked_add(chunk.bytes().len()).ok_or(
                    OrderedEconomicsError::Prerequisite("seal certificate chunk overflow"),
                )?;
                certificate_bytes.extend_from_slice(chunk.bytes());
            }
            Ok(PortableBlobChunkOutcome::Corrupt) | Err(_) => {
                return Err(OrderedEconomicsError::Prerequisite(
                    "seal certificate blob changed or corrupt",
                ));
            }
        }
    }
    let actual_digest: Digest32 =
        seal_certificate_digest(env.resolver(), epoch, &certificate_bytes)
            .map_err(OrderedEconomicsError::Node)?;
    if actual_digest != intent.certificate_digest {
        return Err(OrderedEconomicsError::Prerequisite(
            "seal certificate blob digest mismatch",
        ));
    }
    let certificate: ReadinessCertificate = decode_readiness_certificate(&certificate_bytes)
        .map_err(|_| OrderedEconomicsError::Prerequisite("seal certificate schema"))?;
    if certificate.subject != intent.readiness_subject {
        return Err(OrderedEconomicsError::Unauthenticated(
            "seal certificate subject differs from the candidate intent",
        ));
    }
    let certifier: ReadinessCertifier<'_> =
        ReadinessCertifier::new(env.resolver(), &certificate.subject, &certificate.next_set)
            .map_err(|_| OrderedEconomicsError::Prerequisite("seal readiness certifier context"))?;
    certifier
        .verify_certificate(&certificate)
        .map_err(|_| OrderedEconomicsError::Prerequisite("seal readiness certificate quorum"))?;
    let next_members: Vec<FastPathValidatorEntry> = certificate
        .next_set
        .validators()
        .iter()
        .map(|member| FastPathValidatorEntry {
            id: member.id,
            voting_power: member.voting_power,
            signature_scheme: member.signature_scheme,
            public_key: member.public_key.clone(),
        })
        .collect();
    epoch_transition::check_next_set_eligibility(
        store,
        context,
        env.policy.domain(),
        chain,
        epoch,
        &next_members,
    )
    .map_err(|error: NextSetEligibilityError| match error {
        NextSetEligibilityError::Ineligible => {
            OrderedEconomicsError::Refused(OrderedRefusal::IneligibleNextSet)
        }
        NextSetEligibilityError::Prerequisite => OrderedEconomicsError::Prerequisite(
            "seal successor set lacks a committed eligibility prerequisite",
        ),
        NextSetEligibilityError::Node(error) => OrderedEconomicsError::Node(error),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::business_reconstruction::cut::{BusinessCutCollection, BusinessCutCollectionRoot};
    use consensus::DrainUnionIdentity;

    fn resolver() -> HashSuiteResolver {
        crate::genesis::tests::resolver()
    }

    fn context() -> PublicationContext {
        PublicationContext::new(
            crate::genesis::tests::chain(),
            ProtocolVersion::new(3),
            Epoch::new(5),
        )
        .unwrap()
    }

    fn digest(seed: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Blake3_256, [seed; 32])
    }

    fn root(seed: u8, collection: BusinessCutCollection) -> BusinessCutCollectionRoot {
        BusinessCutCollectionRoot {
            collection,
            count: 0,
            root: digest(seed),
        }
    }

    fn cut_identity_bytes() -> Vec<u8> {
        let identity = BusinessCutIdentity {
            context: context(),
            domain: AtomicityDomainId::new([2; 32]).unwrap(),
            genesis_digest: digest(1),
            validator_set_digest: digest(2),
            ordered_history: OrderedHistoryIdentity {
                context: context(),
                domain: AtomicityDomainId::new([2; 32]).unwrap(),
                genesis_digest: digest(1),
                anchor: digest(3),
                through_height: 9,
                through_view: 9,
                through_digest: digest(4),
            },
            drain_request_id: [0x85; 32],
            drain_block_height: 6,
            drain_candidate_digest: digest(6),
            drain_union: DrainUnionIdentity {
                chain_id: context().chain_id().clone(),
                protocol_version: context().protocol_version(),
                epoch: context().epoch(),
                domain: AtomicityDomainId::new([2; 32]).unwrap(),
                closure_request_id: [7; 32],
                closure_height: 4,
                signer_count: 1,
                member_count: 1,
                entries_digest: digest(8),
            },
            generation_floor: protocol_types::ExecutionGeneration::new(1),
            business: [
                root(9, BusinessCutCollection::State),
                root(10, BusinessCutCollection::Receipts),
                root(11, BusinessCutCollection::ObjectHeads),
                root(12, BusinessCutCollection::ObjectVersions),
            ],
            artifacts: root(13, BusinessCutCollection::Artifacts),
        };
        crate::business_reconstruction::cut::encode_business_cut_identity(&identity).unwrap()
    }

    fn readiness_subject() -> ReadinessSubject {
        ReadinessSubject {
            chain_id: context().chain_id().clone(),
            protocol_version: context().protocol_version(),
            epoch: context().epoch(),
            genesis_digest: digest(1),
            domain: AtomicityDomainId::new([2; 32]).unwrap(),
            outgoing_set_digest: digest(14),
            cut_digest: digest(15),
            next_epoch: Epoch::new(context().epoch().get() + 1),
            next_set_digest: digest(16),
            schedule_digest: consensus::readiness::readiness_schedule_digest(
                &resolver(),
                context().epoch(),
            )
            .unwrap(),
        }
    }

    fn valid_intent() -> SealIntent {
        SealIntent {
            readiness_subject: readiness_subject(),
            cut_identity_bytes: cut_identity_bytes(),
            predecessor_tag: SEAL_PREDECESSOR_TAG_GENESIS,
            predecessor_digest: digest(1),
            certificate_digest: digest(20),
            certificate_length: 123,
        }
    }

    #[test]
    fn seal_intent_round_trips() {
        let intent: SealIntent = valid_intent();
        let bytes: Vec<u8> = encode_seal_intent(&intent).unwrap();
        assert_eq!(decode_seal_intent(&bytes).unwrap(), intent);
    }

    #[test]
    fn seal_intent_encoding_is_deterministic() {
        let a: Vec<u8> = encode_seal_intent(&valid_intent()).unwrap();
        let b: Vec<u8> = encode_seal_intent(&valid_intent()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn seal_intent_rejects_zero_predecessor_tag_and_bad_certificate_length() {
        let mut intent: SealIntent = valid_intent();
        intent.predecessor_tag = 0;
        assert!(encode_seal_intent(&intent).is_err());

        let mut zero_cert: SealIntent = valid_intent();
        zero_cert.certificate_length = 0;
        assert!(encode_seal_intent(&zero_cert).is_err());

        let mut huge_cert: SealIntent = valid_intent();
        huge_cert.certificate_length = u32::try_from(MAX_READINESS_CERTIFICATE_BYTES + 1).unwrap();
        assert!(encode_seal_intent(&huge_cert).is_err());
    }

    #[test]
    fn seal_intent_rejects_oversized_cut_identity() {
        let mut intent: SealIntent = valid_intent();
        intent.cut_identity_bytes = vec![0u8; MAX_SEAL_CUT_IDENTITY_BYTES + 1];
        assert!(encode_seal_intent(&intent).is_err());
    }

    #[test]
    fn seal_intent_decode_rejects_wrong_frame_type() {
        let mut frame = CanonicalStruct::new(0x1234, ENCODING_VERSION);
        frame.field_bytes(1, vec![1, 2, 3]).unwrap();
        let bytes = frame.finish().unwrap();
        assert!(decode_seal_intent(&bytes).is_err());
    }

    #[test]
    fn seal_intent_decode_rejects_truncation() {
        let mut bytes: Vec<u8> = encode_seal_intent(&valid_intent()).unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(decode_seal_intent(&bytes).is_err());
    }

    #[test]
    fn seal_cut_identity_round_trips_through_decode_seal_cut_identity() {
        let intent: SealIntent = valid_intent();
        let identity: BusinessCutIdentity = decode_seal_cut_identity(&intent).unwrap();
        assert_eq!(identity.ordered_history.through_height, 9);
    }

    #[test]
    fn seal_target_and_request_are_deterministic_and_request_bit_is_set() {
        let resolver: HashSuiteResolver = resolver();
        let context: PublicationContext = context();
        let subject_identity: Digest32 = digest(30);
        let target: Digest32 = seal_target_digest(
            &resolver,
            &context,
            subject_identity,
            SEAL_PREDECESSOR_TAG_GENESIS,
            digest(1),
        )
        .unwrap();
        let again: Digest32 = seal_target_digest(
            &resolver,
            &context,
            subject_identity,
            SEAL_PREDECESSOR_TAG_GENESIS,
            digest(1),
        )
        .unwrap();
        assert_eq!(target, again);
        let request: [u8; 32] = seal_request_id(&resolver, &context, target, digest(20)).unwrap();
        assert_eq!(request[0] & 0x80, 0x80);
        let other_cert: [u8; 32] =
            seal_request_id(&resolver, &context, target, digest(21)).unwrap();
        assert_ne!(
            request, other_cert,
            "different certificates diverge the request/candidate"
        );
    }

    #[test]
    fn force_request_high_bit_preserves_an_already_set_bit_exactly() {
        // Explicit fixture whose own first byte already carries the high
        // bit: the OR must leave every byte, including byte 0, unchanged.
        let already_set: Digest32 = Digest32::new(HashAlgorithmId::Blake3_256, [0x81; 32]);
        let forced: [u8; 32] = force_request_high_bit(already_set);
        assert_eq!(forced, already_set.bytes());
        assert_eq!(forced[0], 0x81);
    }

    #[test]
    fn force_request_high_bit_sets_only_the_high_bit_on_a_clear_fixture() {
        // Explicit fixture whose own first byte has the high bit clear:
        // the OR must change only that one bit of byte 0 and nothing else.
        let mut clear_bytes: [u8; 32] = [0x01; 32];
        clear_bytes[0] = 0x05;
        let clear: Digest32 = Digest32::new(HashAlgorithmId::Blake3_256, clear_bytes);
        let forced: [u8; 32] = force_request_high_bit(clear);
        assert_ne!(forced, clear.bytes());
        assert_eq!(forced[0], 0x85);
        assert_eq!(&forced[1..], &clear.bytes()[1..]);
    }

    #[test]
    fn seal_request_id_applies_force_request_high_bit_to_its_own_digest() {
        // Not a roundtrip/determinism check alone: ties the production
        // function to the exact byte-level primitive the two tests above
        // independently characterize.
        let resolver: HashSuiteResolver = resolver();
        let context: PublicationContext = context();
        let target: Digest32 = digest(30);
        let certificate_digest: Digest32 = digest(20);
        let mut frame: CanonicalStruct =
            CanonicalStruct::new(SEAL_REQUEST_PREIMAGE_TYPE, ENCODING_VERSION);
        frame
            .field_bytes(1, encode_digest32(&target).unwrap())
            .unwrap();
        frame
            .field_bytes(2, encode_digest32(&certificate_digest).unwrap())
            .unwrap();
        let raw: Digest32 = hashed_context(&resolver, &context, &frame.finish().unwrap()).unwrap();
        let expected: [u8; 32] = force_request_high_bit(raw);
        let actual: [u8; 32] =
            seal_request_id(&resolver, &context, target, certificate_digest).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn seal_certificate_digest_differs_from_the_same_bytes_under_node_event_purpose() {
        // DR-0187 pins the certificate reference to HashPurpose::Certificate,
        // not the NodeEvent purpose target/request preimages use. Proven
        // independently of any hardcoded hex literal: the two purposes must
        // disagree on the exact same input bytes.
        let resolver: HashSuiteResolver = resolver();
        let epoch: Epoch = context().epoch();
        let bytes: Vec<u8> = vec![7u8; 64];
        let certificate_purpose: Digest32 =
            seal_certificate_digest(&resolver, epoch, &bytes).unwrap();
        let node_event_purpose: Digest32 = resolver
            .hash_for_purpose(epoch, HashPurpose::NodeEvent, &bytes)
            .unwrap();
        assert_ne!(certificate_purpose, node_event_purpose);
    }

    #[test]
    fn seal_intent_and_target_reject_every_unsupported_predecessor_tag() {
        let mut unknown: SealIntent = valid_intent();
        unknown.predecessor_tag = SEAL_PREDECESSOR_TAG_GENESIS.checked_add(1).unwrap();
        assert!(encode_seal_intent(&unknown).is_err());

        let resolver: HashSuiteResolver = resolver();
        let context: PublicationContext = context();
        assert!(
            seal_target_digest(
                &resolver,
                &context,
                digest(30),
                SEAL_PREDECESSOR_TAG_GENESIS.checked_add(1).unwrap(),
                digest(1),
            )
            .is_err()
        );
    }

    #[test]
    fn seal_outcome_round_trips_and_rejects_unset_high_bit() {
        let mut request: [u8; 32] = [1; 32];
        request[0] |= 0x80;
        let outcome: SealOutcome = SealOutcome {
            target: digest(1),
            request,
            seal_block_height: 10,
            seal_block_digest: digest(2),
        };
        let bytes: Vec<u8> = encode_seal_outcome(&outcome).unwrap();
        assert_eq!(decode_seal_outcome(&bytes).unwrap(), outcome);

        let mut unset: SealOutcome = outcome;
        unset.request[0] &= !0x80;
        assert!(encode_seal_outcome(&unset).is_err());

        let mut zero_height: SealOutcome = outcome;
        zero_height.seal_block_height = 0;
        assert!(encode_seal_outcome(&zero_height).is_err());
    }

    #[test]
    fn seal_outcome_decode_rejects_truncation() {
        let mut request: [u8; 32] = [3; 32];
        request[0] |= 0x80;
        let outcome: SealOutcome = SealOutcome {
            target: digest(1),
            request,
            seal_block_height: 10,
            seal_block_digest: digest(2),
        };
        let mut bytes: Vec<u8> = encode_seal_outcome(&outcome).unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(decode_seal_outcome(&bytes).is_err());
    }
}
