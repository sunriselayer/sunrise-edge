//! DR-0154 execution-free publication: durable verified retention of one
//! full-certificate publication bundle before an availability ACK.
//!
//! [`epoch-handoff.md`](../../../../docs/architecture/epoch-handoff.md)
//! requires that, before any owned application, a quorum has durably retained
//! **the full verifying certificate, the original signed intent and every
//! required replay artifact**, and only then exposed an availability
//! acknowledgement. [`retain_publication`] is that step for one operation on
//! one replica.
//!
//! # What retention does
//!
//! 1. Strictly decodes the canonical `0xD035` bundle and refuses a domain
//!    other than this deployment's configured logical atomicity domain: an
//!    untrusted request never selects its own domain.
//! 2. CAS-fences the committed epoch record and the active per-epoch
//!    validator set, exactly as [`super::prepare`] does, and refuses a bundle
//!    bound to a non-current epoch.
//! 3. Verifies the bundle through
//!    [`consensus::bundle::verify_publication_bundle`]: a real quorum of the
//!    committed outgoing set, a witness that hashes to that certificate's
//!    execution commitment, and every declared artifact's actual bytes
//!    present and matching their content digest under a hash suite this
//!    chain's own schedule trusted for that purpose at or before the
//!    certifying epoch -- never a bundle-declared epoch or algorithm, so a
//!    legitimate artifact from a rotated-away-from suite or protocol version
//!    still verifies without reopening a downgrade risk. A hash alone is
//!    never retention.
//! 4. Re-derives the signed intent's own event digest and request identity
//!    through the ordinary authentication pipeline and requires them to equal
//!    the certificate's `tx_hash` and the bundle's declared request id. This
//!    is the binding `consensus` structurally cannot check.
//! 5. Requires the witness to be the handoff-capable `0x6424/v2` profile,
//!    derives the **required** artifact closure from its signed read, head
//!    and mutation operands, and requires the manifest to be exactly that
//!    set: a missing dependency, an unknown artifact kind, a contradictory
//!    version, a duplicate key or a claimed tombstone presented as absence
//!    all refuse the ACK.
//! 6. Persists the publication record, every artifact's exact bytes and the
//!    first ACK identity in **one** atomic commit under the writer, epoch and
//!    validator-set fences already asserted above, and only then exposes
//!    the availability vote. Signing and local verification occur before the
//!    atomic commit so the exact vote can be retained with its artifacts;
//!    a rejected or indeterminate commit
//!    exposes no signature. This is a durable-store fence, not an
//!    apply-admission gate; see "Deliberate non-scope" below.
//!
//! # What retention must not do, and does not
//!
//! Retention does not execute WASM, move objects or custody, charge fees,
//! advance the sender nonce, release or take a lock, or create an original
//! user receipt. It writes only its own publication-scoped rows, through
//! [`runtime::DurableDomainStateStore::commit_durable`] -- a state-only
//! commit with no receipt section at all -- so an honest retainer that holds
//! a **conflicting partial local prepare** for a different request over the
//! same objects verifies and retains this full certificate without
//! overwriting that lock, its object heads, its nonce row or its receipts.
//! Verification never re-runs admission against local heads.
//!
//! # Identity, signer subsets and idempotency
//!
//! The retained identity is the [`consensus::AvailabilityIdentity`] derived
//! from the bundle, which excludes the certificate's signer subset entirely.
//! An equivalent valid proof for the same operation therefore reaches the
//! same identity and returns the **same retained ACK** rather than a second
//! signature or a second stored proof variant; the first accepted proof's
//! exact bytes stay retained for audit. A bundle that derives a *different*
//! identity for an already retained `(chain, request id)` is a typed refusal
//! and signs nothing.
//!
//! # Deliberate non-scope
//!
//! This module owns retention and read-only source assembly, not the separate
//! quorum-gated apply or native HTTP/SDK/CLI composition. Retaining a bundle
//! alone does not authorize application, and an availability certificate is
//! not formed here. It provides no Freeze/DrainSet/Seal control. Bounded
//! *resumable multi-commit* transfer of a closure larger than
//! [`MAX_RETAINED_ARTIFACTS`] (or one atomic commit) is the separate
//! DrainSet-stage contract in DR-0154 and is refused here, never truncated.

use super::*;
use consensus::bundle::{
    ArtifactEntry, ArtifactKind, ArtifactManifest, LOGICAL_COMMITMENT_PROFILE,
    MAX_ENCODED_BUNDLE_BYTES, PublicationBundle, PublicationBundleError, VerifiedPublicationBundle,
    decode_artifact_manifest, decode_publication_bundle, encode_artifact_manifest,
    verify_publication_bundle,
};
use consensus::{
    AvailabilityCertifier, AvailabilityIdentity, AvailabilityVote, decode_availability_identity,
    decode_availability_vote, decode_fast_certificate, encode_availability_identity,
    encode_availability_vote, encode_fast_certificate,
};
use runtime::portable::{
    DurablePortableRepository, DurableRecordChunk, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordMetadata,
    MAX_PORTABLE_CHUNK_BYTES,
};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;

pub(crate) mod witness;

#[cfg(test)]
mod frozen_artifact_tests;
#[cfg(test)]
mod tests;

const FASTPATH_PUBLICATION_RECORD_TYPE: u16 = 0x6455;
const FASTPATH_AVAILABILITY_ACK_RECORD_TYPE: u16 = 0x6456;
const ENCODING_VERSION: u16 = 1;

/// Upper bound on the required artifact closure one atomic retention commit
/// accepts.
///
/// The runtime independently caps one atomic transaction at
/// [`runtime::MAX_ATOMIC_STATE_WRITES`] / [`runtime::MAX_ATOMIC_STATE_READS`]
/// (4,096 each); this leaves generous headroom for the fence, publication and
/// ACK rows on top of one row per artifact. A larger closure is refused with
/// [`PublicationRetentionError::ClosureTooLarge`]: DR-0154's bounded,
/// resumable chunk/cursor transfer is a separate contract, and silently
/// retaining part of a closure would expose an ACK that is not backed by
/// complete artifacts.
pub const MAX_RETAINED_ARTIFACTS: usize = 2_048;

/// Fail-closed publication-retention errors.
///
/// Distinct from [`super::FastPathError`] on purpose: retention is not an
/// admission path, and none of its refusals may be confused with an
/// admission, execution or lock outcome.
#[derive(Debug)]
pub enum PublicationRetentionError {
    /// The canonical bundle failed to decode or verify.
    Bundle(PublicationBundleError),
    /// A consensus signing/verification step failed.
    Consensus(ConsensusError),
    /// A storage or node boundary failure.
    Node(NodeCoreError),
    /// The signed intent failed the ordinary authentication pipeline.
    Admission(Box<PaidExecutionAdmissionError>),
    /// The bundle names an atomicity domain other than this deployment's
    /// configured logical domain.
    ForeignDomain,
    /// The re-derived signed-intent digest is not the certificate's
    /// `tx_hash`: the quorum did not certify these intent bytes.
    SignedIntentDigestMismatch,
    /// The signed intent's own request identity is not the bundle's declared
    /// request id.
    RequestIdMismatch,
    /// The signed intent's publication context is not the expected local
    /// serving context.
    ContextMismatch,
    /// A witness operand could not be strictly decoded.
    MalformedWitnessOperand(&'static str),
    /// A witness operand list declared more items than the encoder's own
    /// ceiling permits.
    WitnessListTooLarge {
        /// Which list.
        what: &'static str,
        /// Declared count.
        actual: usize,
        /// Accepted maximum.
        max: usize,
    },
    /// A signed read carries an observation outside the closed schema, or one
    /// that cannot legally pair with a generic state key.
    UnsupportedReadObservation(u16),
    /// Two required artifacts name the same `(kind, identity)` with different
    /// content digests.
    ContradictoryArtifact {
        /// Artifact kind discriminant.
        kind: u16,
        /// Artifact identity.
        identity: Vec<u8>,
    },
    /// The manifest omits an artifact the witness requires.
    MissingRequiredArtifact {
        /// Artifact kind discriminant.
        kind: u16,
        /// Artifact identity.
        identity: Vec<u8>,
    },
    /// The manifest declares an artifact the witness does not require, or
    /// declares a required one under the wrong content digest.
    UnrequiredArtifact {
        /// Artifact kind discriminant.
        kind: u16,
        /// Artifact identity.
        identity: Vec<u8>,
    },
    /// The required closure exceeds [`MAX_RETAINED_ARTIFACTS`].
    ClosureTooLarge {
        /// Required artifact count.
        actual: usize,
        /// Accepted maximum.
        max: usize,
    },
    /// A different publication identity is already retained for this
    /// `(chain, request id)`.
    ConflictingRetainedIdentity,
    /// The requested post-Freeze proof has not yet been durably imported.
    DrainProofNotReady,
    /// A retained row disagrees with itself or with the derived identity.
    InconsistentRetainedRecord(&'static str),
}

impl fmt::Display for PublicationRetentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DrainProofNotReady => {
                formatter.write_str("drain publication proof is not retained")
            }
            Self::Bundle(error) => error.fmt(formatter),
            Self::Consensus(error) => error.fmt(formatter),
            Self::Node(error) => error.fmt(formatter),
            Self::Admission(error) => error.fmt(formatter),
            Self::ForeignDomain => {
                formatter.write_str("publication bundle names a foreign atomicity domain")
            }
            Self::SignedIntentDigestMismatch => formatter
                .write_str("publication bundle signed intent is not the certified transaction"),
            Self::RequestIdMismatch => formatter
                .write_str("publication bundle request id is not the signed intent's request id"),
            Self::ContextMismatch => {
                formatter.write_str("publication bundle intent context is not the serving context")
            }
            Self::MalformedWitnessOperand(what) => {
                write!(formatter, "malformed commitment witness operand: {what}")
            }
            Self::WitnessListTooLarge { what, actual, max } => write!(
                formatter,
                "commitment witness {what} declares {actual} items, maximum is {max}"
            ),
            Self::UnsupportedReadObservation(tag) => write!(
                formatter,
                "commitment witness state read carries unsupported observation tag {tag}"
            ),
            Self::ContradictoryArtifact { kind, identity } => write!(
                formatter,
                "contradictory required artifact (kind {kind}, {} identity bytes)",
                identity.len()
            ),
            Self::MissingRequiredArtifact { kind, identity } => write!(
                formatter,
                "publication manifest omits required artifact (kind {kind}, {} identity bytes)",
                identity.len()
            ),
            Self::UnrequiredArtifact { kind, identity } => write!(
                formatter,
                "publication manifest declares an artifact the witness does not require (kind {kind}, {} identity bytes)",
                identity.len()
            ),
            Self::ClosureTooLarge { actual, max } => write!(
                formatter,
                "publication closure requires {actual} artifacts, maximum is {max}"
            ),
            Self::ConflictingRetainedIdentity => formatter
                .write_str("a different publication identity is already retained for this request"),
            Self::InconsistentRetainedRecord(what) => {
                write!(formatter, "inconsistent retained publication row: {what}")
            }
        }
    }
}

impl Error for PublicationRetentionError {}

impl From<PublicationBundleError> for PublicationRetentionError {
    fn from(error: PublicationBundleError) -> Self {
        Self::Bundle(error)
    }
}
impl From<ConsensusError> for PublicationRetentionError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}
impl From<crate::EnvelopeError> for PublicationRetentionError {
    fn from(value: crate::EnvelopeError) -> Self {
        <Self as From<NodeCoreError>>::from(NodeCoreError::from(value))
    }
}

impl From<NodeCoreError> for PublicationRetentionError {
    fn from(error: NodeCoreError) -> Self {
        Self::Node(error)
    }
}
impl From<DurableReadError> for PublicationRetentionError {
    fn from(error: DurableReadError) -> Self {
        Self::Node(error.into())
    }
}
impl From<RuntimeError> for PublicationRetentionError {
    fn from(error: RuntimeError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalEncodingError> for PublicationRetentionError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<CanonicalDecodingError> for PublicationRetentionError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Node(NodeCoreError::CanonicalDecoding(error))
    }
}
impl From<HashingError> for PublicationRetentionError {
    fn from(error: HashingError) -> Self {
        Self::Node(error.into())
    }
}
impl From<PaidExecutionAdmissionError> for PublicationRetentionError {
    fn from(error: PaidExecutionAdmissionError) -> Self {
        Self::Admission(Box::new(error))
    }
}
impl From<FastPathError> for PublicationRetentionError {
    fn from(error: FastPathError) -> Self {
        match error {
            FastPathError::Admission(inner) => Self::Admission(inner),
            FastPathError::Consensus(inner) => Self::Consensus(inner),
            FastPathError::Node(inner) => Self::Node(inner),
            FastPathError::Invalid(message) => {
                Self::Node(NodeCoreError::PersistenceInvariant(message))
            }
            FastPathError::Publication(inner) => *inner,
        }
    }
}

type RetentionResult<T> = Result<T, PublicationRetentionError>;

/// The deduplicated required replay-artifact closure derived from one signed
/// `0x6424/v2` witness, keyed by `(kind discriminant, identity)` so the
/// comparison against a manifest is an exact set comparison in canonical
/// order, never a count or digest-of-list.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RequiredArtifacts {
    entries: BTreeMap<(u16, Vec<u8>), [u8; 32]>,
}

impl RequiredArtifacts {
    /// Records one required artifact, refusing a contradictory digest for an
    /// identity already required.
    pub(crate) fn insert(
        &mut self,
        kind: ArtifactKind,
        identity: Vec<u8>,
        content_digest: [u8; 32],
    ) -> RetentionResult<()> {
        let key: (u16, Vec<u8>) = (kind.as_u16(), identity);
        match self.entries.get(&key) {
            Some(existing) if *existing != content_digest => {
                Err(PublicationRetentionError::ContradictoryArtifact {
                    kind: key.0,
                    identity: key.1,
                })
            }
            Some(_) => Ok(()),
            None => {
                self.entries.insert(key, content_digest);
                Ok(())
            }
        }
    }

    /// Returns the number of distinct required artifacts.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterates the closure in canonical `(kind, identity)` order -- the exact
    /// order a conforming [`ArtifactManifest`] declares its entries in.
    ///
    /// Producer-side: used by [`super::prepared_material::retain_prepared_material`]
    /// to fetch and retain each required artifact's actual bytes, and by
    /// [`assemble_publication_bundle`] to rebuild a closed [`ArtifactManifest`]
    /// from durably retained prepare-side material.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&(u16, Vec<u8>), &[u8; 32])> {
        self.entries.iter()
    }

    /// Requires `manifest` to declare exactly this closure: same identities,
    /// same content digests, nothing missing and nothing extra.
    pub(crate) fn require_closed(&self, manifest: &ArtifactManifest) -> RetentionResult<()> {
        let mut declared: BTreeMap<(u16, Vec<u8>), [u8; 32]> = BTreeMap::new();
        for entry in &manifest.entries {
            let key: (u16, Vec<u8>) = (entry.kind.as_u16(), entry.identity.clone());
            // The canonical manifest order already forbids duplicates, so a
            // repeat here would mean a decoder regression; refuse rather than
            // overwrite.
            if declared
                .insert(key.clone(), entry.content_digest.bytes())
                .is_some()
            {
                return Err(PublicationRetentionError::ContradictoryArtifact {
                    kind: key.0,
                    identity: key.1,
                });
            }
        }
        for (key, digest) in &self.entries {
            match declared.get(key) {
                Some(found) if found == digest => {}
                Some(_) => {
                    return Err(PublicationRetentionError::UnrequiredArtifact {
                        kind: key.0,
                        identity: key.1.clone(),
                    });
                }
                None => {
                    return Err(PublicationRetentionError::MissingRequiredArtifact {
                        kind: key.0,
                        identity: key.1.clone(),
                    });
                }
            }
        }
        for key in declared.keys() {
            if !self.entries.contains_key(key) {
                return Err(PublicationRetentionError::UnrequiredArtifact {
                    kind: key.0,
                    identity: key.1.clone(),
                });
            }
        }
        Ok(())
    }
}

/// One retained publication: everything the bundle carried except the
/// artifact contents, which are retained separately under their own
/// content-addressed rows so an equivalent proof never duplicates them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathPublicationRecord {
    /// Serving context this publication was retained under.
    pub context: PublicationContext,
    /// Original signed request identity.
    pub request_id: [u8; 32],
    /// Canonical `0xD030` bytes of the derived availability identity.
    pub identity: Vec<u8>,
    /// Exact original signed intent bytes.
    pub signed_intent: Vec<u8>,
    /// Exact bytes of the first accepted full certificate, retained for
    /// audit. An equivalent valid signer subset never replaces these.
    pub certificate: Vec<u8>,
    /// Exact `0x6424/v2` commitment witness bytes.
    pub witness: Vec<u8>,
    /// Exact canonical `0xD034` artifact manifest bytes.
    pub manifest: Vec<u8>,
}

/// The exact first availability acknowledgement this replica exposed for one
/// publication identity.
///
/// Persisted in the same atomic commit as the publication record and its
/// artifacts, so a signature can never exist without the complete retention
/// it attests to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPathAvailabilityAckRecord {
    /// Canonical `0xD030` bytes of the acknowledged identity.
    pub identity: Vec<u8>,
    /// Canonical `0xD031` bytes of the exposed vote.
    pub vote: Vec<u8>,
}

/// One retained publication record, keyed by the original signed request id.
pub fn fastpath_publication_key(
    chain: &ChainId,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"publication/");
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// One retained publication artifact's exact content bytes, addressed by the
/// artifact kind and its verified content digest.
///
/// Keying by content digest rather than by ordinal means an equivalent proof
/// for the same operation rewrites byte-identical rows instead of
/// accumulating proof variants.
pub fn fastpath_publication_artifact_key(
    chain: &ChainId,
    request_id: &[u8; 32],
    kind: ArtifactKind,
    content_digest: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"publication-artifact/");
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(request_id);
    key.extend_from_slice(&kind.as_u16().to_be_bytes());
    key.extend_from_slice(content_digest);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// This replica's first exposed availability acknowledgement for one request.
pub fn fastpath_availability_ack_key(
    chain: &ChainId,
    request_id: &[u8; 32],
) -> Result<Vec<u8>, NodeCoreError> {
    let mut key: Vec<u8> = local_instance_state::FASTPATH_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"availability-ack/");
    key.extend(canonical_encoding::encode_chain_id(chain)?);
    key.extend_from_slice(request_id);
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Encodes one [`FastPathPublicationRecord`] (`0x6455/v1`).
pub fn encode_fastpath_publication_record(
    record: &FastPathPublicationRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FASTPATH_PUBLICATION_RECORD_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        encode_publication_context(&record.context)
            .map_err(|_| NodeCoreError::PersistenceInvariant("publication record context"))?,
    )?;
    frame.field_bytes(2, record.request_id.to_vec())?;
    frame.field_bytes(3, record.identity.clone())?;
    frame.field_bytes(4, record.signed_intent.clone())?;
    frame.field_bytes(5, record.certificate.clone())?;
    frame.field_bytes(6, record.witness.clone())?;
    frame.field_bytes(7, record.manifest.clone())?;
    Ok(frame.finish()?)
}

/// Strictly decodes one [`FastPathPublicationRecord`], requiring the exact
/// type/version, exactly fields 1-7, a nested identity that itself decodes
/// canonically, and byte-exact re-encoding.
pub fn decode_fastpath_publication_record(
    bytes: &[u8],
) -> Result<FastPathPublicationRecord, NodeCoreError> {
    let frame = canonical_encoding::decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_PUBLICATION_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7])?;
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)
        .map_err(|_| NodeCoreError::PersistenceInvariant("publication record context"))?;
    let request_field: &[u8] = frame.required_field(2)?;
    let request_id: [u8; 32] = request_field
        .try_into()
        .map_err(|_| NodeCoreError::PersistenceInvariant("publication record request id length"))?;
    let identity: Vec<u8> = frame.required_field(3)?.to_vec();
    decode_availability_identity(&identity)
        .map_err(|_| NodeCoreError::PersistenceInvariant("publication record identity"))?;
    let record: FastPathPublicationRecord = FastPathPublicationRecord {
        context,
        request_id,
        identity,
        signed_intent: frame.required_field(4)?.to_vec(),
        certificate: frame.required_field(5)?.to_vec(),
        witness: frame.required_field(6)?.to_vec(),
        manifest: frame.required_field(7)?.to_vec(),
    };
    if encode_fastpath_publication_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical publication record",
        ));
    }
    Ok(record)
}

/// Encodes one [`FastPathAvailabilityAckRecord`] (`0x6456/v1`).
pub fn encode_fastpath_availability_ack_record(
    record: &FastPathAvailabilityAckRecord,
) -> Result<Vec<u8>, NodeCoreError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(FASTPATH_AVAILABILITY_ACK_RECORD_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, record.identity.clone())?;
    frame.field_bytes(2, record.vote.clone())?;
    Ok(frame.finish()?)
}

/// Strictly decodes one [`FastPathAvailabilityAckRecord`], requiring the
/// exact type/version, exactly fields 1-2, nested identity/vote frames that
/// themselves decode canonically, and byte-exact re-encoding.
pub fn decode_fastpath_availability_ack_record(
    bytes: &[u8],
) -> Result<FastPathAvailabilityAckRecord, NodeCoreError> {
    let frame = canonical_encoding::decode_canonical_frame(bytes)?;
    frame.require_type(FASTPATH_AVAILABILITY_ACK_RECORD_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let record: FastPathAvailabilityAckRecord = FastPathAvailabilityAckRecord {
        identity: frame.required_field(1)?.to_vec(),
        vote: frame.required_field(2)?.to_vec(),
    };
    decode_availability_identity(&record.identity)
        .map_err(|_| NodeCoreError::PersistenceInvariant("availability ack identity"))?;
    decode_availability_vote(&record.vote)
        .map_err(|_| NodeCoreError::PersistenceInvariant("availability ack vote"))?;
    if encode_fastpath_availability_ack_record(&record)? != bytes {
        return Err(NodeCoreError::PersistenceInvariant(
            "noncanonical availability ack record",
        ));
    }
    Ok(record)
}

/// Verifies one canonical publication bundle and, on success, durably retains
/// its record, every required artifact's exact bytes and this replica's first
/// availability acknowledgement in one atomic commit -- then returns that
/// acknowledgement.
///
/// See the module documentation for the complete ordered contract, the
/// deliberate non-mutation guarantees and the non-scope.
///
/// `expected` is the locally pinned serving [`PublicationContext`]; `domain`
/// is the deployment's configured logical atomicity domain. Neither may come
/// from the bundle or from an untrusted transport request. `history` mirrors
/// [`super::prepare`]/[`super::apply`]'s own bounded historical-resolver
/// parameter and must be locally pinned, never supplied by the bundle or an
/// untrusted transport request.
#[allow(clippy::too_many_arguments)]
pub fn retain_publication<S, C>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    bundle_bytes: &[u8],
    signer: &C,
) -> RetentionResult<AvailabilityVote>
where
    S: StructuredDurableDomainStateStore,
    C: ConsensusSigner,
{
    retain_publication_gated(
        crate::serving_authority::ServingGate::Original,
        store,
        context,
        domain,
        resolver,
        history,
        expected,
        bundle_bytes,
        signer,
    )
}

/// [`retain_publication`] under one invocation gate. A successor ACK is
/// signed only by the fresh namespace member, and a retained ACK is
/// re-exposed only under the fresh live warrant.
#[allow(clippy::too_many_arguments)]
pub(crate) fn retain_publication_gated<S, C>(
    gate: crate::serving_authority::ServingGate<'_>,
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    bundle_bytes: &[u8],
    signer: &C,
) -> RetentionResult<AvailabilityVote>
where
    S: StructuredDurableDomainStateStore,
    C: ConsensusSigner,
{
    if history.len() > crate::publication::MAX_PUBLICATION_HISTORY {
        return Err(PublicationRetentionError::Node(
            NodeCoreError::PersistenceInvariant("resolver history bound"),
        ));
    }
    let bundle: PublicationBundle = decode_publication_bundle(bundle_bytes)?;
    if bundle.domain != domain {
        return Err(PublicationRetentionError::ForeignDomain);
    }
    let chain: ChainId = expected.chain_id().clone();
    if bundle.certificate.chain_id != chain
        || bundle.certificate.protocol_version != expected.protocol_version()
    {
        return Err(PublicationRetentionError::ContextMismatch);
    }
    gate.require_live(store, context, domain)?;
    gate.require_local_signer(store, signer.validator_id())?;

    // Fence the committed epoch record and the active validator set. Unlike
    // a fresh admission, a matching retained ACK may still be replayed after
    // Freeze; the closure fence is therefore applied below only after the
    // already-retained branch has reconciled its complete saved history.
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let epoch_record: local_instance_state::FastPathEpochRecord =
        mutation_fence::fence_epoch_state(store, context, domain, &chain, &mut reads)?;
    if epoch_record.current_epoch != bundle.certificate.epoch {
        return Err(PublicationRetentionError::Node(
            NodeCoreError::EpochMismatch {
                expected: epoch_record.current_epoch,
                actual: bundle.certificate.epoch,
            },
        ));
    }
    let validator_context: PublicationContext = expected.clone();
    let validator_set: ValidatorSet = load_validator_set(
        store,
        context,
        domain,
        resolver,
        &validator_context,
        &epoch_record,
        &mut reads,
    )?;

    let fast_certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        chain.clone(),
        expected.protocol_version(),
        expected.epoch(),
        validator_set.clone(),
    )?;
    let verified: VerifiedPublicationBundle = verify_publication_bundle(
        &bundle,
        &fast_certifier,
        &FastPathEd25519Verifier,
        resolver,
        history,
    )?;
    let identity: AvailabilityIdentity = verified.identity;

    // The binding `consensus` structurally cannot check: these exact intent
    // bytes really are the certified transaction, and really carry the
    // declared request identity and serving context.
    let (authenticated, event_digest, _request) =
        authenticate_and_identify(resolver, expected, &bundle.signed_intent)?;
    if event_digest != bundle.certificate.tx_hash {
        return Err(PublicationRetentionError::SignedIntentDigestMismatch);
    }
    if authenticated.intent().request_id != bundle.request_id {
        return Err(PublicationRetentionError::RequestIdMismatch);
    }
    if authenticated.intent().context != *expected {
        return Err(PublicationRetentionError::ContextMismatch);
    }

    // Strictly decode the handoff-capable witness and require the manifest to
    // be exactly the closure its signed operands demand.
    let (witness_event_digest, required) = witness::required_artifacts(&bundle.witness)?;
    if witness_event_digest != event_digest {
        return Err(PublicationRetentionError::SignedIntentDigestMismatch);
    }
    if required.len() > MAX_RETAINED_ARTIFACTS {
        return Err(PublicationRetentionError::ClosureTooLarge {
            actual: required.len(),
            max: MAX_RETAINED_ARTIFACTS,
        });
    }
    required.require_closed(&bundle.manifest)?;

    let identity_bytes: Vec<u8> = encode_availability_identity(&identity)?;
    let publication_key: Vec<u8> = fastpath_publication_key(&chain, &bundle.request_id)?;
    let ack_key: Vec<u8> = fastpath_availability_ack_key(&chain, &bundle.request_id)?;
    let observed_publication: VersionedStateValue =
        store.get_versioned_durable(context, domain, &publication_key)?;
    let observed_ack: VersionedStateValue =
        store.get_versioned_durable(context, domain, &ack_key)?;

    let availability_certifier: AvailabilityCertifier = AvailabilityCertifier::new(
        chain.clone(),
        expected.protocol_version(),
        expected.epoch(),
        validator_set,
    )?;
    let staged_artifacts: BTreeMap<Vec<u8>, Vec<u8>> = stage_publication_artifacts(
        &chain,
        &bundle.request_id,
        &bundle.manifest,
        &bundle.contents,
    )?;

    // Reconcile an already retained publication before anything else is
    // written. An equivalent valid proof for the same operation reaches the
    // same identity and returns the same retained ACK; a different identity
    // for this request id fails closed and signs nothing.
    if let Some(bytes) = observed_publication.value() {
        let existing: FastPathPublicationRecord = decode_fastpath_publication_record(bytes)?;
        if existing.identity != identity_bytes {
            return Err(PublicationRetentionError::ConflictingRetainedIdentity);
        }
        if existing.context != *expected
            || existing.request_id != bundle.request_id
            || existing.signed_intent != bundle.signed_intent
            || existing.witness != bundle.witness
            || existing.manifest != encode_artifact_manifest(&bundle.manifest)?
        {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "retained publication operands",
            ));
        }
        let retained_certificate =
            decode_fast_certificate(&existing.certificate).map_err(|_| {
                PublicationRetentionError::InconsistentRetainedRecord(
                    "retained publication certificate",
                )
            })?;
        fast_certifier
            .verify_certificate(&retained_certificate, &FastPathEd25519Verifier)
            .map_err(|_| {
                PublicationRetentionError::InconsistentRetainedRecord(
                    "retained publication certificate",
                )
            })?;
        if retained_certificate.chain_id != bundle.certificate.chain_id
            || retained_certificate.protocol_version != bundle.certificate.protocol_version
            || retained_certificate.epoch != bundle.certificate.epoch
            || retained_certificate.tx_hash != bundle.certificate.tx_hash
            || retained_certificate.execution_effects_hash
                != bundle.certificate.execution_effects_hash
            || retained_certificate.locked_objects_digest
                != bundle.certificate.locked_objects_digest
        {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "retained publication certificate identity",
            ));
        }
        for (key, content) in &staged_artifacts {
            let observed: VersionedStateValue =
                store.get_versioned_durable(context, domain, key)?;
            if observed.value() != Some(content.as_slice()) {
                return Err(PublicationRetentionError::InconsistentRetainedRecord(
                    "retained publication artifact",
                ));
            }
        }
        let retained: &[u8] =
            observed_ack
                .value()
                .ok_or(PublicationRetentionError::InconsistentRetainedRecord(
                    "retained publication without its acknowledgement",
                ))?;
        let ack: FastPathAvailabilityAckRecord = decode_fastpath_availability_ack_record(retained)?;
        if ack.identity != identity_bytes {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "retained acknowledgement identity",
            ));
        }
        let vote: AvailabilityVote = decode_availability_vote(&ack.vote)?;
        if vote.identity != identity
            || vote.validator != signer.validator_id()
            || vote.signature_scheme != signer.signature_scheme()
        {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "retained acknowledgement vote",
            ));
        }
        availability_certifier.verify_vote(&vote, &FastPathEd25519Verifier)?;
        return Ok(vote);
    }
    if observed_ack.value().is_some() {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "acknowledgement retained without its publication",
        ));
    }

    crate::admission_profile::fence_installed_external_request_lane(
        store,
        context,
        domain,
        expected,
        &bundle.request_id,
        crate::admission_profile::ExternalRequestLane::Owned,
        &mut reads,
    )?;

    // A fresh ACK races atomically with the committed Freeze marker. Exact
    // earlier ACK replay above remains available; a new ACK after closure
    // fails without exposing a signature or changing publication rows.
    crate::ordered_economics::fence_admission_open(
        store,
        context,
        domain,
        &chain,
        epoch_record.current_epoch,
        &mut reads,
    )?;

    // Sign only after every verification above has passed. The vote is
    // re-verified before it can be committed, so a misconfigured or rotated
    // local key can never durably retain an unverifiable acknowledgement.
    let vote: AvailabilityVote = availability_certifier.cast_vote(identity.clone(), signer)?;
    availability_certifier.verify_vote(&vote, &FastPathEd25519Verifier)?;

    let record: FastPathPublicationRecord = FastPathPublicationRecord {
        context: expected.clone(),
        request_id: bundle.request_id,
        identity: identity_bytes.clone(),
        signed_intent: bundle.signed_intent.clone(),
        certificate: encode_fast_certificate(&bundle.certificate)?,
        witness: bundle.witness.clone(),
        manifest: encode_artifact_manifest(&bundle.manifest)?,
    };
    let ack: FastPathAvailabilityAckRecord = FastPathAvailabilityAckRecord {
        identity: identity_bytes,
        vote: encode_availability_vote(&vote)?,
    };

    let mut mutations: Vec<StateMutationEntry> = Vec::new();
    for (key, content) in &staged_artifacts {
        let observed: VersionedStateValue = store.get_versioned_durable(context, domain, key)?;
        reads.insert(key.clone(), observed.revision());
        mutations.push(StateMutationEntry::new(
            key.clone(),
            StateMutation::Put(content.clone()),
        )?);
    }
    reads.insert(publication_key.clone(), observed_publication.revision());
    reads.insert(ack_key.clone(), observed_ack.revision());
    mutations.push(StateMutationEntry::new(
        publication_key,
        StateMutation::Put(encode_fastpath_publication_record(&record)?),
    )?);
    mutations.push(StateMutationEntry::new(
        ack_key,
        StateMutation::Put(encode_fastpath_availability_ack_record(&ack)?),
    )?);

    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision))
        .collect::<Result<_, RuntimeError>>()?;
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(assertions)?,
        AtomicStateMutationSet::new(mutations)?,
    )?;
    match gate.commit_durable(store, context, transaction) {
        DurableCommitOutcome::Committed => Ok(vote),
        DurableCommitOutcome::Rejected(
            DurableCommitRejection::Conflict { .. }
            | DurableCommitRejection::RequestAlreadyCommitted,
        ) => Err(PublicationRetentionError::Node(
            NodeCoreError::StateConflict,
        )),
        DurableCommitOutcome::Rejected(reason) => Err(PublicationRetentionError::Node(
            NodeCoreError::DurableCommitRejected(reason),
        )),
        // An ambiguous commit must never expose a fresh signature: the caller
        // receives the ambiguity, not the vote it would otherwise have sent.
        DurableCommitOutcome::Indeterminate(reason) => Err(PublicationRetentionError::Node(
            NodeCoreError::DurableCommitIndeterminate(reason),
        )),
    }
}

/// Read-only, restart-safe assembly of one canonical [`PublicationBundle`]
/// from this replica's own durably retained prepare-side material --
/// [`prepared_material::fastpath_prepared_witness_key`] and every
/// [`prepared_material::fastpath_prepared_artifact_key`] row
/// [`prepared_material::retain_prepared_material`] committed during a
/// handoff-capable [`super::prepare`] -- plus a genuine, independently
/// supplied [`consensus::FastCertificate`].
///
/// This performs no durable write: it never calls `prepare`, `apply` or
/// [`retain_publication`], reads only already-committed rows, and therefore
/// behaves identically before or after a process restart, as long as the
/// original `prepare` commit succeeded. `certificate_bytes` must already be a
/// real quorum certificate over this exact operation; this function
/// independently re-verifies it against the durably installed validator set
/// and independently re-verifies the whole assembled bundle through
/// [`verify_publication_bundle`] before returning it, so a caller receives
/// only an already-verified bundle -- never a partially assembled one.
///
/// Fails closed if this replica never prepared this request under the
/// handoff-capable profile, if its retained material disagrees with
/// `certificate_bytes` or the supplied `signed_bytes`, or if any required
/// artifact row is missing.
#[allow(clippy::too_many_arguments)]
pub fn assemble_publication_bundle<S>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    signed_bytes: &[u8],
    certificate_bytes: &[u8],
) -> RetentionResult<PublicationBundle>
where
    S: StructuredDurableDomainStateStore,
{
    if history.len() > crate::publication::MAX_PUBLICATION_HISTORY {
        return Err(PublicationRetentionError::Node(
            NodeCoreError::PersistenceInvariant("resolver history bound"),
        ));
    }
    let (authenticated, event_digest, _request) =
        authenticate_and_identify(resolver, expected, signed_bytes)?;
    if authenticated.intent().context != *expected {
        return Err(PublicationRetentionError::ContextMismatch);
    }
    let chain: ChainId = expected.chain_id().clone();
    let request_id: [u8; 32] = authenticated.intent().request_id;

    let mut profile_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    crate::admission_profile::fence_installed_external_request_lane(
        store,
        context,
        domain,
        expected,
        &request_id,
        crate::admission_profile::ExternalRequestLane::Owned,
        &mut profile_reads,
    )?;

    let prepared_key: Vec<u8> = fastpath_prepared_record_key(&chain, &request_id)?;
    let observed_prepared: VersionedStateValue =
        store.get_versioned_durable(context, domain, &prepared_key)?;
    let prepared_bytes: &[u8] =
        observed_prepared
            .value()
            .ok_or(PublicationRetentionError::InconsistentRetainedRecord(
                "no local prepared record for this request",
            ))?;
    let prepared: FastPathPreparedRecord =
        records::decode_fastpath_prepared_record(prepared_bytes)?;
    if prepared.signed_intent_digest != event_digest
        || prepared.context != *expected
        || prepared.request_id != request_id
    {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "prepared record does not match the supplied signed intent",
        ));
    }

    let witness_key: Vec<u8> =
        prepared_material::fastpath_prepared_witness_key(&chain, &request_id)?;
    let observed_witness: VersionedStateValue =
        store.get_versioned_durable(context, domain, &witness_key)?;
    let witness_bytes: Vec<u8> = observed_witness
        .value()
        .ok_or(PublicationRetentionError::InconsistentRetainedRecord(
            "no retained prepare-side commitment witness for this request",
        ))?
        .to_vec();

    let certificate: FastCertificate = decode_fast_certificate(certificate_bytes)?;
    if certificate.chain_id != chain
        || certificate.protocol_version != expected.protocol_version()
        || certificate.epoch != expected.epoch()
        || certificate.tx_hash != event_digest
        || certificate.execution_effects_hash != prepared.commitment
    {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "supplied certificate does not attest this replica's retained prepared commitment",
        ));
    }

    let (witness_event_digest, required) = witness::required_artifacts(&witness_bytes)?;
    if witness_event_digest != event_digest {
        return Err(PublicationRetentionError::SignedIntentDigestMismatch);
    }

    let mut entries: Vec<ArtifactEntry> = Vec::with_capacity(required.len());
    let mut contents: Vec<Vec<u8>> = Vec::with_capacity(required.len());
    for ((kind_tag, identity), digest) in required.iter() {
        let kind: ArtifactKind = ArtifactKind::from_u16(*kind_tag)?;
        let key: Vec<u8> =
            prepared_material::fastpath_prepared_artifact_key(&chain, &request_id, kind, digest)?;
        let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
        let content: Vec<u8> = observed
            .value()
            .ok_or(PublicationRetentionError::MissingRequiredArtifact {
                kind: kind.as_u16(),
                identity: identity.clone(),
            })?
            .to_vec();
        let content_digest: Digest32 = std::iter::once(resolver)
            .chain(history)
            .find_map(|candidate| {
                candidate
                    .hash_for_purpose(expected.epoch(), kind.hash_purpose(), &content)
                    .ok()
                    .filter(|computed| computed.bytes() == *digest)
            })
            .ok_or(PublicationRetentionError::InconsistentRetainedRecord(
                "retained artifact content no longer matches the witness-signed digest",
            ))?;
        entries.push(ArtifactEntry {
            kind,
            identity: identity.clone(),
            content_digest,
            content_length: u32::try_from(content.len()).map_err(|_| {
                PublicationRetentionError::Node(NodeCoreError::PersistenceInvariant(
                    "retained artifact content length",
                ))
            })?,
        });
        contents.push(content);
    }

    let bundle: PublicationBundle = PublicationBundle {
        domain,
        request_id,
        commitment_profile: LOGICAL_COMMITMENT_PROFILE,
        signed_intent: signed_bytes.to_vec(),
        certificate,
        witness: witness_bytes,
        manifest: ArtifactManifest { entries },
        contents,
    };

    // Self-verify before returning: a caller must never receive a bundle
    // this replica itself could not independently verify.
    let mut throwaway_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let epoch_record: local_instance_state::FastPathEpochRecord =
        mutation_fence::fence_epoch_state(store, context, domain, &chain, &mut throwaway_reads)?;
    let validator_set: ValidatorSet = load_validator_set(
        store,
        context,
        domain,
        resolver,
        expected,
        &epoch_record,
        &mut throwaway_reads,
    )?;
    let fast_certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        chain,
        expected.protocol_version(),
        expected.epoch(),
        validator_set,
    )?;
    let _verified: VerifiedPublicationBundle = verify_publication_bundle(
        &bundle,
        &fast_certifier,
        &FastPathEd25519Verifier,
        resolver,
        history,
    )?;

    Ok(bundle)
}

/// Reconstructs and re-verifies one locally retained full-certificate
/// publication without re-running application admission or touching locks.
/// A frozen-frontier signer uses this for every enumerated row before its
/// identity may enter the signed log. It rejects a missing ACK or artifact,
/// a corrupt original proof, and any mismatch with the signed intent. Artifact
/// metadata and the complete declared content budget are checked before body
/// allocation; exact descriptor-pinned range reads never fetch whole artifacts.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_retained_publication<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    expected: &PublicationContext,
    validator_set: &ValidatorSet,
    local_validator: ValidatorId,
    request_id: &[u8; 32],
) -> RetentionResult<AvailabilityIdentity> {
    if history.len() > crate::publication::MAX_PUBLICATION_HISTORY {
        return Err(PublicationRetentionError::Node(
            NodeCoreError::PersistenceInvariant("resolver history bound"),
        ));
    }
    let chain: ChainId = expected.chain_id().clone();
    let publication_key: Vec<u8> = fastpath_publication_key(&chain, request_id)?;
    let observed_publication: VersionedStateValue =
        store.get_versioned_durable(context, domain, &publication_key)?;
    let record_bytes: &[u8] = observed_publication.value().ok_or(
        PublicationRetentionError::InconsistentRetainedRecord(
            "missing or tombstoned frozen publication",
        ),
    )?;
    let record: FastPathPublicationRecord = decode_fastpath_publication_record(record_bytes)?;
    if record.context != *expected || record.request_id != *request_id {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "frozen publication context or request id",
        ));
    }
    let (authenticated, event_digest, _request) =
        authenticate_and_identify(resolver, expected, &record.signed_intent)?;
    if authenticated.intent().request_id != *request_id {
        return Err(PublicationRetentionError::RequestIdMismatch);
    }
    let mut profile_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    crate::admission_profile::fence_installed_external_request_lane(
        store,
        context,
        domain,
        expected,
        request_id,
        crate::admission_profile::ExternalRequestLane::Owned,
        &mut profile_reads,
    )?;
    let manifest: ArtifactManifest = decode_artifact_manifest(&record.manifest)?;
    let descriptors: Vec<DurableRecordDescriptor> =
        frozen_artifact_descriptors(store, context, domain, &chain, request_id, &manifest)?;
    let mut contents: Vec<Vec<u8>> = Vec::new();
    contents.try_reserve_exact(descriptors.len()).map_err(|_| {
        PublicationRetentionError::InconsistentRetainedRecord(
            "frozen publication artifact allocation failed",
        )
    })?;
    for descriptor in &descriptors {
        contents.push(read_frozen_artifact(store, context, domain, descriptor)?);
    }
    let bundle: PublicationBundle = PublicationBundle {
        domain,
        request_id: *request_id,
        commitment_profile: LOGICAL_COMMITMENT_PROFILE,
        signed_intent: record.signed_intent.clone(),
        certificate: decode_fast_certificate(&record.certificate)?,
        witness: record.witness.clone(),
        manifest,
        contents,
    };
    let fast_certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        chain.clone(),
        expected.protocol_version(),
        expected.epoch(),
        validator_set.clone(),
    )?;
    let verified: VerifiedPublicationBundle = verify_publication_bundle(
        &bundle,
        &fast_certifier,
        &FastPathEd25519Verifier,
        resolver,
        history,
    )?;
    if event_digest != bundle.certificate.tx_hash {
        return Err(PublicationRetentionError::SignedIntentDigestMismatch);
    }
    let (witness_event_digest, required): (Digest32, RequiredArtifacts) =
        witness::required_artifacts(&bundle.witness)?;
    if witness_event_digest != event_digest {
        return Err(PublicationRetentionError::SignedIntentDigestMismatch);
    }
    required.require_closed(&bundle.manifest)?;
    if record.identity != encode_availability_identity(&verified.identity)? {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "frozen publication identity",
        ));
    }
    let ack_key: Vec<u8> = fastpath_availability_ack_key(&chain, request_id)?;
    let observed_ack: VersionedStateValue =
        store.get_versioned_durable(context, domain, &ack_key)?;
    let ack_bytes: &[u8] =
        observed_ack
            .value()
            .ok_or(PublicationRetentionError::InconsistentRetainedRecord(
                "frozen publication without an acknowledgement",
            ))?;
    let ack: FastPathAvailabilityAckRecord = decode_fastpath_availability_ack_record(ack_bytes)?;
    if ack.identity != record.identity {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "frozen acknowledgement identity",
        ));
    }
    let vote: AvailabilityVote = decode_availability_vote(&ack.vote)?;
    if vote.identity != verified.identity || vote.validator != local_validator {
        return Err(PublicationRetentionError::InconsistentRetainedRecord(
            "frozen acknowledgement vote identity",
        ));
    }
    let availability_certifier: AvailabilityCertifier = AvailabilityCertifier::new(
        chain,
        expected.protocol_version(),
        expected.epoch(),
        validator_set.clone(),
    )?;
    availability_certifier.verify_vote(&vote, &FastPathEd25519Verifier)?;
    Ok(verified.identity)
}

/// Resolves all bounded body-free metadata before allocating any artifact
/// content. Declared lengths are untrusted until each exact state descriptor
/// agrees; a tombstone is never treated as a present empty value.
fn frozen_artifact_descriptors<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    chain: &ChainId,
    request_id: &[u8; 32],
    manifest: &ArtifactManifest,
) -> RetentionResult<Vec<DurableRecordDescriptor>> {
    if manifest.entries.len() > MAX_RETAINED_ARTIFACTS {
        return Err(PublicationRetentionError::ClosureTooLarge {
            actual: manifest.entries.len(),
            max: MAX_RETAINED_ARTIFACTS,
        });
    }
    let mut total_content_bytes: usize = 0;
    for entry in &manifest.entries {
        let declared_length: usize = usize::try_from(entry.content_length).map_err(|_| {
            PublicationRetentionError::InconsistentRetainedRecord(
                "frozen publication artifact length overflow",
            )
        })?;
        total_content_bytes = total_content_bytes.checked_add(declared_length).ok_or(
            PublicationRetentionError::InconsistentRetainedRecord(
                "frozen publication artifact length overflow",
            ),
        )?;
        if total_content_bytes > MAX_ENCODED_BUNDLE_BYTES {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "frozen publication artifact budget exceeded",
            ));
        }
    }
    let mut descriptors: Vec<DurableRecordDescriptor> = Vec::new();
    descriptors
        .try_reserve_exact(manifest.entries.len())
        .map_err(|_| {
            PublicationRetentionError::InconsistentRetainedRecord(
                "frozen publication descriptor allocation failed",
            )
        })?;
    for entry in &manifest.entries {
        let key: DurableRecordKey =
            DurableRecordKey::State(artifact_key(chain, request_id, entry)?);
        let descriptor: DurableRecordDescriptor = store
            .read_portable_descriptor(context, domain, &key)?
            .ok_or(PublicationRetentionError::InconsistentRetainedRecord(
                "missing frozen publication artifact descriptor",
            ))?;
        let declared_length: usize = usize::try_from(entry.content_length).map_err(|_| {
            PublicationRetentionError::InconsistentRetainedRecord(
                "frozen publication artifact length overflow",
            )
        })?;
        if descriptor.key() != &key
            || !matches!(
                descriptor.metadata(),
                DurableRecordMetadata::State { revision, value_length }
                    if *revision != StateRevision::INITIAL
                        && *value_length == Some(declared_length)
            )
        {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "frozen publication artifact descriptor mismatch or tombstone",
            ));
        }
        descriptors.push(descriptor);
    }
    Ok(descriptors)
}

/// Reconstructs one bounded artifact through strict ranges of a single exact
/// descriptor. Present declared-empty content receives one pinned terminal
/// empty read; every nonempty response must make positive exact progress.
pub(crate) fn read_frozen_artifact<S: DurablePortableRepository>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    descriptor: &DurableRecordDescriptor,
) -> RetentionResult<Vec<u8>> {
    let length: usize = match (descriptor.key(), descriptor.metadata()) {
        (
            DurableRecordKey::State(_),
            DurableRecordMetadata::State {
                revision,
                value_length: Some(length),
            },
        ) if *revision != StateRevision::INITIAL && *length <= MAX_ENCODED_BUNDLE_BYTES => *length,
        _ => {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "invalid frozen publication artifact metadata",
            ));
        }
    };
    let limit: NonZeroUsize = NonZeroUsize::new(MAX_PORTABLE_CHUNK_BYTES).ok_or(
        PublicationRetentionError::InconsistentRetainedRecord(
            "invalid frozen artifact chunk bound",
        ),
    )?;
    let mut content: Vec<u8> = Vec::new();
    content.try_reserve_exact(length).map_err(|_| {
        PublicationRetentionError::InconsistentRetainedRecord(
            "frozen publication artifact allocation failed",
        )
    })?;
    let mut offset: usize = 0;
    loop {
        let request: DurableRecordChunkRequest =
            DurableRecordChunkRequest::new(descriptor.clone(), offset, limit)?;
        let expected_end: usize = request.range().end;
        let expected_length: usize = expected_end.checked_sub(offset).ok_or(
            PublicationRetentionError::InconsistentRetainedRecord("frozen artifact range overflow"),
        )?;
        let chunk: Box<DurableRecordChunk> =
            match store.read_portable_chunk(context, domain, &request)? {
                DurableRecordChunkOutcome::Chunk(chunk) => chunk,
                DurableRecordChunkOutcome::Changed => {
                    return Err(PublicationRetentionError::InconsistentRetainedRecord(
                        "frozen publication artifact changed during range read",
                    ));
                }
            };
        if chunk.request() != &request
            || chunk.bytes().len() != expected_length
            || (length != 0 && expected_length == 0)
            || chunk.is_last() != (expected_end == length)
        {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "frozen publication artifact chunk mismatch",
            ));
        }
        let next_offset: usize = offset.checked_add(chunk.bytes().len()).ok_or(
            PublicationRetentionError::InconsistentRetainedRecord(
                "frozen artifact offset overflow",
            ),
        )?;
        if next_offset != expected_end || next_offset > length {
            return Err(PublicationRetentionError::InconsistentRetainedRecord(
                "frozen publication artifact chunk exceeds declared length",
            ));
        }
        content.extend_from_slice(chunk.bytes());
        if chunk.is_last() {
            if content.len() != length {
                return Err(PublicationRetentionError::InconsistentRetainedRecord(
                    "incomplete frozen publication artifact",
                ));
            }
            return Ok(content);
        }
        offset = next_offset;
    }
}

fn artifact_key(
    chain: &ChainId,
    request_id: &[u8; 32],
    entry: &ArtifactEntry,
) -> Result<Vec<u8>, NodeCoreError> {
    fastpath_publication_artifact_key(chain, request_id, entry.kind, &entry.content_digest.bytes())
}

/// Stages one manifest's artifacts for the atomic commit, deduplicating by
/// exact storage key.
///
/// Artifact rows are content-addressed by `(kind, content digest)`
/// ([`artifact_key`]/[`fastpath_publication_artifact_key`]), not by manifest
/// identity: two distinct required identities of the same kind that happen to
/// hold byte-identical content share one storage row by design. Keying by
/// storage key here first means such a pair is staged once rather than pushed
/// twice into one atomic mutation set, which
/// [`runtime::AtomicStateMutationSet::new`] would otherwise refuse outright as
/// a duplicate write key for an entirely legitimate manifest. Two entries
/// that share a storage key but disagree on content -- which would mean a
/// hash collision already accepted by [`verify_publication_bundle`] -- are
/// refused rather than silently resolved by picking one.
fn stage_publication_artifacts(
    chain: &ChainId,
    request_id: &[u8; 32],
    manifest: &ArtifactManifest,
    contents: &[Vec<u8>],
) -> RetentionResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut staged: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (entry, content) in manifest.entries.iter().zip(contents.iter()) {
        let key: Vec<u8> = artifact_key(chain, request_id, entry)?;
        match staged.get(&key) {
            Some(existing) if existing != content => {
                return Err(PublicationRetentionError::Node(
                    NodeCoreError::PersistenceInvariant(
                        "publication artifact content disagrees under one content-addressed key",
                    ),
                ));
            }
            _ => {
                staged.insert(key, content.clone());
            }
        }
    }
    Ok(staged)
}
/// Strictly decodes the event digest and canonical paid result in a
/// commitment witness. This is read-only parsing, not authentication:
/// callers must first verify the publication bundle's certificate, witness
/// commitment, context and exact signed intent, then compare the returned
/// digest and canonical result to the member response they accept.
pub fn decode_certified_execution_witness(
    bytes: &[u8],
) -> Result<(Digest32, execution::paid_execution::PaidExecutionResult), NodeCoreError> {
    let decoded: super::commitment::DecodedCommitmentWitness =
        super::commitment::decode_witness(bytes)?;
    Ok((decoded.event_digest, decoded.paid_execution_result))
}
