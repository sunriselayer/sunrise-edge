//! DR-0189 closed source-free frames: 0xD054 SuccessorActivationSubject and
//! 0xD055 SuccessorActivationManifest. Canonical encoding version 1, closed
//! fields, exact decode/re-encode and checked lengths. Both digests use the
//! NodeEvent purpose at the outgoing epoch, like the 0xD051/0xD052 preimages
//! they embed. Neither frame carries a path or any other local-only value.

use crate::NodeCoreError;
use crate::ordered_economics::{
    OrderedEconomicsError, OrderedHistoryIdentity, decode_ordered_history_identity,
    encode_ordered_history_identity,
};
use canonical_encoding::{
    CanonicalStruct, MAX_CANONICAL_FRAME_BYTES, decode_canonical_frame, decode_digest32,
    encode_chain_id, encode_digest32,
};
use consensus::readiness::MAX_READINESS_CERTIFICATE_BYTES;
use hashing::HashSuiteResolver;
use protocol_types::{ChainId, Digest32, Epoch, HashPurpose, ProtocolVersion};
use runtime::AtomicityDomainId;

/// Frame type of the hash-only successor activation subject.
pub const SUCCESSOR_ACTIVATION_SUBJECT_TYPE: u16 = 0xD054;
/// Frame type of the source-free successor activation manifest.
pub const SUCCESSOR_ACTIVATION_MANIFEST_TYPE: u16 = 0xD055;
/// Closed subject bound.
pub const MAX_SUCCESSOR_ACTIVATION_SUBJECT_BYTES: usize = 2 * 1024;
/// Closed manifest bound.
pub const MAX_SUCCESSOR_ACTIVATION_MANIFEST_BYTES: usize = 2 * 1024;
const ENCODING_VERSION: u16 = 1;

fn invalid(message: &'static str) -> NodeCoreError {
    NodeCoreError::PersistenceInvariant(message)
}

/// 0xD054: the exact Seal-terminated predecessor and verified successor
/// identity a first successor is activated from. Hash-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorActivationSubject {
    /// Field 1: chain.
    pub chain_id: ChainId,
    /// Field 2: protocol version.
    pub protocol_version: ProtocolVersion,
    /// Field 3: outgoing epoch e.
    pub outgoing_epoch: Epoch,
    /// Field 4: original pinned genesis digest.
    pub genesis_digest: Digest32,
    /// Field 5: logical atomicity domain.
    pub domain: AtomicityDomainId,
    /// Field 6: Seal target digest (0xD051).
    pub seal_target: Digest32,
    /// Field 7: exact Seal candidate request id. Its high bit is already set
    /// by the 0xD052 derivation; verification requires it and never sets it.
    pub seal_request: [u8; 32],
    /// Field 8: Seal block height h.
    pub seal_height: u64,
    /// Field 9: Seal block digest.
    pub seal_block_digest: Digest32,
    /// Field 10: successor epoch, exactly e+1.
    pub successor_epoch: Epoch,
    /// Field 11: certified successor set digest.
    pub successor_set_digest: Digest32,
    /// Field 12: readiness schedule digest.
    pub schedule_digest: Digest32,
    /// Field 13: semantic cut digest.
    pub cut_digest: Digest32,
}

fn validate_subject(subject: &SuccessorActivationSubject) -> Result<(), NodeCoreError> {
    if subject.protocol_version.get() == 0 {
        return Err(invalid("successor subject protocol version is zero"));
    }
    if subject.outgoing_epoch.get().checked_add(1) != Some(subject.successor_epoch.get()) {
        return Err(invalid("successor subject epoch is not the adjacent epoch"));
    }
    if subject.seal_request[0] & 0x80 == 0 {
        return Err(invalid(
            "successor subject Seal request lacks the sealed bit",
        ));
    }
    if subject.seal_height == 0 {
        return Err(invalid("successor subject Seal height is zero"));
    }
    Ok(())
}

/// Encodes frame 0xD054/v1.
pub fn encode_successor_activation_subject(
    subject: &SuccessorActivationSubject,
) -> Result<Vec<u8>, NodeCoreError> {
    validate_subject(subject)?;
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(SUCCESSOR_ACTIVATION_SUBJECT_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_chain_id(&subject.chain_id)?)?;
    frame.field_u32(2, subject.protocol_version.get())?;
    frame.field_u64(3, subject.outgoing_epoch.get())?;
    frame.field_bytes(4, encode_digest32(&subject.genesis_digest)?)?;
    frame.field_bytes(5, subject.domain.as_bytes().to_vec())?;
    frame.field_bytes(6, encode_digest32(&subject.seal_target)?)?;
    frame.field_bytes(7, subject.seal_request.to_vec())?;
    frame.field_u64(8, subject.seal_height)?;
    frame.field_bytes(9, encode_digest32(&subject.seal_block_digest)?)?;
    frame.field_u64(10, subject.successor_epoch.get())?;
    frame.field_bytes(11, encode_digest32(&subject.successor_set_digest)?)?;
    frame.field_bytes(12, encode_digest32(&subject.schedule_digest)?)?;
    frame.field_bytes(13, encode_digest32(&subject.cut_digest)?)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_SUCCESSOR_ACTIVATION_SUBJECT_BYTES {
        return Err(invalid("successor subject exceeds its frame bound"));
    }
    Ok(bytes)
}

fn decode_chain(bytes: &[u8]) -> Result<ChainId, NodeCoreError> {
    let frame = decode_canonical_frame(bytes)?;
    let text: &str = std::str::from_utf8(frame.required_field(1)?)
        .map_err(|_| invalid("successor subject chain text"))?;
    let chain: ChainId = ChainId::new(text).map_err(|_| invalid("successor subject chain id"))?;
    if encode_chain_id(&chain)? != bytes {
        return Err(invalid("noncanonical successor subject chain"));
    }
    Ok(chain)
}

fn decode_domain(bytes: &[u8]) -> Result<AtomicityDomainId, NodeCoreError> {
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid("successor subject domain length"))?;
    AtomicityDomainId::new(raw).map_err(|_| invalid("successor subject domain is zero"))
}

/// Strictly decodes frame 0xD054/v1.
pub fn decode_successor_activation_subject(
    bytes: &[u8],
) -> Result<SuccessorActivationSubject, NodeCoreError> {
    if bytes.len() > MAX_SUCCESSOR_ACTIVATION_SUBJECT_BYTES {
        return Err(invalid("successor subject exceeds its frame bound"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(SUCCESSOR_ACTIVATION_SUBJECT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13])?;
    let seal_request: [u8; 32] = frame
        .required_field(7)?
        .try_into()
        .map_err(|_| invalid("successor subject Seal request length"))?;
    let subject: SuccessorActivationSubject = SuccessorActivationSubject {
        chain_id: decode_chain(frame.required_field(1)?)?,
        protocol_version: ProtocolVersion::new(frame.required_u32(2)?),
        outgoing_epoch: Epoch::new(frame.required_u64(3)?),
        genesis_digest: decode_digest32(frame.required_field(4)?)?,
        domain: decode_domain(frame.required_field(5)?)?,
        seal_target: decode_digest32(frame.required_field(6)?)?,
        seal_request,
        seal_height: frame.required_u64(8)?,
        seal_block_digest: decode_digest32(frame.required_field(9)?)?,
        successor_epoch: Epoch::new(frame.required_u64(10)?),
        successor_set_digest: decode_digest32(frame.required_field(11)?)?,
        schedule_digest: decode_digest32(frame.required_field(12)?)?,
        cut_digest: decode_digest32(frame.required_field(13)?)?,
    };
    if encode_successor_activation_subject(&subject)? != bytes {
        return Err(invalid("noncanonical successor subject"));
    }
    Ok(subject)
}

/// 0xD055: the source-free activation manifest naming the exact readiness
/// certificate, history identity through h, the verified Seal commit proof
/// component and the saved-cut package and raw-plan digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorActivationManifest {
    /// Field 1: exact 0xD054 subject.
    pub subject: SuccessorActivationSubject,
    /// Field 2: readiness certificate digest (Certificate purpose at e).
    pub certificate_digest: Digest32,
    /// Field 3: readiness certificate length.
    pub certificate_length: u32,
    /// Field 4: ordered history identity through the Seal height h.
    pub history: OrderedHistoryIdentity,
    /// Field 5: Seal commit-proof component digest.
    pub seal_proof_digest: Digest32,
    /// Field 6: Seal commit-proof component length.
    pub seal_proof_length: u32,
    /// Field 7: saved-cut package digest.
    pub package_digest: Digest32,
    /// Field 8: raw-plan digest.
    pub plan_digest: Digest32,
}

fn ordered_identity_error(error: OrderedEconomicsError) -> NodeCoreError {
    match error {
        OrderedEconomicsError::Node(error) => error,
        _ => invalid("successor manifest history identity"),
    }
}

fn validate_manifest(manifest: &SuccessorActivationManifest) -> Result<(), NodeCoreError> {
    let subject: &SuccessorActivationSubject = &manifest.subject;
    let history: &OrderedHistoryIdentity = &manifest.history;
    let certificate_length: usize = usize::try_from(manifest.certificate_length)
        .map_err(|_| invalid("successor manifest certificate length"))?;
    let proof_length: usize = usize::try_from(manifest.seal_proof_length)
        .map_err(|_| invalid("successor manifest proof length"))?;
    if certificate_length == 0 || certificate_length > MAX_READINESS_CERTIFICATE_BYTES {
        return Err(invalid("successor manifest certificate length bound"));
    }
    if proof_length == 0 || proof_length > MAX_CANONICAL_FRAME_BYTES {
        return Err(invalid("successor manifest proof length bound"));
    }
    if history.context.chain_id() != &subject.chain_id
        || history.context.protocol_version() != subject.protocol_version
        || history.context.epoch() != subject.outgoing_epoch
        || history.domain != subject.domain
        || history.genesis_digest != subject.genesis_digest
        || history.through_height != subject.seal_height
        || history.through_digest != subject.seal_block_digest
    {
        return Err(invalid(
            "successor manifest history does not end at the subject Seal",
        ));
    }
    Ok(())
}

/// Encodes frame 0xD055/v1.
pub fn encode_successor_activation_manifest(
    manifest: &SuccessorActivationManifest,
) -> Result<Vec<u8>, NodeCoreError> {
    validate_manifest(manifest)?;
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(SUCCESSOR_ACTIVATION_MANIFEST_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_successor_activation_subject(&manifest.subject)?)?;
    frame.field_bytes(2, encode_digest32(&manifest.certificate_digest)?)?;
    frame.field_u32(3, manifest.certificate_length)?;
    frame.field_bytes(
        4,
        encode_ordered_history_identity(&manifest.history).map_err(ordered_identity_error)?,
    )?;
    frame.field_bytes(5, encode_digest32(&manifest.seal_proof_digest)?)?;
    frame.field_u32(6, manifest.seal_proof_length)?;
    frame.field_bytes(7, encode_digest32(&manifest.package_digest)?)?;
    frame.field_bytes(8, encode_digest32(&manifest.plan_digest)?)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_SUCCESSOR_ACTIVATION_MANIFEST_BYTES {
        return Err(invalid("successor manifest exceeds its frame bound"));
    }
    Ok(bytes)
}

/// Strictly decodes frame 0xD055/v1.
pub fn decode_successor_activation_manifest(
    bytes: &[u8],
) -> Result<SuccessorActivationManifest, NodeCoreError> {
    if bytes.len() > MAX_SUCCESSOR_ACTIVATION_MANIFEST_BYTES {
        return Err(invalid("successor manifest exceeds its frame bound"));
    }
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(SUCCESSOR_ACTIVATION_MANIFEST_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8])?;
    let manifest: SuccessorActivationManifest = SuccessorActivationManifest {
        subject: decode_successor_activation_subject(frame.required_field(1)?)?,
        certificate_digest: decode_digest32(frame.required_field(2)?)?,
        certificate_length: frame.required_u32(3)?,
        history: decode_ordered_history_identity(frame.required_field(4)?)
            .map_err(ordered_identity_error)?,
        seal_proof_digest: decode_digest32(frame.required_field(5)?)?,
        seal_proof_length: frame.required_u32(6)?,
        package_digest: decode_digest32(frame.required_field(7)?)?,
        plan_digest: decode_digest32(frame.required_field(8)?)?,
    };
    if encode_successor_activation_manifest(&manifest)? != bytes {
        return Err(invalid("noncanonical successor manifest"));
    }
    Ok(manifest)
}

fn outgoing_node_event_digest(
    resolver: &HashSuiteResolver,
    subject: &SuccessorActivationSubject,
    bytes: &[u8],
) -> Result<Digest32, NodeCoreError> {
    if resolver.chain_id() != &subject.chain_id
        || resolver.protocol_version() != subject.protocol_version
    {
        return Err(invalid("successor frame hash context differs"));
    }
    resolver
        .hash_for_purpose(subject.outgoing_epoch, HashPurpose::NodeEvent, bytes)
        .map_err(|_| invalid("successor frame hash suite unavailable"))
}

/// NodeEvent digest of the exact 0xD054 bytes at the outgoing epoch.
pub fn successor_activation_subject_digest(
    resolver: &HashSuiteResolver,
    subject: &SuccessorActivationSubject,
) -> Result<Digest32, NodeCoreError> {
    let bytes: Vec<u8> = encode_successor_activation_subject(subject)?;
    outgoing_node_event_digest(resolver, subject, &bytes)
}

/// NodeEvent digest of the exact 0xD055 bytes at the outgoing epoch.
pub fn successor_activation_manifest_digest(
    resolver: &HashSuiteResolver,
    manifest: &SuccessorActivationManifest,
) -> Result<Digest32, NodeCoreError> {
    let bytes: Vec<u8> = encode_successor_activation_manifest(manifest)?;
    outgoing_node_event_digest(resolver, &manifest.subject, &bytes)
}
