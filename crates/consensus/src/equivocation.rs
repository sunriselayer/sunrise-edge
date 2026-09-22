//! DR-0133 (phase 2 slice 3): canonical FastVote/EpochTransitionVote
//! equivocation evidence.
//!
//! Three independent conflicting-statement classes exist (DR-0133 §1):
//!
//! * (a) [`FastVoteEquivocationEvidence`] (`0xD00D`) -- the same validator
//!   signed two [`crate::FastVote`]s for the identical `tx_hash` with a
//!   differing payload.
//! * (b) [`FastVoteObjectConflictEvidence`] (`0xD00E`) -- the same validator
//!   signed [`crate::FastVote`]s for two *different* transactions whose
//!   [`LockedObjectSetPreimage`]s (`0xD00C`) share an identical `(ObjectId,
//!   version)` pair.
//! * (c) [`EpochTransitionEquivocationEvidence`] (`0xD00F`) -- the same
//!   outgoing-epoch validator signed two [`crate::EpochTransitionVote`]s with
//!   a differing target tuple.
//!
//! Every `build_*` function here is pure (no I/O, no resolver) and operates
//! on already-decoded, already-structurally-valid statements, exactly like
//! [`crate::FastPathCertifier::try_form_certificate`] operates on
//! already-decoded votes. Every `verify_*` function is pure given a
//! caller-supplied [`ValidatorSet`]; hashing a [`LockedObjectSetPreimage`]
//! against a vote's signed `locked_objects_digest` needs a
//! `HashSuiteResolver` and is therefore `crate::node_core`-side (this crate
//! has no `node_core` module; see `crates/node-core/src/equivocation.rs`).
//! No new signing operation exists anywhere in this module: evidence
//! submission only re-verifies already-signed statements.

use crate::{
    ConsensusError, ConsensusVerifier, EpochTransitionCertifier, EpochTransitionVote,
    FastPathCertifier, FastVote, decode_epoch_transition_vote, decode_fast_vote,
    encode_epoch_transition_vote, encode_epoch_transition_vote_payload, encode_fast_vote,
    encode_fast_vote_payload,
};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalStruct, decode_canonical_frame, decode_digest32,
    encode_digest32,
};
use objects::{ObjectId, ObjectRef};
use protocol_types::{ChainId, Digest32, Epoch, ProtocolVersion, ValidatorId};
use std::collections::BTreeSet;
use validator_set::ValidatorSet;

const LOCKED_OBJECT_SET_PREIMAGE_TYPE_ID: u16 = 0xD00C;
const FAST_VOTE_EQUIVOCATION_EVIDENCE_TYPE_ID: u16 = 0xD00D;
const FAST_VOTE_OBJECT_CONFLICT_EVIDENCE_TYPE_ID: u16 = 0xD00E;
const EPOCH_TRANSITION_EQUIVOCATION_EVIDENCE_TYPE_ID: u16 = 0xD00F;
const ENCODING_VERSION: u16 = 1;

/// Matches `runtime::MAX_DURABLE_OBJECT_MUTATIONS`, the existing ceiling on
/// how many `Write`/`Consume` objects one admitted request can ever declare
/// (`consensus` does not depend on `runtime`, so the bound is duplicated as a
/// literal, not imported).
pub const MAX_LOCKED_OBJECT_SET_ENTRIES: usize = 4_096;

/// A bounded, canonical, validator-independent ordered set of exact
/// `(ObjectId, version, digest)` references a [`FastVote`]'s
/// `locked_objects_digest` is hashed over (`0xD00C/v1`, DR-0133 §3). Unlike
/// a true digest-only preimage, this frame is transmitted and durably
/// stored: class (b) evidence must carry it so a verifier can recompute the
/// digest without re-deriving the original admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockedObjectSetPreimage {
    /// Chain replay boundary, taken from the same authenticated intent
    /// context whose admission produced `entries`.
    pub chain_id: ChainId,
    /// Protocol replay boundary.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay boundary.
    pub epoch: Epoch,
    /// Strictly ascending by `ObjectId`, no duplicates.
    pub entries: Vec<ObjectRef>,
}

/// Class (a): the same validator signed two [`FastVote`]s for the identical
/// `tx_hash` with a differing payload (`0xD00D/v1`, DR-0133 §1/§5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastVoteEquivocationEvidence {
    /// Chain replay boundary, shared by `low`/`high`.
    pub chain_id: ChainId,
    /// Protocol replay boundary, shared by `low`/`high`.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay boundary, shared by `low`/`high`.
    pub epoch: Epoch,
    /// Conflicted transaction hash, shared by `low`/`high`.
    pub tx_hash: Digest32,
    /// Equivocating validator, shared by `low`/`high`.
    pub validator: ValidatorId,
    /// The canonically smaller (by signable payload bytes) of the two
    /// conflicting votes.
    pub low: FastVote,
    /// The canonically larger of the two conflicting votes.
    pub high: FastVote,
}

/// Class (b): the same validator signed two [`FastVote`]s for *different*
/// transactions whose locked-object sets share an identical `(ObjectId,
/// version)` pair (`0xD00E/v1`, DR-0133 §1/§5). Both attached preimages keep
/// every locked entry exactly as decoded, so either statement's signed
/// digest remains independently re-verifiable; `conflicting_object_id`/
/// `conflicting_version` names only the smallest shared pair, solely for a
/// deterministic single-valued evidence identity (DR-0133 §5 step 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastVoteObjectConflictEvidence {
    /// Chain replay boundary, shared by `low`/`high`.
    pub chain_id: ChainId,
    /// Protocol replay boundary, shared by `low`/`high`.
    pub protocol_version: ProtocolVersion,
    /// Epoch replay boundary, shared by `low`/`high`.
    pub epoch: Epoch,
    /// Equivocating validator, shared by `low`/`high`.
    pub validator: ValidatorId,
    /// The smallest `(ObjectId, version)` pair the two preimages share.
    pub conflicting_object_id: ObjectId,
    /// The version half of the named conflicting pair.
    pub conflicting_version: u64,
    /// The canonically smaller (by `tx_hash`) of the two conflicting votes.
    pub low: FastVote,
    /// `low`'s own attached locked-object-set preimage.
    pub low_preimage: LockedObjectSetPreimage,
    /// The canonically larger (by `tx_hash`) of the two conflicting votes.
    pub high: FastVote,
    /// `high`'s own attached locked-object-set preimage.
    pub high_preimage: LockedObjectSetPreimage,
}

/// Class (c): the same outgoing-epoch validator signed two
/// [`EpochTransitionVote`]s with a differing activation target
/// (`0xD00F/v1`, DR-0133 §1/§5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochTransitionEquivocationEvidence {
    /// Chain replay boundary, shared by `low`/`high`.
    pub chain_id: ChainId,
    /// Protocol replay boundary, shared by `low`/`high`.
    pub protocol_version: ProtocolVersion,
    /// The outgoing epoch, shared by `low`/`high`.
    pub epoch: Epoch,
    /// Equivocating validator, shared by `low`/`high`.
    pub validator: ValidatorId,
    /// The canonically smaller (by signable payload bytes) of the two
    /// conflicting votes.
    pub low: EpochTransitionVote,
    /// The canonically larger of the two conflicting votes.
    pub high: EpochTransitionVote,
}

/// Encodes `0xD00C/v1`.
pub fn encode_locked_object_set_preimage(
    preimage: &LockedObjectSetPreimage,
) -> Result<Vec<u8>, ConsensusError> {
    if preimage.entries.len() > MAX_LOCKED_OBJECT_SET_ENTRIES {
        return Err(ConsensusError::NonCanonicalLockedObjectOrder);
    }
    let mut canonical = CanonicalStruct::new(LOCKED_OBJECT_SET_PREIMAGE_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, preimage.chain_id.as_str())?;
    canonical.field_u32(2, preimage.protocol_version.get())?;
    canonical.field_u64(3, preimage.epoch.get())?;
    canonical.field_u32(
        4,
        u32::try_from(preimage.entries.len())
            .map_err(|_| ConsensusError::NonCanonicalLockedObjectOrder)?,
    )?;
    for (index, entry) in preimage.entries.iter().enumerate() {
        let field =
            u16::try_from(index + 5).map_err(|_| ConsensusError::NonCanonicalLockedObjectOrder)?;
        canonical.field_bytes(field, objects::encode_object_ref(entry)?)?;
    }
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one canonical [`LockedObjectSetPreimage`].
///
/// Beyond the shared canonical-frame guarantees, this requires the exact
/// type/version/field set, `count` bounded by
/// [`MAX_LOCKED_OBJECT_SET_ENTRIES`] and matching the declared field count,
/// strict ascending `ObjectId` order with no duplicate, and byte-exact
/// re-encoding.
pub fn decode_locked_object_set_preimage(
    input: &[u8],
) -> Result<LockedObjectSetPreimage, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(LOCKED_OBJECT_SET_PREIMAGE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let chain_id =
        ChainId::new(frame.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let count = usize::try_from(frame.required_u32(4)?)
        .map_err(|_| ConsensusError::NonCanonicalLockedObjectOrder)?;
    if count > MAX_LOCKED_OBJECT_SET_ENTRIES {
        return Err(ConsensusError::NonCanonicalLockedObjectOrder);
    }
    let expected_field_count = count
        .checked_add(4)
        .ok_or(ConsensusError::NonCanonicalLockedObjectOrder)?;
    if frame.field_count() != expected_field_count {
        return Err(ConsensusError::NonCanonicalLockedObjectOrder);
    }
    let mut entries: Vec<ObjectRef> = Vec::with_capacity(count);
    let mut previous: Option<ObjectId> = None;
    for index in 0..count {
        let field =
            u16::try_from(index + 5).map_err(|_| ConsensusError::NonCanonicalLockedObjectOrder)?;
        let entry = objects::decode_object_ref(frame.required_field(field)?)?;
        if previous.is_some_and(|id| id >= entry.id) {
            return Err(ConsensusError::NonCanonicalLockedObjectOrder);
        }
        previous = Some(entry.id);
        entries.push(entry);
    }
    let preimage = LockedObjectSetPreimage {
        chain_id,
        protocol_version,
        epoch,
        entries,
    };
    if encode_locked_object_set_preimage(&preimage)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalLockedObjectOrder);
    }
    Ok(preimage)
}

fn require_preimage_matches_vote_context(
    preimage: &LockedObjectSetPreimage,
    vote: &FastVote,
) -> Result<(), ConsensusError> {
    if preimage.chain_id != vote.chain_id
        || preimage.protocol_version != vote.protocol_version
        || preimage.epoch != vote.epoch
    {
        return Err(ConsensusError::CertificateVoteMismatch);
    }
    Ok(())
}

/// The complete set of `(ObjectId, version)` pairs `low_preimage` and
/// `high_preimage` share, matched on identity/version only -- digest
/// agreement between the two matched entries is never required (DR-0133
/// §5).
fn shared_object_versions(
    low_preimage: &LockedObjectSetPreimage,
    high_preimage: &LockedObjectSetPreimage,
) -> BTreeSet<(ObjectId, u64)> {
    let low_set: BTreeSet<(ObjectId, u64)> = low_preimage
        .entries
        .iter()
        .map(|entry| (entry.id, entry.version))
        .collect();
    high_preimage
        .entries
        .iter()
        .map(|entry| (entry.id, entry.version))
        .filter(|key| low_set.contains(key))
        .collect()
}

/// Requires the claimed `(conflicting_object_id, conflicting_version)` to be
/// exactly the smallest `(ObjectId, version)` pair `low_preimage`/
/// `high_preimage` share, and each preimage's own `(chain_id,
/// protocol_version, epoch)` to echo its attached vote. Shared by
/// [`decode_fast_vote_object_conflict_evidence`] and
/// [`verify_fast_vote_object_conflict_evidence`] (DR-0133 §5).
fn require_canonical_object_conflict(
    low: &FastVote,
    low_preimage: &LockedObjectSetPreimage,
    high: &FastVote,
    high_preimage: &LockedObjectSetPreimage,
    conflicting_object_id: ObjectId,
    conflicting_version: u64,
) -> Result<(), ConsensusError> {
    require_preimage_matches_vote_context(low_preimage, low)?;
    require_preimage_matches_vote_context(high_preimage, high)?;
    let smallest = shared_object_versions(low_preimage, high_preimage)
        .into_iter()
        .next()
        .ok_or(ConsensusError::ObjectConflictNotProvenByPreimages)?;
    if smallest != (conflicting_object_id, conflicting_version) {
        return Err(ConsensusError::ObjectConflictNotProvenByPreimages);
    }
    Ok(())
}

/// Class (a) build (DR-0133 §5): requires the equal-field conflict key and
/// payload divergence, then orders `(low, high)` ascending by signable
/// payload bytes. Total and independent of caller argument order.
pub fn build_fast_vote_equivocation_evidence(
    a: &FastVote,
    b: &FastVote,
) -> Result<FastVoteEquivocationEvidence, ConsensusError> {
    if a.chain_id != b.chain_id
        || a.protocol_version != b.protocol_version
        || a.epoch != b.epoch
        || a.validator != b.validator
        || a.tx_hash != b.tx_hash
    {
        return Err(ConsensusError::EquivocationEvidenceConflictKeyMismatch);
    }
    let payload_a = encode_fast_vote_payload(a)?;
    let payload_b = encode_fast_vote_payload(b)?;
    if payload_a == payload_b {
        return Err(ConsensusError::EquivocationEvidenceStatementsIdentical);
    }
    let (low, high) = if payload_a < payload_b {
        (a.clone(), b.clone())
    } else {
        (b.clone(), a.clone())
    };
    Ok(FastVoteEquivocationEvidence {
        chain_id: a.chain_id.clone(),
        protocol_version: a.protocol_version,
        epoch: a.epoch,
        tx_hash: a.tx_hash,
        validator: a.validator,
        low,
        high,
    })
}

/// Class (c) build, structurally mirroring
/// [`build_fast_vote_equivocation_evidence`] (DR-0133 §5): requires the
/// equal-field conflict key and payload divergence, then orders `(low,
/// high)` ascending by signable payload bytes.
pub fn build_epoch_transition_equivocation_evidence(
    a: &EpochTransitionVote,
    b: &EpochTransitionVote,
) -> Result<EpochTransitionEquivocationEvidence, ConsensusError> {
    if a.chain_id != b.chain_id
        || a.protocol_version != b.protocol_version
        || a.epoch != b.epoch
        || a.validator != b.validator
    {
        return Err(ConsensusError::EquivocationEvidenceConflictKeyMismatch);
    }
    let payload_a = encode_epoch_transition_vote_payload(a)?;
    let payload_b = encode_epoch_transition_vote_payload(b)?;
    if payload_a == payload_b {
        return Err(ConsensusError::EquivocationEvidenceStatementsIdentical);
    }
    let (low, high) = if payload_a < payload_b {
        (a.clone(), b.clone())
    } else {
        (b.clone(), a.clone())
    };
    Ok(EpochTransitionEquivocationEvidence {
        chain_id: a.chain_id.clone(),
        protocol_version: a.protocol_version,
        epoch: a.epoch,
        validator: a.validator,
        low,
        high,
    })
}

/// Class (b) build (DR-0133 §5): operates on already-decoded,
/// already-structurally-valid [`FastVote`]/[`LockedObjectSetPreimage`]
/// values, exactly like class (a) operates on already-decoded votes.
///
/// 1. Requires the equal-field conflict key.
/// 2. Requires `a.tx_hash != b.tx_hash`.
/// 3. Requires each preimage's own context to echo its respective vote.
/// 4. Finds every `(ObjectId, version)` pair shared by both preimages,
///    matched on identity/version only -- digest agreement between the two
///    matched entries is never required or checked here.
/// 5. Names the smallest shared pair as the canonical conflict; every other
///    shared pair stays visible in the retained preimages.
/// 6. Orders `(low, high)` ascending by `tx_hash`, moving each vote's own
///    preimage with it.
pub fn build_fast_vote_object_conflict_evidence(
    a: &FastVote,
    b: &FastVote,
    a_preimage: &LockedObjectSetPreimage,
    b_preimage: &LockedObjectSetPreimage,
) -> Result<FastVoteObjectConflictEvidence, ConsensusError> {
    if a.chain_id != b.chain_id
        || a.protocol_version != b.protocol_version
        || a.epoch != b.epoch
        || a.validator != b.validator
    {
        return Err(ConsensusError::EquivocationEvidenceConflictKeyMismatch);
    }
    if a.tx_hash == b.tx_hash {
        return Err(ConsensusError::ObjectConflictRequiresDistinctTransactions);
    }
    require_preimage_matches_vote_context(a_preimage, a)?;
    require_preimage_matches_vote_context(b_preimage, b)?;
    let (conflicting_object_id, conflicting_version) =
        shared_object_versions(a_preimage, b_preimage)
            .into_iter()
            .next()
            .ok_or(ConsensusError::ObjectConflictNotFound)?;
    let (low, low_preimage, high, high_preimage) = if a.tx_hash < b.tx_hash {
        (a.clone(), a_preimage.clone(), b.clone(), b_preimage.clone())
    } else {
        (b.clone(), b_preimage.clone(), a.clone(), a_preimage.clone())
    };
    Ok(FastVoteObjectConflictEvidence {
        chain_id: a.chain_id.clone(),
        protocol_version: a.protocol_version,
        epoch: a.epoch,
        validator: a.validator,
        conflicting_object_id,
        conflicting_version,
        low,
        low_preimage,
        high,
        high_preimage,
    })
}

/// Class (a) verify (DR-0133 §5): [`FastPathCertifier::verify_vote`] on both
/// `low` and `high` against the caller-supplied `validator_set` for the
/// evidence's own claimed epoch.
pub fn verify_fast_vote_equivocation_evidence<V: ConsensusVerifier>(
    evidence: &FastVoteEquivocationEvidence,
    validator_set: ValidatorSet,
    verifier: &V,
) -> Result<(), ConsensusError> {
    let certifier = FastPathCertifier::new(
        evidence.chain_id.clone(),
        evidence.protocol_version,
        evidence.epoch,
        validator_set,
    )?;
    certifier.verify_vote(&evidence.low, verifier)?;
    certifier.verify_vote(&evidence.high, verifier)?;
    Ok(())
}

/// Class (c) verify, structurally mirroring
/// [`verify_fast_vote_equivocation_evidence`] with
/// [`EpochTransitionCertifier::verify_vote`].
pub fn verify_epoch_transition_equivocation_evidence<V: ConsensusVerifier>(
    evidence: &EpochTransitionEquivocationEvidence,
    validator_set: ValidatorSet,
    verifier: &V,
) -> Result<(), ConsensusError> {
    let certifier = EpochTransitionCertifier::new(
        evidence.chain_id.clone(),
        evidence.protocol_version,
        evidence.epoch,
        validator_set,
    )?;
    certifier.verify_vote(&evidence.low, verifier)?;
    certifier.verify_vote(&evidence.high, verifier)?;
    Ok(())
}

/// Class (b) verify (DR-0133 §5): [`FastPathCertifier::verify_vote`] on both
/// `low` and `high` (signature validity only), plus an independent
/// re-derivation of build steps 3-5 in full -- not merely a presence check.
/// This does not hash either preimage against its vote's signed
/// `locked_objects_digest`: that authenticity binding needs a
/// `HashSuiteResolver` and is node-core's responsibility.
pub fn verify_fast_vote_object_conflict_evidence<V: ConsensusVerifier>(
    evidence: &FastVoteObjectConflictEvidence,
    validator_set: ValidatorSet,
    verifier: &V,
) -> Result<(), ConsensusError> {
    let certifier = FastPathCertifier::new(
        evidence.chain_id.clone(),
        evidence.protocol_version,
        evidence.epoch,
        validator_set,
    )?;
    certifier.verify_vote(&evidence.low, verifier)?;
    certifier.verify_vote(&evidence.high, verifier)?;
    require_canonical_object_conflict(
        &evidence.low,
        &evidence.low_preimage,
        &evidence.high,
        &evidence.high_preimage,
        evidence.conflicting_object_id,
        evidence.conflicting_version,
    )
}

/// Encodes `0xD00D/v1`.
pub fn encode_fast_vote_equivocation_evidence(
    evidence: &FastVoteEquivocationEvidence,
) -> Result<Vec<u8>, ConsensusError> {
    let mut canonical =
        CanonicalStruct::new(FAST_VOTE_EQUIVOCATION_EVIDENCE_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, evidence.chain_id.as_str())?;
    canonical.field_u32(2, evidence.protocol_version.get())?;
    canonical.field_u64(3, evidence.epoch.get())?;
    canonical.field_bytes(4, encode_digest32(&evidence.tx_hash)?)?;
    canonical.field_bytes(5, evidence.validator.as_bytes())?;
    canonical.field_bytes(6, encode_fast_vote(&evidence.low)?)?;
    canonical.field_bytes(7, encode_fast_vote(&evidence.high)?)?;
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one canonical
/// [`FastVoteEquivocationEvidence`].
///
/// Beyond the shared canonical-frame guarantees: exact type/version/field
/// set, `low`/`high` each decode under [`decode_fast_vote`], the header
/// fields equal both nested votes' corresponding fields
/// ([`ConsensusError::CertificateVoteMismatch`] otherwise), `low`'s payload
/// strictly precedes `high`'s
/// ([`ConsensusError::NonCanonicalEquivocationEvidenceOrder`] otherwise,
/// which also rejects a byte-identical pair), and byte-exact re-encoding.
/// This proves the envelope is internally self-consistent; it does not
/// itself verify any signature.
pub fn decode_fast_vote_equivocation_evidence(
    input: &[u8],
) -> Result<FastVoteEquivocationEvidence, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FAST_VOTE_EQUIVOCATION_EVIDENCE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7])?;
    let chain_id =
        ChainId::new(frame.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let tx_hash = decode_digest32(frame.required_field(4)?)?;
    let validator_field = frame.required_field(5)?;
    let validator_bytes: [u8; 32] = validator_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 5,
            expected: 32,
            actual: validator_field.len(),
        })
    })?;
    let validator = ValidatorId::new(validator_bytes);
    let low = decode_fast_vote(frame.required_field(6)?)?;
    let high = decode_fast_vote(frame.required_field(7)?)?;
    if low.chain_id != chain_id
        || low.protocol_version != protocol_version
        || low.epoch != epoch
        || low.tx_hash != tx_hash
        || low.validator != validator
        || high.chain_id != chain_id
        || high.protocol_version != protocol_version
        || high.epoch != epoch
        || high.tx_hash != tx_hash
        || high.validator != validator
    {
        return Err(ConsensusError::CertificateVoteMismatch);
    }
    if encode_fast_vote_payload(&low)? >= encode_fast_vote_payload(&high)? {
        return Err(ConsensusError::NonCanonicalEquivocationEvidenceOrder);
    }
    let evidence = FastVoteEquivocationEvidence {
        chain_id,
        protocol_version,
        epoch,
        tx_hash,
        validator,
        low,
        high,
    };
    if encode_fast_vote_equivocation_evidence(&evidence)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalEquivocationEvidenceOrder);
    }
    Ok(evidence)
}

/// Encodes `0xD00F/v1`.
pub fn encode_epoch_transition_equivocation_evidence(
    evidence: &EpochTransitionEquivocationEvidence,
) -> Result<Vec<u8>, ConsensusError> {
    let mut canonical = CanonicalStruct::new(
        EPOCH_TRANSITION_EQUIVOCATION_EVIDENCE_TYPE_ID,
        ENCODING_VERSION,
    );
    canonical.field_str(1, evidence.chain_id.as_str())?;
    canonical.field_u32(2, evidence.protocol_version.get())?;
    canonical.field_u64(3, evidence.epoch.get())?;
    canonical.field_bytes(4, evidence.validator.as_bytes())?;
    canonical.field_bytes(5, encode_epoch_transition_vote(&evidence.low)?)?;
    canonical.field_bytes(6, encode_epoch_transition_vote(&evidence.high)?)?;
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one canonical
/// [`EpochTransitionEquivocationEvidence`], structurally mirroring
/// [`decode_fast_vote_equivocation_evidence`] with
/// [`decode_epoch_transition_vote`].
pub fn decode_epoch_transition_equivocation_evidence(
    input: &[u8],
) -> Result<EpochTransitionEquivocationEvidence, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(EPOCH_TRANSITION_EQUIVOCATION_EVIDENCE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
    let chain_id =
        ChainId::new(frame.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let validator_field = frame.required_field(4)?;
    let validator_bytes: [u8; 32] = validator_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 4,
            expected: 32,
            actual: validator_field.len(),
        })
    })?;
    let validator = ValidatorId::new(validator_bytes);
    let low = decode_epoch_transition_vote(frame.required_field(5)?)?;
    let high = decode_epoch_transition_vote(frame.required_field(6)?)?;
    if low.chain_id != chain_id
        || low.protocol_version != protocol_version
        || low.epoch != epoch
        || low.validator != validator
        || high.chain_id != chain_id
        || high.protocol_version != protocol_version
        || high.epoch != epoch
        || high.validator != validator
    {
        return Err(ConsensusError::CertificateVoteMismatch);
    }
    if encode_epoch_transition_vote_payload(&low)? >= encode_epoch_transition_vote_payload(&high)? {
        return Err(ConsensusError::NonCanonicalEquivocationEvidenceOrder);
    }
    let evidence = EpochTransitionEquivocationEvidence {
        chain_id,
        protocol_version,
        epoch,
        validator,
        low,
        high,
    };
    if encode_epoch_transition_equivocation_evidence(&evidence)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalEquivocationEvidenceOrder);
    }
    Ok(evidence)
}

/// Encodes `0xD00E/v1`.
pub fn encode_fast_vote_object_conflict_evidence(
    evidence: &FastVoteObjectConflictEvidence,
) -> Result<Vec<u8>, ConsensusError> {
    let mut canonical =
        CanonicalStruct::new(FAST_VOTE_OBJECT_CONFLICT_EVIDENCE_TYPE_ID, ENCODING_VERSION);
    canonical.field_str(1, evidence.chain_id.as_str())?;
    canonical.field_u32(2, evidence.protocol_version.get())?;
    canonical.field_u64(3, evidence.epoch.get())?;
    canonical.field_bytes(4, evidence.validator.as_bytes())?;
    canonical.field_bytes(5, evidence.conflicting_object_id.as_bytes())?;
    canonical.field_u64(6, evidence.conflicting_version)?;
    canonical.field_bytes(7, encode_fast_vote(&evidence.low)?)?;
    canonical.field_bytes(
        8,
        encode_locked_object_set_preimage(&evidence.low_preimage)?,
    )?;
    canonical.field_bytes(9, encode_fast_vote(&evidence.high)?)?;
    canonical.field_bytes(
        10,
        encode_locked_object_set_preimage(&evidence.high_preimage)?,
    )?;
    Ok(canonical.finish()?)
}

/// Decodes and strictly re-validates one canonical
/// [`FastVoteObjectConflictEvidence`].
///
/// Beyond the shared canonical-frame guarantees: exact type/version/field
/// set, `low`/`high`/`low_preimage`/`high_preimage` each decode under their
/// own strict decoder, the header fields equal both nested votes'
/// corresponding fields, `low.tx_hash != high.tx_hash`, `low.tx_hash`
/// strictly precedes `high.tx_hash`, each preimage's own `(chain_id,
/// protocol_version, epoch)` echoes its attached vote, and the claimed
/// `conflicting_object_id`/`conflicting_version` is exactly the smallest
/// `(ObjectId, version)` pair the two preimages actually share -- never
/// merely a present one (DR-0133 §5). This proves the envelope is
/// internally self-consistent; it does not, and cannot, prove the attached
/// preimages are the ones the validator actually signed for (that
/// authenticity binding is node-core's responsibility).
pub fn decode_fast_vote_object_conflict_evidence(
    input: &[u8],
) -> Result<FastVoteObjectConflictEvidence, ConsensusError> {
    let frame = decode_canonical_frame(input)?;
    frame.require_type(FAST_VOTE_OBJECT_CONFLICT_EVIDENCE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
    let chain_id =
        ChainId::new(frame.required_str(1)?.to_owned()).map_err(ConsensusError::ProtocolType)?;
    let protocol_version = ProtocolVersion::new(frame.required_u32(2)?);
    let epoch = Epoch::new(frame.required_u64(3)?);
    let validator_field = frame.required_field(4)?;
    let validator_bytes: [u8; 32] = validator_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 4,
            expected: 32,
            actual: validator_field.len(),
        })
    })?;
    let validator = ValidatorId::new(validator_bytes);
    let object_id_field = frame.required_field(5)?;
    let object_id_bytes: [u8; 32] = object_id_field.try_into().map_err(|_| {
        ConsensusError::CanonicalDecoding(CanonicalDecodingError::InvalidFieldLength {
            field_id: 5,
            expected: 32,
            actual: object_id_field.len(),
        })
    })?;
    let conflicting_object_id = ObjectId::new(object_id_bytes);
    let conflicting_version = frame.required_u64(6)?;
    let low = decode_fast_vote(frame.required_field(7)?)?;
    let low_preimage = decode_locked_object_set_preimage(frame.required_field(8)?)?;
    let high = decode_fast_vote(frame.required_field(9)?)?;
    let high_preimage = decode_locked_object_set_preimage(frame.required_field(10)?)?;

    if low.chain_id != chain_id
        || low.protocol_version != protocol_version
        || low.epoch != epoch
        || low.validator != validator
        || high.chain_id != chain_id
        || high.protocol_version != protocol_version
        || high.epoch != epoch
        || high.validator != validator
    {
        return Err(ConsensusError::CertificateVoteMismatch);
    }
    if low.tx_hash == high.tx_hash {
        return Err(ConsensusError::ObjectConflictRequiresDistinctTransactions);
    }
    if low.tx_hash >= high.tx_hash {
        return Err(ConsensusError::NonCanonicalEquivocationEvidenceOrder);
    }
    require_canonical_object_conflict(
        &low,
        &low_preimage,
        &high,
        &high_preimage,
        conflicting_object_id,
        conflicting_version,
    )?;

    let evidence = FastVoteObjectConflictEvidence {
        chain_id,
        protocol_version,
        epoch,
        validator,
        conflicting_object_id,
        conflicting_version,
        low,
        low_preimage,
        high,
        high_preimage,
    };
    if encode_fast_vote_object_conflict_evidence(&evidence)?.as_slice() != input {
        return Err(ConsensusError::NonCanonicalEquivocationEvidenceOrder);
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConsensusSigner;
    use ed25519_zebra::{Signature, SigningKey, VerificationKey};
    use protocol_types::{HashAlgorithmId, SignatureSchemeId};
    use validator_set::ValidatorInfo;

    fn chain() -> ChainId {
        ChainId::new("dr0133-test-chain").unwrap()
    }
    fn protocol_version() -> ProtocolVersion {
        ProtocolVersion::new(3)
    }
    fn epoch() -> Epoch {
        Epoch::new(9)
    }
    fn validator_id(byte: u8) -> ValidatorId {
        ValidatorId::new([byte; 32])
    }
    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from([byte; 32])
    }
    fn public_key_bytes(key: &SigningKey) -> Vec<u8> {
        VerificationKey::from(key).as_ref().to_vec()
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }
    fn object_ref(id_byte: u8, version: u64, digest_byte: u8) -> ObjectRef {
        ObjectRef {
            id: ObjectId::new([id_byte; 32]),
            version,
            digest: digest(digest_byte),
        }
    }
    fn preimage(entries: Vec<ObjectRef>) -> LockedObjectSetPreimage {
        let mut sorted = entries;
        sorted.sort_by_key(|entry| entry.id);
        LockedObjectSetPreimage {
            chain_id: chain(),
            protocol_version: protocol_version(),
            epoch: epoch(),
            entries: sorted,
        }
    }

    struct Ed25519TestSigner {
        id: ValidatorId,
        key: SigningKey,
    }
    impl ConsensusSigner for Ed25519TestSigner {
        fn validator_id(&self) -> ValidatorId {
            self.id
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
            Ok(self.key.sign(framed).to_bytes().to_vec())
        }
    }

    struct Ed25519TestVerifier;
    impl ConsensusVerifier for Ed25519TestVerifier {
        fn verify_framed(
            &self,
            _validator: ValidatorId,
            _scheme: SignatureSchemeId,
            public_key: &[u8],
            framed: &[u8],
            signature: &[u8],
        ) -> Result<bool, String> {
            let verification_key =
                VerificationKey::try_from(public_key).map_err(|error| error.to_string())?;
            let signature_bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| "signature is not 64 bytes".to_string())?;
            Ok(verification_key
                .verify(&Signature::from(signature_bytes), framed)
                .is_ok())
        }
    }

    fn validator_set(count: u8) -> ValidatorSet {
        let validators: Vec<ValidatorInfo> = (1..=count)
            .map(|byte| ValidatorInfo {
                id: validator_id(byte),
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: public_key_bytes(&signing_key(byte)),
            })
            .collect();
        ValidatorSet::new(epoch(), validators).unwrap()
    }

    fn fast_certifier() -> FastPathCertifier {
        FastPathCertifier::new(chain(), protocol_version(), epoch(), validator_set(4)).unwrap()
    }
    fn transition_certifier() -> EpochTransitionCertifier {
        EpochTransitionCertifier::new(chain(), protocol_version(), epoch(), validator_set(4))
            .unwrap()
    }

    fn fast_vote(
        certifier: &FastPathCertifier,
        byte: u8,
        tx_hash: Digest32,
        effects: Digest32,
        locked: Digest32,
    ) -> FastVote {
        certifier
            .cast_vote(
                tx_hash,
                effects,
                locked,
                &Ed25519TestSigner {
                    id: validator_id(byte),
                    key: signing_key(byte),
                },
            )
            .unwrap()
    }

    fn transition_vote(
        certifier: &EpochTransitionCertifier,
        byte: u8,
        current_digest: Digest32,
        next_digest: Digest32,
        activation_digest: Digest32,
    ) -> EpochTransitionVote {
        certifier
            .cast_vote(
                Epoch::new(epoch().get() + 1),
                current_digest,
                next_digest,
                activation_digest,
                &Ed25519TestSigner {
                    id: validator_id(byte),
                    key: signing_key(byte),
                },
            )
            .unwrap()
    }

    // ---- LockedObjectSetPreimage (0xD00C) ----

    #[test]
    fn locked_object_set_preimage_encode_decode_round_trips() {
        let value = preimage(vec![object_ref(0x10, 1, 0x20), object_ref(0x30, 2, 0x40)]);
        let bytes = encode_locked_object_set_preimage(&value).unwrap();
        assert_eq!(decode_locked_object_set_preimage(&bytes), Ok(value));
    }

    #[test]
    fn decode_locked_object_set_preimage_rejects_misordered_entries() {
        let entries = [object_ref(0x30, 1, 0x20), object_ref(0x10, 1, 0x40)];
        let mut canonical =
            CanonicalStruct::new(LOCKED_OBJECT_SET_PREIMAGE_TYPE_ID, ENCODING_VERSION);
        canonical.field_str(1, chain().as_str()).unwrap();
        canonical.field_u32(2, protocol_version().get()).unwrap();
        canonical.field_u64(3, epoch().get()).unwrap();
        canonical.field_u32(4, 2).unwrap();
        canonical
            .field_bytes(5, objects::encode_object_ref(&entries[0]).unwrap())
            .unwrap();
        canonical
            .field_bytes(6, objects::encode_object_ref(&entries[1]).unwrap())
            .unwrap();
        let bytes = canonical.finish().unwrap();
        assert_eq!(
            decode_locked_object_set_preimage(&bytes),
            Err(ConsensusError::NonCanonicalLockedObjectOrder)
        );
    }

    #[test]
    fn decode_locked_object_set_preimage_rejects_duplicate_object_id() {
        let entry = object_ref(0x10, 1, 0x20);
        let mut canonical =
            CanonicalStruct::new(LOCKED_OBJECT_SET_PREIMAGE_TYPE_ID, ENCODING_VERSION);
        canonical.field_str(1, chain().as_str()).unwrap();
        canonical.field_u32(2, protocol_version().get()).unwrap();
        canonical.field_u64(3, epoch().get()).unwrap();
        canonical.field_u32(4, 2).unwrap();
        canonical
            .field_bytes(5, objects::encode_object_ref(&entry).unwrap())
            .unwrap();
        canonical
            .field_bytes(6, objects::encode_object_ref(&entry).unwrap())
            .unwrap();
        let bytes = canonical.finish().unwrap();
        assert_eq!(
            decode_locked_object_set_preimage(&bytes),
            Err(ConsensusError::NonCanonicalLockedObjectOrder)
        );
    }

    // ---- Class (a): FastVoteEquivocationEvidence (0xD00D) ----

    #[test]
    fn build_and_verify_fast_vote_equivocation_evidence_with_real_ed25519() {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x01), digest(0x04), digest(0x03));
        let evidence = build_fast_vote_equivocation_evidence(&a, &b).unwrap();
        assert_eq!(
            verify_fast_vote_equivocation_evidence(
                &evidence,
                validator_set(4),
                &Ed25519TestVerifier
            ),
            Ok(())
        );
        let bytes = encode_fast_vote_equivocation_evidence(&evidence).unwrap();
        assert_eq!(
            decode_fast_vote_equivocation_evidence(&bytes),
            Ok(evidence.clone())
        );

        let reordered = build_fast_vote_equivocation_evidence(&b, &a).unwrap();
        assert_eq!(
            encode_fast_vote_equivocation_evidence(&evidence).unwrap(),
            encode_fast_vote_equivocation_evidence(&reordered).unwrap()
        );
    }

    #[test]
    fn build_fast_vote_equivocation_evidence_rejects_conflict_key_mismatch() {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x09), digest(0x04), digest(0x03));
        assert_eq!(
            build_fast_vote_equivocation_evidence(&a, &b),
            Err(ConsensusError::EquivocationEvidenceConflictKeyMismatch)
        );
    }

    #[test]
    fn build_fast_vote_equivocation_evidence_rejects_identical_payloads_with_different_signature_bytes()
     {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let mut b = a.clone();
        b.signature = vec![0xFF; 64];
        assert_eq!(
            build_fast_vote_equivocation_evidence(&a, &b),
            Err(ConsensusError::EquivocationEvidenceStatementsIdentical)
        );
    }

    #[test]
    fn decode_fast_vote_equivocation_evidence_rejects_a_header_that_disagrees_with_a_nested_statement()
     {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x01), digest(0x04), digest(0x03));
        let evidence = build_fast_vote_equivocation_evidence(&a, &b).unwrap();
        let mut tampered = evidence;
        tampered.validator = validator_id(99);
        let bytes = encode_fast_vote_equivocation_evidence(&tampered).unwrap();
        assert_eq!(
            decode_fast_vote_equivocation_evidence(&bytes),
            Err(ConsensusError::CertificateVoteMismatch)
        );
    }

    // ---- Class (c): EpochTransitionEquivocationEvidence (0xD00F) ----

    #[test]
    fn build_and_verify_epoch_transition_equivocation_evidence_with_real_ed25519() {
        let certifier = transition_certifier();
        let a = transition_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = transition_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x04));
        let evidence = build_epoch_transition_equivocation_evidence(&a, &b).unwrap();
        assert_eq!(
            verify_epoch_transition_equivocation_evidence(
                &evidence,
                validator_set(4),
                &Ed25519TestVerifier
            ),
            Ok(())
        );
        let bytes = encode_epoch_transition_equivocation_evidence(&evidence).unwrap();
        assert_eq!(
            decode_epoch_transition_equivocation_evidence(&bytes),
            Ok(evidence.clone())
        );

        let reordered = build_epoch_transition_equivocation_evidence(&b, &a).unwrap();
        assert_eq!(
            encode_epoch_transition_equivocation_evidence(&evidence).unwrap(),
            encode_epoch_transition_equivocation_evidence(&reordered).unwrap()
        );
    }

    #[test]
    fn build_epoch_transition_equivocation_evidence_rejects_conflict_key_mismatch() {
        let certifier = transition_certifier();
        let a = transition_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = transition_vote(&certifier, 2, digest(0x01), digest(0x02), digest(0x04));
        assert_eq!(
            build_epoch_transition_equivocation_evidence(&a, &b),
            Err(ConsensusError::EquivocationEvidenceConflictKeyMismatch)
        );
    }

    #[test]
    fn build_epoch_transition_equivocation_evidence_rejects_identical_payloads_with_different_signature_bytes()
     {
        let certifier = transition_certifier();
        let a = transition_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let mut b = a.clone();
        b.signature = vec![0xFF; 64];
        assert_eq!(
            build_epoch_transition_equivocation_evidence(&a, &b),
            Err(ConsensusError::EquivocationEvidenceStatementsIdentical)
        );
    }

    #[test]
    fn decode_epoch_transition_equivocation_evidence_rejects_a_header_that_disagrees_with_a_nested_statement()
     {
        let certifier = transition_certifier();
        let a = transition_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = transition_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x04));
        let evidence = build_epoch_transition_equivocation_evidence(&a, &b).unwrap();
        let mut tampered = evidence;
        tampered.validator = validator_id(99);
        let bytes = encode_epoch_transition_equivocation_evidence(&tampered).unwrap();
        assert_eq!(
            decode_epoch_transition_equivocation_evidence(&bytes),
            Err(ConsensusError::CertificateVoteMismatch)
        );
    }

    // ---- Class (b): FastVoteObjectConflictEvidence (0xD00E) ----

    #[test]
    fn build_and_verify_fast_vote_object_conflict_evidence_with_real_ed25519() {
        let certifier = fast_certifier();
        let shared = object_ref(0x10, 1, 0x20);
        let a_preimage = preimage(vec![shared.clone(), object_ref(0x30, 1, 0x40)]);
        let b_preimage = preimage(vec![shared.clone(), object_ref(0x50, 1, 0x60)]);
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x02), digest(0x04), digest(0x05));
        let evidence =
            build_fast_vote_object_conflict_evidence(&a, &b, &a_preimage, &b_preimage).unwrap();
        assert_eq!(evidence.conflicting_object_id, shared.id);
        assert_eq!(evidence.conflicting_version, shared.version);
        assert_eq!(
            verify_fast_vote_object_conflict_evidence(
                &evidence,
                validator_set(4),
                &Ed25519TestVerifier
            ),
            Ok(())
        );
        let bytes = encode_fast_vote_object_conflict_evidence(&evidence).unwrap();
        assert_eq!(
            decode_fast_vote_object_conflict_evidence(&bytes),
            Ok(evidence.clone())
        );

        let reordered =
            build_fast_vote_object_conflict_evidence(&b, &a, &b_preimage, &a_preimage).unwrap();
        assert_eq!(
            encode_fast_vote_object_conflict_evidence(&evidence).unwrap(),
            encode_fast_vote_object_conflict_evidence(&reordered).unwrap()
        );
    }

    #[test]
    fn build_fast_vote_object_conflict_evidence_rejects_equal_tx_hash() {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x01), digest(0x04), digest(0x05));
        let value = preimage(vec![object_ref(0x10, 1, 0x20)]);
        assert_eq!(
            build_fast_vote_object_conflict_evidence(&a, &b, &value, &value),
            Err(ConsensusError::ObjectConflictRequiresDistinctTransactions)
        );
    }

    #[test]
    fn build_fast_vote_object_conflict_evidence_rejects_no_intersection() {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x02), digest(0x04), digest(0x05));
        let a_preimage = preimage(vec![object_ref(0x10, 1, 0x20)]);
        let b_preimage = preimage(vec![object_ref(0x30, 1, 0x40)]);
        assert_eq!(
            build_fast_vote_object_conflict_evidence(&a, &b, &a_preimage, &b_preimage),
            Err(ConsensusError::ObjectConflictNotFound)
        );
    }

    #[test]
    fn build_fast_vote_object_conflict_evidence_rejects_a_preimage_whose_own_context_disagrees_with_its_vote()
     {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x02), digest(0x04), digest(0x05));
        let mut a_preimage = preimage(vec![object_ref(0x10, 1, 0x20)]);
        a_preimage.epoch = Epoch::new(epoch().get() + 1);
        let b_preimage = preimage(vec![object_ref(0x10, 1, 0x20)]);
        assert_eq!(
            build_fast_vote_object_conflict_evidence(&a, &b, &a_preimage, &b_preimage),
            Err(ConsensusError::CertificateVoteMismatch)
        );
    }

    #[test]
    fn build_matches_on_object_id_and_version_even_when_the_two_entries_digests_differ() {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x02), digest(0x04), digest(0x05));
        let a_preimage = preimage(vec![object_ref(0x10, 1, 0x20)]);
        let b_preimage = preimage(vec![object_ref(0x10, 1, 0x99)]);
        let evidence =
            build_fast_vote_object_conflict_evidence(&a, &b, &a_preimage, &b_preimage).unwrap();
        assert_eq!(evidence.conflicting_object_id, ObjectId::new([0x10; 32]));
        assert_eq!(evidence.conflicting_version, 1);
        assert_eq!(
            verify_fast_vote_object_conflict_evidence(
                &evidence,
                validator_set(4),
                &Ed25519TestVerifier
            ),
            Ok(())
        );
    }

    #[test]
    fn build_picks_the_smallest_object_id_version_pair_as_the_canonical_evidence_when_multiple_pairs_overlap_and_all_overlaps_remain_visible_in_the_preimages()
     {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x02), digest(0x04), digest(0x05));
        let shared_low = object_ref(0x10, 1, 0x20);
        let shared_high = object_ref(0x20, 1, 0x30);
        let a_preimage = preimage(vec![shared_low.clone(), shared_high.clone()]);
        let b_preimage = preimage(vec![shared_low.clone(), shared_high.clone()]);
        let evidence =
            build_fast_vote_object_conflict_evidence(&a, &b, &a_preimage, &b_preimage).unwrap();
        assert_eq!(evidence.conflicting_object_id, shared_low.id);
        assert_eq!(evidence.conflicting_version, shared_low.version);
        assert_eq!(evidence.low_preimage.entries.len(), 2);
        assert_eq!(evidence.high_preimage.entries.len(), 2);
    }

    #[test]
    fn decode_fast_vote_object_conflict_evidence_rejects_a_header_that_disagrees_with_a_nested_statement()
     {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x02), digest(0x04), digest(0x05));
        let shared = object_ref(0x10, 1, 0x20);
        let value = preimage(vec![shared]);
        let evidence = build_fast_vote_object_conflict_evidence(&a, &b, &value, &value).unwrap();
        let mut tampered = evidence;
        tampered.validator = validator_id(99);
        let bytes = encode_fast_vote_object_conflict_evidence(&tampered).unwrap();
        assert_eq!(
            decode_fast_vote_object_conflict_evidence(&bytes),
            Err(ConsensusError::CertificateVoteMismatch)
        );
    }

    #[test]
    fn decode_fast_vote_object_conflict_evidence_rejects_an_unproven_intersection_claim() {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x02), digest(0x04), digest(0x05));
        let shared = object_ref(0x10, 1, 0x20);
        let value = preimage(vec![shared]);
        let evidence = build_fast_vote_object_conflict_evidence(&a, &b, &value, &value).unwrap();
        let mut tampered = evidence;
        tampered.conflicting_object_id = ObjectId::new([0x99; 32]);
        let bytes = encode_fast_vote_object_conflict_evidence(&tampered).unwrap();
        assert_eq!(
            decode_fast_vote_object_conflict_evidence(&bytes),
            Err(ConsensusError::ObjectConflictNotProvenByPreimages)
        );
    }

    #[test]
    fn decode_and_verify_fast_vote_object_conflict_evidence_reject_a_real_but_non_canonical_overlap_when_a_smaller_shared_pair_also_exists()
     {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x02), digest(0x04), digest(0x05));
        let shared_low = object_ref(0x10, 1, 0x20);
        let shared_high = object_ref(0x20, 1, 0x30);
        let a_preimage = preimage(vec![shared_low.clone(), shared_high.clone()]);
        let b_preimage = preimage(vec![shared_low.clone(), shared_high.clone()]);
        let evidence =
            build_fast_vote_object_conflict_evidence(&a, &b, &a_preimage, &b_preimage).unwrap();
        let mut tampered = evidence;
        tampered.conflicting_object_id = shared_high.id;
        tampered.conflicting_version = shared_high.version;
        let bytes = encode_fast_vote_object_conflict_evidence(&tampered).unwrap();
        assert_eq!(
            decode_fast_vote_object_conflict_evidence(&bytes),
            Err(ConsensusError::ObjectConflictNotProvenByPreimages)
        );
        assert_eq!(
            verify_fast_vote_object_conflict_evidence(
                &tampered,
                validator_set(4),
                &Ed25519TestVerifier
            ),
            Err(ConsensusError::ObjectConflictNotProvenByPreimages)
        );
    }

    #[test]
    fn decode_fast_vote_object_conflict_evidence_rejects_a_preimage_whose_own_context_disagrees_with_its_attached_vote()
     {
        let certifier = fast_certifier();
        let a = fast_vote(&certifier, 1, digest(0x01), digest(0x02), digest(0x03));
        let b = fast_vote(&certifier, 1, digest(0x02), digest(0x04), digest(0x05));
        let shared = object_ref(0x10, 1, 0x20);
        let value = preimage(vec![shared]);
        let evidence = build_fast_vote_object_conflict_evidence(&a, &b, &value, &value).unwrap();
        let mut tampered = evidence;
        tampered.low_preimage.epoch = Epoch::new(epoch().get() + 1);
        let bytes = encode_fast_vote_object_conflict_evidence(&tampered).unwrap();
        assert_eq!(
            decode_fast_vote_object_conflict_evidence(&bytes),
            Err(ConsensusError::CertificateVoteMismatch)
        );
    }

    // Pinned literal vectors for the 4 type ids this module allocates
    // (`0xD00C`-`0xD00F`), independently reconstructed byte-for-byte by
    // `scripts/fast-vote-vectors.mjs` without invoking this Rust encoder.
    // Fixed, non-cryptographic signature bytes are used here deliberately,
    // matching `fast_vote.rs`'s own vector precedent.

    fn vector_preimage() -> LockedObjectSetPreimage {
        LockedObjectSetPreimage {
            chain_id: ChainId::new("dr0133-vectors").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(9),
            entries: vec![
                ObjectRef {
                    id: ObjectId::new([0x10; 32]),
                    version: 1,
                    digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x20; 32]),
                },
                ObjectRef {
                    id: ObjectId::new([0x30; 32]),
                    version: 2,
                    digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x40; 32]),
                },
            ],
        }
    }

    #[test]
    fn locked_object_set_preimage_encoding_vector_0xd00c_is_stable() {
        let bytes = encode_locked_object_set_preimage(&vector_preimage()).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e52450cd00100060001000e0000006472303133332d766563746f72730200040000000300000003000800000009000000000000000400040000000200000005008c000000534e5245044001000300010030000000534e524501400100010001002000000010101010101010101010101010101010101010101010101010101010101010100200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000202020202020202020202020202020202020202020202020202020202020202006008c000000534e5245044001000300010030000000534e524501400100010001002000000030303030303030303030303030303030303030303030303030303030303030300200080000000200000000000000030038000000534e524503010100020001000200000001000200200000004040404040404040404040404040404040404040404040404040404040404040"
        );
    }

    fn vector_fast_vote_a() -> FastVote {
        FastVote {
            chain_id: ChainId::new("dr0133-vectors").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(9),
            tx_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0xAA; 32]),
            execution_effects_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0xBB; 32]),
            validator: ValidatorId::new([0x01; 32]),
            signature_scheme: SignatureSchemeId::Ed25519,
            locked_objects_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xCC; 32]),
            signature: vec![0x5A; 64],
        }
    }
    fn vector_fast_vote_b() -> FastVote {
        let mut vote = vector_fast_vote_a();
        vote.execution_effects_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xDD; 32]);
        vote.signature = vec![0x7C; 64];
        vote
    }
    fn vector_fast_vote_c() -> FastVote {
        let mut vote = vector_fast_vote_a();
        vote.tx_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
        vote.signature = vec![0x9B; 64];
        vote
    }

    #[test]
    fn fast_vote_equivocation_evidence_vector_0xd00d_is_stable() {
        let evidence =
            build_fast_vote_equivocation_evidence(&vector_fast_vote_a(), &vector_fast_vote_b())
                .unwrap();
        let bytes = encode_fast_vote_equivocation_evidence(&evidence).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e52450dd00100070001000e0000006472303133332d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0500200000000101010101010101010101010101010101010101010101010101010101010101060074010000534e524507d00100020001001e010000534e524506d00100080001000e0000006472303133332d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb06002000000001010101010101010101010101010101010101010101010101010101010101010700020000000100080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a070074010000534e524507d00100020001001e010000534e524506d00100080001000e0000006472303133332d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd06002000000001010101010101010101010101010101010101010101010101010101010101010700020000000100080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200400000007c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c"
        );
    }

    fn vector_locked_object_set_preimage() -> LockedObjectSetPreimage {
        LockedObjectSetPreimage {
            chain_id: ChainId::new("dr0133-vectors").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(9),
            entries: vec![ObjectRef {
                id: ObjectId::new([0x10; 32]),
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x20; 32]),
            }],
        }
    }

    #[test]
    fn fast_vote_object_conflict_evidence_vector_0xd00e_is_stable() {
        let evidence = build_fast_vote_object_conflict_evidence(
            &vector_fast_vote_a(),
            &vector_fast_vote_c(),
            &vector_locked_object_set_preimage(),
            &vector_locked_object_set_preimage(),
        )
        .unwrap();
        let bytes = encode_fast_vote_object_conflict_evidence(&evidence).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e52450ed001000a0001000e0000006472303133332d766563746f7273020004000000030000000300080000000900000000000000040020000000010101010101010101010101010101010101010101010101010101010101010105002000000010101010101010101010101010101010101010101010101010101010101010100600080000000100000000000000070074010000534e524507d00100020001001e010000534e524506d00100080001000e0000006472303133332d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb06002000000001010101010101010101010101010101010101010101010101010101010101010700020000000100080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0800d2000000534e52450cd00100050001000e0000006472303133332d766563746f72730200040000000300000003000800000009000000000000000400040000000100000005008c000000534e5245044001000300010030000000534e524501400100010001002000000010101010101010101010101010101010101010101010101010101010101010100200080000000100000000000000030038000000534e524503010100020001000200000001000200200000002020202020202020202020202020202020202020202020202020202020202020090074010000534e524507d00100020001001e010000534e524506d00100080001000e0000006472303133332d766563746f7273020004000000030000000300080000000900000000000000040038000000534e52450301010002000100020000000100020020000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee050038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb06002000000001010101010101010101010101010101010101010101010101010101010101010700020000000100080038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0200400000009b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b0a00d2000000534e52450cd00100050001000e0000006472303133332d766563746f72730200040000000300000003000800000009000000000000000400040000000100000005008c000000534e5245044001000300010030000000534e524501400100010001002000000010101010101010101010101010101010101010101010101010101010101010100200080000000100000000000000030038000000534e524503010100020001000200000001000200200000002020202020202020202020202020202020202020202020202020202020202020"
        );
    }

    fn vector_transition_vote_a() -> EpochTransitionVote {
        EpochTransitionVote {
            chain_id: ChainId::new("dr0133-vectors").unwrap(),
            protocol_version: ProtocolVersion::new(3),
            epoch: Epoch::new(9),
            next_epoch: Epoch::new(10),
            current_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xAA; 32]),
            next_validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xBB; 32]),
            activation_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xCC; 32]),
            validator: ValidatorId::new([0x01; 32]),
            signature_scheme: SignatureSchemeId::Ed25519,
            signature: vec![0x5A; 64],
        }
    }
    fn vector_transition_vote_b() -> EpochTransitionVote {
        let mut vote = vector_transition_vote_a();
        vote.activation_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xDD; 32]);
        vote.signature = vec![0x7C; 64];
        vote
    }

    #[test]
    fn epoch_transition_equivocation_evidence_vector_0xd00f_is_stable() {
        let evidence = build_epoch_transition_equivocation_evidence(
            &vector_transition_vote_a(),
            &vector_transition_vote_b(),
        )
        .unwrap();
        let bytes = encode_epoch_transition_equivocation_evidence(&evidence).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e52450fd00100060001000e0000006472303133332d766563746f72730200040000000300000003000800000009000000000000000400200000000101010101010101010101010101010101010101010101010101010101010101050082010000534e52450ad00100020001002c010000534e524509d00100090001000e0000006472303133332d766563746f72730200040000000300000003000800000009000000000000000400080000000a00000000000000050038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa060038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb070038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc080020000000010101010101010101010101010101010101010101010101010101010101010109000200000001000200400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a060082010000534e52450ad00100020001002c010000534e524509d00100090001000e0000006472303133332d766563746f72730200040000000300000003000800000009000000000000000400080000000a00000000000000050038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa060038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb070038000000534e52450301010002000100020000000100020020000000dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd080020000000010101010101010101010101010101010101010101010101010101010101010109000200000001000200400000007c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c"
        );
    }
}
