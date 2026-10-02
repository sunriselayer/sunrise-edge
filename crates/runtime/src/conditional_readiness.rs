//! Bounded, storage-only conditional-readiness retention. These records do not
//! authenticate a vote or grant signing, ordinary execution or activation.

use crate::inactive_import::{
    decode_import_binding, decode_import_progress, encode_import_binding, encode_import_progress,
};
use crate::portable::{PortableSnapshotError, PortableSnapshotToken};
use crate::{
    AtomicityDomainId, DurableCommitOutcome, DurableOperationContext, ImportBinding,
    ImportProgress, InactiveImportRepository, RuntimeError, ValidatorId, WriterFenceGeneration,
};
use canonical_encoding::{
    CanonicalFrame, CanonicalStruct, decode_canonical_frame, decode_digest32, encode_digest32,
};
use protocol_types::Digest32;

mod memory;
#[cfg(test)]
mod tests;

/// Maximum exact canonical protected-slot key.
pub const MAX_READINESS_SLOT_BYTES: usize = 256;
/// Maximum opaque canonical vote supplied by the verifying core owner.
pub const MAX_READINESS_VOTE_BYTES: usize = 4 * 1024;
/// Maximum entire canonical protected record, including local observations.
pub const MAX_READINESS_RECORD_BYTES: usize = 16 * 1024;

/// Nonexclusive semantic subject and registered signer, scoped to one store.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReadinessSlot {
    /// Semantic subject digest; local package variants are not its identity.
    pub identity: Digest32,
    /// Registered signer identity, verified by core rather than storage.
    pub signer: ValidatorId,
}

/// Exact local retention, not a constructor of verified protocol authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadinessRecord {
    /// Exact namespace-local lookup key.
    pub slot: ReadinessSlot,
    /// Immutable destination import binding, including the local plan.
    pub binding: ImportBinding,
    /// Exact completed import progress, not a caller-created completion flag.
    pub progress: ImportProgress,
    /// Immutable pre-insertion observation; never current retry authority.
    pub creation_token: PortableSnapshotToken,
    /// Core owns canonical vote/signature verification; storage bounds bytes.
    pub vote_bytes: Vec<u8>,
}

/// One exact bounded slot observation. Tombstones never mean absence.
// One bounded record is deliberately owned inline, matching the exact-slot API.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadinessSlotObservation {
    /// No record exists; this is not a virgin-key or signing assertion.
    Absent,
    /// The exact original record after bounded decoding and local linkage.
    Present(ReadinessRecord),
    /// A known tombstone refuses both insertion and exact replay.
    Tombstoned,
}

/// Opt-in protected metadata seam. No default or ordinary-host authority.
pub trait ReadinessRetentionRepository: InactiveImportRepository {
    /// Inspect one slot after atomically checking current authority, token,
    /// CompleteInactive origin and exact binding/progress.
    #[allow(clippy::too_many_arguments)]
    fn read_ready_slot_at(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        slot: &ReadinessSlot,
    ) -> Result<ReadinessSlotObservation, PortableSnapshotError>;

    /// Insert and advance the covered sequence atomically, or compare an exact
    /// present record read-only. A stale token never authorizes either path.
    #[allow(clippy::too_many_arguments)]
    fn retain_ready_slot(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        expected_observation: &ReadinessSlotObservation,
        record: &ReadinessRecord,
    ) -> DurableCommitOutcome;
}

fn invalid() -> RuntimeError {
    RuntimeError::InvalidReadinessRequest
}

/// Encode the closed 0x64D0/v1 protected-slot frame.
pub fn encode_readiness_slot(slot: &ReadinessSlot) -> Result<Vec<u8>, RuntimeError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64D0, 1);
    frame
        .field_bytes(1, encode_digest32(&slot.identity).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(2, slot.signer.as_bytes().to_vec())
        .map_err(|_| invalid())?;
    let bytes: Vec<u8> = frame.finish().map_err(|_| invalid())?;
    if bytes.len() > MAX_READINESS_SLOT_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Strictly decode a bounded slot, including exact re-encoding equality.
pub fn decode_readiness_slot(bytes: &[u8]) -> Result<ReadinessSlot, RuntimeError> {
    if bytes.len() > MAX_READINESS_SLOT_BYTES {
        return Err(invalid());
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes).map_err(|_| invalid())?;
    frame.require_type(0x64D0).map_err(|_| invalid())?;
    frame.require_version(1).map_err(|_| invalid())?;
    frame.require_only_fields(&[1, 2]).map_err(|_| invalid())?;
    let slot: ReadinessSlot = ReadinessSlot {
        identity: decode_digest32(frame.required_field(1).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        signer: ValidatorId::new(
            frame
                .required_field(2)
                .map_err(|_| invalid())?
                .try_into()
                .map_err(|_| invalid())?,
        ),
    };
    if encode_readiness_slot(&slot)? != bytes {
        return Err(invalid());
    }
    Ok(slot)
}

/// Encode the closed 0x64D2/v1 local creation-observation frame.
pub fn encode_readiness_creation_token(
    token: &PortableSnapshotToken,
) -> Result<Vec<u8>, RuntimeError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64D2, 1);
    frame
        .field_bytes(1, token.namespace().to_vec())
        .map_err(|_| invalid())?;
    frame
        .field_bytes(2, token.domain().as_bytes().to_vec())
        .map_err(|_| invalid())?;
    frame
        .field_u64(3, token.writer_fence().get())
        .map_err(|_| invalid())?;
    frame
        .field_u64(4, token.mutation_sequence())
        .map_err(|_| invalid())?;
    frame.finish().map_err(|_| invalid())
}

/// Strictly decode the bounded namespace/domain/fence/sequence observation.
pub fn decode_readiness_creation_token(
    bytes: &[u8],
) -> Result<PortableSnapshotToken, RuntimeError> {
    if bytes.len() > MAX_READINESS_RECORD_BYTES {
        return Err(invalid());
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes).map_err(|_| invalid())?;
    frame.require_type(0x64D2).map_err(|_| invalid())?;
    frame.require_version(1).map_err(|_| invalid())?;
    frame
        .require_only_fields(&[1, 2, 3, 4])
        .map_err(|_| invalid())?;
    let namespace: &[u8] = frame.required_field(1).map_err(|_| invalid())?;
    if namespace.is_empty()
        || namespace.len() > crate::portable::MAX_PORTABLE_SNAPSHOT_NAMESPACE_BYTES
    {
        return Err(invalid());
    }
    let domain: AtomicityDomainId = AtomicityDomainId::new(
        frame
            .required_field(2)
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    let fence: WriterFenceGeneration =
        WriterFenceGeneration::new(frame.required_u64(3).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
    let token: PortableSnapshotToken = PortableSnapshotToken::new(
        namespace.to_vec(),
        domain,
        fence,
        frame.required_u64(4).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    if encode_readiness_creation_token(&token)? != bytes {
        return Err(invalid());
    }
    Ok(token)
}

/// Encode the closed 0x64D1/v1 local record; this does not verify its vote.
pub fn encode_readiness_record(record: &ReadinessRecord) -> Result<Vec<u8>, RuntimeError> {
    if record.vote_bytes.is_empty()
        || record.vote_bytes.len() > MAX_READINESS_VOTE_BYTES
        || record.progress.next_ordinal != record.binding.row_count
        || record.creation_token.domain() != record.binding.domain
    {
        return Err(invalid());
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64D1, 1);
    frame
        .field_bytes(1, encode_readiness_slot(&record.slot)?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(2, encode_import_binding(&record.binding)?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(3, encode_import_progress(&record.progress)?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(4, encode_readiness_creation_token(&record.creation_token)?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(5, record.vote_bytes.clone())
        .map_err(|_| invalid())?;
    let bytes: Vec<u8> = frame.finish().map_err(|_| invalid())?;
    if bytes.len() > MAX_READINESS_RECORD_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Strictly decode one bounded local record, not protocol signing authority.
pub fn decode_readiness_record(bytes: &[u8]) -> Result<ReadinessRecord, RuntimeError> {
    if bytes.len() > MAX_READINESS_RECORD_BYTES {
        return Err(invalid());
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes).map_err(|_| invalid())?;
    frame.require_type(0x64D1).map_err(|_| invalid())?;
    frame.require_version(1).map_err(|_| invalid())?;
    frame
        .require_only_fields(&[1, 2, 3, 4, 5])
        .map_err(|_| invalid())?;
    let vote: &[u8] = frame.required_field(5).map_err(|_| invalid())?;
    if vote.is_empty() || vote.len() > MAX_READINESS_VOTE_BYTES {
        return Err(invalid());
    }
    let record: ReadinessRecord = ReadinessRecord {
        slot: decode_readiness_slot(frame.required_field(1).map_err(|_| invalid())?)?,
        binding: decode_import_binding(frame.required_field(2).map_err(|_| invalid())?)?,
        progress: decode_import_progress(frame.required_field(3).map_err(|_| invalid())?)?,
        creation_token: decode_readiness_creation_token(
            frame.required_field(4).map_err(|_| invalid())?,
        )?,
        vote_bytes: vote.to_vec(),
    };
    if encode_readiness_record(&record)? != bytes {
        return Err(invalid());
    }
    Ok(record)
}

impl ReadinessRecord {
    /// Local linkage of a present record. The old observation is not authority
    /// over current state and is never used instead of the current token.
    /// The storage caller must already have atomically checked `current`.
    pub fn validate_present_at(
        &self,
        slot: &ReadinessSlot,
        binding: &ImportBinding,
        progress: &ImportProgress,
        current: &PortableSnapshotToken,
    ) -> Result<(), RuntimeError> {
        encode_readiness_record(self)?;
        if &self.slot != slot
            || &self.binding != binding
            || &self.progress != progress
            || self.creation_token.namespace() != current.namespace()
            || self.creation_token.domain() != current.domain()
            || self.creation_token.writer_fence().get() > current.writer_fence().get()
            || self.creation_token.mutation_sequence() >= current.mutation_sequence()
        {
            return Err(invalid());
        }
        Ok(())
    }
}
