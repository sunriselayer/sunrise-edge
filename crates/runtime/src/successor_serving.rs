//! DR-0189 first successor target-local activation and authenticated serving.
//!
//! This module owns protected, non-business raw continuity metadata only. An
//! installed record or slot observation is never cryptographic or membership
//! authority; core independently re-verifies full evidence on every
//! invocation. Storage here validates local continuity and closed sections.

use crate::conditional_readiness::{
    decode_readiness_creation_token, encode_readiness_creation_token,
};
use crate::inactive_import::{
    decode_import_binding, decode_import_progress, encode_import_binding, encode_import_progress,
};
use crate::portable::PortableSnapshotToken;
use crate::*;
use canonical_encoding::{CanonicalStruct, decode_canonical_frame, decode_digest32, encode_digest32};

/// Closed 0x64D5 protected-record byte bound.
pub const MAX_SUCCESSOR_SERVING_RECORD_BYTES: usize = 16 * 1024;
/// Closed 0x64D6 protected-slot byte bound.
pub const MAX_SUCCESSOR_SERVING_SLOT_BYTES: usize = 17 * 1024;

fn invalid() -> RuntimeError {
    RuntimeError::InvalidSuccessorServingRequest
}

/// Raw continuity data tying an installed protected record to its
/// destination lifecycle. `record` is the exact closed 0x64D5 frame bytes;
/// `binding` and `progress` are decoded from its own fields 3 and 4 so a
/// caller can compare them without redecoding on every check. This is never
/// cryptographic or membership authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorServingObservation {
    pub record: Vec<u8>,
    pub binding: ImportBinding,
    pub progress: ImportProgress,
}

/// Closed 0x64D6 protected slot. Only `Inactive` precedes activation; once
/// `Serving`, it never reverts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuccessorServingSlot {
    Inactive,
    Serving(SuccessorServingObservation),
}

impl SuccessorServingSlot {
    #[must_use]
    pub const fn is_serving(&self) -> bool {
        matches!(self, Self::Serving(_))
    }

    #[must_use]
    pub const fn serving(&self) -> Option<&SuccessorServingObservation> {
        match self {
            Self::Serving(observation) => Some(observation),
            Self::Inactive => None,
        }
    }
}

/// Decoded closed 0x64D5 protected record fields. The observation is raw
/// continuity only; core independently re-verifies membership and signing
/// authority before trusting any of these fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessorServingRecord {
    pub subject: Digest32,
    pub manifest: Digest32,
    pub binding: ImportBinding,
    pub progress: ImportProgress,
    pub activation_token: PortableSnapshotToken,
    pub anchor: Digest32,
    pub validator: ValidatorId,
    pub public_key: [u8; 32],
}

/// Encodes the closed 0x64D5/v1 protected record.
pub fn encode_successor_serving_record(
    value: &SuccessorServingRecord,
) -> Result<Vec<u8>, RuntimeError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64D5, 1);
    frame
        .field_bytes(1, encode_digest32(&value.subject).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(2, encode_digest32(&value.manifest).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(3, encode_import_binding(&value.binding)?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(4, encode_import_progress(&value.progress)?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(5, encode_readiness_creation_token(&value.activation_token)?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(6, encode_digest32(&value.anchor).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(7, value.validator.as_bytes().to_vec())
        .map_err(|_| invalid())?;
    frame
        .field_bytes(8, value.public_key.to_vec())
        .map_err(|_| invalid())?;
    let bytes: Vec<u8> = frame.finish().map_err(|_| invalid())?;
    if bytes.len() > MAX_SUCCESSOR_SERVING_RECORD_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Decodes and re-verifies the closed 0x64D5/v1 protected record.
pub fn decode_successor_serving_record(
    bytes: &[u8],
) -> Result<SuccessorServingRecord, RuntimeError> {
    if bytes.len() > MAX_SUCCESSOR_SERVING_RECORD_BYTES {
        return Err(invalid());
    }
    let frame = decode_canonical_frame(bytes).map_err(|_| invalid())?;
    frame.require_type(0x64D5).map_err(|_| invalid())?;
    frame.require_version(1).map_err(|_| invalid())?;
    frame
        .require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8])
        .map_err(|_| invalid())?;
    let public_key: [u8; 32] = frame
        .required_field(8)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    let value: SuccessorServingRecord = SuccessorServingRecord {
        subject: decode_digest32(frame.required_field(1).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        manifest: decode_digest32(frame.required_field(2).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        binding: decode_import_binding(frame.required_field(3).map_err(|_| invalid())?)?,
        progress: decode_import_progress(frame.required_field(4).map_err(|_| invalid())?)?,
        activation_token: decode_readiness_creation_token(
            frame.required_field(5).map_err(|_| invalid())?,
        )?,
        anchor: decode_digest32(frame.required_field(6).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        validator: ValidatorId::new(
            frame
                .required_field(7)
                .map_err(|_| invalid())?
                .try_into()
                .map_err(|_| invalid())?,
        ),
        public_key,
    };
    if encode_successor_serving_record(&value)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

/// Encodes the closed 0x64D6/v1 protected slot.
pub fn encode_successor_serving_slot(
    value: &SuccessorServingSlot,
) -> Result<Vec<u8>, RuntimeError> {
    let (phase, record_bytes): (u16, Vec<u8>) = match value {
        SuccessorServingSlot::Inactive => (1, Vec::new()),
        SuccessorServingSlot::Serving(observation) => {
            let record: SuccessorServingRecord =
                decode_successor_serving_record(&observation.record)?;
            if record.binding != observation.binding || record.progress != observation.progress {
                return Err(invalid());
            }
            (2, observation.record.clone())
        }
    };
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64D6, 1);
    frame.field_u16(1, phase).map_err(|_| invalid())?;
    frame.field_bytes(2, record_bytes).map_err(|_| invalid())?;
    let bytes: Vec<u8> = frame.finish().map_err(|_| invalid())?;
    if bytes.len() > MAX_SUCCESSOR_SERVING_SLOT_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Decodes and re-verifies the closed 0x64D6/v1 protected slot.
pub fn decode_successor_serving_slot(bytes: &[u8]) -> Result<SuccessorServingSlot, RuntimeError> {
    if bytes.len() > MAX_SUCCESSOR_SERVING_SLOT_BYTES {
        return Err(invalid());
    }
    let frame = decode_canonical_frame(bytes).map_err(|_| invalid())?;
    frame.require_type(0x64D6).map_err(|_| invalid())?;
    frame.require_version(1).map_err(|_| invalid())?;
    frame.require_only_fields(&[1, 2]).map_err(|_| invalid())?;
    let phase: u16 = frame.required_u16(1).map_err(|_| invalid())?;
    let record_bytes: &[u8] = frame.required_field(2).map_err(|_| invalid())?;
    let value: SuccessorServingSlot = match (phase, record_bytes.is_empty()) {
        (1, true) => SuccessorServingSlot::Inactive,
        (2, false) => {
            let record: SuccessorServingRecord = decode_successor_serving_record(record_bytes)?;
            SuccessorServingSlot::Serving(SuccessorServingObservation {
                record: record_bytes.to_vec(),
                binding: record.binding,
                progress: record.progress,
            })
        }
        _ => return Err(invalid()),
    };
    if encode_successor_serving_slot(&value)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

/// Opt-in protected first-successor activation and serving seam. No default
/// or ordinary-host authority; `successor_serving_repository` returns `None`
/// unless a store is explicitly bound to this capability. Every method
/// rechecks fence, deadline, domain, lifecycle, barrier and slot inside its
/// own lock or transaction; a caller must not rely on an earlier observation.
pub trait SuccessorServingRepository: InactiveImportRepository {
    /// Reads the persisted physical namespace validator. This is raw
    /// continuity data, never membership or signing authority.
    fn read_namespace_validator(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<ValidatorId, DurableReadError>;

    /// Commits the one-time atomic activation transaction while the slot is
    /// still `Inactive`, installing `record` as the permanent `Serving`
    /// observation. `Inactive` never reverts and this never writes twice.
    #[allow(clippy::too_many_arguments)]
    fn commit_successor_activation(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        record: &[u8],
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome;

    /// Commits one durable successor state transaction after rechecking the
    /// exact installed `Serving` observation inside this same lock.
    fn commit_successor_durable(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome;

    /// Commits one structured successor invocation after rechecking the
    /// exact installed `Serving` observation inside this same lock.
    fn commit_successor_invocation(
        &self,
        context: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome;
}

mod memory;
#[cfg(test)]
mod tests;
