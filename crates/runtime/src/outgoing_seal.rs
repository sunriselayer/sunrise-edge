//! DR-0187 mandatory outgoing barrier and first-epoch ordered Seal storage.
//!
//! This module owns protected, non-business metadata only. It grants no
//! signing, readiness, membership, or activation authority and performs no
//! business cut; private core preparation owns those decisions. Storage here
//! validates local continuity and closed sections, never protocol authority.

use crate::*;
use canonical_encoding::{
    CanonicalStruct, decode_canonical_frame, decode_digest32, encode_digest32,
};

/// Closed 0x64D4 sealed-record byte bound.
pub const MAX_SEAL_BARRIER_BYTES: usize = 1024;
/// Closed 0x64D3 protected-barrier byte bound.
pub const MAX_OUTGOING_BARRIER_BYTES: usize = 1536;

fn invalid() -> RuntimeError {
    RuntimeError::InvalidOutgoingBarrier
}

/// Closed transition-history marker. Positive history bound to a committed
/// Seal, never inferred from an absent cache. Only Virgin is defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionHistoryState {
    /// Initialized together with the first accepted Seal in this namespace.
    Virgin,
}

impl TransitionHistoryState {
    const fn tag(self) -> u16 {
        match self {
            Self::Virgin => 1,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, RuntimeError> {
        match tag {
            1 => Ok(Self::Virgin),
            _ => Err(invalid()),
        }
    }
}

/// Closed 0x64D4 sealed record: the exact original committed Seal outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealBarrier {
    pub outgoing_epoch: Epoch,
    /// Request preimage bytes with request_id[0] |= 0x80 already applied.
    pub request: [u8; 32],
    pub height: u64,
    pub block_digest: Digest32,
    pub target_digest: Digest32,
    pub transition_history: TransitionHistoryState,
}

/// Non-removable protected 0x64D3 barrier.
///
/// Unsealed proves only that no outgoing Seal has committed in this
/// namespace; it is never membership or serving permission. Sealed never
/// reverts to Unsealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutgoingBarrier {
    Unsealed,
    Sealed(SealBarrier),
}

impl OutgoingBarrier {
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }

    #[must_use]
    pub const fn sealed(&self) -> Option<&SealBarrier> {
        match self {
            Self::Sealed(record) => Some(record),
            Self::Unsealed => None,
        }
    }
}

/// Encodes the closed 0x64D4 sealed-record frame.
pub fn encode_seal_barrier(value: &SealBarrier) -> Result<Vec<u8>, RuntimeError> {
    if value.request[0] & 0x80 == 0 || value.height == 0 {
        return Err(invalid());
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64D4, 1);
    frame
        .field_u64(1, value.outgoing_epoch.get())
        .map_err(|_| invalid())?;
    frame
        .field_bytes(2, value.request.to_vec())
        .map_err(|_| invalid())?;
    frame.field_u64(3, value.height).map_err(|_| invalid())?;
    frame
        .field_bytes(
            4,
            encode_digest32(&value.block_digest).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
    frame
        .field_bytes(
            5,
            encode_digest32(&value.target_digest).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
    frame
        .field_u16(6, value.transition_history.tag())
        .map_err(|_| invalid())?;
    let bytes: Vec<u8> = frame.finish().map_err(|_| invalid())?;
    if bytes.len() > MAX_SEAL_BARRIER_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Decodes and re-verifies the closed 0x64D3 protected-barrier frame.
pub fn decode_outgoing_barrier(bytes: &[u8]) -> Result<OutgoingBarrier, RuntimeError> {
    if bytes.len() > MAX_OUTGOING_BARRIER_BYTES {
        return Err(invalid());
    }
    let frame = decode_canonical_frame(bytes).map_err(|_| invalid())?;
    frame.require_type(0x64D3).map_err(|_| invalid())?;
    frame.require_version(1).map_err(|_| invalid())?;
    frame.require_only_fields(&[1, 2]).map_err(|_| invalid())?;
    let phase: u16 = frame.required_u16(1).map_err(|_| invalid())?;
    let record_bytes: &[u8] = frame.required_field(2).map_err(|_| invalid())?;
    let value: OutgoingBarrier = match (phase, record_bytes.is_empty()) {
        (1, true) => OutgoingBarrier::Unsealed,
        (2, false) => OutgoingBarrier::Sealed(decode_seal_barrier(record_bytes)?),
        _ => return Err(invalid()),
    };
    if encode_outgoing_barrier(&value)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

/// Narrow, optionally supported Seal production capability.
///
/// Only native SQLite and explicitly domain-bound memory stores implement
/// this; PostgreSQL, Durable Object, and every other facade have no default
/// Seal capability. The capability always refers to the same owning store,
/// never a caller-supplied foreign writer. Both methods recheck namespace,
/// domain, fence, deadline, origin, and barrier phase inside their own
/// lock or transaction; a caller must not rely on an earlier observation.
pub trait OutgoingSealRepository:
    StructuredDurableDomainStateStore + portable::DurablePortableSnapshotRepository
{
    /// Commits one token-checked state transaction while the barrier is
    /// still Unsealed. This never selects or installs the Seal target.
    fn commit_seal_retention(
        &self,
        context: &DurableOperationContext,
        token: &portable::PortableSnapshotToken,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome;

    /// Commits the original Seal invocation and installs sealed as the
    /// permanent barrier record, atomically with the invocation and the
    /// checked mutation-sequence advance. sealed never becomes Unsealed.
    fn commit_seal_completion(
        &self,
        context: &DurableOperationContext,
        token: &portable::PortableSnapshotToken,
        transaction: DurableInvocationTransaction,
        sealed: SealBarrier,
    ) -> DurableCommitOutcome;
}

mod memory;
pub(crate) fn sealed_outbox_is_consistent(
    data: &MemoryDurableStoreData,
    domain: AtomicityDomainId,
) -> bool {
    !data.outgoing_barrier.is_sealed() || memory::seal_outbox_is_empty(data, domain)
}
#[cfg(test)]
mod tests;

/// Decodes and re-verifies the closed 0x64D4 sealed-record frame.
pub fn decode_seal_barrier(bytes: &[u8]) -> Result<SealBarrier, RuntimeError> {
    if bytes.len() > MAX_SEAL_BARRIER_BYTES {
        return Err(invalid());
    }
    let frame = decode_canonical_frame(bytes).map_err(|_| invalid())?;
    frame.require_type(0x64D4).map_err(|_| invalid())?;
    frame.require_version(1).map_err(|_| invalid())?;
    frame
        .require_only_fields(&[1, 2, 3, 4, 5, 6])
        .map_err(|_| invalid())?;
    let request: [u8; 32] = frame
        .required_field(2)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    let value: SealBarrier = SealBarrier {
        outgoing_epoch: Epoch::new(frame.required_u64(1).map_err(|_| invalid())?),
        request,
        height: frame.required_u64(3).map_err(|_| invalid())?,
        block_digest: decode_digest32(frame.required_field(4).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        target_digest: decode_digest32(frame.required_field(5).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        transition_history: TransitionHistoryState::from_tag(
            frame.required_u16(6).map_err(|_| invalid())?,
        )?,
    };
    if encode_seal_barrier(&value)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

/// Encodes the closed 0x64D3 protected-barrier frame.
pub fn encode_outgoing_barrier(value: &OutgoingBarrier) -> Result<Vec<u8>, RuntimeError> {
    let (phase, record_bytes): (u16, Vec<u8>) = match value {
        OutgoingBarrier::Unsealed => (1, Vec::new()),
        OutgoingBarrier::Sealed(record) => (2, encode_seal_barrier(record)?),
    };
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64D3, 1);
    frame.field_u16(1, phase).map_err(|_| invalid())?;
    frame.field_bytes(2, record_bytes).map_err(|_| invalid())?;
    let bytes: Vec<u8> = frame.finish().map_err(|_| invalid())?;
    if bytes.len() > MAX_OUTGOING_BARRIER_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}
