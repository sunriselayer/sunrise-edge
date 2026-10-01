//! DR-0176 storage-only inactive installation. These types do not authenticate
//! a cut or grant execution, signing, readiness or activation authority.

use crate::*;
use canonical_encoding::{
    CanonicalStruct, decode_canonical_frame, decode_digest32, encode_digest32,
};
use protocol_types::ExecutionGeneration;

/// Maximum rows admitted by one inactive installation transaction.
pub const MAX_IMPORT_BATCH_ROWS: usize = 128;
/// Aggregate envelope bound, preserving a legal 32 MiB owning record.
pub const MAX_IMPORT_BATCH_BYTES: usize = 64 * 1024 * 1024;
/// A binding or progress frame is small even for an arbitrarily long history.
pub const MAX_IMPORT_METADATA_BYTES: usize = 16 * 1024;

/// Locally configured outgoing context; never a serving-epoch permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportContext {
    pub chain_id: ChainId,
    pub protocol_version: ProtocolVersion,
    pub epoch: Epoch,
}

/// Immutable storage binding. Core independently authenticates these claims
/// before creating a target; runtime never calls a stored binding verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportBinding {
    pub context: ImportContext,
    pub domain: AtomicityDomainId,
    pub genesis_digest: Digest32,
    pub validator_set_digest: Digest32,
    pub cut_digest: Digest32,
    pub package_digest: Digest32,
    pub plan_digest: Digest32,
    pub row_count: u64,
    pub blob_count: u64,
    pub generation_floor: ExecutionGeneration,
}

/// Exact local progress. A cursor or completion flag is not business proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportProgress {
    pub next_ordinal: u64,
    pub last_batch_digest: Option<Digest32>,
    pub accumulator: Digest32,
}

/// Non-removable origin plus its closed local installation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamespaceLifecycle {
    /// Explicitly initialized ordinary origin, not proof of active membership.
    Ordinary,
    FreshImport(ImportBinding),
    Importing {
        binding: ImportBinding,
        progress: ImportProgress,
    },
    CompleteInactive {
        binding: ImportBinding,
        progress: ImportProgress,
    },
}

impl NamespaceLifecycle {
    #[must_use]
    pub const fn is_ordinary(&self) -> bool {
        matches!(self, Self::Ordinary)
    }
    #[must_use]
    pub const fn binding(&self) -> Option<&ImportBinding> {
        match self {
            Self::Ordinary => None,
            Self::FreshImport(binding)
            | Self::Importing { binding, .. }
            | Self::CompleteInactive { binding, .. } => Some(binding),
        }
    }
    #[must_use]
    pub const fn progress(&self) -> Option<&ImportProgress> {
        match self {
            Self::Importing { progress, .. } | Self::CompleteInactive { progress, .. } => {
                Some(progress)
            }
            Self::Ordinary | Self::FreshImport(_) => None,
        }
    }
}

/// A head's semantic observation, with no caller-selected physical revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportObjectHead {
    Current {
        object_version: DurableObjectVersion,
        digest: Digest32,
        owner_projection: DurableObjectOwnerProjection,
        routing_projection: DurableObjectRoutingProjection,
    },
    Tombstoned {
        last_object_version: DurableObjectVersion,
    },
}

/// Closed installation rows, separate from ordinary object transitions and
/// their one-original-receipt invocation contract. Blobs are installed first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportRow {
    State {
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    },
    ObjectVersion(DurableObjectVersionRecord),
    ObjectHead {
        object_id: ObjectId,
        head: ImportObjectHead,
    },
    Receipt(DurableRequestReceipt),
}

impl ImportRow {
    /// Closed plan order: State, immutable versions, heads, original receipts.
    /// Object identifiers and unsigned version suffixes have exact BE order.
    #[must_use]
    pub fn locator(&self) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::new();
        match self {
            Self::State { key: natural, .. } => {
                key.push(1);
                key.extend_from_slice(natural);
            }
            Self::ObjectVersion(version) => {
                key.push(2);
                key.extend_from_slice(version.object_id().as_bytes());
                key.extend_from_slice(&version.object_version().get().to_be_bytes());
            }
            Self::ObjectHead { object_id, .. } => {
                key.push(3);
                key.extend_from_slice(object_id.as_bytes());
            }
            Self::Receipt(receipt) => {
                key.push(4);
                key.extend_from_slice(receipt.request_id().as_bytes());
            }
        }
        key
    }
    /// Storage envelope capacity, not a semantic or authentication digest.
    pub fn represented_bytes(&self) -> Result<usize, RuntimeError> {
        let mut count: usize = self.locator().len();
        let additional: usize = match self {
            Self::State { key, value } => {
                validate_state_key(key)?;
                if let Some(value) = value {
                    validate_state_value(value)?;
                }
                value.as_ref().map_or(0, Vec::len)
            }
            Self::Receipt(receipt) => receipt.canonical_bytes().len(),
            Self::ObjectVersion(version) => {
                if version.schema_version() == 0
                    || version.provenance().protocol_version().get() == 0
                    || version.provenance().chain_id().as_str().len() > 128
                {
                    return Err(RuntimeError::InvalidImportRequest);
                }
                match version.payload() {
                    DurableObjectPayload::Inline(inline) => inline.canonical_bytes().len(),
                    DurableObjectPayload::BlobReference(_) => 34,
                }
            }
            Self::ObjectHead { head, .. } => match head {
                ImportObjectHead::Current {
                    owner_projection,
                    routing_projection,
                    ..
                } => owner_projection
                    .bytes()
                    .map_or(0, <[u8]>::len)
                    .checked_add(routing_projection.bytes().map_or(0, <[u8]>::len))
                    .ok_or(RuntimeError::InvalidImportRequest)?,
                ImportObjectHead::Tombstoned { .. } => 0,
            },
        };
        count = count
            .checked_add(additional)
            .and_then(|bytes| bytes.checked_add(512))
            .ok_or(RuntimeError::InvalidImportRequest)?;
        Ok(count)
    }
}

/// Bounded rows with exact before/after progress. Digests are computed by core
/// using the committed suite; storage verifies identity/retry rows, not hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportBatch {
    binding: ImportBinding,
    expected: ImportProgress,
    next: ImportProgress,
    rows: Vec<ImportRow>,
}

impl ImportBatch {
    pub fn new(
        binding: ImportBinding,
        expected: ImportProgress,
        batch_digest: Digest32,
        next_accumulator: Digest32,
        rows: Vec<ImportRow>,
    ) -> Result<Self, RuntimeError> {
        encode_import_binding(&binding)?;
        encode_import_progress(&expected)?;
        if rows.is_empty() || rows.len() > MAX_IMPORT_BATCH_ROWS {
            return Err(RuntimeError::InvalidImportRequest);
        }
        let mut bytes: usize = MAX_IMPORT_METADATA_BYTES;
        let mut previous: Option<Vec<u8>> = None;
        for row in &rows {
            let key: Vec<u8> = row.locator();
            if previous.as_ref().is_some_and(|before| *before >= key) {
                return Err(RuntimeError::InvalidImportRequest);
            }
            previous = Some(key);
            bytes = bytes
                .checked_add(row.represented_bytes()?)
                .ok_or(RuntimeError::InvalidImportRequest)?;
        }
        if bytes > MAX_IMPORT_BATCH_BYTES {
            return Err(RuntimeError::InvalidImportRequest);
        }
        let next_ordinal: u64 = expected
            .next_ordinal
            .checked_add(u64::try_from(rows.len()).map_err(|_| RuntimeError::InvalidImportRequest)?)
            .ok_or(RuntimeError::InvalidImportRequest)?;
        if next_ordinal > binding.row_count {
            return Err(RuntimeError::InvalidImportRequest);
        }
        Ok(Self {
            binding,
            expected,
            next: ImportProgress {
                next_ordinal,
                last_batch_digest: Some(batch_digest),
                accumulator: next_accumulator,
            },
            rows,
        })
    }
    #[must_use]
    pub const fn binding(&self) -> &ImportBinding {
        &self.binding
    }
    #[must_use]
    pub const fn expected(&self) -> &ImportProgress {
        &self.expected
    }
    #[must_use]
    pub const fn next(&self) -> &ImportProgress {
        &self.next
    }
    #[must_use]
    pub fn rows(&self) -> &[ImportRow] {
        &self.rows
    }
}

/// A storage-only inactive installation seam. No backend default or ordinary
/// handler override exists. CompleteInactive is not cryptographic readiness.
pub trait InactiveImportRepository:
    StructuredDurableDomainStateStore + portable::DurablePortableSnapshotRepository
{
    fn begin_import(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        initial_accumulator: Digest32,
    ) -> DurableCommitOutcome;
    fn read_import_progress(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<Option<ImportProgress>, DurableReadError>;
    fn commit_import_batch(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        batch: &ImportBatch,
    ) -> DurableCommitOutcome;
    fn finish_import(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        expected: &ImportProgress,
        verified_target: &portable::PortableSnapshotToken,
    ) -> DurableCommitOutcome;
}

fn invalid() -> RuntimeError {
    RuntimeError::InvalidImportRequest
}

fn decode_chain(bytes: &[u8]) -> Result<ChainId, RuntimeError> {
    let frame = decode_canonical_frame(bytes).map_err(|_| invalid())?;
    frame.require_type(0x0105).map_err(|_| invalid())?;
    frame.require_version(1).map_err(|_| invalid())?;
    frame.require_only_fields(&[1]).map_err(|_| invalid())?;
    let text: &str = std::str::from_utf8(frame.required_field(1).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let chain: ChainId = ChainId::new(text).map_err(|_| invalid())?;
    if canonical_encoding::encode_chain_id(&chain).map_err(|_| invalid())? != bytes {
        return Err(invalid());
    }
    Ok(chain)
}

/// New closed persisted frame 0x64C0/v1; old protocol frames are unchanged.
pub fn encode_import_binding(value: &ImportBinding) -> Result<Vec<u8>, RuntimeError> {
    if value.context.chain_id.as_str().len() > 128 || value.context.protocol_version.get() == 0 {
        return Err(invalid());
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64C0, 1);
    frame
        .field_bytes(
            1,
            canonical_encoding::encode_chain_id(&value.context.chain_id).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
    frame
        .field_u32(2, value.context.protocol_version.get())
        .map_err(|_| invalid())?;
    frame
        .field_u64(3, value.context.epoch.get())
        .map_err(|_| invalid())?;
    frame
        .field_bytes(4, value.domain.as_bytes().to_vec())
        .map_err(|_| invalid())?;
    for (id, digest) in [
        (5, value.genesis_digest),
        (6, value.validator_set_digest),
        (7, value.cut_digest),
        (8, value.package_digest),
        (9, value.plan_digest),
    ] {
        frame
            .field_bytes(id, encode_digest32(&digest).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    }
    frame
        .field_u64(10, value.row_count)
        .map_err(|_| invalid())?;
    frame
        .field_u64(11, value.blob_count)
        .map_err(|_| invalid())?;
    frame
        .field_u64(12, value.generation_floor.get())
        .map_err(|_| invalid())?;
    let bytes: Vec<u8> = frame.finish().map_err(|_| invalid())?;
    if bytes.len() > MAX_IMPORT_METADATA_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

pub fn decode_import_binding(bytes: &[u8]) -> Result<ImportBinding, RuntimeError> {
    if bytes.len() > MAX_IMPORT_METADATA_BYTES {
        return Err(invalid());
    }
    let frame = decode_canonical_frame(bytes).map_err(|_| invalid())?;
    frame.require_type(0x64C0).map_err(|_| invalid())?;
    frame.require_version(1).map_err(|_| invalid())?;
    frame
        .require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        .map_err(|_| invalid())?;
    let value: ImportBinding = ImportBinding {
        context: ImportContext {
            chain_id: decode_chain(frame.required_field(1).map_err(|_| invalid())?)?,
            protocol_version: ProtocolVersion::new(frame.required_u32(2).map_err(|_| invalid())?),
            epoch: Epoch::new(frame.required_u64(3).map_err(|_| invalid())?),
        },
        domain: AtomicityDomainId::new(
            frame
                .required_field(4)
                .map_err(|_| invalid())?
                .try_into()
                .map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?,
        genesis_digest: decode_digest32(frame.required_field(5).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        validator_set_digest: decode_digest32(frame.required_field(6).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        cut_digest: decode_digest32(frame.required_field(7).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        package_digest: decode_digest32(frame.required_field(8).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        plan_digest: decode_digest32(frame.required_field(9).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
        row_count: frame.required_u64(10).map_err(|_| invalid())?,
        blob_count: frame.required_u64(11).map_err(|_| invalid())?,
        generation_floor: ExecutionGeneration::new(frame.required_u64(12).map_err(|_| invalid())?),
    };
    if encode_import_binding(&value)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

pub fn encode_import_progress(value: &ImportProgress) -> Result<Vec<u8>, RuntimeError> {
    if (value.next_ordinal == 0) != value.last_batch_digest.is_none() {
        return Err(invalid());
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64C1, 1);
    frame
        .field_u64(1, value.next_ordinal)
        .map_err(|_| invalid())?;
    frame
        .field_bytes(
            2,
            value
                .last_batch_digest
                .as_ref()
                .map(encode_digest32)
                .transpose()
                .map_err(|_| invalid())?
                .unwrap_or_default(),
        )
        .map_err(|_| invalid())?;
    frame
        .field_bytes(
            3,
            encode_digest32(&value.accumulator).map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
    frame.finish().map_err(|_| invalid())
}

pub fn decode_import_progress(bytes: &[u8]) -> Result<ImportProgress, RuntimeError> {
    if bytes.len() > MAX_IMPORT_METADATA_BYTES {
        return Err(invalid());
    }
    let frame = decode_canonical_frame(bytes).map_err(|_| invalid())?;
    frame.require_type(0x64C1).map_err(|_| invalid())?;
    frame.require_version(1).map_err(|_| invalid())?;
    frame
        .require_only_fields(&[1, 2, 3])
        .map_err(|_| invalid())?;
    let last: &[u8] = frame.required_field(2).map_err(|_| invalid())?;
    let value: ImportProgress = ImportProgress {
        next_ordinal: frame.required_u64(1).map_err(|_| invalid())?,
        last_batch_digest: if last.is_empty() {
            None
        } else {
            Some(decode_digest32(last).map_err(|_| invalid())?)
        },
        accumulator: decode_digest32(frame.required_field(3).map_err(|_| invalid())?)
            .map_err(|_| invalid())?,
    };
    if encode_import_progress(&value)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

mod memory;
#[cfg(test)]
mod tests;
