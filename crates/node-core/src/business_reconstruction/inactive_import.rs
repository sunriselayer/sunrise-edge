//! DR-0176 independently verified raw business installation. The opaque plan
//! can only target a permanently import-origin namespace; it grants no live
//! admission, signing, readiness, Seal or activation authority.
//!
//! Reverification and private material have linear history cost. Individual
//! rows, digest ranges and storage batches retain their owning bounds; there
//! is no aggregate history cap or body-containing whole-history frame.

use super::{
    BusinessReconstructionError, BusinessReconstructionPlan, SourceBusinessSnapshot,
    SourceSnapshotRecord, cut, projection,
};
use canonical_encoding::{CanonicalStruct, encode_chain_id, encode_digest32};
use cut::{BusinessCutError, SavedBusinessCut, business_cut_component_digest};
use execution::publication::{PublicationContext, encode_publication_context};
use hashing::HashSuiteResolver;
use protocol_types::{Digest32, HashPurpose};
use runtime::inactive_import::{
    ImportBatch, ImportBinding, ImportContext, ImportObjectHead, ImportProgress, ImportRow,
    InactiveImportRepository, MAX_IMPORT_BATCH_BYTES, MAX_IMPORT_BATCH_ROWS,
    MAX_IMPORT_METADATA_BYTES, NamespaceLifecycle, encode_import_progress,
};
use runtime::portable::{
    DurablePayloadDescriptor, DurableRecordKey, DurableRecordMetadata, MAX_PORTABLE_CHUNK_BYTES,
    PortableBlobChunkOutcome, PortableBlobChunkRequest, PortableBlobRepository,
    PortableSnapshotToken,
};
use runtime::{
    BlobStore, DurableCommitOutcome, DurableCommitRejection, DurableObjectHead,
    DurableObjectPayload, DurableObjectVersionRecord, DurableOperationContext, DurableReadError,
    DurableRequestReceipt, IndeterminateCommitReason, RuntimeError,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    num::NonZeroUsize,
};

/// Successfully performed local storage work, never an activation permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BusinessImportAdvance {
    Partial {
        progress: ImportProgress,
        new_batches: usize,
    },
    CompleteInactive {
        progress: ImportProgress,
        new_batches: usize,
    },
}

impl BusinessImportAdvance {
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::CompleteInactive { .. })
    }
}

/// Only independently executed saved proof closure can construct this plan.
/// Raw rows and batches are deliberately private: decoded cut roots, a public
/// equality report, or a supplied completion flag cannot construct a permit.
pub struct VerifiedImportPlan {
    binding: ImportBinding,
    initial: ImportProgress,
    rows: Vec<ImportRow>,
    blobs: BTreeMap<Digest32, Vec<u8>>,
    batches: Vec<ImportBatch>,
}

impl VerifiedImportPlan {
    /// Immutable identity needed by the dedicated fresh/open-import-existing
    /// storage composition. This is not an ordinary-store admission token.
    #[must_use]
    pub const fn binding(&self) -> &ImportBinding {
        &self.binding
    }

    fn progress_index(&self, progress: &ImportProgress) -> Result<usize, BusinessImportError> {
        if progress == &self.initial {
            return Ok(0);
        }
        self.batches
            .iter()
            .position(|batch| batch.next() == progress)
            .and_then(|index| index.checked_add(1))
            .ok_or(invalid(
                "inactive progress is not an exact verified plan prefix",
            ))
    }

    fn lifecycle<S: InactiveImportRepository>(
        &self,
        destination: &S,
        operation: &DurableOperationContext,
    ) -> Result<NamespaceLifecycle, BusinessImportError> {
        let lifecycle: NamespaceLifecycle =
            destination.get_namespace_lifecycle(operation, self.binding.domain)?;
        if lifecycle.binding() != Some(&self.binding) {
            return Err(invalid(
                "destination origin/binding differs from verified plan",
            ));
        }
        Ok(lifecycle)
    }

    /// Installs only the next batch's authenticated immutable body closure,
    /// then at most the supplied number of NEW bounded row batches. Each
    /// batch's rows plus distinct required bodies fit a 64 MiB work budget.
    /// Resume verifies exact progress; an
    /// ambiguous commit is reconciled under a fresh destination-local fence.
    /// Before completion every row and referenced body is enumerated again and
    /// compared with this private plan, then finish fences that snapshot.
    ///
    /// Immutable blob publication preceding a raced row commit can leave an
    /// unreachable orphan, never a partially admitted business operation.
    pub fn advance<S, B>(
        &self,
        destination: &S,
        destination_blobs: &B,
        operation: &DurableOperationContext,
        max_new_batches: NonZeroUsize,
    ) -> Result<BusinessImportAdvance, BusinessImportError>
    where
        S: InactiveImportRepository,
        B: BlobStore + PortableBlobRepository,
    {
        let mut lifecycle: NamespaceLifecycle = self.lifecycle(destination, operation)?;
        if matches!(lifecycle, NamespaceLifecycle::FreshImport(_)) {
            let outcome: DurableCommitOutcome = destination.begin_import(
                operation,
                self.binding.domain,
                &self.binding,
                self.initial.accumulator,
            );
            match outcome {
                DurableCommitOutcome::Committed => {}
                DurableCommitOutcome::Rejected(reason) => {
                    return Err(BusinessImportError::Rejected(reason));
                }
                DurableCommitOutcome::Indeterminate(reason) => {
                    lifecycle = self.lifecycle(destination, operation)?;
                    if lifecycle.progress() != Some(&self.initial) {
                        return Err(BusinessImportError::Indeterminate(reason));
                    }
                    self.verify_prefix(destination, destination_blobs, operation, 0)?;
                }
            }
            lifecycle = self.lifecycle(destination, operation)?;
        }
        let mut progress: ImportProgress = lifecycle
            .progress()
            .ok_or(invalid("import origin has no initialized progress"))?
            .clone();
        let mut index: usize = self.progress_index(&progress)?;
        let mut new_batches: usize = 0;
        if matches!(lifecycle, NamespaceLifecycle::CompleteInactive { .. })
            && index != self.batches.len()
        {
            return Err(invalid(
                "inactive completion is not the complete plan prefix",
            ));
        }
        // A matching cursor alone does not authenticate already installed rows.
        // Refuse corruption before NEW body/row side effects on every resume;
        // history reverification is deliberately outside the new-work budget.
        self.verify_prefix(
            destination,
            destination_blobs,
            operation,
            progress.next_ordinal,
        )?;
        while index < self.batches.len() && new_batches < max_new_batches.get() {
            let batch: &ImportBatch = &self.batches[index];
            if batch.expected() != &progress {
                return Err(invalid("verified batch does not follow exact progress"));
            }
            // A limit of one cannot eagerly publish later batches' bodies.
            // The configured destination fence is checked before publication;
            // a later raced commit may leave only an unreachable orphan.
            for digest in required_blobs(batch.rows()) {
                self.lifecycle(destination, operation)?;
                let bytes: &Vec<u8> = self.blobs.get(&digest).ok_or(invalid(
                    "verified batch required body is absent from private closure",
                ))?;
                if !verify_destination_blob(destination_blobs, digest, bytes)? {
                    destination_blobs.put_blob(digest, bytes.clone())?;
                }
            }
            match destination.commit_import_batch(operation, self.binding.domain, batch) {
                DurableCommitOutcome::Committed => {}
                DurableCommitOutcome::Rejected(reason) => {
                    return Err(BusinessImportError::Rejected(reason));
                }
                DurableCommitOutcome::Indeterminate(reason) => {
                    let observed: NamespaceLifecycle = self.lifecycle(destination, operation)?;
                    if observed.progress() != Some(batch.next()) {
                        // An unchanged cursor is not permission to retry an
                        // uncertain transaction in the same invocation.
                        return Err(BusinessImportError::Indeterminate(reason));
                    }
                    self.verify_prefix(
                        destination,
                        destination_blobs,
                        operation,
                        batch.next().next_ordinal,
                    )?;
                }
            }
            progress = batch.next().clone();
            index = index
                .checked_add(1)
                .ok_or(invalid("import batch index overflow"))?;
            new_batches = new_batches
                .checked_add(1)
                .ok_or(invalid("import work counter overflow"))?;
        }
        if index != self.batches.len() {
            let observed: NamespaceLifecycle = self.lifecycle(destination, operation)?;
            if observed.progress() != Some(&progress) {
                return Err(invalid(
                    "destination progress changed before partial result",
                ));
            }
            return Ok(BusinessImportAdvance::Partial {
                progress,
                new_batches,
            });
        }
        let token: PortableSnapshotToken = self.verify_prefix(
            destination,
            destination_blobs,
            operation,
            self.binding.row_count,
        )?;
        match destination.finish_import(
            operation,
            self.binding.domain,
            &self.binding,
            &progress,
            &token,
        ) {
            DurableCommitOutcome::Committed => {}
            DurableCommitOutcome::Rejected(reason) => {
                return Err(BusinessImportError::Rejected(reason));
            }
            DurableCommitOutcome::Indeterminate(reason) => {
                let observed: NamespaceLifecycle = self.lifecycle(destination, operation)?;
                if !matches!(observed, NamespaceLifecycle::CompleteInactive { .. })
                    || observed.progress() != Some(&progress)
                {
                    return Err(BusinessImportError::Indeterminate(reason));
                }
                self.verify_prefix(
                    destination,
                    destination_blobs,
                    operation,
                    self.binding.row_count,
                )?;
            }
        }
        let final_lifecycle: NamespaceLifecycle = self.lifecycle(destination, operation)?;
        if !matches!(final_lifecycle, NamespaceLifecycle::CompleteInactive { .. })
            || final_lifecycle.progress() != Some(&progress)
        {
            return Err(invalid("finish did not retain exact inactive completion"));
        }
        Ok(BusinessImportAdvance::CompleteInactive {
            progress,
            new_batches,
        })
    }

    fn verify_prefix<S, B>(
        &self,
        destination: &S,
        destination_blobs: &B,
        operation: &DurableOperationContext,
        through: u64,
    ) -> Result<PortableSnapshotToken, BusinessImportError>
    where
        S: InactiveImportRepository,
        B: PortableBlobRepository,
    {
        let count: usize =
            usize::try_from(through).map_err(|_| invalid("import ordinal capacity"))?;
        let expected: &[ImportRow] = self
            .rows
            .get(..count)
            .ok_or(invalid("import ordinal range"))?;
        for digest in required_blobs(expected) {
            let bytes: &Vec<u8> = self.blobs.get(&digest).ok_or(invalid(
                "verified prefix required body is absent from private closure",
            ))?;
            if !verify_destination_blob(destination_blobs, digest, bytes)? {
                return Err(invalid("destination required immutable body is missing"));
            }
        }
        let snapshot: SourceBusinessSnapshot = cut::capture_import_target(
            destination,
            destination_blobs,
            operation,
            self.binding.domain,
        )?;
        let actual: Vec<ImportRow> = raw_rows(&snapshot, false)?;
        if actual != expected {
            return Err(invalid(
                "complete destination raw inventory differs from verified plan",
            ));
        }
        for (digest, bytes) in &snapshot.referenced_blobs {
            if self.blobs.get(digest) != Some(bytes) {
                return Err(invalid(
                    "destination referenced body differs from verified plan",
                ));
            }
        }
        // capture checks EmptyOnlyV1 and the SAME token after all body reads.
        // finish checks it atomically with origin/binding/progress.
        self.lifecycle(destination, operation)?;
        Ok(snapshot.token)
    }
}

/// Reexecutes the exact saved cut under local pins while the raw private store
/// still exists. No decoded comparison subject is a restoration codec.
pub fn verify_saved_business_import(
    plan: BusinessReconstructionPlan<'_>,
    saved: &SavedBusinessCut,
) -> Result<VerifiedImportPlan, BusinessImportError> {
    let resolver: &HashSuiteResolver = plan.resolver;
    let context: PublicationContext = plan.genesis.context().clone();
    let (cut, overlay, carriers) = cut::proof::verify_saved_with_overlay(plan, saved)?;
    let snapshot: SourceBusinessSnapshot = projection::private_import_snapshot(&overlay)?;
    let mut rows: Vec<ImportRow> = raw_rows(&snapshot, true)?;
    for (request, bytes) in carriers {
        // Full carrier B can differ from the retainer/replay carrier A. It has
        // already been independently verified against the actually applied
        // subject; only its owning canonical encoder is used for restoration.
        let record = crate::fast_path::records::decode_fastpath_certificate_record(&bytes)
            .map_err(|_| invalid("verified application carrier schema"))?;
        let canonical: Vec<u8> =
            crate::fast_path::records::encode_fastpath_certificate_record(&record)
                .map_err(|_| invalid("verified application carrier encoding"))?;
        if canonical != bytes {
            return Err(invalid("verified application carrier is noncanonical"));
        }
        let key: Vec<u8> =
            crate::local_instance_state::fastpath_certificate_key(context.chain_id(), &request)
                .map_err(|_| invalid("verified application carrier key"))?;
        let row: &mut ImportRow = rows
            .iter_mut()
            .find(|row| matches!(row, ImportRow::State { key: natural, .. } if *natural == key))
            .ok_or(invalid(
                "independently produced application carrier missing",
            ))?;
        *row = ImportRow::State {
            key,
            value: Some(canonical),
        };
    }
    let mut binding: ImportBinding = ImportBinding {
        context: ImportContext {
            chain_id: context.chain_id().clone(),
            protocol_version: context.protocol_version(),
            epoch: context.epoch(),
        },
        domain: cut.identity().domain,
        genesis_digest: cut.identity().genesis_digest,
        validator_set_digest: cut.identity().validator_set_digest,
        cut_digest: cut.cut_digest(),
        package_digest: cut.package_digest(),
        // The non-circular seed below does not read this temporary field.
        plan_digest: cut.cut_digest(),
        row_count: u64::try_from(rows.len()).map_err(|_| invalid("import row count overflow"))?,
        blob_count: u64::try_from(snapshot.referenced_blobs.len())
            .map_err(|_| invalid("import blob count overflow"))?,
        generation_floor: cut.identity().generation_floor,
    };
    let descriptors: Vec<Vec<u8>> = rows
        .iter()
        .map(|row| row_descriptor(resolver, &context, row))
        .collect::<Result<Vec<Vec<u8>>, BusinessImportError>>()?;
    let mut accumulator: Digest32 = hash(resolver, &context, &plan_seed(&binding)?)?;
    for descriptor in &descriptors {
        accumulator = hash(
            resolver,
            &context,
            &inventory_fold(accumulator, 1, descriptor)?,
        )?;
    }
    for (digest, bytes) in &snapshot.referenced_blobs {
        let descriptor: Vec<u8> = blob_descriptor(resolver, &context, *digest, bytes)?;
        accumulator = hash(
            resolver,
            &context,
            &inventory_fold(accumulator, 2, &descriptor)?,
        )?;
    }
    binding.plan_digest = accumulator;
    let initial: ImportProgress = ImportProgress {
        next_ordinal: 0,
        last_batch_digest: None,
        accumulator: hash(resolver, &context, &progress_seed(binding.plan_digest)?)?,
    };
    let batches: Vec<ImportBatch> = batches(
        resolver,
        &context,
        &binding,
        &initial,
        &rows,
        &descriptors,
        &snapshot.referenced_blobs,
    )?;
    Ok(VerifiedImportPlan {
        binding,
        initial,
        rows,
        blobs: snapshot.referenced_blobs,
        batches,
    })
}

/// Physical revisions are absent from the storage-only rows. Only this fresh
/// logical inactive profile rebases the runtime-owned version checkpoint to 0;
/// original State, logical observations and signed/hash-linked checkpoints
/// inside their owning bytes remain untouched.
fn raw_rows(
    snapshot: &SourceBusinessSnapshot,
    rebase_physical_checkpoint: bool,
) -> Result<Vec<ImportRow>, BusinessImportError> {
    snapshot.validate()?;
    let mut rows: BTreeMap<Vec<u8>, ImportRow> = BTreeMap::new();
    for record in &snapshot.records {
        let row: ImportRow = raw_row(record, rebase_physical_checkpoint)?;
        if rows.insert(row.locator(), row).is_some() {
            return Err(invalid("duplicate raw installation locator"));
        }
    }
    Ok(rows.into_values().collect())
}

fn raw_row(
    record: &SourceSnapshotRecord,
    rebase_physical_checkpoint: bool,
) -> Result<ImportRow, BusinessImportError> {
    match (record.descriptor.key(), record.descriptor.metadata()) {
        (DurableRecordKey::State(key), DurableRecordMetadata::State { .. }) => {
            Ok(ImportRow::State {
                key: key.clone(),
                value: record.value.clone(),
            })
        }
        (
            DurableRecordKey::Receipt(request),
            DurableRecordMetadata::Receipt { event_digest, .. },
        ) => Ok(ImportRow::Receipt(
            DurableRequestReceipt::new(
                *request,
                *event_digest,
                record
                    .value
                    .clone()
                    .ok_or(invalid("raw original receipt body absent"))?,
            )
            .map_err(|_| invalid("raw original receipt shape"))?,
        )),
        (DurableRecordKey::ObjectHead(object_id), DurableRecordMetadata::ObjectHead(head)) => {
            let head: ImportObjectHead = match head {
                DurableObjectHead::Absent => return Err(invalid("raw head cannot be virgin")),
                DurableObjectHead::Current {
                    object_version,
                    digest,
                    owner_projection,
                    routing_projection,
                    ..
                } => ImportObjectHead::Current {
                    object_version: *object_version,
                    digest: *digest,
                    owner_projection: owner_projection.clone(),
                    routing_projection: routing_projection.clone(),
                },
                DurableObjectHead::Tombstoned {
                    last_object_version,
                    ..
                } => ImportObjectHead::Tombstoned {
                    last_object_version: *last_object_version,
                },
            };
            Ok(ImportRow::ObjectHead {
                object_id: *object_id,
                head,
            })
        }
        (
            DurableRecordKey::ObjectVersion(object_id, object_version),
            DurableRecordMetadata::ObjectVersion {
                digest,
                schema_version,
                provenance,
                payload,
                created_checkpoint,
            },
        ) => {
            let checkpoint: u64 = if rebase_physical_checkpoint {
                0
            } else {
                *created_checkpoint
            };
            let version: DurableObjectVersionRecord = match payload {
                DurablePayloadDescriptor::Inline(_) => {
                    DurableObjectVersionRecord::from_inline_canonical_bytes(
                        record
                            .value
                            .clone()
                            .ok_or(invalid("raw inline object body absent"))?,
                        *digest,
                        provenance.clone(),
                        checkpoint,
                    )
                    .map_err(|_| invalid("raw inline immutable version schema"))?
                }
                DurablePayloadDescriptor::BlobReference(blob) => {
                    DurableObjectVersionRecord::from_blob_reference(
                        *object_id,
                        *object_version,
                        *digest,
                        *schema_version,
                        provenance.clone(),
                        checkpoint,
                        *blob,
                    )
                }
            };
            if version.object_id() != *object_id
                || version.object_version() != *object_version
                || version.schema_version() != *schema_version
            {
                return Err(invalid("raw immutable version linkage differs"));
            }
            Ok(ImportRow::ObjectVersion(version))
        }
        _ => Err(invalid("raw installation owner schema differs")),
    }
}

#[allow(clippy::too_many_arguments)]
fn batches(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    binding: &ImportBinding,
    initial: &ImportProgress,
    rows: &[ImportRow],
    descriptors: &[Vec<u8>],
    blobs: &BTreeMap<Digest32, Vec<u8>>,
) -> Result<Vec<ImportBatch>, BusinessImportError> {
    let mut result: Vec<ImportBatch> = Vec::new();
    let mut start: usize = 0;
    let mut expected: ImportProgress = initial.clone();
    while start < rows.len() {
        let mut end: usize = start;
        let mut bytes: usize = MAX_IMPORT_METADATA_BYTES;
        let mut work_bytes: usize = MAX_IMPORT_METADATA_BYTES;
        let mut needed_bodies: BTreeSet<Digest32> = BTreeSet::new();
        let mut row_root: Digest32 = expected.accumulator;
        while end < rows.len() && end - start < MAX_IMPORT_BATCH_ROWS {
            let next_bytes: usize = bytes
                .checked_add(rows[end].represented_bytes()?)
                .ok_or(invalid("import represented bytes overflow"))?;
            let mut next_work_bytes: usize = work_bytes
                .checked_add(rows[end].represented_bytes()?)
                .ok_or(invalid("import new-work bytes overflow"))?;
            let next_body: Option<Digest32> = required_blob(&rows[end]);
            if let Some(digest) = next_body
                && !needed_bodies.contains(&digest)
            {
                let length: usize = blobs
                    .get(&digest)
                    .ok_or(invalid("private version body closure is incomplete"))?
                    .len();
                next_work_bytes = next_work_bytes
                    .checked_add(length)
                    .ok_or(invalid("import body work bytes overflow"))?;
            }
            if next_bytes > MAX_IMPORT_BATCH_BYTES || next_work_bytes > MAX_IMPORT_BATCH_BYTES {
                break;
            }
            bytes = next_bytes;
            work_bytes = next_work_bytes;
            if let Some(digest) = next_body {
                needed_bodies.insert(digest);
            }
            row_root = hash(
                resolver,
                context,
                &inventory_fold(row_root, 1, &descriptors[end])?,
            )?;
            end = end
                .checked_add(1)
                .ok_or(invalid("import batch range overflow"))?;
        }
        if end == start {
            return Err(invalid(
                "legal raw row cannot fit bounded installation batch",
            ));
        }
        let end_ordinal: u64 =
            u64::try_from(end).map_err(|_| invalid("import ordinal overflow"))?;
        let digest: Digest32 = hash(
            resolver,
            context,
            &batch_frame(binding.plan_digest, &expected, end_ordinal, row_root)?,
        )?;
        let next_accumulator: Digest32 = hash(
            resolver,
            context,
            &progress_fold(expected.accumulator, digest, end_ordinal)?,
        )?;
        let batch: ImportBatch = ImportBatch::new(
            binding.clone(),
            expected,
            digest,
            next_accumulator,
            rows[start..end].to_vec(),
        )?;
        expected = batch.next().clone();
        result.push(batch);
        start = end;
    }
    Ok(result)
}

/// Only an owning immutable ObjectVersion BlobReference creates a required
/// body. State/protocol bytes are never scanned for arbitrary digest patterns.
fn required_blob(row: &ImportRow) -> Option<Digest32> {
    match row {
        ImportRow::ObjectVersion(version) => match version.payload() {
            DurableObjectPayload::BlobReference(digest) => Some(*digest),
            DurableObjectPayload::Inline(_) => None,
        },
        _ => None,
    }
}

fn required_blobs(rows: &[ImportRow]) -> BTreeSet<Digest32> {
    rows.iter().filter_map(required_blob).collect()
}

/// Never call BlobStore::get_blob on resumed storage: a corrupt SQL value can
/// have arbitrary length. Validate the private exact length before even one
/// bounded range, and compare each range against independently verified bytes.
fn verify_destination_blob<B: PortableBlobRepository>(
    destination: &B,
    digest: Digest32,
    expected: &[u8],
) -> Result<bool, BusinessImportError> {
    let Some(descriptor) = destination.read_portable_blob_descriptor(&digest)? else {
        return Ok(false);
    };
    if descriptor.digest() != digest || descriptor.length() != expected.len() {
        return Err(invalid("destination immutable body descriptor conflicts"));
    }
    let mut offset: usize = 0;
    loop {
        let count: usize = MAX_PORTABLE_CHUNK_BYTES.min(expected.len() - offset);
        let request: PortableBlobChunkRequest = PortableBlobChunkRequest::new(
            descriptor,
            offset,
            NonZeroUsize::new(count.max(1)).ok_or(invalid("import body chunk capacity"))?,
        )?;
        let PortableBlobChunkOutcome::Chunk(chunk) =
            destination.read_portable_blob_chunk(&request)?
        else {
            return Err(invalid(
                "destination immutable body changed during bounded read",
            ));
        };
        let end: usize = offset
            .checked_add(count)
            .ok_or(invalid("import body range overflow"))?;
        if chunk.request() != &request
            || chunk.bytes() != &expected[offset..end]
            || chunk.is_last() != (end == expected.len())
        {
            return Err(invalid("destination immutable body conflicts"));
        }
        offset = end;
        if chunk.is_last() {
            return Ok(true);
        }
    }
}

// Swept 0x64C2..0x64C8/v1. Runtime owns C0/C1. These small integrity frames
// contain descriptors/digests only, never full 32 MiB bodies or all history.
fn row_descriptor(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    row: &ImportRow,
) -> Result<Vec<u8>, BusinessImportError> {
    let mut metadata: CanonicalStruct = CanonicalStruct::new(0x64C3, 1);
    let body: &[u8] = match row {
        ImportRow::State { value, .. } => {
            metadata.field_u16(1, 1)?;
            metadata.field_u16(2, u16::from(value.is_some()))?;
            value.as_deref().unwrap_or_default()
        }
        ImportRow::Receipt(receipt) => {
            metadata.field_u16(1, 4)?;
            metadata.field_bytes(2, encode_digest32(&receipt.event_digest())?)?;
            receipt.canonical_bytes()
        }
        ImportRow::ObjectVersion(version) => {
            metadata.field_u16(1, 2)?;
            metadata.field_bytes(2, encode_digest32(&version.digest())?)?;
            metadata.field_u32(3, version.schema_version())?;
            metadata.field_bytes(4, encode_chain_id(version.provenance().chain_id())?)?;
            metadata.field_u32(5, version.provenance().protocol_version().get())?;
            metadata.field_u64(6, version.created_checkpoint())?;
            match version.payload() {
                DurableObjectPayload::Inline(inline) => {
                    metadata.field_u16(7, 1)?;
                    metadata.field_bytes(8, Vec::new())?;
                    inline.canonical_bytes()
                }
                DurableObjectPayload::BlobReference(digest) => {
                    metadata.field_u16(7, 2)?;
                    metadata.field_bytes(8, encode_digest32(digest)?)?;
                    &[]
                }
            }
        }
        ImportRow::ObjectHead { head, .. } => {
            metadata.field_u16(1, 3)?;
            metadata.field_bytes(2, head_metadata(head)?)?;
            &[]
        }
    };
    descriptor(row.locator(), metadata.finish()?, body, resolver, context)
}
fn descriptor(
    key: Vec<u8>,
    metadata: Vec<u8>,
    body: &[u8],
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
) -> Result<Vec<u8>, BusinessImportError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64C2, 1);
    frame.field_bytes(1, key)?;
    frame.field_bytes(2, metadata)?;
    frame.field_u64(
        3,
        u64::try_from(body.len()).map_err(|_| invalid("import body length overflow"))?,
    )?;
    frame.field_bytes(
        4,
        encode_digest32(&business_cut_component_digest(resolver, context, body)?)?,
    )?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_IMPORT_METADATA_BYTES {
        return Err(invalid("import descriptor capacity"));
    }
    Ok(bytes)
}
fn blob_descriptor(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    digest: Digest32,
    body: &[u8],
) -> Result<Vec<u8>, BusinessImportError> {
    descriptor(
        encode_digest32(&digest)?,
        Vec::new(),
        body,
        resolver,
        context,
    )
}
fn head_metadata(head: &ImportObjectHead) -> Result<Vec<u8>, BusinessImportError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64C4, 1);
    match head {
        ImportObjectHead::Current {
            object_version,
            digest,
            owner_projection,
            routing_projection,
        } => {
            frame.field_u16(1, 1)?;
            frame.field_u64(2, object_version.get())?;
            frame.field_bytes(3, encode_digest32(digest)?)?;
            frame.field_u16(4, u16::from(owner_projection.bytes().is_some()))?;
            frame.field_bytes(5, owner_projection.bytes().unwrap_or_default().to_vec())?;
            frame.field_u16(6, u16::from(routing_projection.bytes().is_some()))?;
            frame.field_bytes(7, routing_projection.bytes().unwrap_or_default().to_vec())?;
        }
        ImportObjectHead::Tombstoned {
            last_object_version,
        } => {
            frame.field_u16(1, 2)?;
            frame.field_u64(2, last_object_version.get())?;
            for id in [3, 5, 7] {
                frame.field_bytes(id, Vec::new())?;
            }
            frame.field_u16(4, 0)?;
            frame.field_u16(6, 0)?;
        }
    }
    Ok(frame.finish()?)
}
fn plan_seed(binding: &ImportBinding) -> Result<Vec<u8>, BusinessImportError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64C5, 1);
    let context: PublicationContext = PublicationContext::new(
        binding.context.chain_id.clone(),
        binding.context.protocol_version,
        binding.context.epoch,
    )
    .map_err(|_| invalid("import seed context"))?;
    frame.field_bytes(
        1,
        encode_publication_context(&context)
            .map_err(|_| invalid("import seed context encoding"))?,
    )?;
    frame.field_bytes(2, binding.domain.as_bytes().to_vec())?;
    for (id, digest) in [
        (3, binding.genesis_digest),
        (4, binding.validator_set_digest),
        (5, binding.cut_digest),
        (6, binding.package_digest),
    ] {
        frame.field_bytes(id, encode_digest32(&digest)?)?;
    }
    frame.field_u64(7, binding.generation_floor.get())?;
    frame.field_u64(8, binding.row_count)?;
    frame.field_u64(9, binding.blob_count)?;
    Ok(frame.finish()?)
}
fn inventory_fold(
    previous: Digest32,
    kind: u16,
    descriptor: &[u8],
) -> Result<Vec<u8>, BusinessImportError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64C6, 1);
    frame.field_bytes(1, encode_digest32(&previous)?)?;
    frame.field_u16(2, kind)?;
    frame.field_bytes(3, descriptor.to_vec())?;
    Ok(frame.finish()?)
}
fn batch_frame(
    plan: Digest32,
    before: &ImportProgress,
    end: u64,
    rows_root: Digest32,
) -> Result<Vec<u8>, BusinessImportError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64C7, 1);
    frame.field_bytes(1, encode_digest32(&plan)?)?;
    frame.field_bytes(2, encode_import_progress(before)?)?;
    frame.field_u64(3, end)?;
    frame.field_bytes(4, encode_digest32(&rows_root)?)?;
    Ok(frame.finish()?)
}
fn progress_seed(plan: Digest32) -> Result<Vec<u8>, BusinessImportError> {
    progress_frame(plan, None, 0)
}
fn progress_fold(
    before: Digest32,
    batch: Digest32,
    end: u64,
) -> Result<Vec<u8>, BusinessImportError> {
    progress_frame(before, Some(batch), end)
}
fn progress_frame(
    before: Digest32,
    batch: Option<Digest32>,
    end: u64,
) -> Result<Vec<u8>, BusinessImportError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x64C8, 1);
    frame.field_bytes(1, encode_digest32(&before)?)?;
    frame.field_bytes(
        2,
        batch
            .as_ref()
            .map(encode_digest32)
            .transpose()?
            .unwrap_or_default(),
    )?;
    frame.field_u64(3, end)?;
    Ok(frame.finish()?)
}
fn hash(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    bytes: &[u8],
) -> Result<Digest32, BusinessImportError> {
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(invalid("import committed hash context differs"));
    }
    resolver
        .hash_for_purpose(context.epoch(), HashPurpose::NodeEvent, bytes)
        .map_err(|_| invalid("import committed hash suite unavailable"))
}
fn invalid(reason: &'static str) -> BusinessImportError {
    BusinessImportError::Invalid(reason)
}

/// Closed verification, immutable target conflict, fencing or uncertain commit.
#[derive(Debug)]
pub enum BusinessImportError {
    Invalid(&'static str),
    Cut(BusinessCutError),
    Reconstruction(Box<BusinessReconstructionError>),
    Runtime(RuntimeError),
    Read(DurableReadError),
    Rejected(DurableCommitRejection),
    Indeterminate(IndeterminateCommitReason),
    Encoding(canonical_encoding::CanonicalEncodingError),
}
impl fmt::Display for BusinessImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "inactive business import refused: {reason}"),
            Self::Cut(error) => error.fmt(f),
            Self::Reconstruction(error) => error.fmt(f),
            Self::Runtime(error) => error.fmt(f),
            Self::Read(error) => write!(f, "inactive target read refused: {error:?}"),
            Self::Rejected(reason) => write!(f, "inactive target proved no commit: {reason:?}"),
            Self::Indeterminate(reason) => write!(
                f,
                "inactive target commit remains indeterminate: {reason:?}"
            ),
            Self::Encoding(error) => error.fmt(f),
        }
    }
}
impl Error for BusinessImportError {}
impl From<BusinessCutError> for BusinessImportError {
    fn from(value: BusinessCutError) -> Self {
        Self::Cut(value)
    }
}
impl From<BusinessReconstructionError> for BusinessImportError {
    fn from(value: BusinessReconstructionError) -> Self {
        Self::Reconstruction(Box::new(value))
    }
}
impl From<RuntimeError> for BusinessImportError {
    fn from(value: RuntimeError) -> Self {
        Self::Runtime(value)
    }
}
impl From<DurableReadError> for BusinessImportError {
    fn from(value: DurableReadError) -> Self {
        Self::Read(value)
    }
}
impl From<canonical_encoding::CanonicalEncodingError> for BusinessImportError {
    fn from(value: canonical_encoding::CanonicalEncodingError) -> Self {
        Self::Encoding(value)
    }
}

#[cfg(test)]
mod tests;
