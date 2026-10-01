//! Read-only, source-local consistent capture for the business audit.
//!
//! Snapshot tokens provide continuity, not network freshness or cut authority.
//! All reads use the original token inside the backend read transaction. No
//! writer fence is claimed and no source invocation is committed here.

use std::{collections::BTreeMap, error::Error, io, num::NonZeroUsize};

use node_core::business_reconstruction::{
    SourceBusinessSnapshot, SourceSnapshotRecord, referenced_blob_bounds,
};
use protocol_types::{AtomicityDomainId, Digest32};
use runtime::DurableOperationContext;
use runtime::portable::{
    DurableCollection, DurablePortableSnapshotRepository, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordPage,
    DurableRecordScan, MAX_PORTABLE_CHUNK_BYTES, MAX_PORTABLE_PAGE_KEYS, PortableBlobChunkOutcome,
    PortableBlobChunkRequest, PortableBlobDescriptor, PortableBlobRepository,
    PortableSnapshotToken,
};

fn invalid(reason: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, reason))
}

fn read_value<S: DurablePortableSnapshotRepository>(
    source: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    token: &PortableSnapshotToken,
    descriptor: &DurableRecordDescriptor,
) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let Some(length) = descriptor.payload_length() else {
        return Ok(None);
    };
    let mut value: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    while offset < length {
        let count: usize = MAX_PORTABLE_CHUNK_BYTES.min(length - offset);
        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
            descriptor.clone(),
            offset,
            NonZeroUsize::new(count).ok_or_else(|| invalid("zero row chunk progress"))?,
        )?;
        let outcome: DurableRecordChunkOutcome =
            source.read_portable_chunk_at(operation, domain, token, &request)?;
        let DurableRecordChunkOutcome::Chunk(chunk) = outcome else {
            return Err(invalid(
                "source row changed during business snapshot capture",
            ));
        };
        if chunk.request() != &request || chunk.bytes().len() != count {
            return Err(invalid(
                "source chunk differs from its requested bounded range",
            ));
        }
        value.extend_from_slice(chunk.bytes());
        offset = offset
            .checked_add(count)
            .ok_or_else(|| invalid("row range overflow"))?;
    }
    Ok(Some(value))
}

fn read_blob<B: PortableBlobRepository>(
    source: &B,
    digest: Digest32,
    maximum: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let descriptor: PortableBlobDescriptor = source
        .read_portable_blob_descriptor(&digest)?
        .ok_or_else(|| invalid("business snapshot referenced blob is missing"))?;
    if descriptor.digest() != digest || descriptor.length() > maximum {
        return Err(invalid("blob descriptor names a different digest"));
    }
    let mut value: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let count: usize = MAX_PORTABLE_CHUNK_BYTES.min(descriptor.length() - offset);
        let request: PortableBlobChunkRequest = PortableBlobChunkRequest::new(
            descriptor,
            offset,
            NonZeroUsize::new(count.max(1)).ok_or_else(|| invalid("zero blob chunk progress"))?,
        )?;
        let PortableBlobChunkOutcome::Chunk(chunk) = source.read_portable_blob_chunk(&request)?
        else {
            return Err(invalid("referenced blob changed or became unavailable"));
        };
        if chunk.request() != &request || chunk.bytes().len() != count {
            return Err(invalid(
                "blob chunk differs from its requested bounded range",
            ));
        }
        value.extend_from_slice(chunk.bytes());
        offset = offset
            .checked_add(count)
            .ok_or_else(|| invalid("blob range overflow"))?;
        if chunk.is_last() {
            break;
        }
    }
    Ok(value)
}

/// Captures all four collections without a whole-history protocol ceiling.
/// Individual pages, descriptors and body reads keep their runtime bounds.
/// A concurrent mutation or reopened writer refuses the entire observation.
pub fn capture_source_business_snapshot<
    S: DurablePortableSnapshotRepository,
    B: PortableBlobRepository,
>(
    source: &S,
    blobs: &B,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    page_size: NonZeroUsize,
) -> Result<SourceBusinessSnapshot, Box<dyn Error>> {
    if page_size.get() > MAX_PORTABLE_PAGE_KEYS {
        return Err(invalid(
            "business snapshot page size exceeds the runtime bound",
        ));
    }
    let token: PortableSnapshotToken = source.begin_portable_snapshot(operation, domain)?;
    source.check_portable_outbox_empty_at(operation, domain, &token)?;
    let mut records: Vec<SourceSnapshotRecord> = Vec::new();
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        let mut after: Option<DurableRecordKey> = None;
        loop {
            let scan: DurableRecordScan =
                DurableRecordScan::new(collection, after.clone(), page_size)?;
            let page: DurableRecordPage =
                source.scan_portable_keys_at(operation, domain, &token, &scan)?;
            for key in page.keys() {
                let descriptor: DurableRecordDescriptor = source
                    .read_portable_descriptor_at(operation, domain, &token, key)?
                    .ok_or_else(|| invalid("enumerated source record disappeared"))?;
                if descriptor.key() != key {
                    return Err(invalid("source descriptor differs from the enumerated key"));
                }
                let value: Option<Vec<u8>> =
                    read_value(source, operation, domain, &token, &descriptor)?;
                records.push(SourceSnapshotRecord { descriptor, value });
            }
            let Some(next) = page.continuation() else {
                break;
            };
            if after.as_ref().is_some_and(|previous| next <= previous) {
                return Err(invalid("source snapshot cursor did not advance"));
            }
            after = Some(next.clone());
        }
    }
    let mut captured: SourceBusinessSnapshot = SourceBusinessSnapshot {
        token,
        records,
        referenced_blobs: BTreeMap::new(),
    };
    for (digest, maximum) in referenced_blob_bounds(&captured)? {
        captured
            .referenced_blobs
            .insert(digest, read_blob(blobs, digest, maximum)?);
    }
    // No separate before/after emulation: this last guarded read validates the
    // token inside its backend snapshot, including outbox continuity.
    source.check_portable_outbox_empty_at(operation, domain, &captured.token)?;
    Ok(captured)
}
