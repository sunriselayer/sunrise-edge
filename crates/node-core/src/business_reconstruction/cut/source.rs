//! Read-only generic source capture under one backend-enforced observation.
use super::super::{SourceBusinessSnapshot, SourceSnapshotRecord, referenced_blob_bounds};
use super::*;
use runtime::DurableOperationContext;
use runtime::portable::{
    DurableCollection, DurableRecordChunkOutcome, DurableRecordChunkRequest,
    DurableRecordDescriptor, DurableRecordKey, DurableRecordScan, MAX_PORTABLE_CHUNK_BYTES,
    MAX_PORTABLE_PAGE_KEYS, PortableBlobChunkOutcome, PortableBlobChunkRequest,
    PortableBlobDescriptor,
};

fn body<S: DurablePortableSnapshotRepository>(
    source: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    token: &PortableSnapshotToken,
    descriptor: &DurableRecordDescriptor,
) -> Result<Option<Vec<u8>>, BusinessCutError> {
    let Some(length) = descriptor.payload_length() else {
        return Ok(None);
    };
    let mut bytes: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    while offset < length {
        let count: usize = MAX_PORTABLE_CHUNK_BYTES.min(length - offset);
        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
            descriptor.clone(),
            offset,
            NonZeroUsize::new(count).ok_or(invalid("source chunk zero progress"))?,
        )
        .map_err(|_| invalid("source chunk shape"))?;
        let DurableRecordChunkOutcome::Chunk(chunk) = source
            .read_portable_chunk_at(operation, domain, token, &request)
            .map_err(|_| invalid("source chunk read refused"))?
        else {
            return Err(invalid("source descriptor changed during capture"));
        };
        if chunk.request() != &request
            || chunk.bytes().len() != count
            || chunk.is_last() != (offset + count == length)
        {
            return Err(invalid("source chunk does not match exact bounded range"));
        }
        bytes.extend_from_slice(chunk.bytes());
        offset = offset
            .checked_add(count)
            .ok_or(invalid("source chunk range overflow"))?;
    }
    Ok(Some(bytes))
}
fn blob<B: PortableBlobRepository>(
    source: &B,
    digest: Digest32,
    maximum: usize,
) -> Result<Vec<u8>, BusinessCutError> {
    let descriptor: PortableBlobDescriptor = source
        .read_portable_blob_descriptor(&digest)
        .map_err(|_| invalid("source blob descriptor read refused"))?
        .ok_or(invalid("source required blob is missing"))?;
    if descriptor.digest() != digest || descriptor.length() > maximum {
        return Err(invalid("source blob descriptor digest/owning capacity"));
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let count: usize = MAX_PORTABLE_CHUNK_BYTES.min(descriptor.length() - offset);
        let request: PortableBlobChunkRequest = PortableBlobChunkRequest::new(
            descriptor,
            offset,
            NonZeroUsize::new(count.max(1)).ok_or(invalid("source blob zero progress"))?,
        )
        .map_err(|_| invalid("source blob chunk shape"))?;
        let PortableBlobChunkOutcome::Chunk(chunk) = source
            .read_portable_blob_chunk(&request)
            .map_err(|_| invalid("source blob read refused"))?
        else {
            return Err(invalid("source blob descriptor changed"));
        };
        if chunk.request() != &request
            || chunk.bytes().len() != count
            || chunk.is_last() != (offset + count == descriptor.length())
        {
            return Err(invalid(
                "source blob chunk differs from exact bounded range",
            ));
        }
        bytes.extend_from_slice(chunk.bytes());
        offset = offset
            .checked_add(count)
            .ok_or(invalid("source blob range overflow"))?;
        if chunk.is_last() {
            break;
        }
    }
    Ok(bytes)
}

pub(super) fn capture<S: DurablePortableSnapshotRepository, B: PortableBlobRepository>(
    source: &S,
    blobs: &B,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> Result<SourceBusinessSnapshot, BusinessCutError> {
    let token: PortableSnapshotToken = source
        .begin_portable_snapshot(operation, domain)
        .map_err(|_| invalid("source snapshot observation refused"))?;
    source
        .check_portable_outbox_empty_at(operation, domain, &token)
        .map_err(|_| invalid("source EmptyOnlyV1 or snapshot check refused"))?;
    let mut records: Vec<SourceSnapshotRecord> = Vec::new();
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        let mut after: Option<DurableRecordKey> = None;
        loop {
            let scan: DurableRecordScan = DurableRecordScan::new(
                collection,
                after.clone(),
                NonZeroUsize::new(MAX_PORTABLE_PAGE_KEYS).ok_or(invalid("source page capacity"))?,
            )
            .map_err(|_| invalid("source page request shape"))?;
            let page = source
                .scan_portable_keys_at(operation, domain, &token, &scan)
                .map_err(|_| invalid("source snapshot page refused"))?;
            let mut previous: Option<&DurableRecordKey> = after.as_ref();
            for key in page.keys() {
                if key.collection() != collection || previous.is_some_and(|before| key <= before) {
                    return Err(invalid("source page collection/order differs"));
                }
                let descriptor: DurableRecordDescriptor = source
                    .read_portable_descriptor_at(operation, domain, &token, key)
                    .map_err(|_| invalid("source descriptor read refused"))?
                    .ok_or(invalid("source enumerated record disappeared"))?;
                if descriptor.key() != key {
                    return Err(invalid("source descriptor natural key differs"));
                }
                let value: Option<Vec<u8>> = body(source, operation, domain, &token, &descriptor)?;
                records.push(SourceSnapshotRecord { descriptor, value });
                previous = Some(key);
            }
            let Some(next) = page.continuation() else {
                break;
            };
            if page.keys().last() != Some(next) || after.as_ref().is_some_and(|key| next <= key) {
                return Err(invalid("source page continuation does not advance exactly"));
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
            .insert(digest, blob(blobs, digest, maximum)?);
    }
    captured.validate()?;
    source
        .check_portable_outbox_empty_at(operation, domain, &captured.token)
        .map_err(|_| invalid("source snapshot changed after complete capture"))?;
    Ok(captured)
}
