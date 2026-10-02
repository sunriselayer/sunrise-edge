//! Exact structured capture: complete State, Receipts, ObjectHeads,
//! ObjectVersions and referenced blob bytes under one fenced local
//! snapshot, scanning every collection with no allowlist or hand-selected
//! source business rows. Relocated from the owning
//! `business_reconstruction` causal-placement test module, whose existing
//! consumers keep using its [`captured_source`] re-export.

use crate::business_reconstruction::{
    SourceBusinessSnapshot, SourceSnapshotRecord, referenced_blob_bounds,
};
use protocol_types::Digest32;
use runtime::portable::{
    DurableCollection, DurablePortableSnapshotRepository, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordPage,
    DurableRecordScan, PortableBlobChunkOutcome, PortableBlobChunkRequest, PortableBlobDescriptor,
    PortableBlobRepository, PortableSnapshotToken,
};
use runtime::{AtomicityDomainId, DurableOperationContext};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;

/// Compare exact persisted records and referenced bytes across independent
/// stores. Snapshot tokens prove continuity only in their owning backend.
pub(crate) fn assert_same_records_and_blobs(
    actual: &SourceBusinessSnapshot,
    expected: &SourceBusinessSnapshot,
) {
    assert_eq!(
        actual.records, expected.records,
        "complete structured records"
    );
    assert_eq!(
        actual.referenced_blobs, expected.referenced_blobs,
        "complete referenced blob bytes"
    );
}

fn captured_value<S: DurablePortableSnapshotRepository>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    token: &PortableSnapshotToken,
    descriptor: &DurableRecordDescriptor,
) -> Option<Vec<u8>> {
    let length: usize = descriptor.payload_length()?;
    let mut bytes: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let count: usize = 1024.min(length.checked_sub(offset).unwrap());
        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
            descriptor.clone(),
            offset,
            NonZeroUsize::new(count.max(1)).unwrap(),
        )
        .unwrap();
        let DurableRecordChunkOutcome::Chunk(chunk) = store
            .read_portable_chunk_at(operation, domain, token, &request)
            .unwrap()
        else {
            panic!("source changed while capturing one consistent snapshot");
        };
        assert_eq!(chunk.request(), &request);
        assert_eq!(chunk.bytes().len(), count);
        bytes.extend_from_slice(chunk.bytes());
        offset = offset.checked_add(count).unwrap();
        if chunk.is_last() {
            break;
        }
    }
    assert_eq!(bytes.len(), length);
    Some(bytes)
}

fn captured_blob<B: PortableBlobRepository>(
    source: &B,
    digest: Digest32,
    maximum: usize,
) -> Vec<u8> {
    let descriptor: PortableBlobDescriptor = source
        .read_portable_blob_descriptor(&digest)
        .unwrap()
        .unwrap();
    assert_eq!(descriptor.digest(), digest);
    assert!(descriptor.length() <= maximum);
    let mut bytes: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let count: usize = 1024.min(descriptor.length().checked_sub(offset).unwrap());
        let request: PortableBlobChunkRequest = PortableBlobChunkRequest::new(
            descriptor,
            offset,
            NonZeroUsize::new(count.max(1)).unwrap(),
        )
        .unwrap();
        let PortableBlobChunkOutcome::Chunk(chunk) =
            source.read_portable_blob_chunk(&request).unwrap()
        else {
            panic!("genuine source referenced blob is missing or changed");
        };
        assert_eq!(chunk.request(), &request);
        assert_eq!(chunk.bytes().len(), count);
        bytes.extend_from_slice(chunk.bytes());
        offset = offset.checked_add(count).unwrap();
        if chunk.is_last() {
            break;
        }
    }
    bytes
}

// No allowlist or hand-selected source business rows: scan all four complete
// collections, including local tombstones and original/synthetic receipts.
pub(crate) fn captured_source<S: DurablePortableSnapshotRepository, B: PortableBlobRepository>(
    store: &S,
    blobs: &B,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> SourceBusinessSnapshot {
    let token: PortableSnapshotToken = store.begin_portable_snapshot(operation, domain).unwrap();
    store
        .check_portable_outbox_empty_at(operation, domain, &token)
        .unwrap();
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
                DurableRecordScan::new(collection, after.clone(), NonZeroUsize::new(7).unwrap())
                    .unwrap();
            let page: DurableRecordPage = store
                .scan_portable_keys_at(operation, domain, &token, &scan)
                .unwrap();
            for key in page.keys() {
                let descriptor: DurableRecordDescriptor = store
                    .read_portable_descriptor_at(operation, domain, &token, key)
                    .unwrap()
                    .unwrap();
                assert_eq!(descriptor.key(), key);
                let value: Option<Vec<u8>> =
                    captured_value(store, operation, domain, &token, &descriptor);
                records.push(SourceSnapshotRecord { descriptor, value });
            }
            let Some(next) = page.continuation() else {
                break;
            };
            assert!(after.as_ref().is_none_or(|previous| next > previous));
            after = Some(next.clone());
        }
    }
    let mut snapshot: SourceBusinessSnapshot = SourceBusinessSnapshot {
        token,
        records,
        referenced_blobs: BTreeMap::new(),
    };
    for (digest, maximum) in referenced_blob_bounds(&snapshot).unwrap() {
        snapshot
            .referenced_blobs
            .insert(digest, captured_blob(blobs, digest, maximum));
    }
    store
        .check_portable_outbox_empty_at(operation, domain, &snapshot.token)
        .unwrap();
    snapshot.validate().unwrap();
    snapshot
}

#[cfg(test)]
mod tests;
