use super::*;
use crate::{StorageCorrelationId, StorageDeadline, StoredStateValue, WriterFenceGeneration};
use protocol_types::HashAlgorithmId;

fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([1; 32]).unwrap()
}
fn context() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(100).unwrap(),
        StorageCorrelationId::new([1; 16]).unwrap(),
    )
}
fn store() -> MemoryDurableStateStore {
    MemoryDurableStateStore::new_bound(domain(), WriterFenceGeneration::new(1).unwrap())
}
fn install(store: &MemoryDurableStateStore, key: &[u8], value: Option<Vec<u8>>, revision: u64) {
    let mut data = store.inner.write().unwrap();
    data.state_domains
        .entry(*domain().as_bytes())
        .or_default()
        .insert(
            key.to_vec(),
            StoredStateValue {
                revision: StateRevision::new(revision),
                value,
            },
        );
}
fn scan(
    collection: DurableCollection,
    after: Option<DurableRecordKey>,
    count: usize,
) -> DurableRecordScan {
    DurableRecordScan::new(collection, after, NonZeroUsize::new(count).unwrap()).unwrap()
}

#[test]
fn portable_repository_shared_memory_conformance() {
    let store: MemoryDurableStateStore = store();
    let chain: protocol_types::ChainId = protocol_types::ChainId::new("portable-memory").unwrap();
    conformance::seed(&store, &context(), domain(), &chain);
    conformance::verify(&store, &context(), domain(), &chain);
    conformance::assert_changed(&store, &context(), domain());
    conformance::verify(&store, &context(), domain(), &chain);
}

#[test]
fn pages_reject_foreign_duplicate_reordered_overlimit_and_cursor_keys() {
    let request: DurableRecordScan = scan(DurableCollection::State, None, 2);
    let key: DurableRecordKey = DurableRecordKey::State(b"a".to_vec());
    for keys in [
        vec![key.clone(), key.clone()],
        vec![DurableRecordKey::State(b"b".to_vec()), key.clone()],
        vec![DurableRecordKey::Receipt(
            DurableRequestId::new([1; 32]).unwrap(),
        )],
        vec![key.clone(); 4],
    ] {
        assert!(DurableRecordPage::from_ordered_candidates(&request, keys).is_err());
    }
    assert!(
        DurableRecordScan::new(
            DurableCollection::Receipts,
            Some(key.clone()),
            NonZeroUsize::new(1).unwrap()
        )
        .is_err()
    );
    assert!(
        DurableRecordScan::new(
            DurableCollection::State,
            None,
            NonZeroUsize::new(MAX_PORTABLE_PAGE_KEYS + 1).unwrap()
        )
        .is_err()
    );
    let resumed: DurableRecordScan = scan(DurableCollection::State, Some(key.clone()), 2);
    assert!(DurableRecordPage::from_ordered_candidates(&resumed, vec![key]).is_err());
}

#[test]
fn pages_bound_maximum_length_keys_and_lookahead() {
    let request: DurableRecordScan = scan(DurableCollection::State, None, MAX_PORTABLE_PAGE_KEYS);
    let keys: Vec<DurableRecordKey> = (0..=MAX_PORTABLE_PAGE_KEYS)
        .map(|index| {
            let mut key: Vec<u8> = vec![0; crate::MAX_STATE_KEY_BYTES];
            key[..2].copy_from_slice(&u16::try_from(index).unwrap().to_be_bytes());
            DurableRecordKey::State(key)
        })
        .collect();
    let result: DurableRecordPage =
        DurableRecordPage::from_ordered_candidates(&request, keys).unwrap();
    assert_eq!(result.keys().len(), MAX_PORTABLE_PAGE_KEYS);
    assert_eq!(result.continuation(), result.keys().last());
}

#[test]
fn object_versions_use_numeric_unsigned_order() {
    let id: ObjectId = ObjectId::new([1; 32]);
    let versions: Vec<DurableRecordKey> = [9, 10, 99, 100, u64::MAX]
        .into_iter()
        .map(|n| DurableRecordKey::ObjectVersion(id, DurableObjectVersion::new(n).unwrap()))
        .collect();
    let request: DurableRecordScan = scan(DurableCollection::ObjectVersions, None, 5);
    assert_eq!(
        DurableRecordPage::from_ordered_candidates(&request, versions.clone())
            .unwrap()
            .keys(),
        versions
    );
}

#[test]
fn descriptors_distinguish_absence_tombstone_and_empty() {
    let store: MemoryDurableStateStore = store();
    install(&store, b"deleted", None, 2);
    install(&store, b"empty", Some(Vec::new()), 1);
    assert_eq!(
        store
            .read_portable_descriptor(
                &context(),
                domain(),
                &DurableRecordKey::State(b"absent".to_vec())
            )
            .unwrap(),
        None
    );
    let deleted: DurableRecordDescriptor = store
        .read_portable_descriptor(
            &context(),
            domain(),
            &DurableRecordKey::State(b"deleted".to_vec()),
        )
        .unwrap()
        .unwrap();
    let empty: DurableRecordDescriptor = store
        .read_portable_descriptor(
            &context(),
            domain(),
            &DurableRecordKey::State(b"empty".to_vec()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(deleted.payload_length(), None);
    assert_eq!(empty.payload_length(), Some(0));
    assert!(DurableRecordChunkRequest::new(deleted, 0, NonZeroUsize::new(1).unwrap()).is_err());
    let request: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(empty, 0, NonZeroUsize::new(1).unwrap()).unwrap();
    let DurableRecordChunkOutcome::Chunk(chunk) = store
        .read_portable_chunk(&context(), domain(), &request)
        .unwrap()
    else {
        panic!("expected empty terminal chunk")
    };
    assert_eq!(chunk.bytes(), b"");
    assert!(chunk.is_last());
}

#[test]
fn maximum_legal_value_downloads_in_strictly_bounded_chunks() {
    let store: MemoryDurableStateStore = store();
    let body: Vec<u8> = vec![0x5a; MAX_STATE_VALUE_BYTES];
    install(&store, b"large", Some(body.clone()), 1);
    let first: DurableRecordPage = store
        .scan_portable_keys(
            &context(),
            domain(),
            &scan(DurableCollection::State, None, 1),
        )
        .unwrap();
    let descriptor: DurableRecordDescriptor = store
        .read_portable_descriptor(&context(), domain(), &first.keys()[0])
        .unwrap()
        .unwrap();
    let mut downloaded: Vec<u8> = Vec::new();
    while downloaded.len() < body.len() {
        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
            descriptor.clone(),
            downloaded.len(),
            NonZeroUsize::new(MAX_PORTABLE_CHUNK_BYTES).unwrap(),
        )
        .unwrap();
        let DurableRecordChunkOutcome::Chunk(chunk) = store
            .read_portable_chunk(&context(), domain(), &request)
            .unwrap()
        else {
            panic!("stable descriptor changed")
        };
        assert!(chunk.bytes().len() <= MAX_PORTABLE_CHUNK_BYTES);
        assert!(!chunk.bytes().is_empty());
        downloaded.extend_from_slice(chunk.bytes());
        assert_eq!(chunk.is_last(), downloaded.len() == body.len());
    }
    assert_eq!(downloaded, body);
    assert!(
        DurableRecordChunkRequest::new(
            descriptor.clone(),
            body.len(),
            NonZeroUsize::new(1).unwrap()
        )
        .is_err()
    );
    assert!(
        DurableRecordChunkRequest::new(descriptor, usize::MAX, NonZeroUsize::new(1).unwrap())
            .is_err()
    );
}

#[test]
fn changed_same_length_value_or_deletion_cannot_stitch_revisions() {
    let store: MemoryDurableStateStore = store();
    install(&store, b"value", Some(vec![1; 8]), 1);
    let key: DurableRecordKey = DurableRecordKey::State(b"value".to_vec());
    let descriptor: DurableRecordDescriptor = store
        .read_portable_descriptor(&context(), domain(), &key)
        .unwrap()
        .unwrap();
    let request: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor, 0, NonZeroUsize::new(4).unwrap()).unwrap();
    install(&store, b"value", Some(vec![2; 8]), 2);
    assert_eq!(
        store
            .read_portable_chunk(&context(), domain(), &request)
            .unwrap(),
        DurableRecordChunkOutcome::Changed
    );
    install(&store, b"value", None, 3);
    assert_eq!(
        store
            .read_portable_chunk(&context(), domain(), &request)
            .unwrap(),
        DurableRecordChunkOutcome::Changed
    );
}

#[test]
fn constructor_bounds_and_chunk_lengths_are_closed() {
    let key: DurableRecordKey = DurableRecordKey::State(b"key".to_vec());
    assert!(
        DurableRecordDescriptor::new(
            key.clone(),
            DurableRecordMetadata::State {
                revision: StateRevision::INITIAL,
                value_length: Some(1)
            }
        )
        .is_err()
    );
    assert!(
        DurableRecordDescriptor::new(
            key.clone(),
            DurableRecordMetadata::State {
                revision: StateRevision::new(1),
                value_length: Some(MAX_STATE_VALUE_BYTES + 1)
            }
        )
        .is_err()
    );
    let descriptor: DurableRecordDescriptor = DurableRecordDescriptor::new(
        key,
        DurableRecordMetadata::State {
            revision: StateRevision::new(1),
            value_length: Some(8),
        },
    )
    .unwrap();
    assert!(
        DurableRecordChunkRequest::new(
            descriptor.clone(),
            0,
            NonZeroUsize::new(MAX_PORTABLE_CHUNK_BYTES + 1).unwrap()
        )
        .is_err()
    );
    let request: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor, 0, NonZeroUsize::new(4).unwrap()).unwrap();
    assert!(DurableRecordChunk::new(request.clone(), vec![0; 3]).is_err());
    assert!(DurableRecordChunk::new(request, vec![0; 5]).is_err());
}

#[test]
fn foreign_domain_stale_fence_expired_and_poisoned_lock_refuse() {
    let store: MemoryDurableStateStore = store();
    install(&store, b"key", Some(vec![1]), 1);
    let key: DurableRecordKey = DurableRecordKey::State(b"key".to_vec());
    let descriptor: DurableRecordDescriptor = store
        .read_portable_descriptor(&context(), domain(), &key)
        .unwrap()
        .unwrap();
    let request: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor, 0, NonZeroUsize::new(1).unwrap()).unwrap();
    let scan: DurableRecordScan = scan(DurableCollection::State, None, 1);
    let foreign: AtomicityDomainId = AtomicityDomainId::new([2; 32]).unwrap();
    assert!(matches!(
        store.scan_portable_keys(&context(), foreign, &scan),
        Err(DurableReadError::InvalidRequest(
            RuntimeError::AtomicityDomainMismatch
        ))
    ));
    store.set_active_writer_fence(WriterFenceGeneration::new(2).unwrap());
    assert!(matches!(
        store.read_portable_descriptor(&context(), domain(), &key),
        Err(DurableReadError::WriterFenced { .. })
    ));
    assert!(matches!(
        store.read_portable_chunk(&context(), domain(), &request),
        Err(DurableReadError::WriterFenced { .. })
    ));
    store.set_active_writer_fence(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    assert_eq!(
        store.scan_portable_keys(&context(), domain(), &scan),
        Err(DurableReadError::DeadlineExceeded)
    );
    let cloned: MemoryDurableStateStore = store.clone();
    let _ = std::thread::spawn(move || {
        let _guard = cloned.inner.write().unwrap();
        panic!("fixture poison")
    })
    .join();
    assert_eq!(
        store.read_portable_chunk(&context(), domain(), &request),
        Err(DurableReadError::Unavailable)
    );
}

#[test]
fn receipt_pages_keep_complete_continuation_without_payloads() {
    let store: MemoryDurableStateStore = store();
    for byte in 1..=3 {
        let id: DurableRequestId = DurableRequestId::new([byte; 32]).unwrap();
        let receipt: crate::DurableRequestReceipt = crate::DurableRequestReceipt::new(
            id,
            Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]),
            vec![byte; MAX_PORTABLE_CHUNK_BYTES + 1],
        )
        .unwrap();
        store
            .inner
            .write()
            .unwrap()
            .receipts
            .insert((*domain().as_bytes(), *id.as_bytes()), receipt);
    }
    let first: DurableRecordPage = store
        .scan_portable_keys(
            &context(),
            domain(),
            &scan(DurableCollection::Receipts, None, 2),
        )
        .unwrap();
    let second: DurableRecordPage = store
        .scan_portable_keys(
            &context(),
            domain(),
            &scan(
                DurableCollection::Receipts,
                first.continuation().cloned(),
                2,
            ),
        )
        .unwrap();
    assert_eq!(first.keys().len(), 2);
    assert_eq!(second.keys().len(), 1);
    assert_eq!(second.continuation(), None);
    let descriptor: DurableRecordDescriptor = store
        .read_portable_descriptor(&context(), domain(), &first.keys()[0])
        .unwrap()
        .unwrap();
    assert_eq!(
        descriptor.payload_length(),
        Some(MAX_PORTABLE_CHUNK_BYTES + 1)
    );
}
