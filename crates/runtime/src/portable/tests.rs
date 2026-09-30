use super::*;
use crate::{
    DurableDomainStateStore, IndexedOutboxRepository, StorageCorrelationId, StorageDeadline,
    StoredStateValue, WriterFenceGeneration,
};
use protocol_types::HashAlgorithmId;

fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([1; 32]).unwrap()
}

#[test]
fn exhausted_memory_identity_allocator_disables_snapshot_support_without_wrapping_or_panicking() {
    let counter: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX - 1);
    let last: Vec<u8> = crate::allocate_memory_portable_namespace(&counter);
    assert!(!last.is_empty());
    let exhausted: Vec<u8> = crate::allocate_memory_portable_namespace(&counter);
    assert!(exhausted.is_empty());
    assert!(crate::allocate_memory_portable_namespace(&counter).is_empty());
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), u64::MAX);
    let source: MemoryDurableStateStore = store();
    let token: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    source.inner.write().unwrap().portable_namespace = exhausted;
    assert!(
        source
            .begin_portable_snapshot(&context(), domain())
            .is_err()
    );
    assert_eq!(
        source.check_portable_outbox_empty_at(&context(), domain(), &token),
        Err(PortableSnapshotError::Changed)
    );
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
fn chunk_of(
    store: &MemoryDurableStateStore,
    request: &DurableRecordChunkRequest,
) -> DurableRecordChunk {
    let outcome: DurableRecordChunkOutcome = store
        .read_portable_chunk(&context(), domain(), request)
        .unwrap();
    let DurableRecordChunkOutcome::Chunk(chunk) = outcome else {
        panic!()
    };
    *chunk
}

fn require_chunk(outcome: PortableBlobChunkOutcome) -> Box<PortableBlobChunk> {
    match outcome {
        PortableBlobChunkOutcome::Chunk(chunk) => chunk,
        PortableBlobChunkOutcome::Corrupt => panic!("expected chunk"),
    }
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
fn snapshot_shared_memory_conformance_detects_new_keys_between_pages() {
    let store: MemoryDurableStateStore = store();
    let chain: protocol_types::ChainId = protocol_types::ChainId::new("snapshot-memory").unwrap();
    conformance::seed(&store, &context(), domain(), &chain);
    conformance::verify_snapshot(&store, &context(), domain());
    conformance::assert_snapshot_changed(&store, &context(), domain());
}

#[test]
fn snapshot_shared_memory_outbox_mutation_conformance() {
    conformance::verify_snapshot_outbox_mutations(&store(), &context(), domain());
}

#[test]
fn snapshot_refuses_corrupt_pending_empty_delivery() {
    let source: MemoryDurableStateStore = store();
    crate::outbox_guard::conformance::assert_clear_after_empty_batch(
        &source,
        &context(),
        domain(),
        0xf1,
    );
    source
        .inner
        .write()
        .unwrap()
        .deliveries
        .get_mut(&(*domain().as_bytes(), [0xf1; 32]))
        .unwrap()
        .completed = false;
    let token: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    assert_eq!(
        source.check_portable_outbox_empty_at(&context(), domain(), &token),
        Err(PortableSnapshotError::NonemptyOutbox)
    );
}

fn write_snapshot_state(
    store: &MemoryDurableStateStore,
    key: &[u8],
    revision: StateRevision,
) -> crate::DurableCommitOutcome {
    let transaction: crate::AtomicStateTransaction = crate::AtomicStateTransaction::new(
        domain(),
        crate::AtomicStateReadSet::new(vec![
            crate::StateReadAssertion::new(key.to_vec(), revision).unwrap(),
        ])
        .unwrap(),
        crate::AtomicStateMutationSet::new(vec![
            crate::StateMutationEntry::new(key.to_vec(), crate::StateMutation::Put(vec![2]))
                .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    store.commit_durable(&context(), transaction)
}

#[test]
fn snapshot_rejects_other_instance_domain_writer_deadline_and_sequence() {
    let source: MemoryDurableStateStore = store();
    let token: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    let request: DurableRecordScan = scan(DurableCollection::State, None, 1);
    assert!(matches!(
        store().scan_portable_keys_at(&context(), domain(), &token, &request),
        Err(PortableSnapshotError::Changed)
    ));
    let foreign: AtomicityDomainId = AtomicityDomainId::new([2; 32]).unwrap();
    assert!(matches!(
        source.scan_portable_keys_at(&context(), foreign, &token, &request),
        Err(PortableSnapshotError::Read(_))
    ));
    let forged: PortableSnapshotToken = PortableSnapshotToken::new(
        token.namespace().to_vec(),
        foreign,
        token.writer_fence(),
        token.mutation_sequence(),
    )
    .unwrap();
    assert!(matches!(
        source.scan_portable_keys_at(&context(), domain(), &forged, &request),
        Err(PortableSnapshotError::Changed)
    ));
    source.set_active_writer_fence(WriterFenceGeneration::new(2).unwrap());
    assert!(matches!(
        source.begin_portable_snapshot(&context(), domain()),
        Err(PortableSnapshotError::Read(
            DurableReadError::WriterFenced { .. }
        ))
    ));
    let new_context: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(2).unwrap(),
        context().deadline(),
        context().correlation_id(),
    );
    assert!(matches!(
        source.scan_portable_keys_at(&new_context, domain(), &token, &request),
        Err(PortableSnapshotError::Changed)
    ));
    source.set_time(100);
    assert!(matches!(
        source.begin_portable_snapshot(&new_context, domain()),
        Err(PortableSnapshotError::Read(
            DurableReadError::DeadlineExceeded
        ))
    ));
}

#[test]
fn snapshot_conflict_and_overflow_leave_sequence_and_business_rows_unchanged() {
    let source: MemoryDurableStateStore = store();
    assert!(matches!(
        write_snapshot_state(&source, b"key", StateRevision::INITIAL),
        crate::DurableCommitOutcome::Committed
    ));
    let token: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    assert!(matches!(
        write_snapshot_state(&source, b"key", StateRevision::INITIAL),
        crate::DurableCommitOutcome::Rejected(crate::DurableCommitRejection::Conflict { .. })
    ));
    assert_eq!(
        token,
        source
            .begin_portable_snapshot(&context(), domain())
            .unwrap()
    );
    source
        .inner
        .write()
        .unwrap()
        .mutation_sequences
        .insert(*domain().as_bytes(), u64::MAX);
    let before: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    assert!(matches!(
        write_snapshot_state(&source, b"new", StateRevision::INITIAL),
        crate::DurableCommitOutcome::Rejected(
            crate::DurableCommitRejection::CommitSequenceOverflow
        )
    ));
    assert_eq!(
        before,
        source
            .begin_portable_snapshot(&context(), domain())
            .unwrap()
    );
    assert!(
        source
            .get_versioned_durable(&context(), domain(), b"new")
            .unwrap()
            .value()
            .is_none()
    );
}

fn snapshot_outbox_invocation(
    request_byte: u8,
    nonempty: bool,
) -> crate::DurableInvocationTransaction {
    let request: DurableRequestId = DurableRequestId::new([request_byte; 32]).unwrap();
    let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [3; 32]);
    let messages: Vec<crate::DurableOutboxMessage> = if nonempty {
        vec![crate::DurableOutboxMessage::new(digest, vec![4]).unwrap()]
    } else {
        Vec::new()
    };
    crate::DurableInvocationTransaction::new(
        domain(),
        None,
        crate::DurableObjectChanges::empty(),
        crate::DurableRequestReceipt::new(request, digest, vec![5]).unwrap(),
        Some(crate::DurableOutboxBatch::new(request, digest, messages).unwrap()),
    )
    .unwrap()
}

#[test]
fn snapshot_receipt_only_and_empty_outbox_commits_advance_atomically() {
    let source: MemoryDurableStateStore = store();
    let before: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    let invocation: crate::DurableInvocationTransaction = snapshot_outbox_invocation(8, false);
    assert!(matches!(
        source.commit_invocation(&context(), invocation.clone()),
        crate::DurableCommitOutcome::Committed
    ));
    let after: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    assert_eq!(after.mutation_sequence(), before.mutation_sequence() + 1);
    source
        .check_portable_outbox_empty_at(&context(), domain(), &after)
        .unwrap();
    assert!(matches!(
        source.commit_invocation(&context(), invocation),
        crate::DurableCommitOutcome::Rejected(
            crate::DurableCommitRejection::RequestAlreadyCommitted
        )
    ));
    assert_eq!(
        after,
        source
            .begin_portable_snapshot(&context(), domain())
            .unwrap()
    );
}

#[test]
fn snapshot_tracks_claim_ack_and_expiration_and_refuses_completed_nonempty_outbox() {
    let source: MemoryDurableStateStore = store();
    assert!(matches!(
        source.commit_invocation(&context(), snapshot_outbox_invocation(9, true)),
        crate::DurableCommitOutcome::Committed
    ));
    let before: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    assert!(matches!(
        source.check_portable_outbox_empty_at(&context(), domain(), &before),
        Err(PortableSnapshotError::NonemptyOutbox)
    ));
    let lease: crate::DurableOutboxLeaseId = crate::DurableOutboxLeaseId::new([1; 32]).unwrap();
    let claim: crate::DueOutboxClaimRequest =
        crate::DueOutboxClaimRequest::new(domain(), 0, lease, 10).unwrap();
    assert!(matches!(
        source.claim_due_outbox(&context(), claim),
        crate::DurableOutboxClaimOutcome::Claimed(_)
    ));
    let claimed: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    assert_eq!(claimed.mutation_sequence(), before.mutation_sequence() + 1);
    // Exact live-lease replay reads retained bytes without advancing sequence.
    assert!(matches!(
        source.claim_due_outbox(&context(), claim),
        crate::DurableOutboxClaimOutcome::Claimed(_)
    ));
    assert_eq!(
        claimed,
        source
            .begin_portable_snapshot(&context(), domain())
            .unwrap()
    );
    // Existing lease expiry reconciliation mutates attempt/delivery rows even
    // when it refuses lease reuse. That mutation must also invalidate a token.
    let expired: crate::DueOutboxClaimRequest =
        crate::DueOutboxClaimRequest::new(domain(), 10, lease, 20).unwrap();
    assert!(matches!(
        source.claim_due_outbox(&context(), expired),
        crate::DurableOutboxClaimOutcome::Rejected(
            crate::DurableOutboxClaimRejection::LeaseIdReuse
        )
    ));
    let expiry: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    assert_eq!(expiry.mutation_sequence(), claimed.mutation_sequence() + 1);
    let next_lease: crate::DurableOutboxLeaseId =
        crate::DurableOutboxLeaseId::new([2; 32]).unwrap();
    let exact: crate::RequestOutboxClaimRequest = crate::RequestOutboxClaimRequest::new(
        domain(),
        crate::OutboxRequestId::new([9; 32]).unwrap(),
        10,
        next_lease,
        20,
    )
    .unwrap();
    assert!(matches!(
        source.claim_request_outbox(&context(), exact),
        crate::DurableOutboxClaimOutcome::Claimed(_)
    ));
    let acknowledged: crate::DurableOutboxAcknowledgement =
        crate::DurableOutboxAcknowledgement::new(
            domain(),
            crate::OutboxRequestId::new([9; 32]).unwrap(),
            0,
            next_lease,
        );
    let before_ack: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    assert!(matches!(
        source.acknowledge_outbox(&context(), acknowledged),
        crate::DurableOutboxAcknowledgementOutcome::Acknowledged
    ));
    let after_ack: PortableSnapshotToken = source
        .begin_portable_snapshot(&context(), domain())
        .unwrap();
    assert_eq!(
        after_ack.mutation_sequence(),
        before_ack.mutation_sequence() + 1
    );
    assert!(matches!(
        source.acknowledge_outbox(&context(), acknowledged),
        crate::DurableOutboxAcknowledgementOutcome::Acknowledged
    ));
    assert_eq!(
        after_ack,
        source
            .begin_portable_snapshot(&context(), domain())
            .unwrap()
    );
    assert!(matches!(
        source.check_portable_outbox_empty_at(&context(), domain(), &after_ack),
        Err(PortableSnapshotError::NonemptyOutbox)
    ));
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
fn internal_wrong_family_cursor_refuses_even_when_the_collection_is_empty() {
    let store: MemoryDurableStateStore = store();
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        let wrong: DurableRecordKey = if collection == DurableCollection::State {
            DurableRecordKey::Receipt(DurableRequestId::new([1; 32]).unwrap())
        } else {
            DurableRecordKey::State(b"foreign".to_vec())
        };
        // Deliberately construct an impossible internal value. The public
        // constructor still rejects it; no unchecked test-only API is exposed.
        let scan: DurableRecordScan = DurableRecordScan {
            collection,
            after: Some(wrong),
            limit: NonZeroUsize::new(1).unwrap(),
        };
        assert_eq!(
            store.scan_portable_keys(&context(), domain(), &scan),
            Err(DurableReadError::InvalidPersistedState)
        );
    }
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
fn blob_chunk_constructor_rejects_wrong_byte_count() {
    let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x90; 32]);
    let descriptor: PortableBlobDescriptor = PortableBlobDescriptor::new(digest, 8);
    let request: PortableBlobChunkRequest =
        PortableBlobChunkRequest::new(descriptor, 0, NonZeroUsize::new(4).unwrap()).unwrap();
    assert!(PortableBlobChunk::new(request.clone(), vec![0; 3]).is_err());
    assert!(PortableBlobChunk::new(request, vec![0; 5]).is_err());
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
fn chunk_request_range_and_is_last_match_resolved_length_at_every_boundary() {
    let store: MemoryDurableStateStore = store();
    install(&store, b"ten", Some(vec![7; 10]), 1);
    let descriptor: DurableRecordDescriptor = store
        .read_portable_descriptor(
            &context(),
            domain(),
            &DurableRecordKey::State(b"ten".to_vec()),
        )
        .unwrap()
        .unwrap();
    let first: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor.clone(), 0, NonZeroUsize::new(4).unwrap())
            .unwrap();
    assert_eq!(first.range(), 0..4);
    assert!(!chunk_of(&store, &first).is_last());
    let middle: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor.clone(), 6, NonZeroUsize::new(8).unwrap())
            .unwrap();
    assert_eq!(middle.range(), 6..10);
    assert!(chunk_of(&store, &middle).is_last());
    let last_byte: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor, 9, NonZeroUsize::new(1).unwrap()).unwrap();
    assert_eq!(last_byte.range(), 9..10);
    assert!(chunk_of(&store, &last_byte).is_last());
    install(&store, b"empty", Some(Vec::new()), 1);
    let empty_descriptor: DurableRecordDescriptor = store
        .read_portable_descriptor(
            &context(),
            domain(),
            &DurableRecordKey::State(b"empty".to_vec()),
        )
        .unwrap()
        .unwrap();
    let empty_request: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(empty_descriptor, 0, NonZeroUsize::new(1).unwrap()).unwrap();
    assert_eq!(empty_request.range(), 0..0);
    assert!(chunk_of(&store, &empty_request).is_last());
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

#[test]
fn blob_repository_memory_conformance() {
    let store: crate::MemoryBlobStore = crate::MemoryBlobStore::default();
    let fixture: conformance::BlobFixture = conformance::seed_blob(&store);
    conformance::verify_blob(&store, &fixture);
    conformance::assert_blob_chunk_corrupt(&store, &fixture);
    conformance::verify_blob(&store, &fixture);
}

#[test]
fn blob_chunk_request_bounds_offset_limit_and_is_last() {
    let store: crate::MemoryBlobStore = crate::MemoryBlobStore::default();
    let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x77; 32]);
    crate::BlobStore::put_blob(&store, digest, vec![7; 10]).unwrap();
    let descriptor: PortableBlobDescriptor = store
        .read_portable_blob_descriptor(&digest)
        .unwrap()
        .unwrap();
    assert_eq!(descriptor.length(), 10);

    let first: PortableBlobChunkRequest =
        PortableBlobChunkRequest::new(descriptor, 0, NonZeroUsize::new(4).unwrap()).unwrap();
    assert_eq!(first.range(), 0..4);
    let outcome: PortableBlobChunkOutcome = store.read_portable_blob_chunk(&first).unwrap();
    let first_chunk: Box<PortableBlobChunk> = require_chunk(outcome);
    assert!(!first_chunk.is_last());

    let last_byte: PortableBlobChunkRequest =
        PortableBlobChunkRequest::new(descriptor, 9, NonZeroUsize::new(1).unwrap()).unwrap();
    assert_eq!(last_byte.range(), 9..10);
    let last_outcome: PortableBlobChunkOutcome =
        store.read_portable_blob_chunk(&last_byte).unwrap();
    let last_chunk: Box<PortableBlobChunk> = require_chunk(last_outcome);
    assert!(last_chunk.is_last());

    assert!(PortableBlobChunkRequest::new(descriptor, 10, NonZeroUsize::new(1).unwrap()).is_err());
    assert!(
        PortableBlobChunkRequest::new(descriptor, usize::MAX, NonZeroUsize::new(1).unwrap())
            .is_err()
    );
    assert!(
        PortableBlobChunkRequest::new(
            descriptor,
            0,
            NonZeroUsize::new(MAX_PORTABLE_CHUNK_BYTES + 1).unwrap()
        )
        .is_err()
    );
}

#[test]
fn blob_missing_and_present_empty_are_distinct() {
    let store: crate::MemoryBlobStore = crate::MemoryBlobStore::default();
    let missing: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x88; 32]);
    assert_eq!(store.read_portable_blob_descriptor(&missing).unwrap(), None);

    let empty: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x89; 32]);
    crate::BlobStore::put_blob(&store, empty, Vec::new()).unwrap();
    let descriptor: PortableBlobDescriptor = store
        .read_portable_blob_descriptor(&empty)
        .unwrap()
        .unwrap();
    assert_eq!(descriptor.length(), 0);
    let request: PortableBlobChunkRequest =
        PortableBlobChunkRequest::new(descriptor, 0, NonZeroUsize::new(1).unwrap()).unwrap();
    assert_eq!(request.range(), 0..0);
    let outcome: PortableBlobChunkOutcome = store.read_portable_blob_chunk(&request).unwrap();
    let chunk: Box<PortableBlobChunk> = require_chunk(outcome);
    assert_eq!(chunk.bytes(), b"");
    assert!(chunk.is_last());
}
