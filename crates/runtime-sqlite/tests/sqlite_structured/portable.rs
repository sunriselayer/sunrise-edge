//! File-backed portable reads, restart and authority refusals. No cut or
//! activation proof is inferred from this storage-only test.

use super::*;
use runtime::portable::{
    DurableCollection, DurablePortableRepository, DurablePortableSnapshotRepository,
    DurableRecordChunkOutcome, DurableRecordChunkRequest, DurableRecordDescriptor,
    DurableRecordKey, DurableRecordPage, DurableRecordScan, PortableSnapshotError,
    PortableSnapshotToken, conformance,
};
use std::num::NonZeroUsize;

fn context(fence: WriterFenceGeneration) -> DurableOperationContext {
    let now: u64 = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    DurableOperationContext::new(
        fence,
        StorageDeadline::new(now.checked_add(120_000).unwrap()).unwrap(),
        StorageCorrelationId::new([0xab; 16]).unwrap(),
    )
}

#[test]
fn sqlite_portable_reads_survive_close_reopen_and_fence_old_writer() {
    let database: TestDatabase = TestDatabase::new();
    let namespace: SqliteNamespace = namespace("portable-sqlite", 0xc1, 0xc2);
    let first: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let second: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&database.path, namespace.clone(), first).unwrap();
    let live: DurableOperationContext = context(first);
    conformance::seed(&store, &live, namespace.domain(), namespace.chain_id());
    conformance::verify(&store, &live, namespace.domain(), namespace.chain_id());
    conformance::assert_changed(&store, &live, namespace.domain());
    drop(store);

    // No original store handle survives this reopen.
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&database.path, namespace.clone(), first).unwrap();
    conformance::verify(
        &store,
        &context(first),
        namespace.domain(),
        namespace.chain_id(),
    );
    let descriptor: DurableRecordDescriptor = store
        .read_portable_descriptor(
            &context(first),
            namespace.domain(),
            &DurableRecordKey::State(b"b-empty".to_vec()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(store.advance_writer_fence(first, second).unwrap(), second);
    conformance::assert_refused(
        &store,
        &context(first),
        namespace.domain(),
        &descriptor,
        DurableReadError::WriterFenced {
            active_generation: second,
        },
    );
    let expired: DurableOperationContext = DurableOperationContext::new(
        second,
        StorageDeadline::new(1).unwrap(),
        StorageCorrelationId::new([0xcd; 16]).unwrap(),
    );
    conformance::assert_refused(
        &store,
        &expired,
        namespace.domain(),
        &descriptor,
        DurableReadError::DeadlineExceeded,
    );
    conformance::assert_refused(
        &store,
        &context(second),
        AtomicityDomainId::new([0xee; 32]).unwrap(),
        &descriptor,
        DurableReadError::InvalidRequest(runtime::RuntimeError::AtomicityDomainMismatch),
    );

    let admin: Connection = Connection::open(&database.path).unwrap();
    admin
        .execute(
            "UPDATE durable_metadata SET schema_identity = ?1",
            params![b"unsupported".as_slice()],
        )
        .unwrap();
    conformance::assert_refused(
        &store,
        &context(second),
        namespace.domain(),
        &descriptor,
        DurableReadError::SchemaMismatch,
    );
    admin
        .execute(
            "UPDATE durable_metadata SET schema_identity = ?1",
            params![SQLITE_STRUCTURED_SCHEMA_IDENTITY],
        )
        .unwrap();
    drop(admin);
    conformance::verify(
        &store,
        &context(second),
        namespace.domain(),
        namespace.chain_id(),
    );
    drop(store);
    let reopened: SqliteDurableStore =
        SqliteDurableStore::open(&database.path, namespace.clone(), second).unwrap();
    conformance::verify(
        &reopened,
        &context(second),
        namespace.domain(),
        namespace.chain_id(),
    );
}

#[test]
fn sqlite_portable_scan_rejects_oversized_and_wrong_type_stored_keys() {
    let database: TestDatabase = TestDatabase::new();
    let namespace: SqliteNamespace = namespace("portable-corrupt-key", 0xd1, 0xd2);
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();
    let admin: Connection = Connection::open(&database.path).unwrap();
    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        None,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    for key in [
        rusqlite::types::Value::Blob(vec![0x61; 2 * 1024 * 1024]),
        rusqlite::types::Value::Text("text-key".to_owned()),
    ] {
        admin
            .execute(
                "INSERT INTO durable_state(key,revision,value) VALUES (?1,?2,NULL)",
                params![key, 1u64.to_be_bytes().as_slice()],
            )
            .unwrap();
        assert_eq!(
            store.scan_portable_keys(&context(fence), namespace.domain(), &scan),
            Err(DurableReadError::InvalidPersistedState)
        );
        admin.execute("DELETE FROM durable_state", []).unwrap();
    }
}

/// Commits one outbox-bearing invocation with one message so a test can
/// claim and acknowledge it and observe the checked outbox-empty guard.
fn commit_outbox_batch(
    store: &SqliteDurableStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    request_id: OutboxRequestId,
) {
    let event_digest: protocol_types::Digest32 =
        protocol_types::Digest32::new(protocol_types::HashAlgorithmId::Sha2_256, [0x71; 32]);
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(request_id, event_digest, vec![0x72]).unwrap();
    let message: DurableOutboxMessage = DurableOutboxMessage::new(
        protocol_types::Digest32::new(protocol_types::HashAlgorithmId::Sha3_256, [0x73; 32]),
        vec![0x74],
    )
    .unwrap();
    let outbox: DurableOutboxBatch =
        DurableOutboxBatch::new(request_id, event_digest, vec![message]).unwrap();
    let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        None,
        DurableObjectChanges::empty(),
        receipt,
        Some(outbox),
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(context, invocation),
        DurableCommitOutcome::Committed
    );
}

/// A guarded token observes the exact same unchanged source across a real
/// close/reopen, invalidates on any covered write (a same-length rewrite),
/// and reports a present outbox even once fully acknowledged; only a truly
/// empty outbox is allowed.
#[test]
fn sqlite_portable_snapshot_token_enforces_reads_across_reopen_and_change() {
    let db = TestDatabase::new();
    let ns = namespace("portable-snapshot-begin", 0xf1, 0xf2);
    let fence = WriterFenceGeneration::new(1).unwrap();
    let store = SqliteDurableStore::open(&db.path, ns.clone(), fence).unwrap();
    let live = context(fence);
    conformance::seed(&store, &live, ns.domain(), ns.chain_id());
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&live, ns.domain()).unwrap();
    store
        .check_portable_outbox_empty_at(&live, ns.domain(), &token)
        .unwrap();
    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        None,
        NonZeroUsize::new(8).unwrap(),
    )
    .unwrap();
    let page: DurableRecordPage = store
        .scan_portable_keys_at(&live, ns.domain(), &token, &scan)
        .unwrap();
    assert_eq!(
        store
            .scan_portable_keys_at(&live, ns.domain(), &token, &scan)
            .unwrap(),
        page
    );
    let key: DurableRecordKey = DurableRecordKey::State(b"a-large".to_vec());
    let descriptor: DurableRecordDescriptor = store
        .read_portable_descriptor_at(&live, ns.domain(), &token, &key)
        .unwrap()
        .unwrap();
    let chunk_request: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor.clone(), 0, NonZeroUsize::new(4).unwrap())
            .unwrap();
    assert!(matches!(
        store
            .read_portable_chunk_at(&live, ns.domain(), &token, &chunk_request)
            .unwrap(),
        DurableRecordChunkOutcome::Chunk(_)
    ));
    drop(store);
    let store: SqliteDurableStore = SqliteDurableStore::open(&db.path, ns.clone(), fence).unwrap();
    assert_eq!(
        store
            .scan_portable_keys_at(&live, ns.domain(), &token, &scan)
            .unwrap(),
        page
    );
    conformance::assert_changed(&store, &live, ns.domain());
    assert!(matches!(
        store.scan_portable_keys_at(&live, ns.domain(), &token, &scan),
        Err(PortableSnapshotError::Changed)
    ));
    assert!(matches!(
        store.read_portable_descriptor_at(&live, ns.domain(), &token, &key),
        Err(PortableSnapshotError::Changed)
    ));
    assert!(matches!(
        store.read_portable_chunk_at(&live, ns.domain(), &token, &chunk_request),
        Err(PortableSnapshotError::Changed)
    ));
    assert!(matches!(
        store.check_portable_outbox_empty_at(&live, ns.domain(), &token),
        Err(PortableSnapshotError::Changed)
    ));
    let request_id: OutboxRequestId = OutboxRequestId::new([0x75; 32]).unwrap();
    commit_outbox_batch(&store, &live, ns.domain(), request_id);
    let lease_id: DurableOutboxLeaseId = DurableOutboxLeaseId::new([0x76; 32]).unwrap();
    let claim_outcome = store.claim_due_outbox(
        &live,
        DueOutboxClaimRequest::new(ns.domain(), 0, lease_id, 60_000).unwrap(),
    );
    assert!(matches!(
        claim_outcome,
        DurableOutboxClaimOutcome::Claimed(_)
    ));
    let ack_outcome = store.acknowledge_outbox(
        &live,
        DurableOutboxAcknowledgement::new(ns.domain(), request_id, 0, lease_id),
    );
    assert_eq!(
        ack_outcome,
        runtime::DurableOutboxAcknowledgementOutcome::Acknowledged
    );
    let acked_token: PortableSnapshotToken =
        store.begin_portable_snapshot(&live, ns.domain()).unwrap();
    assert!(matches!(
        store.check_portable_outbox_empty_at(&live, ns.domain(), &acked_token),
        Err(PortableSnapshotError::NonemptyOutbox)
    ));
}

#[test]
fn sqlite_portable_snapshot_token_refuses_wrong_domain_writer_and_schema() {
    let database: TestDatabase = TestDatabase::new();
    let ns: SqliteNamespace = namespace("portable-snapshot-authority", 0xf3, 0xf4);
    let first: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let second: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&database.path, ns.clone(), first).unwrap();
    let live: DurableOperationContext = context(first);
    conformance::seed(&store, &live, ns.domain(), ns.chain_id());
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&live, ns.domain()).unwrap();
    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        None,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    let wrong_domain: AtomicityDomainId = AtomicityDomainId::new([0xf5; 32]).unwrap();
    assert!(matches!(
        store.scan_portable_keys_at(&live, wrong_domain, &token, &scan),
        Err(PortableSnapshotError::Read(
            DurableReadError::InvalidRequest(_)
        ))
    ));
    assert_eq!(store.advance_writer_fence(first, second).unwrap(), second);
    assert!(matches!(
        store.scan_portable_keys_at(&live, ns.domain(), &token, &scan),
        Err(PortableSnapshotError::Read(
            DurableReadError::WriterFenced { .. }
        ))
    ));
    let live: DurableOperationContext = context(second);
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&live, ns.domain()).unwrap();
    let admin: Connection = Connection::open(&database.path).unwrap();
    admin
        .execute(
            "UPDATE durable_metadata SET schema_identity = ?1",
            params![b"unsupported".as_slice()],
        )
        .unwrap();
    assert!(matches!(
        store.scan_portable_keys_at(&live, ns.domain(), &token, &scan),
        Err(PortableSnapshotError::Read(
            DurableReadError::SchemaMismatch
        ))
    ));
    admin
        .execute(
            "UPDATE durable_metadata SET schema_identity = ?1",
            params![SQLITE_STRUCTURED_SCHEMA_IDENTITY],
        )
        .unwrap();
}

#[test]
fn sqlite_portable_snapshot_mutation_sequence_overflow_rolls_back_the_commit() {
    let database: TestDatabase = TestDatabase::new();
    let ns: SqliteNamespace = namespace("portable-snapshot-overflow", 0xf6, 0xf7);
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&database.path, ns.clone(), fence).unwrap();
    let live: DurableOperationContext = context(fence);
    let admin: Connection = Connection::open(&database.path).unwrap();
    admin
        .execute(
            "UPDATE durable_metadata SET mutation_sequence = ?1",
            params![u64::MAX.to_be_bytes().as_slice()],
        )
        .unwrap();
    let before: PortableSnapshotToken = store.begin_portable_snapshot(&live, ns.domain()).unwrap();
    let key: Vec<u8> = b"overflow-new".to_vec();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        ns.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.clone(), StateMutation::Put(vec![0x01])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        store.commit_durable(&live, transaction),
        DurableCommitOutcome::Rejected(DurableCommitRejection::CommitSequenceOverflow)
    ));
    assert_eq!(
        before,
        store.begin_portable_snapshot(&live, ns.domain()).unwrap()
    );
    assert!(
        store
            .get_versioned_durable(&live, ns.domain(), &key)
            .unwrap()
            .value()
            .is_none()
    );
}

#[test]
fn sqlite_portable_snapshot_outbox_mutations_and_pending_empty_delivery() {
    let db: TestDatabase = TestDatabase::new();
    let ns: SqliteNamespace = namespace("snapshot-outbox", 0xe1, 0xe2);
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let store: SqliteDurableStore = SqliteDurableStore::open(&db.path, ns.clone(), fence).unwrap();
    let live: DurableOperationContext = context(fence);
    conformance::verify_snapshot_outbox_mutations(&store, &live, ns.domain());
    let clean_db: TestDatabase = TestDatabase::new();
    let clean: SqliteDurableStore =
        SqliteDurableStore::open(&clean_db.path, ns.clone(), fence).unwrap();
    runtime::outbox_guard::conformance::assert_clear_after_empty_batch(
        &clean,
        &live,
        ns.domain(),
        0xd1,
    );
    // Unsupported/corrupt pending-empty delivery may have no message row.
    // It must not slip through the ordinary empty-batch normalization.
    let admin: Connection = Connection::open(&clean_db.path).unwrap();
    admin
        .execute("UPDATE durable_outbox_delivery SET completed = 0", [])
        .unwrap();
    let token: PortableSnapshotToken = clean.begin_portable_snapshot(&live, ns.domain()).unwrap();
    assert_eq!(
        clean.check_portable_outbox_empty_at(&live, ns.domain(), &token),
        Err(PortableSnapshotError::NonemptyOutbox)
    );
}

#[test]
fn sqlite_portable_snapshot_refuses_old_metadata_shape_without_rewriting_it() {
    let db: TestDatabase = TestDatabase::new();
    let ns: SqliteNamespace = namespace("snapshot-old-schema", 0xe3, 0xe4);
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    drop(SqliteDurableStore::open(&db.path, ns.clone(), fence).unwrap());
    let admin: Connection = Connection::open(&db.path).unwrap();
    // Reproduce the prior metadata shape, not just an unsupported identity
    // in a current table. No data migration or auto-bootstrap is authorized.
    admin
        .execute(
            "ALTER TABLE durable_metadata DROP COLUMN mutation_sequence",
            [],
        )
        .unwrap();
    let old: &[u8] = b"sunrise-edge/sqlite/structured/schema/v1";
    admin
        .execute(
            "UPDATE durable_metadata SET schema_identity = ?1",
            params![old],
        )
        .unwrap();
    assert!(SqliteDurableStore::open_existing(&db.path, ns.clone()).is_err());
    assert!(SqliteDurableStore::open(&db.path, ns, fence).is_err());
    let identity: Vec<u8> = admin
        .query_row("SELECT schema_identity FROM durable_metadata", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(identity, old);
    let column_count: i64 = admin.query_row("SELECT count(*) FROM pragma_table_info('durable_metadata') WHERE name = 'mutation_sequence'", [], |row| row.get(0)).unwrap();
    assert_eq!(column_count, 0);
}

/// Two independently bootstrapped SQLite files that happen to share every
/// logical identity field (chain, validator, domain) and, after a fresh
/// bootstrap, the very same writer fence and mutation sequence (both start
/// at their initial values) must still never validate the same token: only
/// the random per-file `source_instance_id` distinguishes them.
#[test]
fn sqlite_portable_snapshot_rejects_token_from_a_different_fresh_file_with_identical_namespace_and_counter()
 {
    let first_db: TestDatabase = TestDatabase::new();
    let second_db: TestDatabase = TestDatabase::new();
    let ns: SqliteNamespace = namespace("portable-fresh-file-identity", 0x51, 0x52);
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let first: SqliteDurableStore =
        SqliteDurableStore::open(&first_db.path, ns.clone(), fence).unwrap();
    let second: SqliteDurableStore =
        SqliteDurableStore::open(&second_db.path, ns.clone(), fence).unwrap();
    let live: DurableOperationContext = context(fence);
    conformance::seed(&first, &live, ns.domain(), ns.chain_id());
    conformance::seed(&second, &live, ns.domain(), ns.chain_id());
    // Equal writes leave equal counters, but not equal physical sources.
    let token_from_first: PortableSnapshotToken =
        first.begin_portable_snapshot(&live, ns.domain()).unwrap();
    assert_eq!(
        token_from_first.mutation_sequence(),
        second
            .begin_portable_snapshot(&live, ns.domain())
            .unwrap()
            .mutation_sequence()
    );
    assert_ne!(
        token_from_first,
        second.begin_portable_snapshot(&live, ns.domain()).unwrap()
    );
    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        None,
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        second.scan_portable_keys_at(&live, ns.domain(), &token_from_first, &scan),
        Err(PortableSnapshotError::Changed)
    ));
    assert!(matches!(
        second.check_portable_outbox_empty_at(&live, ns.domain(), &token_from_first),
        Err(PortableSnapshotError::Changed)
    ));
    let key: DurableRecordKey = DurableRecordKey::State(b"a-large".to_vec());
    assert!(matches!(
        second.read_portable_descriptor_at(&live, ns.domain(), &token_from_first, &key),
        Err(PortableSnapshotError::Changed)
    ));
    let descriptor: DurableRecordDescriptor = second
        .read_portable_descriptor(&live, ns.domain(), &key)
        .unwrap()
        .unwrap();
    let request: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor, 0, NonZeroUsize::new(8).unwrap()).unwrap();
    assert!(matches!(
        second.read_portable_chunk_at(&live, ns.domain(), &token_from_first, &request),
        Err(PortableSnapshotError::Changed)
    ));
    // The same token still validates unchanged against its own source.
    first
        .check_portable_outbox_empty_at(&live, ns.domain(), &token_from_first)
        .unwrap();
    drop(first);
    let reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(&first_db.path, ns.clone()).unwrap();
    assert_eq!(
        token_from_first,
        reopened
            .begin_portable_snapshot(&live, ns.domain())
            .unwrap()
    );
    reopened
        .check_portable_outbox_empty_at(&live, ns.domain(), &token_from_first)
        .unwrap();
}
