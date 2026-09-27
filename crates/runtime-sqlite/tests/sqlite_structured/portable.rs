//! File-backed portable reads, restart and authority refusals. No cut or
//! activation proof is inferred from this storage-only test.

use super::*;
use runtime::portable::{
    DurableCollection, DurablePortableRepository, DurableRecordDescriptor, DurableRecordKey,
    DurableRecordScan, conformance,
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
