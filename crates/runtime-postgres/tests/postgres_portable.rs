//! Live namespace-scoped portable reads. These are not authenticated cut,
//! restore or network activation evidence.

use postgres::{Client, NoTls};
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::portable::{
    DurableCollection, DurablePortableRepository, DurablePortableSnapshotRepository,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordScan,
    PortableSnapshotError, PortableSnapshotToken, conformance,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableCommitRejection, DurableDomainStateStore, DurableOperationContext, DurableReadError,
    StateMutation, StateMutationEntry, StateReadAssertion, StateRevision, StorageCorrelationId,
    StorageDeadline, WriterFenceGeneration,
};
use runtime_postgres::{
    POSTGRES_SCHEMA_GENERATION, PostgresDurableStore, PostgresNamespace, PostgresPoolConfig,
    PostgresTransactionPolicy, advance_writer_fence, apply_initial_schema, bootstrap_namespace,
    build_postgres_pool,
};
use std::{
    num::{NonZeroU32, NonZeroUsize},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod support;

type Manager = PostgresConnectionManager<NoTls>;

struct RestoreNamespaceIdentity<'a> {
    admin: &'a mut Client,
    namespace: &'a PostgresNamespace,
    identity: Vec<u8>,
}

impl Drop for RestoreNamespaceIdentity<'_> {
    fn drop(&mut self) {
        let _ = self.admin.execute(
            "UPDATE sunrise_edge.storage_metadata SET schema_identity = $4 WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3",
            &[&self.namespace.chain_id_bytes(), &&self.namespace.validator_id().as_bytes()[..], &&self.namespace.domain().as_bytes()[..], &self.identity],
        );
    }
}

struct RestoreSourceInstanceId<'a> {
    admin: &'a mut Client,
    namespace: &'a PostgresNamespace,
    source_instance_id: Vec<u8>,
}

impl Drop for RestoreSourceInstanceId<'_> {
    fn drop(&mut self) {
        let _ = self.admin.execute(
            "UPDATE sunrise_edge.storage_metadata SET source_instance_id = $4 WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3",
            &[&self.namespace.chain_id_bytes(), &&self.namespace.validator_id().as_bytes()[..], &&self.namespace.domain().as_bytes()[..], &self.source_instance_id],
        );
    }
}

fn pool(url: &str) -> Pool<Manager> {
    build_postgres_pool(
        url.parse().unwrap(),
        NoTls,
        PostgresPoolConfig::new(
            NonZeroU32::new(2).unwrap(),
            Duration::from_secs(5),
            Duration::from_secs(30),
            Duration::from_secs(300),
        )
        .unwrap(),
    )
    .unwrap()
}

fn store(pool: Pool<Manager>, namespace: PostgresNamespace) -> PostgresDurableStore<Manager> {
    PostgresDurableStore::new(
        pool,
        namespace,
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    )
}

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
        StorageCorrelationId::new([0xef; 16]).unwrap(),
    )
}

#[test]
fn postgres_portable_reads_survive_reconnect_and_reject_stale_authority() {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL portable reads: {} unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };
    let url: String = url.into_string().expect("test URL is UTF-8");
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: Client = Client::connect(&url, NoTls).unwrap();
    let database: String = admin
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, "sunrise_edge_test",
        "refusing to write a non-test database"
    );
    apply_initial_schema(&mut admin).unwrap();
    let nanos: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let chain: ChainId = ChainId::new(format!("portable-{}-{nanos}", std::process::id())).unwrap();
    let namespace: PostgresNamespace = PostgresNamespace::new(
        &chain,
        ValidatorId::new([0xa1; 32]),
        AtomicityDomainId::new([0xa2; 32]).unwrap(),
    )
    .unwrap();
    let first: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let second: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
    bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, first).unwrap();
    let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    let live: DurableOperationContext = context(first);
    conformance::seed(&current, &live, namespace.domain(), &chain);
    conformance::verify(&current, &live, namespace.domain(), &chain);
    conformance::assert_changed(&current, &live, namespace.domain());
    drop(current);

    // A fresh pool and store reconstruct from database rows, not process cache.
    let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    conformance::verify(&current, &context(first), namespace.domain(), &chain);
    let descriptor: DurableRecordDescriptor = current
        .read_portable_descriptor(
            &context(first),
            namespace.domain(),
            &DurableRecordKey::State(b"b-empty".to_vec()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        advance_writer_fence(&mut admin, &namespace, first, second)
            .unwrap()
            .writer_fence(),
        second
    );
    conformance::assert_refused(
        &current,
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
        &current,
        &expired,
        namespace.domain(),
        &descriptor,
        DurableReadError::DeadlineExceeded,
    );
    conformance::assert_refused(
        &current,
        &context(second),
        AtomicityDomainId::new([0xee; 32]).unwrap(),
        &descriptor,
        DurableReadError::InvalidRequest(runtime::RuntimeError::AtomicityDomainMismatch),
    );

    // Restore the exact namespace even on assertion unwind. No shared
    // migration identity or unrelated namespace is modified.
    let identity: Vec<u8> = admin.query_one("SELECT schema_identity FROM sunrise_edge.storage_metadata WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3", &[&namespace.chain_id_bytes(), &&namespace.validator_id().as_bytes()[..], &&namespace.domain().as_bytes()[..]]).unwrap().get(0);
    let unsupported_identity: Vec<u8> = vec![0; 32];
    admin.execute("UPDATE sunrise_edge.storage_metadata SET schema_identity = $4 WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3", &[&namespace.chain_id_bytes(), &&namespace.validator_id().as_bytes()[..], &&namespace.domain().as_bytes()[..], &unsupported_identity]).unwrap();
    {
        let _restore: RestoreNamespaceIdentity<'_> = RestoreNamespaceIdentity {
            admin: &mut admin,
            namespace: &namespace,
            identity,
        };
        conformance::assert_refused(
            &current,
            &context(second),
            namespace.domain(),
            &descriptor,
            DurableReadError::SchemaMismatch,
        );
    }

    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        None,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();
    for kind in [0i32, 2] {
        admin.execute("INSERT INTO sunrise_edge.state_records SELECT chain_id_bytes,validator_id,atomicity_domain_id,$4,state_key,type_id,encoding_version,revision,canonical_bytes,tombstone FROM sunrise_edge.state_records WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3 AND record_kind_id = 1 AND state_key = $5", &[&namespace.chain_id_bytes(), &&namespace.validator_id().as_bytes()[..], &&namespace.domain().as_bytes()[..], &kind, &b"b-empty".as_slice()]).unwrap();
        let result = current.scan_portable_keys(&context(second), namespace.domain(), &scan);
        admin.execute("DELETE FROM sunrise_edge.state_records WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3 AND record_kind_id = $4", &[&namespace.chain_id_bytes(), &&namespace.validator_id().as_bytes()[..], &&namespace.domain().as_bytes()[..], &kind]).unwrap();
        assert_eq!(result, Err(DurableReadError::InvalidPersistedState));
    }
    // The broad SQL schema can hold longer keys, but the portable runtime
    // contract rejects them before returning a truncated apparent key.
    let oversized: Vec<u8> = vec![0x61; runtime::MAX_STATE_KEY_BYTES + 1];
    admin.execute("INSERT INTO sunrise_edge.state_records SELECT chain_id_bytes,validator_id,atomicity_domain_id,record_kind_id,$4,type_id,encoding_version,revision,canonical_bytes,tombstone FROM sunrise_edge.state_records WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3 AND record_kind_id = 1 AND state_key = $5", &[&namespace.chain_id_bytes(), &&namespace.validator_id().as_bytes()[..], &&namespace.domain().as_bytes()[..], &oversized, &b"b-empty".as_slice()]).unwrap();
    let result = current.scan_portable_keys(&context(second), namespace.domain(), &scan);
    admin.execute("DELETE FROM sunrise_edge.state_records WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3 AND state_key = $4", &[&namespace.chain_id_bytes(), &&namespace.validator_id().as_bytes()[..], &&namespace.domain().as_bytes()[..], &oversized]).unwrap();
    assert_eq!(result, Err(DurableReadError::InvalidPersistedState));
    conformance::verify(&current, &context(second), namespace.domain(), &chain);
}

#[test]
fn postgres_portable_snapshot_token_survives_reconnect_and_rejects_foreign_identity() {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL snapshot token reconnect test: {} unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };
    let url: String = url.into_string().expect("test URL is UTF-8");
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: Client = Client::connect(&url, NoTls).unwrap();
    let database: String = admin
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, "sunrise_edge_test",
        "refusing to write a non-test database"
    );
    apply_initial_schema(&mut admin).unwrap();
    let nanos: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid: u32 = std::process::id();
    let chain_a: ChainId = ChainId::new(format!("portable-snap-a-{pid}-{nanos}")).unwrap();
    let namespace_a: PostgresNamespace = PostgresNamespace::new(
        &chain_a,
        ValidatorId::new([0xb1; 32]),
        AtomicityDomainId::new([0xb2; 32]).unwrap(),
    )
    .unwrap();
    let fence_one: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let fence_two: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
    bootstrap_namespace(
        &mut admin,
        &namespace_a,
        POSTGRES_SCHEMA_GENERATION,
        fence_one,
    )
    .unwrap();
    let live: DurableOperationContext = context(fence_one);

    let current: PostgresDurableStore<Manager> = store(pool(&url), namespace_a.clone());
    conformance::seed(&current, &live, namespace_a.domain(), &chain_a);
    let token: PortableSnapshotToken =
        conformance::verify_snapshot(&current, &live, namespace_a.domain());
    drop(current);

    // A freshly built pool/store still honors the original token: the token
    // is a database-observed fact, never process-local cache.
    let reconnected: PostgresDurableStore<Manager> = store(pool(&url), namespace_a.clone());
    assert!(
        reconnected
            .check_portable_outbox_empty_at(&live, namespace_a.domain(), &token)
            .is_ok()
    );
    let scan: DurableRecordScan = DurableRecordScan::new(
        DurableCollection::State,
        None,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();
    assert!(
        reconnected
            .scan_portable_keys_at(&live, namespace_a.domain(), &token, &scan)
            .is_ok()
    );

    // A new row invalidates even the reconnected store's use of the token.
    conformance::assert_snapshot_changed(&reconnected, &live, namespace_a.domain());

    // A different namespace produces a token that never compares equal, even
    // when every other observed field could coincide.
    let chain_b: ChainId = ChainId::new(format!("portable-snap-b-{pid}-{nanos}")).unwrap();
    let namespace_b: PostgresNamespace = PostgresNamespace::new(
        &chain_b,
        ValidatorId::new([0xb3; 32]),
        AtomicityDomainId::new([0xb4; 32]).unwrap(),
    )
    .unwrap();
    bootstrap_namespace(
        &mut admin,
        &namespace_b,
        POSTGRES_SCHEMA_GENERATION,
        fence_one,
    )
    .unwrap();
    let other: PostgresDurableStore<Manager> = store(pool(&url), namespace_b.clone());
    let token_foreign_namespace: PortableSnapshotToken = other
        .begin_portable_snapshot(&live, namespace_b.domain())
        .unwrap();
    assert_ne!(token, token_foreign_namespace);
    conformance::verify_snapshot_outbox_mutations(&other, &live, namespace_b.domain());

    let current_token: PortableSnapshotToken = reconnected
        .begin_portable_snapshot(&live, namespace_a.domain())
        .unwrap();
    let key: DurableRecordKey = DurableRecordKey::State(b"a-large".to_vec());
    let descriptor: DurableRecordDescriptor = reconnected
        .read_portable_descriptor_at(&live, namespace_a.domain(), &current_token, &key)
        .unwrap()
        .unwrap();
    let chunk: DurableRecordChunkRequest =
        DurableRecordChunkRequest::new(descriptor, 0, NonZeroUsize::new(8).unwrap()).unwrap();
    // Preserve every other field, so rejection actually exercises identity
    // comparison instead of a coincidental sequence mismatch.
    let foreign_namespace: PortableSnapshotToken = PortableSnapshotToken::new(
        token_foreign_namespace.namespace().to_vec(),
        current_token.domain(),
        current_token.writer_fence(),
        current_token.mutation_sequence(),
    )
    .unwrap();

    let token_foreign_domain: PortableSnapshotToken = PortableSnapshotToken::new(
        token.namespace().to_vec(),
        AtomicityDomainId::new([0xb5; 32]).unwrap(),
        token.writer_fence(),
        token.mutation_sequence(),
    )
    .unwrap();
    assert_ne!(token, token_foreign_domain);
    let foreign_domain: PortableSnapshotToken = PortableSnapshotToken::new(
        current_token.namespace().to_vec(),
        token_foreign_domain.domain(),
        current_token.writer_fence(),
        current_token.mutation_sequence(),
    )
    .unwrap();
    for bad in [&foreign_namespace, &foreign_domain] {
        assert_eq!(
            reconnected.scan_portable_keys_at(&live, namespace_a.domain(), bad, &scan),
            Err(PortableSnapshotError::Changed)
        );
        assert_eq!(
            reconnected.read_portable_descriptor_at(&live, namespace_a.domain(), bad, &key),
            Err(PortableSnapshotError::Changed)
        );
        assert_eq!(
            reconnected.read_portable_chunk_at(&live, namespace_a.domain(), bad, &chunk),
            Err(PortableSnapshotError::Changed)
        );
        assert_eq!(
            reconnected.check_portable_outbox_empty_at(&live, namespace_a.domain(), bad),
            Err(PortableSnapshotError::Changed)
        );
    }

    assert_eq!(
        advance_writer_fence(&mut admin, &namespace_a, fence_one, fence_two)
            .unwrap()
            .writer_fence(),
        fence_two
    );
    let token_foreign_fence: PortableSnapshotToken = PortableSnapshotToken::new(
        token.namespace().to_vec(),
        namespace_a.domain(),
        fence_two,
        token.mutation_sequence(),
    )
    .unwrap();
    assert_ne!(token, token_foreign_fence);
    assert_eq!(
        reconnected.scan_portable_keys_at(
            &context(fence_two),
            namespace_a.domain(),
            &current_token,
            &scan
        ),
        Err(PortableSnapshotError::Changed)
    );
    assert_eq!(
        reconnected.scan_portable_keys_at(&live, namespace_a.domain(), &current_token, &scan),
        Err(PortableSnapshotError::Read(
            DurableReadError::WriterFenced {
                active_generation: fence_two
            }
        ))
    );
}

#[test]
fn postgres_portable_commit_sequence_overflow_rejects_without_mutating_row_or_counter() {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL commit-sequence overflow test: {} unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };
    let url: String = url.into_string().expect("test URL is UTF-8");
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: Client = Client::connect(&url, NoTls).unwrap();
    let database: String = admin
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, "sunrise_edge_test",
        "refusing to write a non-test database"
    );
    apply_initial_schema(&mut admin).unwrap();
    let nanos: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let chain: ChainId =
        ChainId::new(format!("portable-overflow-{}-{nanos}", std::process::id())).unwrap();
    let namespace: PostgresNamespace = PostgresNamespace::new(
        &chain,
        ValidatorId::new([0xc1; 32]),
        AtomicityDomainId::new([0xc2; 32]).unwrap(),
    )
    .unwrap();
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, fence).unwrap();
    admin
        .execute(
            "UPDATE sunrise_edge.storage_metadata
             SET commit_sequence = 18446744073709551615
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
            ],
        )
        .unwrap();

    let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    let live: DurableOperationContext = context(fence);
    let overflow_key: Vec<u8> = b"overflow-key".to_vec();
    let overflow_transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        namespace.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(overflow_key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(overflow_key.clone(), StateMutation::Put(vec![0x77])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        current.commit_durable(&live, overflow_transaction),
        DurableCommitOutcome::Rejected(DurableCommitRejection::CommitSequenceOverflow)
    );
    assert_eq!(
        current
            .read_portable_descriptor(
                &live,
                namespace.domain(),
                &DurableRecordKey::State(overflow_key),
            )
            .unwrap(),
        None
    );
    let commit_sequence_after: String = admin
        .query_one(
            "SELECT commit_sequence::TEXT FROM sunrise_edge.storage_metadata
             WHERE chain_id_bytes = $1 AND validator_id = $2
               AND atomicity_domain_id = $3",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(commit_sequence_after, "18446744073709551615");
}

#[test]
fn postgres_portable_snapshot_rejects_token_after_source_instance_id_replaced_with_identical_sequence_and_fence()
 {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        eprintln!(
            "skipping live PostgreSQL source-instance-identity test: {} unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };
    let url: String = url.into_string().expect("test URL is UTF-8");
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: Client = Client::connect(&url, NoTls).unwrap();
    let database: String = admin
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        database, "sunrise_edge_test",
        "refusing to write a non-test database"
    );
    apply_initial_schema(&mut admin).unwrap();
    let nanos: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let chain: ChainId =
        ChainId::new(format!("portable-source-{}-{nanos}", std::process::id())).unwrap();
    let namespace: PostgresNamespace = PostgresNamespace::new(
        &chain,
        ValidatorId::new([0xd1; 32]),
        AtomicityDomainId::new([0xd2; 32]).unwrap(),
    )
    .unwrap();
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, fence).unwrap();
    let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    let live: DurableOperationContext = context(fence);
    conformance::seed(&current, &live, namespace.domain(), &chain);
    let token: PortableSnapshotToken =
        conformance::verify_snapshot(&current, &live, namespace.domain());

    let metadata_row = |admin: &mut Client| -> (Vec<u8>, String) {
        let row = admin
            .query_one(
                "SELECT source_instance_id, commit_sequence::TEXT FROM sunrise_edge.storage_metadata
                 WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3",
                &[
                    &namespace.chain_id_bytes(),
                    &&namespace.validator_id().as_bytes()[..],
                    &&namespace.domain().as_bytes()[..],
                ],
            )
            .unwrap();
        (row.get(0), row.get(1))
    };
    let (original_source_instance_id, commit_sequence_before): (Vec<u8>, String) =
        metadata_row(&mut admin);

    // A fixed, deliberately different 16-byte value: the actual bootstrap
    // value is a `gen_random_uuid()` byte string, so an equal fixed pattern
    // is practically impossible.
    let replaced_source_instance_id: Vec<u8> = vec![0x77; 16];
    assert_ne!(original_source_instance_id, replaced_source_instance_id);
    admin
        .execute(
            "UPDATE sunrise_edge.storage_metadata SET source_instance_id = $4
             WHERE chain_id_bytes = $1 AND validator_id = $2 AND atomicity_domain_id = $3",
            &[
                &namespace.chain_id_bytes(),
                &&namespace.validator_id().as_bytes()[..],
                &&namespace.domain().as_bytes()[..],
                &replaced_source_instance_id,
            ],
        )
        .unwrap();
    {
        let _restore: RestoreSourceInstanceId<'_> = RestoreSourceInstanceId {
            admin: &mut admin,
            namespace: &namespace,
            source_instance_id: original_source_instance_id,
        };

        // The writer fence and commit sequence are untouched: only the
        // random source identity changed, but every guarded read still
        // refuses the previously issued token, read inside the very same
        // transaction as the replaced row.
        let scan: DurableRecordScan = DurableRecordScan::new(
            DurableCollection::State,
            None,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap();
        assert_eq!(
            current.scan_portable_keys_at(&live, namespace.domain(), &token, &scan),
            Err(PortableSnapshotError::Changed)
        );
        let key: DurableRecordKey = DurableRecordKey::State(b"a-large".to_vec());
        assert_eq!(
            current.read_portable_descriptor_at(&live, namespace.domain(), &token, &key),
            Err(PortableSnapshotError::Changed)
        );
        let descriptor: DurableRecordDescriptor = current
            .read_portable_descriptor(&live, namespace.domain(), &key)
            .unwrap()
            .unwrap();
        let chunk: DurableRecordChunkRequest =
            DurableRecordChunkRequest::new(descriptor, 0, NonZeroUsize::new(8).unwrap()).unwrap();
        assert_eq!(
            current.read_portable_chunk_at(&live, namespace.domain(), &token, &chunk),
            Err(PortableSnapshotError::Changed)
        );
        assert_eq!(
            current.check_portable_outbox_empty_at(&live, namespace.domain(), &token),
            Err(PortableSnapshotError::Changed)
        );

        // Every business row and the fence/sequence pair are byte-for-byte
        // unchanged: only the physical source identity moved.
        conformance::verify(&current, &live, namespace.domain(), &chain);
        let (_, commit_sequence_after): (Vec<u8>, String) = metadata_row(_restore.admin);
        assert_eq!(commit_sequence_after, commit_sequence_before);
        let replaced_token: PortableSnapshotToken = current
            .begin_portable_snapshot(&live, namespace.domain())
            .unwrap();
        assert_eq!(replaced_token.writer_fence(), token.writer_fence());
        assert_eq!(
            replaced_token.mutation_sequence(),
            token.mutation_sequence()
        );
        assert_ne!(replaced_token, token);
    }

    // Restoring the original source instance id (`RestoreSourceInstanceId`'s
    // `Drop`) makes even a freshly reconnected pool/store honor the
    // original token again: it is a database-observed fact, never a
    // process-local cache.
    let reconnected: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    assert!(
        reconnected
            .check_portable_outbox_empty_at(&live, namespace.domain(), &token)
            .is_ok()
    );
}
