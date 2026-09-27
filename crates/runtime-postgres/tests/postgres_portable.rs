//! Live namespace-scoped portable reads. These are not authenticated cut,
//! restore or network activation evidence.

use postgres::{Client, NoTls};
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::portable::{
    DurableCollection, DurablePortableRepository, DurableRecordDescriptor, DurableRecordKey,
    DurableRecordScan, conformance,
};
use runtime::{
    DurableOperationContext, DurableReadError, StorageCorrelationId, StorageDeadline,
    WriterFenceGeneration,
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
