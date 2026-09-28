//! Live namespace-scoped outbox-exclusion reads. Storage conformance only;
//! see `runtime::outbox_guard` module docs for the probe-vs-fence limit.

use postgres::NoTls;
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::outbox_guard::{
    StructuredOutboxExclusionGuard, StructuredOutboxInventory, conformance,
};
use runtime::{
    DurableOperationContext, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
};
use runtime_postgres::{
    POSTGRES_SCHEMA_GENERATION, PostgresDurableStore, PostgresNamespace, PostgresPoolConfig,
    PostgresTransactionPolicy, apply_initial_schema, bootstrap_namespace, build_postgres_pool,
};
use std::{
    num::NonZeroU32,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod support;

type Manager = PostgresConnectionManager<NoTls>;

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
        StorageCorrelationId::new([0x5e; 16]).unwrap(),
    )
}

#[test]
fn postgres_outbox_exclusion_normalizes_empty_and_pending_and_survives_reconnect() {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        return;
    };
    let url: String = url.into_string().expect("test URL is UTF-8");
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: postgres::Client = postgres::Client::connect(&url, NoTls).unwrap();
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
        ChainId::new(format!("outbox-guard-{}-{nanos}", std::process::id())).unwrap();
    let namespace: PostgresNamespace = PostgresNamespace::new(
        &chain,
        ValidatorId::new([0xb1; 32]),
        AtomicityDomainId::new([0xb2; 32]).unwrap(),
    )
    .unwrap();
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, fence).unwrap();
    let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    let live: DurableOperationContext = context(fence);
    conformance::assert_clear_when_unseeded(&current, &live, namespace.domain());
    conformance::assert_clear_after_empty_batch(&current, &live, namespace.domain(), 0x10);
    conformance::assert_blocked_by_pending_message(&current, &live, namespace.domain(), 0x20);
    drop(current);

    // A fresh pool and store reconstruct from database rows, not process cache.
    let reconnected: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    let inventory: StructuredOutboxInventory = reconnected
        .inspect_outbox_exclusion(&context(fence), namespace.domain())
        .unwrap();
    assert!(inventory.blocks_exclusion());
    assert!(inventory.pending_delivery_present());
}

#[test]
fn postgres_outbox_exclusion_blocks_after_full_acknowledgement() {
    let Some(url) = std::env::var_os(support::LIVE_POSTGRES_URL_ENV) else {
        return;
    };
    let url: String = url.into_string().expect("test URL is UTF-8");
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let mut admin: postgres::Client = postgres::Client::connect(&url, NoTls).unwrap();
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
        ChainId::new(format!("outbox-guard-ack-{}-{nanos}", std::process::id())).unwrap();
    let namespace: PostgresNamespace = PostgresNamespace::new(
        &chain,
        ValidatorId::new([0xb3; 32]),
        AtomicityDomainId::new([0xb4; 32]).unwrap(),
    )
    .unwrap();
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    bootstrap_namespace(&mut admin, &namespace, POSTGRES_SCHEMA_GENERATION, fence).unwrap();
    let current: PostgresDurableStore<Manager> = store(pool(&url), namespace.clone());
    let live: DurableOperationContext = context(fence);
    conformance::assert_blocked_after_full_acknowledgement(
        &current,
        &live,
        namespace.domain(),
        0x30,
    );
}
