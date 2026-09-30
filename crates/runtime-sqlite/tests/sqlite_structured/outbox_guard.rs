//! File-backed outbox-exclusion reads and restart persistence. Storage
//! conformance only; see `runtime::outbox_guard` module docs for why a
//! clear probe is never itself a handoff/freeze fence.

use super::*;
use runtime::outbox_guard::{
    StructuredOutboxExclusionGuard, StructuredOutboxInventory, conformance,
};

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
        StorageCorrelationId::new([0x9a; 16]).unwrap(),
    )
}

/// Positive/negative outbox-exclusion evidence plus the important restart
/// case: an observed pending obligation is not an artifact of one
/// in-process store handle. No original store instance survives the
/// close/reopen below.
#[test]
fn sqlite_outbox_exclusion_conformance_and_close_reopen() {
    let database: TestDatabase = TestDatabase::new();
    let namespace: SqliteNamespace = namespace("outbox-guard-sqlite", 0xe0, 0xe1);
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();
    let live: DurableOperationContext = context(fence);
    conformance::assert_clear_when_unseeded(&store, &live, namespace.domain());
    conformance::assert_clear_after_empty_batch(&store, &live, namespace.domain(), 0x10);
    conformance::assert_blocked_by_pending_message(&store, &live, namespace.domain(), 0x20);
    drop(store);

    // No original store handle survives this reopen.
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&database.path, namespace.clone(), fence).unwrap();
    let inventory: StructuredOutboxInventory = store
        .inspect_outbox_exclusion(&context(fence), namespace.domain())
        .unwrap();
    assert!(inventory.blocks_exclusion());
    assert!(inventory.pending_delivery_present());
}
