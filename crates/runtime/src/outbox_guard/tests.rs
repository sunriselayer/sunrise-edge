use super::*;
use crate::{
    MemoryStateStore, StateStore, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
};
use protocol_types::{ChainId, ProtocolVersion};

fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([9; 32]).unwrap()
}

fn context() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(100).unwrap(),
        StorageCorrelationId::new([9; 16]).unwrap(),
    )
}

fn store() -> MemoryDurableStateStore {
    MemoryDurableStateStore::new_bound(domain(), WriterFenceGeneration::new(1).unwrap())
}

#[test]
fn structured_outbox_exclusion_shared_memory_conformance() {
    conformance::assert_clear_when_unseeded(&store(), &context(), domain());
    conformance::assert_clear_after_empty_batch(&store(), &context(), domain(), 0x10);
    conformance::assert_blocked_by_pending_message(&store(), &context(), domain(), 0x20);
    conformance::assert_blocked_after_full_acknowledgement(&store(), &context(), domain(), 0x30);
}

fn layout() -> PersistenceLayout {
    let chain_id: ChainId = ChainId::new("outboxguard").unwrap();
    PersistenceLayout::new(chain_id, ProtocolVersion::new(1))
}

#[test]
fn legacy_prefix_clear_when_unseeded() {
    let store: MemoryStateStore = MemoryStateStore::default();
    let report: LegacyOutboxInventory = inspect_legacy_outbox_prefix(&store, &layout()).unwrap();
    assert!(!report.any_key_present());
    assert!(!report.blocks_exclusion());
}

#[test]
fn legacy_prefix_blocks_when_any_key_present() {
    let store: MemoryStateStore = MemoryStateStore::default();
    let layout: PersistenceLayout = layout();
    store
        .put(layout.outbox_batch_key([0x40; 32]), vec![0x01])
        .unwrap();
    let report: LegacyOutboxInventory = inspect_legacy_outbox_prefix(&store, &layout).unwrap();
    assert!(report.any_key_present());
    assert!(report.blocks_exclusion());
}
