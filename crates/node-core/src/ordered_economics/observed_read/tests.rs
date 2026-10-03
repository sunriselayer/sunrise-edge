use super::*;
use crate::{NodeCoreError, ordered_economics::OrderedRefusal};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, MAX_ATOMIC_STATE_READS, MemoryDurableStateStore, StateMutation,
    StateMutationEntry, StateRevision, StorageCorrelationId, StorageDeadline,
    StructuredDurableDomainStateStore, WriterFenceGeneration,
};
use std::cell::Cell;

fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([1; 32]).unwrap()
}

fn context() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(1_000).unwrap(),
        StorageCorrelationId::new([2; 16]).unwrap(),
    )
}

// This fixture exposes only the actual store's read ports to the scope. The
// writer below is used separately and explicitly to model interference.
struct ReadOnly<'a> {
    inner: &'a MemoryDurableStateStore,
    state_reads: Cell<usize>,
}

impl VersionedStateReader for ReadOnly<'_> {
    fn read_versioned_state(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.state_reads.set(self.state_reads.get() + 1);
        self.inner.read_versioned_state(context, domain, key)
    }
}

impl StructuredStateReader for ReadOnly<'_> {
    fn read_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, DurableReadError> {
        self.inner.read_outgoing_barrier(context, domain)
    }

    fn read_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.inner.read_namespace_lifecycle(context, domain)
    }

    fn read_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: objects::ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.read_object_head(context, domain, object_id)
    }

    fn read_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: objects::ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .read_object_version(context, domain, object_id, version)
    }

    fn read_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.read_request_receipt(context, domain, request_id)
    }
}

#[test]
fn ordered_read_scope_coalesces_physical_reads_without_persisting_anything() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(domain(), context().writer_fence());
    let reader: ReadOnly<'_> = ReadOnly {
        inner: &store,
        state_reads: Cell::new(0),
    };
    let observed: ObservedBusinessReadView<'_, ReadOnly<'_>> =
        ObservedBusinessReadView::new(&reader, domain());
    for _ in 0..2 {
        let row: VersionedStateValue = observed
            .read_versioned_state(&context(), domain(), b"deciding-row")
            .unwrap();
        assert_eq!(row.revision(), StateRevision::INITIAL);
        assert!(row.value().is_none());
    }
    assert!(
        observed
            .read_namespace_lifecycle(&context(), domain())
            .unwrap()
            .is_ordinary()
    );
    assert_eq!(
        observed
            .read_object_head(&context(), domain(), objects::ObjectId::new([3; 32]))
            .unwrap(),
        DurableObjectHead::Absent
    );
    assert!(
        observed
            .read_object_version(
                &context(),
                domain(),
                objects::ObjectId::new([3; 32]),
                DurableObjectVersion::FIRST
            )
            .unwrap()
            .is_none()
    );
    assert!(
        observed
            .read_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new([4; 32]).unwrap()
            )
            .unwrap()
            .is_none()
    );
    let observations: AtomicStateReadSet = observed.finish().unwrap().into_read_set().unwrap();
    assert_eq!(observations.reads().len(), 1);
    assert_eq!(reader.state_reads.get(), 2);
    let unchanged: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), b"deciding-row")
        .unwrap();
    assert_eq!(unchanged.revision(), StateRevision::INITIAL);
    assert!(unchanged.value().is_none());
    assert!(
        store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new([4; 32]).unwrap()
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn ordered_read_scope_poison_precedes_early_signing_refusal() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(domain(), context().writer_fence());
    let observed: ObservedBusinessReadView<'_, MemoryDurableStateStore> =
        ObservedBusinessReadView::new(&store, domain());
    let before: VersionedStateValue = observed
        .read_versioned_state(&context(), domain(), b"closure")
        .unwrap();
    let competing: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"closure".to_vec(), before.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"closure".to_vec(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), competing),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        observed.read_versioned_state(&context(), domain(), b"closure"),
        Err(DurableReadError::InvalidPersistedState)
    );
    let propagated: Result<(), OrderedEconomicsError> =
        Err(OrderedEconomicsError::Refused(OrderedRefusal::ClosedEpoch));
    assert!(matches!(
        observed.finish_with(propagated),
        Err(OrderedEconomicsError::Node(NodeCoreError::StateConflict))
    ));
    // Only the explicit competitor wrote. This attempt neither retained a
    // refusal nor a receipt and cannot expose a signing result.
    assert!(
        store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new([4; 32]).unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), b"closure")
            .unwrap()
            .value(),
        Some([1_u8].as_slice())
    );
}

#[test]
fn ordered_read_scope_preserves_actual_backend_deadline_failure() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(domain(), context().writer_fence());
    store.set_time(context().deadline().unix_millis());
    let observed: ObservedBusinessReadView<'_, MemoryDurableStateStore> =
        ObservedBusinessReadView::new(&store, domain());
    let error: DurableReadError = observed
        .read_versioned_state(&context(), domain(), b"key")
        .unwrap_err();
    assert_eq!(error, DurableReadError::DeadlineExceeded);
    let propagated: Result<(), OrderedEconomicsError> =
        Err(NodeCoreError::DurableRead(error).into());
    assert!(matches!(
        observed.finish_with(propagated),
        Err(OrderedEconomicsError::Node(NodeCoreError::DurableRead(
            DurableReadError::DeadlineExceeded
        )))
    ));
}

#[test]
fn ordered_read_scope_wrong_domain_poison_refuses_before_backend_io() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(domain(), context().writer_fence());
    let reader: ReadOnly<'_> = ReadOnly {
        inner: &store,
        state_reads: Cell::new(0),
    };
    let observed: ObservedBusinessReadView<'_, ReadOnly<'_>> =
        ObservedBusinessReadView::new(&reader, domain());
    let wrong: AtomicityDomainId = AtomicityDomainId::new([9; 32]).unwrap();
    assert_eq!(
        observed.read_versioned_state(&context(), wrong, b"key"),
        Err(DurableReadError::InvalidRequest(
            RuntimeError::AtomicityDomainMismatch
        ))
    );
    assert_eq!(reader.state_reads.get(), 0);
    assert!(matches!(
        observed.finish(),
        Err(OrderedEconomicsError::Node(NodeCoreError::Runtime(
            RuntimeError::AtomicityDomainMismatch
        )))
    ));
}

#[test]
fn ordered_read_scope_capacity_poison_is_bounded_and_sticky() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new_bound(domain(), context().writer_fence());
    let reader: ReadOnly<'_> = ReadOnly {
        inner: &store,
        state_reads: Cell::new(0),
    };
    let observed: ObservedBusinessReadView<'_, ReadOnly<'_>> =
        ObservedBusinessReadView::new(&reader, domain());
    for ordinal in 0..MAX_ATOMIC_STATE_READS {
        let key: Vec<u8> = format!("bounded-read/{ordinal:08}").into_bytes();
        observed
            .read_versioned_state(&context(), domain(), &key)
            .unwrap();
    }
    let expected: RuntimeError = RuntimeError::TooManyStateReads {
        count: MAX_ATOMIC_STATE_READS + 1,
        maximum: MAX_ATOMIC_STATE_READS,
    };
    assert_eq!(
        observed.read_versioned_state(&context(), domain(), b"excess"),
        Err(DurableReadError::InvalidRequest(expected.clone()))
    );
    let at_poison: usize = reader.state_reads.get();
    assert_eq!(
        observed.read_versioned_state(&context(), domain(), b"never-read"),
        Err(DurableReadError::InvalidRequest(expected))
    );
    assert_eq!(reader.state_reads.get(), at_poison);
    assert!(matches!(
        observed.finish(),
        Err(OrderedEconomicsError::Node(NodeCoreError::Runtime(
            RuntimeError::TooManyStateReads { .. }
        )))
    ));
}
