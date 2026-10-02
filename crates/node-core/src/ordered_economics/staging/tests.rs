use super::*;
use runtime::{
    MemoryDurableStateStore, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
};

fn store_context() -> (
    MemoryDurableStateStore,
    DurableOperationContext,
    AtomicityDomainId,
) {
    let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new(generation);
    let context: DurableOperationContext = DurableOperationContext::new(
        generation,
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([1; 16]).unwrap(),
    );
    let domain: AtomicityDomainId = AtomicityDomainId::new([2; 32]).unwrap();
    (store, context, domain)
}

#[test]
fn staging_store_forwards_reads_and_never_publishes_a_captured_commit() {
    let (store, context, domain) = store_context();
    let key: Vec<u8> = b"ordered-economics-staging-probe".to_vec();
    let real_before: VersionedStateValue =
        store.get_versioned_durable(&context, domain, &key).unwrap();
    let staging: StagingStore<'_, MemoryDurableStateStore> = StagingStore::new(&store);
    let observed: VersionedStateValue = staging
        .get_versioned_durable(&context, domain, &key)
        .unwrap();
    assert_eq!(observed.revision(), real_before.revision());

    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.clone(), StateMutation::Put(vec![9, 9, 9])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        staging.commit_durable(&context, transaction),
        DurableCommitOutcome::Committed
    );

    // The real store never saw the write: the staged transaction was
    // captured, not published.
    let real_after: VersionedStateValue =
        store.get_versioned_durable(&context, domain, &key).unwrap();
    assert_eq!(real_after.revision(), real_before.revision());
    assert_eq!(real_after.value(), None);

    let prepared: HandlerPreparation = staging.finish().unwrap();
    let Some(PreparedHandlerWrite::State(captured)) = prepared.write else {
        panic!("expected prepared state transaction");
    };
    assert_eq!(
        store.commit_durable(&context, captured),
        DurableCommitOutcome::Committed
    );
    let real_committed: VersionedStateValue =
        store.get_versioned_durable(&context, domain, &key).unwrap();
    assert_eq!(real_committed.value(), Some(vec![9, 9, 9].as_slice()));
}

#[test]
fn staging_preparation_is_one_shot_and_second_capture_cannot_be_confirmed() {
    let (store, context, domain) = store_context();
    let key: Vec<u8> = b"one-original-completion".to_vec();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.clone(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    let staging: StagingStore<'_, MemoryDurableStateStore> = StagingStore::new(&store);
    assert_eq!(
        staging.commit_durable(&context, transaction.clone()),
        DurableCommitOutcome::Committed
    );
    assert!(matches!(
        staging.commit_durable(&context, transaction),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    ));
    assert!(matches!(
        staging.finish(),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert_eq!(
        store
            .get_versioned_durable(&context, domain, &key)
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );

    let empty: StagingStore<'_, MemoryDurableStateStore> = StagingStore::new(&store);
    assert!(empty.finish().unwrap().write.is_none());
    assert!(matches!(
        empty.finish(),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
}

#[test]
fn staging_disagreeing_observations_cannot_become_a_prepared_refusal() {
    let (store, context, domain) = store_context();
    let key: Vec<u8> = b"healthy-refusal-deciding-row".to_vec();
    let staging: StagingStore<'_, MemoryDurableStateStore> = StagingStore::new(&store);
    let before: VersionedStateValue = staging
        .get_versioned_durable(&context, domain, &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), before.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.clone(), StateMutation::Put(vec![2])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, transaction),
        DurableCommitOutcome::Committed
    );
    staging
        .get_versioned_durable(&context, domain, &key)
        .unwrap();
    assert!(matches!(
        staging.finish(),
        Err(OrderedEconomicsError::Node(NodeCoreError::StateConflict))
    ));
}
