use super::*;
use protocol_types::HashAlgorithmId;
use runtime::{
    DurableCommitRejection, DurableDomainStateStore, DurableObjectHead, DurableOutboxBatch,
    DurableOutboxMessage, MemoryDurableStateStore, ObjectHeadRevision, StorageCorrelationId,
    StorageDeadline, VersionedStateReader, WriterFenceGeneration,
};

fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([1; 32]).unwrap()
}

fn context() -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(1).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([2; 16]).unwrap(),
    )
}

fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

// Structural assembler input only: this does not issue an authenticated
// operation or pretend to be independently verified business execution.
fn structural_preparation() -> PreparedOriginalCompletion {
    let request_id: [u8; 32] = [3; 32];
    let output: NodeOutput = NodeOutput::new(
        vec![
            NodeResponse::new(
                RequestId::new(request_id).unwrap(),
                NodeResponseStatus::Accepted,
                None,
            )
            .unwrap(),
        ],
        Vec::new(),
    )
    .unwrap();
    let receipt: DurableRequestReceipt =
        super::super::engine::build_receipt(request_id, digest(5), &output).unwrap();
    let state: DurableStateTransaction = DurableStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"business".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![StateMutationEntry::new(b"business".to_vec(), StateMutation::Put(vec![6])).unwrap()],
    )
    .unwrap();
    let objects: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            ObjectId::new([7; 32]),
            DurableObjectHead::Absent,
        )],
        Vec::new(),
    )
    .unwrap();
    let outbox: DurableOutboxBatch = DurableOutboxBatch::new(
        receipt.request_id(),
        receipt.event_digest(),
        vec![DurableOutboxMessage::new(digest(8), vec![9]).unwrap()],
    )
    .unwrap();
    PreparedOriginalCompletion {
        outcome: OrderedOutcome {
            // This structural assembly is not a Seal completion.
            candidate_digest: digest(10),
            request_id,
            block_height: 1,
            block_digest: digest(11),
            output,
        },
        seal: None,
        business: DurableInvocationTransaction::new(
            domain(),
            Some(state),
            objects,
            receipt,
            Some(outbox),
        )
        .unwrap(),
        reads: {
            let mut reads: StateObservationSet = StateObservationSet::new(domain());
            reads
                .observe(
                    StateReadAssertion::new(b"deciding-row".to_vec(), StateRevision::INITIAL)
                        .unwrap(),
                )
                .unwrap();
            reads
        },
    }
}

#[test]
fn completion_kernel_assembly_keeps_original_sections_and_deciding_observations() {
    let prepared: PreparedOriginalCompletion = structural_preparation();
    let original_receipt: DurableRequestReceipt = prepared.business.receipt().clone();
    let original_outbox: Option<DurableOutboxBatch> = prepared.business.outbox().cloned();
    let mut coordinator: MergedWrites = MergedWrites::new(domain());
    coordinator
        .mutate(
            b"progress".to_vec(),
            StateRevision::INITIAL,
            StateMutation::Put(vec![12]),
        )
        .unwrap();
    let heads: Vec<DurableObjectHeadRead> = vec![
        DurableObjectHeadRead::new(ObjectId::new([7; 32]), DurableObjectHead::Absent),
        DurableObjectHeadRead::new(ObjectId::new([13; 32]), DurableObjectHead::Absent),
    ];
    let assembled: DurableInvocationTransaction = prepared
        .assemble(domain(), coordinator, &heads)
        .unwrap()
        .transaction;
    assert_eq!(assembled.receipt(), &original_receipt);
    assert_eq!(assembled.outbox(), original_outbox.as_ref());
    let state: &DurableStateTransaction = assembled.state().unwrap();
    assert_eq!(state.reads().len(), 3);
    assert_eq!(state.mutations().len(), 2);
    assert!(
        state
            .reads()
            .iter()
            .any(|read| read.key() == b"deciding-row")
    );
    assert_eq!(assembled.object_changes().reads(), heads);
}

#[test]
fn completion_kernel_head_disagreement_cannot_publish_a_receipt_or_progress() {
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new(context().writer_fence());
    let prepared: PreparedOriginalCompletion = structural_preparation();
    let heads: Vec<DurableObjectHeadRead> = vec![DurableObjectHeadRead::new(
        ObjectId::new([7; 32]),
        DurableObjectHead::Tombstoned {
            last_object_version: runtime::DurableObjectVersion::FIRST,
            head_revision: ObjectHeadRevision::FIRST,
        },
    )];
    let result = prepared.confirm(
        &store,
        &context(),
        domain(),
        MergedWrites::new(domain()),
        &heads,
    );
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Node(
            NodeCoreError::ObjectConflict { .. }
        ))
    ));
    assert!(
        store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new([3; 32]).unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), b"business")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
}

#[test]
fn completion_kernel_disagreeing_state_contributions_stop_before_commit() {
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new(context().writer_fence());
    let prepared: PreparedOriginalCompletion = structural_preparation();
    let mut coordinator: MergedWrites = MergedWrites::new(domain());
    coordinator
        .mutate(
            b"business".to_vec(),
            StateRevision::INITIAL,
            StateMutation::Put(vec![99]),
        )
        .unwrap();
    let result = prepared.confirm(&store, &context(), domain(), coordinator, &[]);
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert!(
        store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new([3; 32]).unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), b"business")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
}

#[test]
fn completion_kernel_wrong_domain_and_stale_writer_never_confirm_preparation() {
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new(context().writer_fence());
    let foreign: AtomicityDomainId = AtomicityDomainId::new([22; 32]).unwrap();
    let result = structural_preparation().confirm(
        &store,
        &context(),
        foreign,
        MergedWrites::new(foreign),
        &[],
    );
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Node(NodeCoreError::Runtime(
            RuntimeError::AtomicityDomainMismatch
        )))
    ));
    let active: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
    store.set_active_writer_fence(active);
    let result = structural_preparation().confirm(
        &store,
        &context(),
        domain(),
        MergedWrites::new(domain()),
        &[],
    );
    assert!(
        matches!(result, Err(OrderedEconomicsError::Node(NodeCoreError::DurableCommitRejected(DurableCommitRejection::WriterFenced { active_generation }))) if active_generation == active)
    );
    let fresh: DurableOperationContext =
        DurableOperationContext::new(active, context().deadline(), context().correlation_id());
    assert!(
        store
            .get_request_receipt(&fresh, domain(), DurableRequestId::new([3; 32]).unwrap())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .get_versioned_durable(&fresh, domain(), b"business")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
}

#[test]
fn completion_kernel_conflicting_reads_precede_a_propagated_handler_stop() {
    let store: MemoryDurableStateStore = MemoryDurableStateStore::new(context().writer_fence());
    let observed: ObservedBusinessReadView<'_, MemoryDurableStateStore> =
        ObservedBusinessReadView::new(&store, domain());
    let key: Vec<u8> = b"deciding-row".to_vec();
    let before: VersionedStateValue = observed
        .read_versioned_state(&context(), domain(), &key)
        .unwrap();
    let competing: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), before.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.clone(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), competing),
        DurableCommitOutcome::Committed
    );
    assert!(matches!(
        observed.read_versioned_state(&context(), domain(), &key),
        Err(runtime::DurableReadError::InvalidPersistedState)
    ));
    let result: LegOutcome = LegOutcome::Stop(OrderedEconomicsError::Prerequisite(
        "handler independently stopped",
    ));
    assert!(matches!(
        finish_handler_attempt(observed, result),
        Err(OrderedEconomicsError::Node(NodeCoreError::StateConflict))
    ));
    assert!(
        store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new([3; 32]).unwrap()
            )
            .unwrap()
            .is_none()
    );
    let after: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    assert_eq!(after.value(), Some([1_u8].as_slice()));
    assert_eq!(after.revision(), before.revision().checked_next().unwrap());
}
