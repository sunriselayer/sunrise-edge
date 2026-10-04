use super::*;
use crate::inactive_import::ImportContext;
use crate::portable::DurablePortableSnapshotRepository;
use protocol_types::{ChainId, Epoch, ExecutionGeneration, HashAlgorithmId, ProtocolVersion};

fn domain(byte: u8) -> AtomicityDomainId {
    AtomicityDomainId::new([byte; 32]).unwrap()
}

fn operation(fence: u64) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(fence).unwrap(),
        StorageDeadline::new(1_000_000).unwrap(),
        StorageCorrelationId::new([9; 16]).unwrap(),
    )
}

fn binding(byte: u8) -> ImportBinding {
    ImportBinding {
        context: ImportContext {
            chain_id: ChainId::new("sunrise-edge-successor-memory-test").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(5),
        },
        domain: domain(byte),
        genesis_digest: Digest32::new(HashAlgorithmId::Sha2_256, [1; 32]),
        validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [2; 32]),
        cut_digest: Digest32::new(HashAlgorithmId::Sha2_256, [3; 32]),
        package_digest: Digest32::new(HashAlgorithmId::Sha2_256, [4; 32]),
        plan_digest: Digest32::new(HashAlgorithmId::Sha2_256, [5; 32]),
        row_count: 0,
        blob_count: 0,
        generation_floor: ExecutionGeneration::new(1),
    }
}

fn progress() -> ImportProgress {
    ImportProgress {
        next_ordinal: 0,
        last_batch_digest: None,
        accumulator: Digest32::new(HashAlgorithmId::Sha2_256, [6; 32]),
    }
}

fn receipt(byte: u8) -> DurableRequestReceipt {
    DurableRequestReceipt::new(
        DurableRequestId::new([byte; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32]),
        vec![0xAB; 4],
    )
    .unwrap()
}

#[test]
fn activation_commits_and_installs_serving_slot_atomically() {
    let validator = ValidatorId::new([42; 32]);
    let store = complete_inactive_store(1, validator, 1);
    let context = operation(1);
    let token = fresh_token(&store, 1, 1, 0);
    let record_value = valid_record(1, validator, &token);
    let record_bytes = encode_successor_serving_record(&record_value).unwrap();

    let outcome = store.commit_successor_activation(
        &context,
        domain(1),
        &binding(1),
        &progress(),
        &token,
        &record_bytes,
        activation_transaction(1, 1),
    );
    assert_eq!(outcome, DurableCommitOutcome::Committed);

    let slot = store.get_successor_serving(&context, domain(1)).unwrap();
    match slot {
        SuccessorServingSlot::Serving(observation) => {
            assert_eq!(observation.record, record_bytes);
            assert_eq!(observation.binding, binding(1));
            assert_eq!(observation.progress, progress());
        }
        SuccessorServingSlot::Inactive => panic!("expected Serving after activation"),
    }
}

#[test]
fn activation_rejects_once_slot_is_no_longer_inactive() {
    let validator = ValidatorId::new([42; 32]);
    let store = complete_inactive_store(2, validator, 1);
    let context = operation(1);
    let token = fresh_token(&store, 2, 1, 0);
    let record_bytes =
        encode_successor_serving_record(&valid_record(2, validator, &token)).unwrap();

    let first = store.commit_successor_activation(
        &context,
        domain(2),
        &binding(2),
        &progress(),
        &token,
        &record_bytes,
        activation_transaction(2, 2),
    );
    assert_eq!(first, DurableCommitOutcome::Committed);

    let retry_token = fresh_token(&store, 2, 1, 1);
    let second = store.commit_successor_activation(
        &context,
        domain(2),
        &binding(2),
        &progress(),
        &retry_token,
        &record_bytes,
        activation_transaction(2, 3),
    );
    assert_eq!(
        second,
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
}

fn activate(byte: u8, validator: ValidatorId, fence: u64) -> (MemoryDurableStateStore, Vec<u8>) {
    let store = complete_inactive_store(byte, validator, fence);
    let context = operation(fence);
    let token = fresh_token(&store, byte, fence, 0);
    let record_bytes =
        encode_successor_serving_record(&valid_record(byte, validator, &token)).unwrap();
    let outcome = store.commit_successor_activation(
        &context,
        domain(byte),
        &binding(byte),
        &progress(),
        &token,
        &record_bytes,
        activation_transaction(byte, byte),
    );
    assert_eq!(outcome, DurableCommitOutcome::Committed);
    (store, record_bytes)
}

#[test]
fn successor_durable_applies_state_after_activation() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(7, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(7),
        progress: progress(),
    };
    let transaction = AtomicStateTransaction::new(
        domain(7),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"key".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"key".to_vec(), StateMutation::Put(vec![9])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_successor_durable(&context, &observation, transaction),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, domain(7), b"key")
            .unwrap()
            .value(),
        Some([9].as_slice())
    );
}

#[test]
fn successor_durable_rejects_mismatched_observation() {
    let validator = ValidatorId::new([42; 32]);
    let (store, _record_bytes) = activate(8, validator, 1);
    let context = operation(1);
    let wrong_observation = SuccessorServingObservation {
        record: vec![0xFF; 4],
        binding: binding(8),
        progress: progress(),
    };
    let transaction = AtomicStateTransaction::new(
        domain(8),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"key".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"key".to_vec(), StateMutation::Put(vec![9])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_successor_durable(&context, &wrong_observation, transaction),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict)
    );
}

#[test]
fn activation_rejects_stale_token() {
    let validator = ValidatorId::new([42; 32]);
    let store = complete_inactive_store(4, validator, 1);
    let context = operation(1);
    let stale = fresh_token(&store, 4, 1, 7);
    let record_bytes =
        encode_successor_serving_record(&valid_record(4, validator, &stale)).unwrap();

    let outcome = store.commit_successor_activation(
        &context,
        domain(4),
        &binding(4),
        &progress(),
        &stale,
        &record_bytes,
        activation_transaction(4, 4),
    );
    assert_eq!(
        outcome,
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
}

#[test]
fn activation_rejects_validator_mismatch() {
    let bound_validator = ValidatorId::new([42; 32]);
    let other_validator = ValidatorId::new([99; 32]);
    let store = complete_inactive_store(5, bound_validator, 1);
    let context = operation(1);
    let token = fresh_token(&store, 5, 1, 0);
    let record_bytes =
        encode_successor_serving_record(&valid_record(5, other_validator, &token)).unwrap();

    let outcome = store.commit_successor_activation(
        &context,
        domain(5),
        &binding(5),
        &progress(),
        &token,
        &record_bytes,
        activation_transaction(5, 5),
    );
    assert_eq!(
        outcome,
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict)
    );
}

#[test]
fn ordinary_commit_refuses_once_slot_is_serving() {
    let store =
        MemoryDurableStateStore::new_bound(domain(6), WriterFenceGeneration::new(1).unwrap());
    let bogus_observation = SuccessorServingObservation {
        record: vec![0xAA; 4],
        binding: binding(6),
        progress: progress(),
    };
    store.inner.write().unwrap().successor_serving =
        SuccessorServingSlot::Serving(Box::new(bogus_observation));

    let context = operation(1);
    let transaction = AtomicStateTransaction::new(
        domain(6),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"key".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"key".to_vec(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context, transaction),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
}

// Builds a store bound to one domain and validator, with lifecycle forced
// directly to CompleteInactive so the repository checks can be exercised
// without driving the full inactive-import flow.
fn complete_inactive_store(
    byte: u8,
    validator: ValidatorId,
    fence: u64,
) -> MemoryDurableStateStore {
    let store = MemoryDurableStateStore::new_successor_bound(
        domain(byte),
        validator,
        WriterFenceGeneration::new(fence).unwrap(),
    );
    store.inner.write().unwrap().lifecycle = NamespaceLifecycle::CompleteInactive {
        binding: binding(byte),
        progress: progress(),
    };
    store
}

fn fresh_token(
    store: &MemoryDurableStateStore,
    byte: u8,
    fence: u64,
    sequence: u64,
) -> PortableSnapshotToken {
    let data = store.inner.read().unwrap();
    PortableSnapshotToken::new(
        data.portable_namespace.clone(),
        domain(byte),
        WriterFenceGeneration::new(fence).unwrap(),
        sequence,
    )
    .unwrap()
}

fn valid_record(
    byte: u8,
    validator: ValidatorId,
    token: &PortableSnapshotToken,
) -> SuccessorServingRecord {
    SuccessorServingRecord {
        subject: Digest32::new(HashAlgorithmId::Sha2_256, [7; 32]),
        manifest: Digest32::new(HashAlgorithmId::Sha2_256, [8; 32]),
        binding: binding(byte),
        progress: progress(),
        activation_token: token.clone(),
        anchor: Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]),
        validator,
        public_key: [10; 32],
    }
}

fn activation_transaction(domain_byte: u8, receipt_byte: u8) -> DurableInvocationTransaction {
    DurableInvocationTransaction::new(
        domain(domain_byte),
        None,
        DurableObjectChanges::empty(),
        receipt(receipt_byte),
        None,
    )
    .unwrap()
}

fn successor_seal_request(byte: u8) -> [u8; 32] {
    let mut request = [byte; 32];
    request[0] |= 0x80;
    request
}

fn successor_sealed(byte: u8) -> SealBarrier {
    SealBarrier {
        outgoing_epoch: Epoch::new(6),
        request: successor_seal_request(byte),
        height: 11,
        block_digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(1); 32]),
        target_digest: Digest32::new(HashAlgorithmId::Sha2_256, [byte.wrapping_add(2); 32]),
        transition_history: TransitionHistoryState::Virgin,
    }
}

fn successor_minimal_invocation(
    domain: AtomicityDomainId,
    sealed: &SealBarrier,
) -> DurableInvocationTransaction {
    let request_id = DurableRequestId::new(sealed.request).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xAB; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![1]).unwrap();
    DurableInvocationTransaction::new(domain, None, DurableObjectChanges::empty(), receipt, None)
        .unwrap()
}

fn successor_state_write(
    domain: AtomicityDomainId,
    key: &[u8],
    value: u8,
    expected: StateRevision,
) -> AtomicStateTransaction {
    AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.to_vec(), expected).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.to_vec(), StateMutation::Put(vec![value])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap()
}

/// A complete test observation, including physical revisions, every receipt,
/// delivery obligation and the mutation sequence. No store equality is
/// invented to make an error assertion compile.
type ObservedMemoryStateDomains =
    BTreeMap<[u8; 32], BTreeMap<Vec<u8>, (StateRevision, Option<Vec<u8>>)>>;

#[derive(Debug, PartialEq, Eq)]
struct MemorySealState {
    lifecycle: NamespaceLifecycle,
    barrier: OutgoingBarrier,
    serving: SuccessorServingSlot,
    validator: Option<ValidatorId>,
    namespace: Vec<u8>,
    sequences: BTreeMap<[u8; 32], u64>,
    readiness: BTreeMap<MemoryReadinessSlotKey, Option<Vec<u8>>>,
    bound_domain: Option<AtomicityDomainId>,
    fence: WriterFenceGeneration,
    now: u64,
    state: ObservedMemoryStateDomains,
    heads: BTreeMap<MemoryDurableObjectHeadKey, MemoryStoredObjectHead>,
    versions: BTreeMap<MemoryDurableObjectVersionKey, DurableObjectVersionRecord>,
    receipts: BTreeMap<MemoryDurableInvocationKey, DurableRequestReceipt>,
    outboxes: BTreeMap<MemoryDurableInvocationKey, DurableOutboxBatch>,
    deliveries: BTreeMap<MemoryDurableInvocationKey, MemoryOutboxDelivery>,
    attempts: BTreeMap<[u8; 32], MemoryOutboxDeliveryAttempt>,
}

fn memory_seal_state(store: &MemoryDurableStateStore) -> MemorySealState {
    let data = store.inner.read().unwrap();
    MemorySealState {
        lifecycle: data.lifecycle.clone(),
        barrier: data.outgoing_barrier,
        serving: data.successor_serving.clone(),
        validator: data.successor_namespace_validator,
        namespace: data.portable_namespace.clone(),
        sequences: data.mutation_sequences.clone(),
        readiness: data.readiness_slots.clone(),
        bound_domain: data.bound_domain,
        fence: data.active_writer_fence,
        now: data.now_unix_millis,
        state: data
            .state_domains
            .iter()
            .map(|(domain, entries)| {
                let rows: BTreeMap<Vec<u8>, (StateRevision, Option<Vec<u8>>)> = entries
                    .iter()
                    .map(|(key, value)| (key.clone(), (value.revision, value.value.clone())))
                    .collect();
                (*domain, rows)
            })
            .collect(),
        heads: data.object_heads.clone(),
        versions: data.object_versions.clone(),
        receipts: data.receipts.clone(),
        outboxes: data.outboxes.clone(),
        deliveries: data.deliveries.clone(),
        attempts: data.delivery_attempts.clone(),
    }
}

fn successor_stateful_invocation(
    domain: AtomicityDomainId,
    sealed: &SealBarrier,
    key: &[u8],
    value: u8,
    expected: StateRevision,
) -> DurableInvocationTransaction {
    let transaction: AtomicStateTransaction = successor_state_write(domain, key, value, expected);
    let section: DurableStateTransaction = transaction.into();
    DurableInvocationTransaction::new(
        domain,
        Some(section),
        DurableObjectChanges::empty(),
        successor_minimal_invocation(domain, sealed)
            .receipt()
            .clone(),
        None,
    )
    .unwrap()
}

fn assert_memory_seal_rejection(
    store: &MemoryDurableStateStore,
    reason: DurableCommitRejection,
    invoke: impl FnOnce() -> DurableCommitOutcome,
) {
    let before: MemorySealState = memory_seal_state(store);
    assert_eq!(invoke(), DurableCommitOutcome::Rejected(reason));
    assert_eq!(memory_seal_state(store), before);
}

#[test]
fn successor_seal_rejects_wrong_binding_and_progress_with_deciding_positive_controls() {
    for wrong_progress in [false, true] {
        let validator: ValidatorId = ValidatorId::new([42; 32]);
        let (store, record): (MemoryDurableStateStore, Vec<u8>) = activate(91, validator, 1);
        let context: DurableOperationContext = operation(1);
        let observation: SuccessorServingObservation = SuccessorServingObservation {
            record,
            binding: binding(91),
            progress: progress(),
        };
        let mut wrong: SuccessorServingObservation = observation.clone();
        if wrong_progress {
            wrong.progress.accumulator = Digest32::new(HashAlgorithmId::Sha2_256, [0xFF; 32]);
        } else {
            wrong.binding.cut_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xFF; 32]);
        }
        let token: PortableSnapshotToken =
            store.begin_portable_snapshot(&context, domain(91)).unwrap();
        assert_memory_seal_rejection(
            &store,
            DurableCommitRejection::ImportBindingMismatch,
            || {
                store.commit_successor_seal_retention(
                    &context,
                    &wrong,
                    &token,
                    successor_state_write(domain(91), b"retention", 1, StateRevision::INITIAL),
                )
            },
        );
        let sealed: SealBarrier = successor_sealed(92);
        assert_memory_seal_rejection(
            &store,
            DurableCommitRejection::ImportBindingMismatch,
            || {
                store.commit_successor_seal_completion(
                    &context,
                    &wrong,
                    &token,
                    successor_stateful_invocation(
                        domain(91),
                        &sealed,
                        b"completion",
                        2,
                        StateRevision::INITIAL,
                    ),
                    sealed,
                )
            },
        );
        assert_eq!(
            store.commit_successor_seal_retention(
                &context,
                &observation,
                &token,
                successor_state_write(domain(91), b"retention", 1, StateRevision::INITIAL),
            ),
            DurableCommitOutcome::Committed
        );
        let next_token: PortableSnapshotToken =
            store.begin_portable_snapshot(&context, domain(91)).unwrap();
        assert_eq!(
            store.commit_successor_seal_completion(
                &context,
                &observation,
                &next_token,
                successor_stateful_invocation(
                    domain(91),
                    &sealed,
                    b"completion",
                    2,
                    StateRevision::INITIAL
                ),
                sealed,
            ),
            DurableCommitOutcome::Committed
        );
        assert_eq!(
            store
                .begin_portable_snapshot(&context, domain(91))
                .unwrap()
                .mutation_sequence(),
            token.mutation_sequence() + 2
        );
    }
}

#[test]
fn successor_seal_completion_rejects_wrong_serving_epoch_without_any_mutation() {
    let validator: ValidatorId = ValidatorId::new([42; 32]);
    let (store, record): (MemoryDurableStateStore, Vec<u8>) = activate(93, validator, 1);
    let context: DurableOperationContext = operation(1);
    let observation: SuccessorServingObservation = SuccessorServingObservation {
        record,
        binding: binding(93),
        progress: progress(),
    };
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&context, domain(93)).unwrap();
    let sealed: SealBarrier = successor_sealed(94);
    let mut wrong: SealBarrier = sealed;
    wrong.outgoing_epoch = Epoch::new(7);
    assert_memory_seal_rejection(&store, DurableCommitRejection::ImportConflict, || {
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            successor_stateful_invocation(
                domain(93),
                &wrong,
                b"completion",
                2,
                StateRevision::INITIAL,
            ),
            wrong,
        )
    });
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            successor_stateful_invocation(
                domain(93),
                &sealed,
                b"completion",
                2,
                StateRevision::INITIAL
            ),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_completion_rejects_stale_cas_and_then_commits_the_same_state_change() {
    let validator: ValidatorId = ValidatorId::new([42; 32]);
    let (store, record): (MemoryDurableStateStore, Vec<u8>) = activate(95, validator, 1);
    let context: DurableOperationContext = operation(1);
    let observation: SuccessorServingObservation = SuccessorServingObservation {
        record,
        binding: binding(95),
        progress: progress(),
    };
    assert_eq!(
        store.commit_successor_durable(
            &context,
            &observation,
            successor_state_write(domain(95), b"cut", 1, StateRevision::INITIAL),
        ),
        DurableCommitOutcome::Committed
    );
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&context, domain(95)).unwrap();
    let sealed: SealBarrier = successor_sealed(96);
    assert_memory_seal_rejection(
        &store,
        DurableCommitRejection::Conflict {
            key: b"cut".to_vec(),
            current_revision: StateRevision::new(1),
        },
        || {
            store.commit_successor_seal_completion(
                &context,
                &observation,
                &token,
                successor_stateful_invocation(
                    domain(95),
                    &sealed,
                    b"cut",
                    2,
                    StateRevision::INITIAL,
                ),
                sealed,
            )
        },
    );
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            successor_stateful_invocation(domain(95), &sealed, b"cut", 2, StateRevision::new(1)),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
    let data = store.inner.read().unwrap();
    assert_eq!(data.outgoing_barrier, OutgoingBarrier::Sealed(sealed));
    assert_eq!(
        data.receipts.get(&(*domain(95).as_bytes(), sealed.request)),
        Some(successor_minimal_invocation(domain(95), &sealed).receipt())
    );
    assert_eq!(
        data.mutation_sequences[domain(95).as_bytes()],
        token.mutation_sequence() + 1
    );
    assert_eq!(
        data.state_domains[domain(95).as_bytes()][b"cut".as_slice()]
            .value
            .as_deref(),
        Some([2].as_slice())
    );
}

#[test]
fn successor_seal_completion_retains_an_explicitly_empty_outbox_atomically() {
    let validator: ValidatorId = ValidatorId::new([42; 32]);
    let (store, record): (MemoryDurableStateStore, Vec<u8>) = activate(97, validator, 1);
    let context: DurableOperationContext = operation(1);
    let observation: SuccessorServingObservation = SuccessorServingObservation {
        record,
        binding: binding(97),
        progress: progress(),
    };
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&context, domain(97)).unwrap();
    let sealed: SealBarrier = successor_sealed(98);
    let base: DurableInvocationTransaction =
        successor_stateful_invocation(domain(97), &sealed, b"cut", 2, StateRevision::INITIAL);
    let receipt: DurableRequestReceipt = base.receipt().clone();
    let outbox: DurableOutboxBatch =
        DurableOutboxBatch::new(receipt.request_id(), receipt.event_digest(), Vec::new()).unwrap();
    let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain(97),
        base.state().cloned(),
        DurableObjectChanges::empty(),
        receipt.clone(),
        Some(outbox.clone()),
    )
    .unwrap();
    assert_eq!(
        store.commit_successor_seal_completion(&context, &observation, &token, invocation, sealed),
        DurableCommitOutcome::Committed
    );
    let data = store.inner.read().unwrap();
    let request: MemoryDurableInvocationKey = (*domain(97).as_bytes(), sealed.request);
    assert_eq!(data.receipts.get(&request), Some(&receipt));
    assert_eq!(data.outboxes.get(&request), Some(&outbox));
    assert!(data.deliveries.get(&request).unwrap().completed);
    assert_eq!(data.outgoing_barrier, OutgoingBarrier::Sealed(sealed));
    assert_eq!(
        data.mutation_sequences[domain(97).as_bytes()],
        token.mutation_sequence() + 1
    );
    assert_eq!(
        data.state_domains[domain(97).as_bytes()][b"cut".as_slice()]
            .value
            .as_deref(),
        Some([2].as_slice())
    );
}

#[test]
fn successor_seal_completion_rejects_an_existing_empty_outbox_for_its_request() {
    let validator: ValidatorId = ValidatorId::new([42; 32]);
    let (store, record): (MemoryDurableStateStore, Vec<u8>) = activate(99, validator, 1);
    let context: DurableOperationContext = operation(1);
    let observation: SuccessorServingObservation = SuccessorServingObservation {
        record,
        binding: binding(99),
        progress: progress(),
    };
    let sealed: SealBarrier = successor_sealed(100);
    let invocation: DurableInvocationTransaction =
        successor_minimal_invocation(domain(99), &sealed);
    let empty: DurableOutboxBatch = DurableOutboxBatch::new(
        invocation.receipt().request_id(),
        invocation.receipt().event_digest(),
        Vec::new(),
    )
    .unwrap();
    let request: MemoryDurableInvocationKey = (*domain(99).as_bytes(), sealed.request);
    store.inner.write().unwrap().outboxes.insert(request, empty);
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&context, domain(99)).unwrap();
    assert_memory_seal_rejection(
        &store,
        DurableCommitRejection::InvalidPersistedState,
        || {
            store.commit_successor_seal_completion(
                &context,
                &observation,
                &token,
                successor_stateful_invocation(
                    domain(99),
                    &sealed,
                    b"cut",
                    2,
                    StateRevision::INITIAL,
                ),
                sealed,
            )
        },
    );
    store.inner.write().unwrap().outboxes.remove(&request);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            successor_stateful_invocation(domain(99), &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_retention_and_completion_seal_the_barrier_and_block_further_successor_writes() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(60, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(60),
        progress: progress(),
    };
    let retention_token = store.begin_portable_snapshot(&context, domain(60)).unwrap();
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &retention_token,
            successor_state_write(domain(60), b"cut", 3, StateRevision::INITIAL),
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.get_outgoing_barrier(&context, domain(60)).unwrap(),
        OutgoingBarrier::Unsealed
    );

    let completion_token = store.begin_portable_snapshot(&context, domain(60)).unwrap();
    let sealed = successor_sealed(61);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &completion_token,
            successor_minimal_invocation(domain(60), &sealed),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.get_outgoing_barrier(&context, domain(60)).unwrap(),
        OutgoingBarrier::Sealed(sealed)
    );

    let after_token = store.begin_portable_snapshot(&context, domain(60)).unwrap();
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &after_token,
            successor_state_write(domain(60), b"cut", 4, StateRevision::new(1)),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::NamespaceSealed)
    );
    assert_eq!(
        store.commit_successor_durable(
            &context,
            &observation,
            successor_state_write(domain(60), b"cut", 5, StateRevision::new(1)),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::NamespaceSealed)
    );
}

#[test]
fn successor_seal_retention_rejects_stale_token() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(62, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(62),
        progress: progress(),
    };
    // Activation already advanced the sequence to 1; sequence 0 is stale.
    let stale_token = fresh_token(&store, 62, 1, 0);
    let before: MemorySealState = memory_seal_state(&store);
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &stale_token,
            successor_state_write(domain(62), b"cut", 1, StateRevision::INITIAL),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(memory_seal_state(&store), before);
    assert_eq!(
        store.get_outgoing_barrier(&context, domain(62)).unwrap(),
        OutgoingBarrier::Unsealed
    );
}

#[test]
fn successor_seal_completion_rejects_foreign_physical_token() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(63, validator, 1);
    let (other_store, _other_record_bytes) = activate(63, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(63),
        progress: progress(),
    };
    let foreign_token = other_store
        .begin_portable_snapshot(&context, domain(63))
        .unwrap();
    let own_token = store.begin_portable_snapshot(&context, domain(63)).unwrap();
    assert_ne!(foreign_token.namespace(), own_token.namespace());
    let sealed = successor_sealed(64);
    let before: MemorySealState = memory_seal_state(&store);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &foreign_token,
            successor_stateful_invocation(domain(63), &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(memory_seal_state(&store), before);
    assert_eq!(
        store.get_outgoing_barrier(&context, domain(63)).unwrap(),
        OutgoingBarrier::Unsealed
    );
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &own_token,
            successor_stateful_invocation(domain(63), &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_retention_rejects_mismatched_observation_record() {
    let validator = ValidatorId::new([42; 32]);
    let (store, _record_bytes) = activate(69, validator, 1);
    let context = operation(1);
    let wrong_observation = SuccessorServingObservation {
        record: vec![0xFF; 4],
        binding: binding(69),
        progress: progress(),
    };
    let token = store.begin_portable_snapshot(&context, domain(69)).unwrap();
    let before: MemorySealState = memory_seal_state(&store);
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &wrong_observation,
            &token,
            successor_state_write(domain(69), b"cut", 1, StateRevision::INITIAL),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict)
    );
    assert_eq!(memory_seal_state(&store), before);
}

#[test]
fn successor_seal_completion_rejects_stale_generation() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(70, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(70),
        progress: progress(),
    };
    let token = store.begin_portable_snapshot(&context, domain(70)).unwrap();
    let advanced = WriterFenceGeneration::new(2).unwrap();
    store.set_active_writer_fence(advanced);
    let sealed = successor_sealed(71);
    let before: MemorySealState = memory_seal_state(&store);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            successor_stateful_invocation(domain(70), &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: advanced,
        })
    );
    assert_eq!(memory_seal_state(&store), before);
    let current_context: DurableOperationContext = operation(advanced.get());
    let current_token: PortableSnapshotToken = store
        .begin_portable_snapshot(&current_context, domain(70))
        .unwrap();
    assert_eq!(
        store.commit_successor_seal_completion(
            &current_context,
            &observation,
            &current_token,
            successor_stateful_invocation(domain(70), &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_completion_rejects_occupied_receipt() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(72, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(72),
        progress: progress(),
    };
    let sealed = successor_sealed(73);
    let existing_receipt = DurableRequestReceipt::new(
        DurableRequestId::new(sealed.request).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0xCC; 32]),
        vec![5],
    )
    .unwrap();
    store
        .inner
        .write()
        .unwrap()
        .receipts
        .insert((*domain(72).as_bytes(), sealed.request), existing_receipt);
    let token = store.begin_portable_snapshot(&context, domain(72)).unwrap();
    let before: MemorySealState = memory_seal_state(&store);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            successor_minimal_invocation(domain(72), &sealed),
            sealed,
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );
    assert_eq!(memory_seal_state(&store), before);
}

#[test]
fn successor_seal_completion_rejects_nonempty_outbox() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(74, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(74),
        progress: progress(),
    };
    let sealed = successor_sealed(75);
    let request_id = DurableRequestId::new(sealed.request).unwrap();
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    let receipt = DurableRequestReceipt::new(request_id, event_digest, vec![1]).unwrap();
    let message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha2_256, [0xFA; 32]),
        vec![9],
    )
    .unwrap();
    let outbox = DurableOutboxBatch::new(request_id, event_digest, vec![message]).unwrap();
    let invocation = DurableInvocationTransaction::new(
        domain(74),
        None,
        DurableObjectChanges::empty(),
        receipt,
        Some(outbox),
    )
    .unwrap();
    let token = store.begin_portable_snapshot(&context, domain(74)).unwrap();
    let before: MemorySealState = memory_seal_state(&store);
    assert_eq!(
        store.commit_successor_seal_completion(&context, &observation, &token, invocation, sealed),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(memory_seal_state(&store), before);
}

#[test]
fn successor_seal_retention_rejects_lifecycle_binding_mismatch_with_positive_control() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(81, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(81),
        progress: progress(),
    };
    // Positive control: the real stored binding/progress commits.
    let token = store.begin_portable_snapshot(&context, domain(81)).unwrap();
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &token,
            successor_state_write(domain(81), b"cut", 1, StateRevision::INITIAL),
        ),
        DurableCommitOutcome::Committed
    );
    // Negative: an observation naming a different binding than the stored
    // CompleteInactive lifecycle (not merely a different record).
    let mismatched_observation = SuccessorServingObservation {
        record: observation.record.clone(),
        binding: binding(82),
        progress: progress(),
    };
    let next_token = store.begin_portable_snapshot(&context, domain(81)).unwrap();
    let before: MemorySealState = memory_seal_state(&store);
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &mismatched_observation,
            &next_token,
            successor_state_write(domain(81), b"cut", 2, StateRevision::new(1)),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportBindingMismatch)
    );
    assert_eq!(memory_seal_state(&store), before);
    assert_eq!(
        store
            .get_versioned_durable(&context, domain(81), b"cut")
            .unwrap()
            .value(),
        Some([1].as_slice())
    );
    assert_eq!(
        store.get_outgoing_barrier(&context, domain(81)).unwrap(),
        OutgoingBarrier::Unsealed
    );
}

#[test]
fn successor_seal_completion_rejects_foreign_physical_validator_with_positive_control() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(83, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(83),
        progress: progress(),
    };
    // Positive control: retention commits under the genuine physical
    // validator that activated this namespace.
    let retention_token = store.begin_portable_snapshot(&context, domain(83)).unwrap();
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &retention_token,
            successor_state_write(domain(83), b"cut", 1, StateRevision::INITIAL),
        ),
        DurableCommitOutcome::Committed
    );
    // Negative: the physical namespace validator is re-bound to a foreign
    // identity; the installed record, lifecycle and slot are untouched.
    let foreign_validator: ValidatorId = ValidatorId::new([99; 32]);
    store.inner.write().unwrap().successor_namespace_validator = Some(foreign_validator);
    let completion_token = store.begin_portable_snapshot(&context, domain(83)).unwrap();
    let sealed = successor_sealed(84);
    let before: MemorySealState = memory_seal_state(&store);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &completion_token,
            successor_stateful_invocation(domain(83), &sealed, b"cut", 2, StateRevision::new(1)),
            sealed,
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict)
    );
    assert_eq!(memory_seal_state(&store), before);
    assert_eq!(
        store.get_outgoing_barrier(&context, domain(83)).unwrap(),
        OutgoingBarrier::Unsealed
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, domain(83), b"cut")
            .unwrap()
            .value(),
        Some([1].as_slice())
    );
    assert!(
        store
            .get_request_receipt(
                &context,
                domain(83),
                DurableRequestId::new(sealed.request).unwrap()
            )
            .unwrap()
            .is_none()
    );
    store.inner.write().unwrap().successor_namespace_validator = Some(validator);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &completion_token,
            successor_stateful_invocation(domain(83), &sealed, b"cut", 2, StateRevision::new(1)),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_retention_rejects_stale_cas_revision_with_positive_control() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(85, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(85),
        progress: progress(),
    };
    // Positive control: establishes the key at revision 1 through the
    // ordinary successor durable path.
    assert_eq!(
        store.commit_successor_durable(
            &context,
            &observation,
            successor_state_write(domain(85), b"cut", 1, StateRevision::INITIAL),
        ),
        DurableCommitOutcome::Committed
    );
    let token = store.begin_portable_snapshot(&context, domain(85)).unwrap();
    let before: MemorySealState = memory_seal_state(&store);
    // Negative: retention asserts the stale INITIAL revision though the
    // real current revision is already 1; a true CAS conflict, not a
    // token or lifecycle problem.
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &token,
            successor_state_write(domain(85), b"cut", 2, StateRevision::INITIAL),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
            key: b"cut".to_vec(),
            current_revision: StateRevision::new(1),
        })
    );
    assert_eq!(memory_seal_state(&store), before);
    assert_eq!(
        store
            .get_versioned_durable(&context, domain(85), b"cut")
            .unwrap()
            .value(),
        Some([1].as_slice())
    );
    assert_eq!(
        store.get_outgoing_barrier(&context, domain(85)).unwrap(),
        OutgoingBarrier::Unsealed
    );
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &token,
            successor_state_write(domain(85), b"cut", 2, StateRevision::new(1)),
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_completion_positive_control_vs_preexisting_outbox_inventory() {
    let validator = ValidatorId::new([42; 32]);

    // Positive control: a clean store with no pre-existing outbox commits.
    let (clean_store, clean_record) = activate(86, validator, 1);
    let clean_observation = SuccessorServingObservation {
        record: clean_record,
        binding: binding(86),
        progress: progress(),
    };
    let clean_context = operation(1);
    let clean_sealed = successor_sealed(87);
    let clean_token = clean_store
        .begin_portable_snapshot(&clean_context, domain(86))
        .unwrap();
    assert_eq!(
        clean_store.commit_successor_seal_retention(
            &clean_context,
            &clean_observation,
            &clean_token,
            successor_state_write(domain(86), b"retention", 1, StateRevision::INITIAL),
        ),
        DurableCommitOutcome::Committed
    );
    let clean_token: PortableSnapshotToken = clean_store
        .begin_portable_snapshot(&clean_context, domain(86))
        .unwrap();
    assert_eq!(
        clean_store.commit_successor_seal_completion(
            &clean_context,
            &clean_observation,
            &clean_token,
            successor_stateful_invocation(
                domain(86),
                &clean_sealed,
                b"cut",
                2,
                StateRevision::INITIAL
            ),
            clean_sealed,
        ),
        DurableCommitOutcome::Committed
    );

    // Negative: a pending, uncompleted, nonempty outbox row is already
    // installed in storage from an earlier unrelated invocation; the Seal
    // completion transaction itself carries no outbox at all, yet the
    // pre-existing inventory still blocks it.
    let (store, record_bytes) = activate(88, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(88),
        progress: progress(),
    };
    let pending_sealed = successor_sealed(89);
    let pending_request_id = DurableRequestId::new(pending_sealed.request).unwrap();
    let pending_event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x5A; 32]);
    let pending_receipt =
        DurableRequestReceipt::new(pending_request_id, pending_event_digest, vec![1]).unwrap();
    let pending_message = DurableOutboxMessage::new(
        Digest32::new(HashAlgorithmId::Sha2_256, [0x5B; 32]),
        vec![9],
    )
    .unwrap();
    let pending_outbox = DurableOutboxBatch::new(
        pending_request_id,
        pending_event_digest,
        vec![pending_message],
    )
    .unwrap();
    let pending_invocation = DurableInvocationTransaction::new(
        domain(88),
        None,
        DurableObjectChanges::empty(),
        pending_receipt,
        Some(pending_outbox),
    )
    .unwrap();
    assert_eq!(
        store.commit_successor_invocation(&context, &observation, pending_invocation),
        DurableCommitOutcome::Committed
    );

    let sealed = successor_sealed(90);
    let token = store.begin_portable_snapshot(&context, domain(88)).unwrap();
    assert_memory_seal_rejection(
        &store,
        DurableCommitRejection::InvalidPersistedState,
        || {
            store.commit_successor_seal_retention(
                &context,
                &observation,
                &token,
                successor_state_write(domain(88), b"retention", 1, StateRevision::INITIAL),
            )
        },
    );
    let before: MemorySealState = memory_seal_state(&store);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            successor_stateful_invocation(domain(88), &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(memory_seal_state(&store), before);
    assert_eq!(
        store.get_outgoing_barrier(&context, domain(88)).unwrap(),
        OutgoingBarrier::Unsealed
    );
    assert!(
        store
            .get_request_receipt(
                &context,
                domain(88),
                DurableRequestId::new(sealed.request).unwrap()
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn successor_seal_completion_rejects_object_changes() {
    let validator = ValidatorId::new([42; 32]);
    let (store, record_bytes) = activate(76, validator, 1);
    let context = operation(1);
    let observation = SuccessorServingObservation {
        record: record_bytes,
        binding: binding(76),
        progress: progress(),
    };
    let object_id = ObjectId::new([77; 32]);
    let version = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::new(1).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [78; 32]),
        1,
        DurableObjectProvenance::new(
            binding(76).context.chain_id.clone(),
            binding(76).context.protocol_version,
        ),
        0,
        Digest32::new(HashAlgorithmId::Sha2_256, [79; 32]),
    );
    let changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            object_id,
            DurableObjectMutation::Create {
                version,
                owner_projection: Default::default(),
                routing_projection: Default::default(),
            },
        )],
    )
    .unwrap();
    let sealed = successor_sealed(80);
    let invocation = DurableInvocationTransaction::new(
        domain(76),
        None,
        changes,
        DurableRequestReceipt::new(
            DurableRequestId::new(sealed.request).unwrap(),
            Digest32::new(HashAlgorithmId::Sha2_256, [0xAB; 32]),
            vec![1],
        )
        .unwrap(),
        None,
    )
    .unwrap();
    let token = store.begin_portable_snapshot(&context, domain(76)).unwrap();
    let before: MemorySealState = memory_seal_state(&store);
    assert_eq!(
        store.commit_successor_seal_completion(&context, &observation, &token, invocation, sealed),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(memory_seal_state(&store), before);
}
