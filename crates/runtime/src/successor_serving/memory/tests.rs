use super::*;
use crate::inactive_import::ImportContext;
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
    let store = MemoryDurableStateStore::new_bound(domain(6), WriterFenceGeneration::new(1).unwrap());
    let bogus_observation = SuccessorServingObservation {
        record: vec![0xAA; 4],
        binding: binding(6),
        progress: progress(),
    };
    store.inner.write().unwrap().successor_serving =
        SuccessorServingSlot::Serving(bogus_observation);

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
fn complete_inactive_store(byte: u8, validator: ValidatorId, fence: u64) -> MemoryDurableStateStore {
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
