//! DR-0189 file-backed activation and live successor-serving coverage for
//! the actual permanent-origin facade, SqliteImportTarget. These tests
//! drive real create/begin_import/finish_import to CompleteInactive, then
//! exercise commit_successor_activation/durable/invocation against a real
//! SQLite file across close/reopen. The installed record is raw
//! continuity data only; it is a synthetic test value, never crypto
//! authority, matching the runtime crate contract.
use super::*;
use protocol_types::{ChainId, Epoch, ExecutionGeneration, HashAlgorithmId, ProtocolVersion};
use runtime::successor_serving::{
    SuccessorServingObservation, SuccessorServingRecord, SuccessorServingRepository,
    SuccessorServingSlot, encode_successor_serving_record,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, DurableCommitRejection, DurableObjectChanges,
    ImportContext, StateMutation, StateMutationEntry, StateReadAssertion, StateRevision,
    StorageCorrelationId, StorageDeadline,
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
struct Database(PathBuf);
impl Database {
    fn new() -> Self {
        let nonce: u64 = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let time: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "sunrise-successor-activation-{}-{time}-{nonce}.db",
            std::process::id()
        )))
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.0.as_os_str().to_owned();
            path.push(suffix);
            match std::fs::remove_file(PathBuf::from(path)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("{error}"),
            }
        }
    }
}

fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

const BOUND_VALIDATOR_BYTES: [u8; 32] = [0x61; 32];

fn pin() -> ImportBinding {
    ImportBinding {
        context: ImportContext {
            chain_id: ChainId::new("sqlite-successor-activation").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(7),
        },
        domain: AtomicityDomainId::new([21; 32]).unwrap(),
        genesis_digest: digest(1),
        validator_set_digest: digest(2),
        cut_digest: digest(3),
        package_digest: digest(4),
        plan_digest: digest(5),
        row_count: 0,
        blob_count: 0,
        generation_floor: ExecutionGeneration::new(11),
    }
}

fn namespace(binding: &ImportBinding) -> SqliteNamespace {
    SqliteNamespace::new(
        binding.context.chain_id.clone(),
        ValidatorId::new(BOUND_VALIDATOR_BYTES),
        binding.domain,
    )
}

fn operation(fence: u64) -> DurableOperationContext {
    let now: u64 = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    DurableOperationContext::new(
        WriterFenceGeneration::new(fence).unwrap(),
        StorageDeadline::new(now.checked_add(60_000).unwrap()).unwrap(),
        StorageCorrelationId::new([5; 16]).unwrap(),
    )
}

fn initial() -> ImportProgress {
    ImportProgress {
        next_ordinal: 0,
        last_batch_digest: None,
        accumulator: digest(6),
    }
}
fn receipt(byte: u8) -> DurableRequestReceipt {
    DurableRequestReceipt::new(
        DurableRequestId::new([byte; 32]).unwrap(),
        digest(byte),
        vec![0x44; 4],
    )
    .unwrap()
}

/// Drives a real file-backed facade through create/begin_import/finish_import
/// with zero rows, reaching CompleteInactive, and returns the file, target,
/// operation context and the fresh snapshot token observed immediately after
/// CompleteInactive (the activation callers own observe_complete analog).
fn complete_inactive_store(
    fence: u64,
) -> (
    Database,
    SqliteImportTarget,
    DurableOperationContext,
    PortableSnapshotToken,
    PortableSnapshotToken,
) {
    let db = Database::new();
    let binding = pin();
    let context = operation(fence);
    let store =
        SqliteImportTarget::create(&db.0, namespace(&binding), context.writer_fence(), &binding)
            .unwrap();
    assert_eq!(
        store.begin_import(&context, binding.domain, &binding, initial().accumulator),
        DurableCommitOutcome::Committed
    );
    let pre_finish_token = store.begin_portable_snapshot(&context, binding.domain).unwrap();
    assert_eq!(
        store.finish_import(&context, binding.domain, &binding, &initial(), &pre_finish_token),
        DurableCommitOutcome::Committed
    );
    let fresh_token = store.begin_portable_snapshot(&context, binding.domain).unwrap();
    (db, store, context, fresh_token, pre_finish_token)
}
fn valid_record(token: &PortableSnapshotToken) -> SuccessorServingRecord {
    SuccessorServingRecord {
        subject: digest(30),
        manifest: digest(31),
        binding: pin(),
        progress: initial(),
        activation_token: token.clone(),
        anchor: digest(32),
        validator: ValidatorId::new(BOUND_VALIDATOR_BYTES),
        public_key: [33; 32],
    }
}
fn activation_transaction(
    domain: AtomicityDomainId,
    receipt_byte: u8,
    key: &[u8],
    value: u8,
) -> DurableInvocationTransaction {
    let state = runtime::DurableStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![StateMutationEntry::new(key.to_vec(), StateMutation::Put(vec![value])).unwrap()],
    )
    .unwrap();
    DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::empty(),
        receipt(receipt_byte),
        None,
    )
    .unwrap()
}
fn ordinary_write(domain: AtomicityDomainId) -> AtomicStateTransaction {
    AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"forbidden".to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(b"forbidden".to_vec(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap()
}

fn durable_write(domain: AtomicityDomainId, key: &[u8], value: u8) -> AtomicStateTransaction {
    AtomicStateTransaction::new(
        domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.to_vec(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key.to_vec(), StateMutation::Put(vec![value])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn activation_commits_persists_across_reopen_and_then_refuses_retry() {
    let (db, store, context, fresh_token, stale_token) = complete_inactive_store(41);
    let binding = pin();
    let record_value = valid_record(&fresh_token);
    let record_bytes = encode_successor_serving_record(&record_value).unwrap();
    let stale_record = encode_successor_serving_record(&valid_record(&stale_token)).unwrap();
    assert_eq!(
        store.commit_successor_activation(
            &context,
            binding.domain,
            &binding,
            &initial(),
            &stale_token,
            &stale_record,
            activation_transaction(binding.domain, 60, b"stale-attempt-key", 6),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(
        store.get_successor_serving(&context, binding.domain).unwrap(),
        SuccessorServingSlot::Inactive
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, binding.domain, b"stale-attempt-key")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
    let outcome = store.commit_successor_activation(
        &context,
        binding.domain,
        &binding,
        &initial(),
        &fresh_token,
        &record_bytes,
        activation_transaction(binding.domain, 61, b"activation-key", 7),
    );
    assert_eq!(outcome, DurableCommitOutcome::Committed);

    let slot = store.get_successor_serving(&context, binding.domain).unwrap();
    match &slot {
        SuccessorServingSlot::Serving(observation) => {
            assert_eq!(observation.record, record_bytes);
            assert_eq!(observation.binding, binding);
            assert_eq!(observation.progress, initial());
        }
        SuccessorServingSlot::Inactive => panic!("expected Serving after activation"),
    }
    assert_eq!(
        store
            .get_versioned_durable(&context, binding.domain, b"activation-key")
            .unwrap()
            .value(),
        Some([7].as_slice())
    );
    assert_eq!(
        store
            .get_request_receipt(&context, binding.domain, receipt(61).request_id())
            .unwrap(),
        Some(receipt(61))
    );
    drop(store);

    let reopened = SqliteImportTarget::open_existing(&db.0, namespace(&binding), &binding).unwrap();
    let reopened_slot = reopened
        .get_successor_serving(&context, binding.domain)
        .unwrap();
    assert_eq!(reopened_slot, slot);
    assert_eq!(
        reopened
            .get_versioned_durable(&context, binding.domain, b"activation-key")
            .unwrap()
            .value(),
        Some([7].as_slice())
    );

    let retry_token = reopened
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let retry = reopened.commit_successor_activation(
        &context,
        binding.domain,
        &binding,
        &initial(),
        &retry_token,
        &record_bytes,
        activation_transaction(binding.domain, 62, b"activation-key-2", 8),
    );
    assert_eq!(
        retry,
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
    assert_eq!(
        reopened
            .get_versioned_durable(&context, binding.domain, b"activation-key-2")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
    assert_eq!(
        reopened
            .get_request_receipt(&context, binding.domain, receipt(62).request_id())
            .unwrap(),
        None
    );
}
fn activate(
    store: &SqliteImportTarget,
    context: &DurableOperationContext,
    fresh_token: &PortableSnapshotToken,
    receipt_byte: u8,
) -> SuccessorServingObservation {
    let binding = pin();
    let record_value = valid_record(fresh_token);
    let record_bytes = encode_successor_serving_record(&record_value).unwrap();
    let outcome = store.commit_successor_activation(
        context,
        binding.domain,
        &binding,
        &initial(),
        fresh_token,
        &record_bytes,
        activation_transaction(binding.domain, receipt_byte, b"activation-only-key", 1),
    );
    assert_eq!(outcome, DurableCommitOutcome::Committed);
    SuccessorServingObservation {
        record: record_bytes,
        binding,
        progress: initial(),
    }
}
#[test]
fn successor_durable_and_invocation_apply_and_reject_mismatch() {
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(42);
    let binding = pin();
    let observation = activate(&store, &context, &fresh_token, 71);

    let wrong_observation = SuccessorServingObservation {
        record: vec![0xEE; 4],
        binding: binding.clone(),
        progress: initial(),
    };
    assert_eq!(
        store.commit_successor_durable(
            &context,
            &wrong_observation,
            durable_write(binding.domain, b"durable-key", 2),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict)
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, binding.domain, b"durable-key")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );

    assert_eq!(
        store.commit_successor_durable(
            &context,
            &observation,
            durable_write(binding.domain, b"durable-key", 2),
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, binding.domain, b"durable-key")
            .unwrap()
            .value(),
        Some([2].as_slice())
    );
}
fn object_create_changes(object_id: ObjectId) -> DurableObjectChanges {
    let version = DurableObjectVersionRecord::from_blob_reference(
        object_id,
        DurableObjectVersion::new(1).unwrap(),
        digest(80),
        1,
        runtime::DurableObjectProvenance::new(pin().context.chain_id.clone(), pin().context.protocol_version),
        0,
        digest(81),
    );
    DurableObjectChanges::new(
        vec![runtime::DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![runtime::DurableObjectMutationEntry::new(
            object_id,
            runtime::DurableObjectMutation::Create {
                version,
                owner_projection: Default::default(),
                routing_projection: Default::default(),
            },
        )],
    )
    .unwrap()
}

fn invocation_with_objects_and_outbox(
    domain: AtomicityDomainId,
    receipt_byte: u8,
    object_id: ObjectId,
) -> DurableInvocationTransaction {
    let receipt_value = receipt(receipt_byte);
    let outbox_message = runtime::DurableOutboxMessage::new(digest(90), vec![0x55; 3]).unwrap();
    let outbox = runtime::DurableOutboxBatch::new(
        receipt_value.request_id(),
        receipt_value.event_digest(),
        vec![outbox_message],
    )
    .unwrap();
    DurableInvocationTransaction::new(
        domain,
        None,
        object_create_changes(object_id),
        receipt_value,
        Some(outbox),
    )
    .unwrap()
}
#[test]
fn successor_invocation_applies_objects_outbox_and_persists_across_reopen() {
    let (db, store, context, fresh_token, _stale_token) = complete_inactive_store(43);
    let binding = pin();
    let observation = activate(&store, &context, &fresh_token, 72);
    let object_id = ObjectId::new([55; 32]);

    let wrong_observation = SuccessorServingObservation {
        record: vec![0xAB; 4],
        binding: binding.clone(),
        progress: initial(),
    };
    assert_eq!(
        store.commit_successor_invocation(
            &context,
            &wrong_observation,
            invocation_with_objects_and_outbox(binding.domain, 73, object_id),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict)
    );

    assert_eq!(
        store.commit_successor_invocation(
            &context,
            &observation,
            invocation_with_objects_and_outbox(binding.domain, 73, object_id),
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.get_request_receipt(&context, binding.domain, receipt(73).request_id()).unwrap(),
        Some(receipt(73))
    );
    assert!(matches!(
        store.get_object_head(&context, binding.domain, object_id).unwrap(),
        DurableObjectHead::Current { .. }
    ));

    drop(store);
    let reopened = SqliteImportTarget::open_existing(&db.0, namespace(&binding), &binding).unwrap();
    assert!(matches!(
        reopened.get_object_head(&context, binding.domain, object_id).unwrap(),
        DurableObjectHead::Current { .. }
    ));
    assert_eq!(
        reopened.get_request_receipt(&context, binding.domain, receipt(73).request_id()).unwrap(),
        Some(receipt(73))
    );
    assert_eq!(
        reopened.commit_successor_invocation(
            &context,
            &observation,
            invocation_with_objects_and_outbox(binding.domain, 73, object_id),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );
}
#[test]
fn activation_rejects_wrong_binding_and_wrong_validator() {
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(44);
    let binding = pin();

    let mut wrong_binding = binding.clone();
    wrong_binding.row_count = 5;
    let wrong_binding_record =
        encode_successor_serving_record(&valid_record(&fresh_token)).unwrap();
    assert_eq!(
        store.commit_successor_activation(
            &context,
            binding.domain,
            &wrong_binding,
            &initial(),
            &fresh_token,
            &wrong_binding_record,
            activation_transaction(binding.domain, 63, b"wrong-binding-key", 1),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportBindingMismatch)
    );

    let mut mismatched_record = valid_record(&fresh_token);
    mismatched_record.validator = ValidatorId::new([0x99; 32]);
    let mismatched_bytes = encode_successor_serving_record(&mismatched_record).unwrap();
    assert_eq!(
        store.commit_successor_activation(
            &context,
            binding.domain,
            &binding,
            &initial(),
            &fresh_token,
            &mismatched_bytes,
            activation_transaction(binding.domain, 64, b"wrong-validator-key", 1),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict)
    );
    assert_eq!(
        store.get_successor_serving(&context, binding.domain).unwrap(),
        SuccessorServingSlot::Inactive
    );
}
#[test]
fn ordinary_ports_refuse_both_inactive_and_serving_imported_origin() {
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(45);
    let binding = pin();

    assert_eq!(
        store.commit_durable(&context, ordinary_write(binding.domain)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );

    let _observation = activate(&store, &context, &fresh_token, 65);

    assert_eq!(
        store.commit_durable(&context, ordinary_write(binding.domain)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
    let invocation = DurableInvocationTransaction::new(
        binding.domain,
        None,
        DurableObjectChanges::empty(),
        receipt(66),
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(&context, invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
}
#[test]
fn only_import_target_exposes_successor_serving_repository() {
    let (db, store, context, fresh_token, _stale_token) = complete_inactive_store(46);
    let binding = pin();
    assert!(
        SuccessorServingRepository::read_namespace_validator(&store, &context, binding.domain)
            .is_ok()
    );
    let _ = activate(&store, &context, &fresh_token, 67);
    drop(store);

    assert!(matches!(
        SqliteDurableStore::open_existing(&db.0, namespace(&binding)),
        Err(SqliteDurableStoreError::InactiveNamespace)
    ));
}
