//! DR-0189 file-backed activation and live successor-serving coverage for
//! the actual permanent-origin facade, SqliteImportTarget. These tests
//! drive real create/begin_import/finish_import to CompleteInactive, then
//! exercise commit_successor_activation/durable/invocation against a real
//! SQLite file across close/reopen. The installed record is raw
//! continuity data only; it is a synthetic test value, never crypto
//! authority, matching the runtime crate contract.
use super::*;
use protocol_types::{ChainId, Epoch, ExecutionGeneration, HashAlgorithmId, ProtocolVersion};
use runtime::OutgoingSealRepository;
use runtime::successor_serving::{
    SuccessorServingObservation, SuccessorServingRecord, SuccessorServingRepository,
    SuccessorServingSlot, decode_successor_serving_record, encode_successor_serving_record,
    encode_successor_serving_slot,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, DurableCommitRejection, DurableObjectChanges,
    ImportContext, OutgoingBarrier, SealBarrier, StateMutation, StateMutationEntry,
    StateReadAssertion, StateRevision, StorageCorrelationId, StorageDeadline,
    TransitionHistoryState,
};
use runtime_sql_durable::{SqlBackendError, SqlSession, SqlSessionError};
use rusqlite::OptionalExtension;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
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

/// Compares every structured row and physical revision, including namespace
/// origin, sequence, permanent barrier, receipts and delivery inventory.
#[derive(Debug, PartialEq)]
struct SqliteSealState(Vec<Vec<Vec<rusqlite::types::Value>>>);

fn sqlite_seal_state(db: &Database) -> SqliteSealState {
    let mut connection: Connection = Connection::open(&db.0).unwrap();
    let transaction: rusqlite::Transaction<'_> = connection.transaction().unwrap();
    let mut tables: Vec<Vec<Vec<rusqlite::types::Value>>> = Vec::new();
    for sql in [
        "SELECT * FROM durable_metadata ORDER BY id",
        "SELECT * FROM durable_import_progress ORDER BY id",
        "SELECT * FROM durable_outgoing_barrier ORDER BY id",
        "SELECT * FROM durable_successor_serving ORDER BY id",
        "SELECT * FROM durable_state ORDER BY key",
        "SELECT * FROM durable_conditional_readiness ORDER BY slot",
        "SELECT * FROM durable_object_heads ORDER BY object_id",
        "SELECT * FROM durable_object_versions ORDER BY object_id, object_version",
        "SELECT * FROM durable_receipts ORDER BY request_id",
        "SELECT * FROM durable_outbox_messages ORDER BY request_id, message_index",
        "SELECT * FROM durable_outbox_delivery ORDER BY request_id",
        "SELECT * FROM durable_outbox_attempts ORDER BY lease_id",
    ] {
        let mut statement: rusqlite::Statement<'_> = transaction.prepare(sql).unwrap();
        let columns: usize = statement.column_count();
        let rows: Vec<Vec<rusqlite::types::Value>> = statement
            .query_map([], |row| {
                let values: Result<Vec<rusqlite::types::Value>, rusqlite::Error> =
                    (0..columns).map(|index| row.get(index)).collect();
                values
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        tables.push(rows);
    }
    SqliteSealState(tables)
}

fn assert_sqlite_seal_rejection(
    db: &Database,
    reason: DurableCommitRejection,
    invoke: impl FnOnce() -> DurableCommitOutcome,
) {
    let before: SqliteSealState = sqlite_seal_state(db);
    assert_eq!(invoke(), DurableCommitOutcome::Rejected(reason));
    assert_eq!(sqlite_seal_state(db), before);
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
    let pre_finish_token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    assert_eq!(
        store.finish_import(
            &context,
            binding.domain,
            &binding,
            &initial(),
            &pre_finish_token
        ),
        DurableCommitOutcome::Committed
    );
    let fresh_token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
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
    durable_write_at(domain, key, value, StateRevision::INITIAL)
}

fn durable_write_at(
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
        store
            .get_successor_serving(&context, binding.domain)
            .unwrap(),
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

    let slot = store
        .get_successor_serving(&context, binding.domain)
        .unwrap();
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
    let retry_record: Vec<u8> =
        encode_successor_serving_record(&valid_record(&retry_token)).unwrap();
    let retry = reopened.commit_successor_activation(
        &context,
        binding.domain,
        &binding,
        &initial(),
        &retry_token,
        &retry_record,
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
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
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
        runtime::DurableObjectProvenance::new(
            pin().context.chain_id.clone(),
            pin().context.protocol_version,
        ),
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
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
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
        store
            .get_request_receipt(&context, binding.domain, receipt(73).request_id())
            .unwrap(),
        Some(receipt(73))
    );
    assert!(matches!(
        store
            .get_object_head(&context, binding.domain, object_id)
            .unwrap(),
        DurableObjectHead::Current { .. }
    ));

    drop(store);
    let reopened = SqliteImportTarget::open_existing(&db.0, namespace(&binding), &binding).unwrap();
    assert!(matches!(
        reopened
            .get_object_head(&context, binding.domain, object_id)
            .unwrap(),
        DurableObjectHead::Current { .. }
    ));
    assert_eq!(
        reopened
            .get_request_receipt(&context, binding.domain, receipt(73).request_id())
            .unwrap(),
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
    let mut wrong_binding_value: SuccessorServingRecord = valid_record(&fresh_token);
    wrong_binding_value.binding = wrong_binding.clone();
    let wrong_binding_record: Vec<u8> =
        encode_successor_serving_record(&wrong_binding_value).unwrap();
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
        store
            .get_successor_serving(&context, binding.domain)
            .unwrap(),
        SuccessorServingSlot::Inactive
    );
}
fn ordinary_port_invocation(
    selected: AtomicityDomainId,
    receipt_byte: u8,
    expected: StateRevision,
    with_message: bool,
) -> DurableInvocationTransaction {
    let base: DurableInvocationTransaction = invocation_with_objects_and_outbox(
        selected,
        receipt_byte,
        ObjectId::new([receipt_byte; 32]),
    );
    let state: runtime::DurableStateTransaction =
        durable_write_at(selected, b"ordinary-port", 9, expected).into();
    let outbox: runtime::DurableOutboxBatch = if with_message {
        base.outbox().unwrap().clone()
    } else {
        runtime::DurableOutboxBatch::new(
            base.receipt().request_id(),
            base.receipt().event_digest(),
            Vec::new(),
        )
        .unwrap()
    };
    DurableInvocationTransaction::new(
        selected,
        Some(state),
        base.object_changes().clone(),
        base.receipt().clone(),
        Some(outbox),
    )
    .unwrap()
}

fn assert_sqlite_ordinary_ports_rejected(
    db: &Database,
    store: &dyn StructuredDurableDomainStateStore,
    context: &DurableOperationContext,
    selected: AtomicityDomainId,
    expected: StateRevision,
    reason: DurableCommitRejection,
) {
    assert_sqlite_seal_rejection(db, reason.clone(), || {
        store.commit_durable(
            context,
            durable_write_at(selected, b"ordinary-port", 9, expected),
        )
    });
    assert_sqlite_seal_rejection(db, reason, || {
        store.commit_invocation(
            context,
            ordinary_port_invocation(selected, 0xD1, expected, true),
        )
    });
}

#[test]
fn ordinary_ports_refuse_genuine_sqlite_import_phases_without_any_mutation() {
    let db: Database = Database::new();
    let mut binding: ImportBinding = pin();
    binding.row_count = 4;
    let context: DurableOperationContext = operation(71);
    let store: SqliteImportTarget =
        SqliteImportTarget::create(&db.0, namespace(&binding), context.writer_fence(), &binding)
            .unwrap();
    assert_eq!(
        store
            .get_namespace_lifecycle(&context, binding.domain)
            .unwrap(),
        NamespaceLifecycle::FreshImport(binding.clone())
    );
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &context,
        binding.domain,
        StateRevision::INITIAL,
        DurableCommitRejection::InactiveNamespace,
    );
    let expected: ImportProgress = initial();
    assert_eq!(
        store.begin_import(&context, binding.domain, &binding, expected.accumulator),
        DurableCommitOutcome::Committed
    );
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &context,
        binding.domain,
        StateRevision::INITIAL,
        DurableCommitRejection::InactiveNamespace,
    );
    let objects: DurableObjectChanges = object_create_changes(ObjectId::new([0xC0; 32]));
    let version: DurableObjectVersionRecord = match objects.mutations()[0].mutation() {
        runtime::DurableObjectMutation::Create { version, .. } => version.clone(),
        _ => panic!("fixture requires one Create"),
    };
    let batch: ImportBatch = ImportBatch::new(
        binding.clone(),
        expected,
        digest(7),
        digest(8),
        vec![
            runtime::ImportRow::State {
                key: b"ordinary-port".to_vec(),
                value: Some(vec![1]),
            },
            runtime::ImportRow::ObjectVersion(version.clone()),
            runtime::ImportRow::ObjectHead {
                object_id: version.object_id(),
                head: runtime::ImportObjectHead::Tombstoned {
                    last_object_version: version.object_version(),
                },
            },
            runtime::ImportRow::Receipt(receipt(0xC0)),
        ],
    )
    .unwrap();
    assert_eq!(
        store.commit_import_batch(&context, binding.domain, &batch),
        DurableCommitOutcome::Committed
    );
    let populated: SqliteSealState = sqlite_seal_state(&db);
    assert_eq!(populated.0[4].len(), 1);
    assert_eq!(populated.0[6].len(), 1);
    assert_eq!(populated.0[7].len(), 1);
    assert_eq!(populated.0[8].len(), 1);
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &context,
        binding.domain,
        StateRevision::new(1),
        DurableCommitRejection::InactiveNamespace,
    );
    let token: PortableSnapshotToken = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    assert_eq!(
        store.finish_import(&context, binding.domain, &binding, batch.next(), &token),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_namespace_lifecycle(&context, binding.domain)
            .unwrap(),
        NamespaceLifecycle::CompleteInactive {
            binding: binding.clone(),
            progress: batch.next().clone(),
        }
    );
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &context,
        binding.domain,
        StateRevision::new(1),
        DurableCommitRejection::InactiveNamespace,
    );

    let expired_and_fenced: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(72).unwrap(),
        StorageDeadline::new(1).unwrap(),
        StorageCorrelationId::new([0xA1; 16]).unwrap(),
    );
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &expired_and_fenced,
        AtomicityDomainId::new([0xFE; 32]).unwrap(),
        StateRevision::new(1),
        DurableCommitRejection::AtomicityDomainMismatch,
    );
    // SQL's initial deadline check precedes its schema/fence/phase checks.
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &expired_and_fenced,
        binding.domain,
        StateRevision::new(1),
        DurableCommitRejection::DeadlineExceededBeforeCommit,
    );
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &operation(72),
        binding.domain,
        StateRevision::new(1),
        DurableCommitRejection::WriterFenced {
            active_generation: context.writer_fence(),
        },
    );
    let before_reopen: SqliteSealState = sqlite_seal_state(&db);
    drop(store);
    let reopened: SqliteImportTarget =
        SqliteImportTarget::open_existing(&db.0, namespace(&binding), &binding).unwrap();
    assert_eq!(sqlite_seal_state(&db), before_reopen);
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &reopened,
        &context,
        binding.domain,
        StateRevision::new(1),
        DurableCommitRejection::InactiveNamespace,
    );
}

#[test]
fn ordinary_ports_preserve_sqlite_receipt_cas_and_genuine_seal_refusal_priority() {
    let db: Database = Database::new();
    let binding: ImportBinding = pin();
    let context: DurableOperationContext = operation(73);
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&db.0, namespace(&binding), context.writer_fence()).unwrap();
    let seed: DurableInvocationTransaction =
        ordinary_port_invocation(binding.domain, 0xC1, StateRevision::INITIAL, false);
    assert_eq!(
        store.commit_invocation(&context, seed),
        DurableCommitOutcome::Committed
    );
    let populated: SqliteSealState = sqlite_seal_state(&db);
    assert_eq!(populated.0[4].len(), 1);
    assert_eq!(populated.0[6].len(), 1);
    assert_eq!(populated.0[7].len(), 1);
    assert_eq!(populated.0[8].len(), 1);
    assert_eq!(populated.0[9].len(), 0);
    assert_eq!(populated.0[10].len(), 1);

    assert_sqlite_seal_rejection(&db, DurableCommitRejection::RequestAlreadyCommitted, || {
        store.commit_invocation(
            &context,
            ordinary_port_invocation(binding.domain, 0xC1, StateRevision::INITIAL, true),
        )
    });
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &context,
        binding.domain,
        StateRevision::INITIAL,
        DurableCommitRejection::Conflict {
            key: b"ordinary-port".to_vec(),
            current_revision: StateRevision::new(1),
        },
    );
    let token: PortableSnapshotToken = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let sealed: SealBarrier = sample_sealed(0xB0);
    assert_eq!(
        store.commit_seal_completion(
            &context,
            &token,
            stateful_sealed_invocation(
                binding.domain,
                &sealed,
                b"sealed",
                3,
                StateRevision::INITIAL
            ),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Sealed(sealed)
    );
    for expected in [StateRevision::new(1), StateRevision::INITIAL] {
        assert_sqlite_ordinary_ports_rejected(
            &db,
            &store,
            &context,
            binding.domain,
            expected,
            DurableCommitRejection::NamespaceSealed,
        );
    }
    assert_sqlite_seal_rejection(&db, DurableCommitRejection::NamespaceSealed, || {
        store.commit_invocation(
            &context,
            ordinary_port_invocation(binding.domain, 0xC1, StateRevision::INITIAL, true),
        )
    });
}

#[test]
fn ordinary_ports_refuse_both_inactive_and_serving_imported_origin() {
    let (db, store, context, fresh_token, _stale_token) = complete_inactive_store(45);
    let binding: ImportBinding = pin();

    assert_sqlite_seal_rejection(&db, DurableCommitRejection::InactiveNamespace, || {
        store.commit_durable(&context, ordinary_write(binding.domain))
    });
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &context,
        binding.domain,
        StateRevision::INITIAL,
        DurableCommitRejection::InactiveNamespace,
    );
    let observation: SuccessorServingObservation = activate(&store, &context, &fresh_token, 65);
    assert_sqlite_seal_rejection(&db, DurableCommitRejection::InactiveNamespace, || {
        store.commit_durable(&context, ordinary_write(binding.domain))
    });
    let original_invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        binding.domain,
        None,
        DurableObjectChanges::empty(),
        receipt(66),
        None,
    )
    .unwrap();
    assert_sqlite_seal_rejection(&db, DurableCommitRejection::InactiveNamespace, || {
        store.commit_invocation(&context, original_invocation)
    });
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &context,
        binding.domain,
        StateRevision::INITIAL,
        DurableCommitRejection::InactiveNamespace,
    );
    // Populate every invocation section through the actual successor port.
    let invocation: DurableInvocationTransaction =
        ordinary_port_invocation(binding.domain, 67, StateRevision::INITIAL, true);
    assert_eq!(
        store.commit_successor_invocation(&context, &observation, invocation),
        DurableCommitOutcome::Committed
    );
    let populated: SqliteSealState = sqlite_seal_state(&db);
    assert_eq!(populated.0[4].len(), 2);
    assert_eq!(populated.0[6].len(), 1);
    assert_eq!(populated.0[7].len(), 1);
    assert_eq!(populated.0[8].len(), 2);
    assert_eq!(populated.0[9].len(), 1);
    assert_eq!(populated.0[10].len(), 1);
    assert_sqlite_ordinary_ports_rejected(
        &db,
        &store,
        &context,
        binding.domain,
        StateRevision::new(1),
        DurableCommitRejection::InactiveNamespace,
    );
    // Even an occupied receipt and stale CAS stay behind the lifecycle refusal.
    assert_sqlite_seal_rejection(&db, DurableCommitRejection::InactiveNamespace, || {
        store.commit_invocation(
            &context,
            ordinary_port_invocation(binding.domain, 67, StateRevision::INITIAL, true),
        )
    });
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

#[test]
fn successor_reopen_refencing_preserves_record_and_rejects_the_old_writer() {
    let (db, store, context, token, _) = complete_inactive_store(51);
    let binding: ImportBinding = pin();
    let observation: SuccessorServingObservation = activate(&store, &context, &token, 81);
    drop(store);
    let reopened: SqliteImportTarget =
        SqliteImportTarget::open_existing(&db.0, namespace(&binding), &binding).unwrap();
    let next: DurableOperationContext = operation(52);
    reopened
        .advance_writer_fence(context.writer_fence(), next.writer_fence())
        .unwrap();
    assert_eq!(
        reopened.commit_successor_durable(
            &context,
            &observation,
            durable_write(binding.domain, b"old-writer", 3),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: next.writer_fence(),
        }),
    );
    assert_eq!(
        reopened
            .get_successor_serving(&next, binding.domain)
            .unwrap(),
        SuccessorServingSlot::Serving(Box::new(observation.clone())),
    );
    assert_eq!(
        reopened.commit_successor_durable(
            &next,
            &observation,
            durable_write(binding.domain, b"new-writer", 4),
        ),
        DurableCommitOutcome::Committed,
    );
    assert_eq!(
        reopened
            .get_versioned_durable(&next, binding.domain, b"old-writer")
            .unwrap()
            .revision(),
        StateRevision::INITIAL,
    );
}

#[test]
fn activation_checks_all_assertions_before_writing_a_record_or_receipt() {
    let (_db, store, context, token, _) = complete_inactive_store(53);
    let binding: ImportBinding = pin();
    let record: Vec<u8> = encode_successor_serving_record(&valid_record(&token)).unwrap();
    let key: &[u8] = b"asserted-key";
    let state: runtime::DurableStateTransaction = runtime::DurableStateTransaction::new(
        binding.domain,
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.to_vec(), StateRevision::new(1)).unwrap(),
        ])
        .unwrap(),
        vec![StateMutationEntry::new(key.to_vec(), StateMutation::Put(vec![5])).unwrap()],
    )
    .unwrap();
    let transaction: DurableInvocationTransaction = DurableInvocationTransaction::new(
        binding.domain,
        Some(state),
        DurableObjectChanges::empty(),
        receipt(82),
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_successor_activation(
            &context,
            binding.domain,
            &binding,
            &initial(),
            &token,
            &record,
            transaction,
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
            key: key.to_vec(),
            current_revision: StateRevision::INITIAL,
        }),
    );
    assert_eq!(
        store
            .begin_portable_snapshot(&context, binding.domain)
            .unwrap(),
        token
    );
    assert_eq!(
        store
            .get_successor_serving(&context, binding.domain)
            .unwrap(),
        SuccessorServingSlot::Inactive
    );
    assert!(
        store
            .get_request_receipt(&context, binding.domain, receipt(82).request_id())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .get_versioned_durable(&context, binding.domain, key)
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
}

#[test]
fn activation_refuses_a_foreign_physical_token_before_any_write() {
    let (_db, store, context, token, _) = complete_inactive_store(54);
    let (_other_db, other, _, other_token, _) = complete_inactive_store(54);
    let binding: ImportBinding = pin();
    assert_ne!(token.namespace(), other_token.namespace());
    let record: Vec<u8> = encode_successor_serving_record(&valid_record(&other_token)).unwrap();
    assert!(matches!(
        store.commit_successor_activation(
            &context,
            binding.domain,
            &binding,
            &initial(),
            &other_token,
            &record,
            activation_transaction(binding.domain, 83, b"foreign-source", 6),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState),
    ));
    assert_eq!(
        store
            .begin_portable_snapshot(&context, binding.domain)
            .unwrap(),
        token
    );
    assert_eq!(
        store
            .get_successor_serving(&context, binding.domain)
            .unwrap(),
        SuccessorServingSlot::Inactive
    );
    drop(other);
}

#[test]
fn successor_slot_missing_corrupt_or_unknown_phase_never_repairs_or_falls_back() {
    let inactive: Vec<u8> =
        runtime::encode_successor_serving_slot(&SuccessorServingSlot::Inactive).unwrap();
    let mut unknown: Vec<u8> = inactive.clone();
    unknown[16] = 3;
    let mut bad_length: Vec<u8> = inactive.clone();
    bad_length[20] = 1;
    for corrupt in [None, Some(vec![0; 16]), Some(unknown), Some(bad_length)] {
        let (db, store, context, _, _) = complete_inactive_store(55);
        let binding: ImportBinding = pin();
        let connection: Connection = Connection::open(&db.0).unwrap();
        match corrupt.as_ref() {
            Some(bytes) => {
                connection
                    .execute("UPDATE durable_successor_serving SET serving = ?1", [bytes])
                    .unwrap();
            }
            None => {
                connection
                    .execute("DELETE FROM durable_successor_serving", [])
                    .unwrap();
            }
        }
        assert_eq!(
            store.get_successor_serving(&context, binding.domain),
            Err(DurableReadError::SchemaMismatch)
        );
        assert_eq!(
            store.commit_durable(&context, ordinary_write(binding.domain)),
            DurableCommitOutcome::Rejected(DurableCommitRejection::SchemaMismatch)
        );
        drop(store);
        assert!(SqliteImportTarget::open_existing(&db.0, namespace(&binding), &binding).is_err());
        let persisted: Option<Vec<u8>> = connection
            .query_row("SELECT serving FROM durable_successor_serving", [], |row| {
                row.get(0)
            })
            .optional()
            .unwrap();
        assert_eq!(persisted, corrupt);
    }
}

struct LostActivationReply {
    inner: NativeSqlBackend,
    armed: AtomicBool,
    land: bool,
}

impl SqlBackend for LostActivationReply {
    fn transaction<T>(
        &self,
        budget: TransactionBudget,
        run: impl FnOnce(&mut dyn SqlSession, u64) -> Result<TransactionDecision<T>, SqlSessionError>,
    ) -> Result<T, SqlBackendError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            if self.land {
                let _: T = self.inner.transaction(budget, run)?;
            }
            return Err(SqlBackendError::CommitIndeterminate);
        }
        self.inner.transaction(budget, run)
    }
}

#[test]
fn activation_reply_loss_is_atomic_in_both_directions_and_observable_after_reopen() {
    for land in [false, true] {
        let (db, store, context, token, _) = complete_inactive_store(56);
        let binding: ImportBinding = pin();
        let record: Vec<u8> = encode_successor_serving_record(&valid_record(&token)).unwrap();
        drop(store);
        let connection: Connection = Connection::open(&db.0).unwrap();
        crate::native_connection::configure_writable(&connection).unwrap();
        let engine: SqlDurableEngine<LostActivationReply> = SqlDurableEngine::new(
            LostActivationReply {
                inner: NativeSqlBackend::new(connection),
                armed: AtomicBool::new(true),
                land,
            },
            namespace(&binding),
        );
        assert_eq!(
            engine.commit_successor_activation(
                &context,
                binding.domain,
                &binding,
                &initial(),
                &token,
                &record,
                activation_transaction(binding.domain, 84, b"reply-loss", 7),
            ),
            DurableCommitOutcome::Indeterminate(runtime::IndeterminateCommitReason::ConnectionLost),
        );
        drop(engine);
        let reopened: SqliteImportTarget =
            SqliteImportTarget::open_existing(&db.0, namespace(&binding), &binding).unwrap();
        let slot: SuccessorServingSlot = reopened
            .get_successor_serving(&context, binding.domain)
            .unwrap();
        assert_eq!(slot.is_serving(), land);
        assert_eq!(
            reopened
                .get_request_receipt(&context, binding.domain, receipt(84).request_id())
                .unwrap(),
            land.then(|| receipt(84))
        );
        let value: runtime::VersionedStateValue = reopened
            .get_versioned_durable(&context, binding.domain, b"reply-loss")
            .unwrap();
        assert_eq!(value.value(), land.then_some([7].as_slice()));
        let after: PortableSnapshotToken = reopened
            .begin_portable_snapshot(&context, binding.domain)
            .unwrap();
        assert_eq!(
            after.mutation_sequence(),
            token.mutation_sequence() + u64::from(land)
        );
        if !land {
            assert_eq!(
                reopened.commit_successor_activation(
                    &context,
                    binding.domain,
                    &binding,
                    &initial(),
                    &token,
                    &record,
                    activation_transaction(binding.domain, 84, b"reply-loss", 7),
                ),
                DurableCommitOutcome::Committed
            );
        }
    }
}

fn seal_request(byte: u8) -> [u8; 32] {
    let mut request = [byte; 32];
    request[0] |= 0x80;
    request
}

fn sample_sealed(byte: u8) -> SealBarrier {
    SealBarrier {
        outgoing_epoch: Epoch::new(8),
        request: seal_request(byte),
        height: 13,
        block_digest: digest(byte.wrapping_add(1)),
        target_digest: digest(byte.wrapping_add(2)),
        transition_history: TransitionHistoryState::Virgin,
    }
}

fn sealed_invocation(
    domain: AtomicityDomainId,
    sealed: &SealBarrier,
) -> DurableInvocationTransaction {
    let request_id = DurableRequestId::new(sealed.request).unwrap();
    let receipt_value = DurableRequestReceipt::new(request_id, digest(0xAB), vec![1]).unwrap();
    DurableInvocationTransaction::new(
        domain,
        None,
        DurableObjectChanges::empty(),
        receipt_value,
        None,
    )
    .unwrap()
}

fn stateful_sealed_invocation(
    domain: AtomicityDomainId,
    sealed: &SealBarrier,
    key: &[u8],
    value: u8,
    expected: StateRevision,
) -> DurableInvocationTransaction {
    let transaction: AtomicStateTransaction = durable_write_at(domain, key, value, expected);
    let section: runtime::DurableStateTransaction = transaction.into();
    DurableInvocationTransaction::new(
        domain,
        Some(section),
        DurableObjectChanges::empty(),
        sealed_invocation(domain, sealed).receipt().clone(),
        None,
    )
    .unwrap()
}

#[test]
fn successor_seal_rejects_wrong_binding_and_progress_with_deciding_positive_controls() {
    for wrong_progress in [false, true] {
        let (db, store, context, token, _) = complete_inactive_store(102);
        let binding: ImportBinding = pin();
        let observation: SuccessorServingObservation = activate(&store, &context, &token, 170);
        let mut wrong: SuccessorServingObservation = observation.clone();
        if wrong_progress {
            wrong.progress.accumulator = digest(0xFF);
        } else {
            wrong.binding.cut_digest = digest(0xFF);
        }
        let token: PortableSnapshotToken = store
            .begin_portable_snapshot(&context, binding.domain)
            .unwrap();
        assert_sqlite_seal_rejection(&db, DurableCommitRejection::ImportBindingMismatch, || {
            store.commit_successor_seal_retention(
                &context,
                &wrong,
                &token,
                durable_write(binding.domain, b"retention", 1),
            )
        });
        let sealed: SealBarrier = sample_sealed(171);
        assert_sqlite_seal_rejection(&db, DurableCommitRejection::ImportBindingMismatch, || {
            store.commit_successor_seal_completion(
                &context,
                &wrong,
                &token,
                stateful_sealed_invocation(
                    binding.domain,
                    &sealed,
                    b"completion",
                    2,
                    StateRevision::INITIAL,
                ),
                sealed,
            )
        });
        assert_eq!(
            store.commit_successor_seal_retention(
                &context,
                &observation,
                &token,
                durable_write(binding.domain, b"retention", 1),
            ),
            DurableCommitOutcome::Committed
        );
        let next: PortableSnapshotToken = store
            .begin_portable_snapshot(&context, binding.domain)
            .unwrap();
        assert_eq!(
            store.commit_successor_seal_completion(
                &context,
                &observation,
                &next,
                stateful_sealed_invocation(
                    binding.domain,
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
                .begin_portable_snapshot(&context, binding.domain)
                .unwrap()
                .mutation_sequence(),
            token.mutation_sequence() + 2
        );
    }
}

#[test]
fn successor_seal_completion_rejects_wrong_serving_epoch_without_any_mutation() {
    let (db, store, context, token, _) = complete_inactive_store(103);
    let binding: ImportBinding = pin();
    let observation: SuccessorServingObservation = activate(&store, &context, &token, 172);
    let token: PortableSnapshotToken = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let sealed: SealBarrier = sample_sealed(173);
    let mut wrong: SealBarrier = sealed;
    wrong.outgoing_epoch = Epoch::new(9);
    assert_sqlite_seal_rejection(&db, DurableCommitRejection::ImportConflict, || {
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            stateful_sealed_invocation(
                binding.domain,
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
            stateful_sealed_invocation(
                binding.domain,
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
fn successor_seal_completion_rejects_foreign_physical_validator_with_deciding_positive_control() {
    let (db, store, context, activation_token, _) = complete_inactive_store(104);
    let binding: ImportBinding = pin();
    let observation: SuccessorServingObservation =
        activate(&store, &context, &activation_token, 174);
    let mut record: SuccessorServingRecord =
        decode_successor_serving_record(&observation.record).unwrap();
    record.validator = ValidatorId::new([0xFF; 32]);
    let wrong: SuccessorServingObservation = SuccessorServingObservation {
        record: encode_successor_serving_record(&record).unwrap(),
        binding: observation.binding.clone(),
        progress: observation.progress.clone(),
    };
    let wrong_slot: Vec<u8> =
        encode_successor_serving_slot(&SuccessorServingSlot::Serving(Box::new(wrong.clone())))
            .unwrap();
    let connection: Connection = Connection::open(&db.0).unwrap();
    connection
        .execute(
            "UPDATE durable_successor_serving SET serving = ?1 WHERE id = 1",
            rusqlite::params![wrong_slot],
        )
        .unwrap();
    let token: PortableSnapshotToken = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let sealed: SealBarrier = sample_sealed(175);
    // Slot, lifecycle, token and CAS all match: only the physical validator
    // differs from the validator decoded from the exact installed record.
    assert_sqlite_seal_rejection(&db, DurableCommitRejection::ImportConflict, || {
        store.commit_successor_seal_completion(
            &context,
            &wrong,
            &token,
            stateful_sealed_invocation(
                binding.domain,
                &sealed,
                b"completion",
                2,
                StateRevision::INITIAL,
            ),
            sealed,
        )
    });
    let own_slot: Vec<u8> = encode_successor_serving_slot(&SuccessorServingSlot::Serving(
        Box::new(observation.clone()),
    ))
    .unwrap();
    connection
        .execute(
            "UPDATE durable_successor_serving SET serving = ?1 WHERE id = 1",
            rusqlite::params![own_slot],
        )
        .unwrap();
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            stateful_sealed_invocation(
                binding.domain,
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
fn successor_seal_retention_and_completion_reject_stale_cas_with_fresh_tokens() {
    let (db, store, context, activation_token, _) = complete_inactive_store(105);
    let binding: ImportBinding = pin();
    let observation: SuccessorServingObservation =
        activate(&store, &context, &activation_token, 176);
    assert_eq!(
        store.commit_successor_durable(
            &context,
            &observation,
            durable_write(binding.domain, b"cut", 1)
        ),
        DurableCommitOutcome::Committed
    );
    let token: PortableSnapshotToken = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let conflict: DurableCommitRejection = DurableCommitRejection::Conflict {
        key: b"cut".to_vec(),
        current_revision: StateRevision::new(1),
    };
    assert_sqlite_seal_rejection(&db, conflict.clone(), || {
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &token,
            durable_write(binding.domain, b"cut", 2),
        )
    });
    let sealed: SealBarrier = sample_sealed(177);
    assert_sqlite_seal_rejection(&db, conflict, || {
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            stateful_sealed_invocation(binding.domain, &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        )
    });
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &token,
            durable_write_at(binding.domain, b"cut", 2, StateRevision::new(1)),
        ),
        DurableCommitOutcome::Committed
    );
    let next: PortableSnapshotToken = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &next,
            stateful_sealed_invocation(binding.domain, &sealed, b"cut", 3, StateRevision::new(2)),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_completion_rejects_an_existing_empty_delivery_for_its_request() {
    let (db, store, context, activation_token, _) = complete_inactive_store(106);
    let binding: ImportBinding = pin();
    let observation: SuccessorServingObservation =
        activate(&store, &context, &activation_token, 178);
    let sealed: SealBarrier = sample_sealed(179);
    let connection: Connection = Connection::open(&db.0).unwrap();
    connection
        .execute(
            "INSERT INTO durable_outbox_delivery (
             request_id, message_count, next_message_index, completed,
             available_at_unix_millis, active_lease_id, lease_expires_at_unix_millis, attempt_count
         ) VALUES (?1, 0, 0, 1, ?2, NULL, NULL, ?2)",
            rusqlite::params![sealed.request.as_slice(), 0u64.to_be_bytes().as_slice()],
        )
        .unwrap();
    let token: PortableSnapshotToken = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    // Empty completed rows pass the inventory guard; this request-specific
    // orphan must still refuse before state, receipt or barrier changes.
    assert_sqlite_seal_rejection(&db, DurableCommitRejection::InvalidPersistedState, || {
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            stateful_sealed_invocation(binding.domain, &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        )
    });
    connection
        .execute(
            "DELETE FROM durable_outbox_delivery WHERE request_id = ?1",
            rusqlite::params![sealed.request.as_slice()],
        )
        .unwrap();
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            stateful_sealed_invocation(binding.domain, &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_completion_retains_an_explicitly_empty_outbox_across_reopen() {
    let (db, store, context, activation_token, _) = complete_inactive_store(107);
    let binding: ImportBinding = pin();
    let observation: SuccessorServingObservation =
        activate(&store, &context, &activation_token, 180);
    let token: PortableSnapshotToken = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let sealed: SealBarrier = sample_sealed(181);
    let base: DurableInvocationTransaction =
        stateful_sealed_invocation(binding.domain, &sealed, b"cut", 2, StateRevision::INITIAL);
    let receipt: DurableRequestReceipt = base.receipt().clone();
    let outbox: runtime::DurableOutboxBatch =
        runtime::DurableOutboxBatch::new(receipt.request_id(), receipt.event_digest(), Vec::new())
            .unwrap();
    let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        binding.domain,
        base.state().cloned(),
        DurableObjectChanges::empty(),
        receipt.clone(),
        Some(outbox),
    )
    .unwrap();
    assert_eq!(
        store.commit_successor_seal_completion(&context, &observation, &token, invocation, sealed),
        DurableCommitOutcome::Committed
    );
    drop(store);
    let reopened: SqliteImportTarget =
        SqliteImportTarget::open_existing(&db.0, namespace(&binding), &binding).unwrap();
    assert_eq!(
        reopened
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Sealed(sealed)
    );
    assert_eq!(
        reopened
            .get_successor_serving(&context, binding.domain)
            .unwrap()
            .serving(),
        Some(&observation)
    );
    assert_eq!(
        reopened
            .get_request_receipt(&context, binding.domain, receipt.request_id())
            .unwrap(),
        Some(receipt)
    );
    assert_eq!(
        reopened
            .get_versioned_durable(&context, binding.domain, b"cut")
            .unwrap()
            .value(),
        Some([2].as_slice())
    );
    assert_eq!(
        reopened
            .begin_portable_snapshot(&context, binding.domain)
            .unwrap()
            .mutation_sequence(),
        token.mutation_sequence() + 1
    );
    let connection: Connection = Connection::open(&db.0).unwrap();
    let delivery: (i64, i64, i64) = connection.query_row(
        "SELECT message_count, next_message_index, completed FROM durable_outbox_delivery WHERE request_id = ?1",
        rusqlite::params![sealed.request.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();
    assert_eq!(delivery, (0, 0, 1));
}

#[test]
fn successor_seal_completion_reply_loss_is_atomic_and_reconciles_after_reopen() {
    for land in [false, true] {
        let (db, store, context, activation_token, _) = complete_inactive_store(108);
        let binding: ImportBinding = pin();
        let observation: SuccessorServingObservation =
            activate(&store, &context, &activation_token, 182);
        let token: PortableSnapshotToken = store
            .begin_portable_snapshot(&context, binding.domain)
            .unwrap();
        let sealed: SealBarrier = sample_sealed(183);
        let before: SqliteSealState = sqlite_seal_state(&db);
        drop(store);
        let connection: Connection = Connection::open(&db.0).unwrap();
        crate::native_connection::configure_writable(&connection).unwrap();
        let engine: SqlDurableEngine<LostActivationReply> = SqlDurableEngine::new(
            LostActivationReply {
                inner: NativeSqlBackend::new(connection),
                armed: AtomicBool::new(true),
                land,
            },
            namespace(&binding),
        );
        assert_eq!(
            engine.commit_successor_seal_completion(
                &context,
                &observation,
                &token,
                stateful_sealed_invocation(
                    binding.domain,
                    &sealed,
                    b"reply-loss",
                    3,
                    StateRevision::INITIAL
                ),
                sealed,
            ),
            DurableCommitOutcome::Indeterminate(runtime::IndeterminateCommitReason::ConnectionLost)
        );
        drop(engine);
        let reopened: SqliteImportTarget =
            SqliteImportTarget::open_existing(&db.0, namespace(&binding), &binding).unwrap();
        assert_eq!(
            reopened
                .get_outgoing_barrier(&context, binding.domain)
                .unwrap(),
            if land {
                OutgoingBarrier::Sealed(sealed)
            } else {
                OutgoingBarrier::Unsealed
            }
        );
        assert_eq!(
            reopened
                .get_namespace_lifecycle(&context, binding.domain)
                .unwrap(),
            NamespaceLifecycle::CompleteInactive {
                binding: binding.clone(),
                progress: initial()
            }
        );
        assert_eq!(
            reopened
                .get_successor_serving(&context, binding.domain)
                .unwrap()
                .serving(),
            Some(&observation)
        );
        let request: DurableRequestId = DurableRequestId::new(sealed.request).unwrap();
        let expected_receipt: DurableRequestReceipt =
            sealed_invocation(binding.domain, &sealed).receipt().clone();
        assert_eq!(
            reopened
                .get_request_receipt(&context, binding.domain, request)
                .unwrap(),
            land.then_some(expected_receipt)
        );
        assert_eq!(
            reopened
                .get_versioned_durable(&context, binding.domain, b"reply-loss")
                .unwrap()
                .value(),
            land.then_some([3].as_slice())
        );
        assert_eq!(
            reopened
                .begin_portable_snapshot(&context, binding.domain)
                .unwrap()
                .mutation_sequence(),
            token.mutation_sequence() + u64::from(land)
        );
        if !land {
            assert_eq!(sqlite_seal_state(&db), before);
            assert_eq!(
                reopened.commit_successor_seal_completion(
                    &context,
                    &observation,
                    &token,
                    stateful_sealed_invocation(
                        binding.domain,
                        &sealed,
                        b"reply-loss",
                        3,
                        StateRevision::INITIAL
                    ),
                    sealed,
                ),
                DurableCommitOutcome::Committed
            );
        }
    }
}

#[test]
fn successor_seal_retention_and_completion_seal_the_barrier_and_persist_across_reopen() {
    let (db, store, context, fresh_token, _stale_token) = complete_inactive_store(90);
    let binding = pin();
    let observation = activate(&store, &context, &fresh_token, 150);

    let retention_token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &retention_token,
            durable_write(binding.domain, b"cut", 3),
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Unsealed
    );

    let completion_token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let sealed = sample_sealed(151);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &completion_token,
            sealed_invocation(binding.domain, &sealed),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Sealed(sealed)
    );

    drop(store);
    let reopened = SqliteImportTarget::open_existing(&db.0, namespace(&binding), &binding).unwrap();
    assert_eq!(
        reopened
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Sealed(sealed)
    );
    assert_eq!(
        reopened
            .get_versioned_durable(&context, binding.domain, b"cut")
            .unwrap()
            .value(),
        Some([3].as_slice())
    );

    let after_token = reopened
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    assert_eq!(
        reopened.commit_successor_seal_retention(
            &context,
            &observation,
            &after_token,
            runtime::AtomicStateTransaction::new(
                binding.domain,
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(b"cut".to_vec(), StateRevision::new(1)).unwrap(),
                ])
                .unwrap(),
                AtomicStateMutationSet::new(vec![
                    StateMutationEntry::new(b"cut".to_vec(), StateMutation::Put(vec![4])).unwrap(),
                ])
                .unwrap(),
            )
            .unwrap(),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::NamespaceSealed)
    );
    assert_eq!(
        reopened.commit_successor_durable(
            &context,
            &observation,
            durable_write(binding.domain, b"cut", 5),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::NamespaceSealed)
    );
}

#[test]
fn successor_seal_retention_rejects_stale_token_before_any_write() {
    let (_db, store, context, fresh_token, stale_token) = complete_inactive_store(91);
    let binding = pin();
    let observation = activate(&store, &context, &fresh_token, 152);
    let before: SqliteSealState = sqlite_seal_state(&_db);
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &stale_token,
            durable_write(binding.domain, b"stale-cut", 1),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(sqlite_seal_state(&_db), before);
    assert_eq!(
        store
            .get_versioned_durable(&context, binding.domain, b"stale-cut")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
    assert_eq!(
        store
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Unsealed
    );
}

#[test]
fn successor_seal_retention_rejects_lifecycle_binding_mismatch_with_positive_control() {
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(99);
    let binding = pin();
    let observation = activate(&store, &context, &fresh_token, 164);
    // Positive control: the real stored binding/progress commits.
    let token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &token,
            durable_write(binding.domain, b"cut", 1),
        ),
        DurableCommitOutcome::Committed
    );
    // Negative: an observation naming a different binding than the stored
    // CompleteInactive lifecycle (not merely a different record).
    let mut wrong_binding: ImportBinding = binding.clone();
    wrong_binding.row_count = 9;
    let mismatched_observation = SuccessorServingObservation {
        record: observation.record.clone(),
        binding: wrong_binding,
        progress: initial(),
    };
    let next_token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let before: SqliteSealState = sqlite_seal_state(&_db);
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &mismatched_observation,
            &next_token,
            durable_write_at(binding.domain, b"cut", 2, StateRevision::new(1)),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportBindingMismatch)
    );
    assert_eq!(sqlite_seal_state(&_db), before);
    assert_eq!(
        store
            .get_versioned_durable(&context, binding.domain, b"cut")
            .unwrap()
            .value(),
        Some([1].as_slice())
    );
    assert_eq!(
        store
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Unsealed
    );
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &next_token,
            durable_write_at(binding.domain, b"cut", 2, StateRevision::new(1)),
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_completion_positive_control_vs_preexisting_outbox_inventory() {
    let binding = pin();

    // Positive control: a clean store with no pre-existing outbox commits.
    let (_clean_db, clean_store, clean_context, clean_fresh_token, _) =
        complete_inactive_store(100);
    let clean_observation = activate(&clean_store, &clean_context, &clean_fresh_token, 165);
    let clean_sealed = sample_sealed(166);
    let clean_token = clean_store
        .begin_portable_snapshot(&clean_context, binding.domain)
        .unwrap();
    assert_eq!(
        clean_store.commit_successor_seal_retention(
            &clean_context,
            &clean_observation,
            &clean_token,
            durable_write(binding.domain, b"retention", 1),
        ),
        DurableCommitOutcome::Committed
    );
    let clean_token: PortableSnapshotToken = clean_store
        .begin_portable_snapshot(&clean_context, binding.domain)
        .unwrap();
    assert_eq!(
        clean_store.commit_successor_seal_completion(
            &clean_context,
            &clean_observation,
            &clean_token,
            stateful_sealed_invocation(
                binding.domain,
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
    // installed from an earlier unrelated invocation; the Seal completion
    // transaction itself carries no outbox at all, yet the pre-existing
    // inventory still blocks it.
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(101);
    let observation = activate(&store, &context, &fresh_token, 167);
    let pending_sealed = sample_sealed(168);
    let pending_request_id = DurableRequestId::new(pending_sealed.request).unwrap();
    let pending_event_digest = digest(0x5A);
    let pending_receipt =
        DurableRequestReceipt::new(pending_request_id, pending_event_digest, vec![1]).unwrap();
    let pending_message = runtime::DurableOutboxMessage::new(digest(0x5B), vec![9]).unwrap();
    let pending_outbox = runtime::DurableOutboxBatch::new(
        pending_request_id,
        pending_event_digest,
        vec![pending_message],
    )
    .unwrap();
    let pending_invocation = DurableInvocationTransaction::new(
        binding.domain,
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

    let sealed = sample_sealed(169);
    let token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    assert_sqlite_seal_rejection(&_db, DurableCommitRejection::InvalidPersistedState, || {
        store.commit_successor_seal_retention(
            &context,
            &observation,
            &token,
            durable_write(binding.domain, b"retention", 1),
        )
    });
    let before: SqliteSealState = sqlite_seal_state(&_db);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            stateful_sealed_invocation(binding.domain, &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(sqlite_seal_state(&_db), before);
    assert_eq!(
        store
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Unsealed
    );
    assert_eq!(
        store
            .get_request_receipt(
                &context,
                binding.domain,
                DurableRequestId::new(sealed.request).unwrap()
            )
            .unwrap(),
        None
    );
}

#[test]
fn successor_seal_completion_rejects_foreign_physical_token_before_any_write() {
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(92);
    let (_other_db, other_store, other_context, other_fresh_token, _) = complete_inactive_store(92);
    let binding = pin();
    let observation = activate(&store, &context, &fresh_token, 153);
    let _other_observation = activate(&other_store, &other_context, &other_fresh_token, 153);
    let foreign_token = other_store
        .begin_portable_snapshot(&other_context, binding.domain)
        .unwrap();
    let own_token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    assert_ne!(foreign_token.namespace(), own_token.namespace());
    let sealed = sample_sealed(154);
    let before: SqliteSealState = sqlite_seal_state(&_db);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &foreign_token,
            stateful_sealed_invocation(binding.domain, &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(sqlite_seal_state(&_db), before);
    assert_eq!(
        store
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Unsealed
    );
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &own_token,
            stateful_sealed_invocation(binding.domain, &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_retention_rejects_mismatched_observation_record() {
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(93);
    let binding = pin();
    let _observation = activate(&store, &context, &fresh_token, 155);
    let wrong_observation = SuccessorServingObservation {
        record: vec![0xEE; 4],
        binding: binding.clone(),
        progress: initial(),
    };
    let token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let before: SqliteSealState = sqlite_seal_state(&_db);
    assert_eq!(
        store.commit_successor_seal_retention(
            &context,
            &wrong_observation,
            &token,
            durable_write(binding.domain, b"mismatch-cut", 1),
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(sqlite_seal_state(&_db), before);
}

#[test]
fn successor_seal_completion_rejects_stale_generation() {
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(94);
    let binding = pin();
    let observation = activate(&store, &context, &fresh_token, 156);
    let token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let next_context = operation(95);
    store
        .advance_writer_fence(context.writer_fence(), next_context.writer_fence())
        .unwrap();
    let sealed = sample_sealed(157);
    let before: SqliteSealState = sqlite_seal_state(&_db);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            stateful_sealed_invocation(binding.domain, &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced {
            active_generation: next_context.writer_fence(),
        })
    );
    assert_eq!(sqlite_seal_state(&_db), before);
    let current_token: PortableSnapshotToken = store
        .begin_portable_snapshot(&next_context, binding.domain)
        .unwrap();
    assert_eq!(
        store.commit_successor_seal_completion(
            &next_context,
            &observation,
            &current_token,
            stateful_sealed_invocation(binding.domain, &sealed, b"cut", 2, StateRevision::INITIAL),
            sealed,
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn successor_seal_completion_rejects_occupied_receipt() {
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(96);
    let binding = pin();
    let observation = activate(&store, &context, &fresh_token, 158);
    let sealed = sample_sealed(159);
    assert_eq!(
        store.commit_successor_invocation(
            &context,
            &observation,
            sealed_invocation(binding.domain, &sealed),
        ),
        DurableCommitOutcome::Committed
    );
    let token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let before: SqliteSealState = sqlite_seal_state(&_db);
    assert_eq!(
        store.commit_successor_seal_completion(
            &context,
            &observation,
            &token,
            sealed_invocation(binding.domain, &sealed),
            sealed,
        ),
        DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
    );
    assert_eq!(sqlite_seal_state(&_db), before);
}

#[test]
fn successor_seal_completion_rejects_nonempty_outbox_before_any_write() {
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(97);
    let binding = pin();
    let observation = activate(&store, &context, &fresh_token, 160);
    let sealed = sample_sealed(161);
    let request_id = DurableRequestId::new(sealed.request).unwrap();
    let event_digest = digest(0xEE);
    let receipt_value = DurableRequestReceipt::new(request_id, event_digest, vec![1]).unwrap();
    let message = runtime::DurableOutboxMessage::new(digest(0xFA), vec![9]).unwrap();
    let outbox = runtime::DurableOutboxBatch::new(request_id, event_digest, vec![message]).unwrap();
    let invocation = DurableInvocationTransaction::new(
        binding.domain,
        None,
        DurableObjectChanges::empty(),
        receipt_value,
        Some(outbox),
    )
    .unwrap();
    let token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let before: SqliteSealState = sqlite_seal_state(&_db);
    assert_eq!(
        store.commit_successor_seal_completion(&context, &observation, &token, invocation, sealed),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(sqlite_seal_state(&_db), before);
    assert_eq!(
        store
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Unsealed
    );
}

#[test]
fn successor_seal_completion_rejects_object_changes_before_any_write() {
    let (_db, store, context, fresh_token, _stale_token) = complete_inactive_store(98);
    let binding = pin();
    let observation = activate(&store, &context, &fresh_token, 162);
    let object_id = ObjectId::new([62; 32]);
    let sealed = sample_sealed(163);
    let invocation = DurableInvocationTransaction::new(
        binding.domain,
        None,
        object_create_changes(object_id),
        DurableRequestReceipt::new(
            DurableRequestId::new(sealed.request).unwrap(),
            digest(0xAB),
            vec![1],
        )
        .unwrap(),
        None,
    )
    .unwrap();
    let token = store
        .begin_portable_snapshot(&context, binding.domain)
        .unwrap();
    let before: SqliteSealState = sqlite_seal_state(&_db);
    assert_eq!(
        store.commit_successor_seal_completion(&context, &observation, &token, invocation, sealed),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState)
    );
    assert_eq!(sqlite_seal_state(&_db), before);
    assert_eq!(
        store
            .get_outgoing_barrier(&context, binding.domain)
            .unwrap(),
        OutgoingBarrier::Unsealed
    );
}
