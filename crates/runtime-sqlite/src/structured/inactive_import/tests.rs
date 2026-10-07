use super::*;
mod readiness;
use protocol_types::{
    ChainId, Epoch, ExecutionGeneration, HashAlgorithmId, ProtocolVersion, ValidatorId,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, DurableCommitRejection, DurableObjectProvenance,
    ImportContext, ImportObjectHead, ImportRow, StateMutation, StateMutationEntry,
    StateReadAssertion, StateRevision, StorageCorrelationId, StorageDeadline,
};
use runtime_sql_durable::{SqlBackendError, SqlSession, SqlSessionError};
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
            "sunrise-inactive-import-{}-{time}-{nonce}.db",
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
fn binding(rows: u64) -> ImportBinding {
    ImportBinding {
        context: ImportContext {
            chain_id: ChainId::new("sqlite-inactive-import").unwrap(),
            protocol_version: ProtocolVersion::new(1),
            epoch: Epoch::new(7),
        },
        domain: AtomicityDomainId::new([8; 32]).unwrap(),
        genesis_digest: digest(1),
        validator_set_digest: digest(2),
        cut_digest: digest(3),
        package_digest: digest(4),
        plan_digest: digest(5),
        row_count: rows,
        blob_count: 0,
        generation_floor: ExecutionGeneration::new(19),
    }
}
fn namespace(binding: &ImportBinding) -> SqliteNamespace {
    SqliteNamespace::new(
        binding.context.chain_id.clone(),
        ValidatorId::new([0x61; 32]),
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
fn state(key: &[u8], bytes: Option<&[u8]>) -> ImportRow {
    ImportRow::State {
        key: key.to_vec(),
        value: bytes.map(<[u8]>::to_vec),
    }
}
fn batch(pin: &ImportBinding, before: &ImportProgress, rows: Vec<ImportRow>) -> ImportBatch {
    ImportBatch::new(pin.clone(), before.clone(), digest(7), digest(8), rows).unwrap()
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

#[test]
fn import_create_and_existing_writable_reopen_verify_full_settings() {
    let db: Database = Database::new();
    let pin: ImportBinding = binding(0);
    let created: SqliteImportTarget =
        SqliteImportTarget::create(&db.0, namespace(&pin), operation(7).writer_fence(), &pin)
            .unwrap();
    for store in [
        created,
        SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).unwrap(),
    ] {
        store.store.engine.backend().inspect_test(|connection| {
            for (name, expected) in [
                ("foreign_keys", 1_i64),
                ("trusted_schema", 0_i64),
                ("synchronous", 2_i64),
                ("wal_autocheckpoint", 1_000_i64),
            ] {
                let actual: i64 = connection
                    .pragma_query_value(None, name, |row| row.get(0))
                    .unwrap();
                assert_eq!(actual, expected, "{name}");
            }
        });
    }
}

#[test]
fn import_reopen_requires_existing_wal_and_preserves_rejected_journal_identity() {
    let db: Database = Database::new();
    let pin: ImportBinding = binding(0);
    drop(
        SqliteImportTarget::create(&db.0, namespace(&pin), operation(7).writer_fence(), &pin)
            .unwrap(),
    );
    let connection: Connection = Connection::open(&db.0).unwrap();
    let mode: String = connection
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    drop(connection);
    assert!(
        matches!(SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin), Err(SqliteDurableStoreError::UnsupportedJournalMode(mode)) if mode == "delete")
    );
    let connection: Connection = Connection::open(&db.0).unwrap();
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
}

#[cfg(unix)]
#[test]
fn reopened_import_lifetime_refuses_replaced_main_file_without_repair() {
    let db: Database = Database::new();
    let pin: ImportBinding = binding(0);
    let created: SqliteImportTarget =
        SqliteImportTarget::create(&db.0, namespace(&pin), operation(7).writer_fence(), &pin)
            .unwrap();
    let reopened: SqliteImportTarget =
        SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).unwrap();
    let retained: PathBuf = db.0.with_extension("retained");
    std::fs::rename(&db.0, &retained).unwrap();
    std::fs::write(&db.0, b"replacement is never repaired").unwrap();
    assert!(
        reopened
            .read_import_progress(&operation(7), pin.domain)
            .is_err()
    );
    assert!(reopened.writer_fence().is_err());
    drop(reopened);
    drop(created);
    assert_eq!(
        std::fs::read(&db.0).unwrap(),
        b"replacement is never repaired"
    );
    std::fs::remove_file(retained).unwrap();
}

#[test]
fn inactive_import_sqlite_fresh_exact_rows_retry_reopen_and_complete_stays_inactive() {
    let db: Database = Database::new();
    let pin: ImportBinding = binding(6);
    let context: DurableOperationContext = operation(7);
    let store: SqliteImportTarget =
        SqliteImportTarget::create(&db.0, namespace(&pin), context.writer_fence(), &pin).unwrap();
    assert_eq!(store.writer_fence().unwrap(), context.writer_fence());
    assert_eq!(
        store.get_namespace_lifecycle(&context, pin.domain).unwrap(),
        NamespaceLifecycle::FreshImport(pin.clone())
    );
    assert!(matches!(
        SqliteDurableStore::open_existing(&db.0, namespace(&pin)),
        Err(SqliteDurableStoreError::InactiveNamespace)
    ));
    assert_eq!(
        store.commit_durable(&context, ordinary_write(pin.domain)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
    assert_eq!(
        store.begin_import(&context, pin.domain, &pin, initial().accumulator),
        DurableCommitOutcome::Committed
    );
    let id: ObjectId = ObjectId::new([9; 32]);
    let first: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        id,
        DurableObjectVersion::new(17).unwrap(),
        digest(10),
        1,
        DurableObjectProvenance::new(pin.context.chain_id.clone(), pin.context.protocol_version),
        0,
        digest(11),
    );
    let last: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        id,
        DurableObjectVersion::new(19).unwrap(),
        digest(12),
        1,
        DurableObjectProvenance::new(pin.context.chain_id.clone(), pin.context.protocol_version),
        0,
        digest(13),
    );
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new([8; 32]).unwrap(),
        digest(14),
        vec![0x61; 72],
    )
    .unwrap();
    let install: ImportBatch = batch(
        &pin,
        &initial(),
        vec![
            state(b"a", Some(b"original")),
            state(b"z", None),
            ImportRow::ObjectVersion(first.clone()),
            ImportRow::ObjectVersion(last.clone()),
            ImportRow::ObjectHead {
                object_id: id,
                head: ImportObjectHead::Tombstoned {
                    last_object_version: last.object_version(),
                },
            },
            ImportRow::Receipt(receipt.clone()),
        ],
    );
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &install),
        DurableCommitOutcome::Committed
    );
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&context, pin.domain).unwrap();
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &install),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.begin_portable_snapshot(&context, pin.domain).unwrap(),
        token
    );
    drop(store);
    let reopened: SqliteImportTarget =
        SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).unwrap();
    assert_eq!(
        reopened.read_import_progress(&context, pin.domain).unwrap(),
        Some(install.next().clone())
    );
    assert_eq!(
        reopened
            .get_request_receipt(&context, pin.domain, receipt.request_id())
            .unwrap(),
        Some(receipt.clone())
    );
    for version in [first, last] {
        assert_eq!(
            reopened
                .get_object_version(&context, pin.domain, id, version.object_version())
                .unwrap(),
            Some(version)
        );
    }
    assert!(
        matches!(reopened.get_object_head(&context, pin.domain, id).unwrap(), DurableObjectHead::Tombstoned { head_revision: runtime::ObjectHeadRevision::FIRST, last_object_version } if last_object_version.get() == 19)
    );
    assert_ne!(
        reopened
            .get_versioned_durable(&context, pin.domain, b"z")
            .unwrap()
            .revision(),
        StateRevision::INITIAL
    );
    let foreign_db: Database = Database::new();
    let foreign: SqliteImportTarget =
        SqliteImportTarget::create(&foreign_db.0, namespace(&pin), context.writer_fence(), &pin)
            .unwrap();
    let foreign_token = foreign
        .begin_portable_snapshot(&context, pin.domain)
        .unwrap();
    assert!(matches!(
        reopened.finish_import(&context, pin.domain, &pin, install.next(), &foreign_token),
        DurableCommitOutcome::Rejected(_)
    ));
    assert_eq!(
        reopened.finish_import(&context, pin.domain, &pin, install.next(), &token),
        DurableCommitOutcome::Committed
    );
    drop(reopened);
    let complete: SqliteImportTarget =
        SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).unwrap();
    assert!(matches!(
        complete
            .get_namespace_lifecycle(&context, pin.domain)
            .unwrap(),
        NamespaceLifecycle::CompleteInactive { .. }
    ));
    assert!(matches!(
        SqliteDurableStore::open(&db.0, namespace(&pin), context.writer_fence()),
        Err(SqliteDurableStoreError::InactiveNamespace)
    ));
    assert_eq!(
        complete.commit_durable(&context, ordinary_write(pin.domain)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
    let invocation = DurableInvocationTransaction::new(
        pin.domain,
        None,
        runtime::DurableObjectChanges::empty(),
        receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        complete.commit_invocation(&context, invocation),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
}

#[test]
fn inactive_import_sqlite_wrong_binding_stale_fence_conflicts_and_missing_progress_do_not_repair() {
    let db: Database = Database::new();
    let pin: ImportBinding = binding(3);
    let context: DurableOperationContext = operation(7);
    let store: SqliteImportTarget =
        SqliteImportTarget::create(&db.0, namespace(&pin), context.writer_fence(), &pin).unwrap();
    assert!(
        SqliteImportTarget::create(&db.0, namespace(&pin), context.writer_fence(), &pin).is_err()
    );
    let mut wrong: ImportBinding = pin.clone();
    wrong.cut_digest = digest(99);
    assert!(SqliteImportTarget::open_existing(&db.0, namespace(&pin), &wrong).is_err());
    assert_eq!(
        store.begin_import(&context, pin.domain, &pin, initial().accumulator),
        DurableCommitOutcome::Committed
    );
    let first: ImportBatch = batch(&pin, &initial(), vec![state(b"z", Some(b"original"))]);
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &first),
        DurableCommitOutcome::Committed
    );
    let conflicting: ImportBatch = batch(
        &pin,
        first.next(),
        vec![
            state(b"a", Some(b"must-rollback")),
            state(b"z", Some(b"conflict")),
        ],
    );
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &conflicting),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict)
    );
    assert!(
        store
            .get_versioned_durable(&context, pin.domain, b"a")
            .unwrap()
            .value()
            .is_none()
    );
    assert_eq!(
        store.read_import_progress(&context, pin.domain).unwrap(),
        Some(first.next().clone())
    );
    store
        .advance_writer_fence(context.writer_fence(), operation(8).writer_fence())
        .unwrap();
    assert!(matches!(
        store.get_namespace_lifecycle(&context, pin.domain),
        Err(DurableReadError::WriterFenced { .. })
    ));
    assert!(matches!(
        store.commit_import_batch(&context, pin.domain, &first),
        DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced { .. })
    ));
    assert!(
        store
            .get_namespace_lifecycle(&operation(8), pin.domain)
            .is_ok()
    );
    drop(store);
    let connection: Connection = Connection::open(&db.0).unwrap();
    connection
        .execute("DELETE FROM durable_import_progress", [])
        .unwrap();
    assert!(SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).is_err());
    assert!(SqliteDurableStore::open_existing(&db.0, namespace(&pin)).is_err());
    assert!(SqliteDurableStore::open(&db.0, namespace(&pin), operation(8).writer_fence()).is_err());
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM durable_import_progress", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT namespace_origin FROM durable_metadata", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        2
    );
}

#[test]
fn inactive_import_sqlite_missing_old_ordinary_and_lost_origin_are_unsupported_not_reset() {
    let missing: Database = Database::new();
    let pin: ImportBinding = binding(1);
    let context: DurableOperationContext = operation(7);
    assert!(SqliteImportTarget::open_existing(&missing.0, namespace(&pin), &pin).is_err());
    assert!(!missing.0.exists());
    let ordinary_db: Database = Database::new();
    let ordinary =
        SqliteDurableStore::open(&ordinary_db.0, namespace(&pin), context.writer_fence()).unwrap();
    assert_eq!(
        ordinary
            .get_namespace_lifecycle(&context, pin.domain)
            .unwrap(),
        NamespaceLifecycle::Ordinary
    );
    assert_eq!(
        ordinary.commit_durable(&context, ordinary_write(pin.domain)),
        DurableCommitOutcome::Committed
    );
    assert!(
        SqliteImportTarget::create(
            &ordinary_db.0,
            namespace(&pin),
            context.writer_fence(),
            &pin
        )
        .is_err()
    );
    assert!(SqliteImportTarget::open_existing(&ordinary_db.0, namespace(&pin), &pin).is_err());
    assert_eq!(
        ordinary
            .get_versioned_durable(&context, pin.domain, b"forbidden")
            .unwrap()
            .value(),
        Some([1].as_slice())
    );
    drop(ordinary);
    let connection = Connection::open(&ordinary_db.0).unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    assert!(matches!(
        SqliteDurableStore::open_existing(&ordinary_db.0, namespace(&pin)),
        Err(SqliteDurableStoreError::SchemaVersion(1))
    ));
    connection
        .pragma_update(None, "user_version", STRUCTURED_SCHEMA_VERSION)
        .unwrap();
    connection
        .execute(
            "ALTER TABLE durable_metadata RENAME COLUMN namespace_origin TO lost_origin",
            [],
        )
        .unwrap();
    assert!(
        SqliteDurableStore::open(&ordinary_db.0, namespace(&pin), context.writer_fence()).is_err()
    );
    assert!(SqliteImportTarget::open_existing(&ordinary_db.0, namespace(&pin), &pin).is_err());
    assert_eq!(
        connection
            .query_row(
                "SELECT value FROM durable_state WHERE key = ?1",
                [b"forbidden".as_slice()],
                |row| row.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
        vec![1]
    );
}

struct LostCommitBackend {
    inner: NativeSqlBackend,
    armed: AtomicBool,
    land: bool,
}

#[test]
fn inactive_import_sqlite_invalid_head_rolls_back_versions_and_current_head_is_preserved() {
    let db: Database = Database::new();
    let pin: ImportBinding = binding(3);
    let context: DurableOperationContext = operation(7);
    let store: SqliteImportTarget =
        SqliteImportTarget::create(&db.0, namespace(&pin), context.writer_fence(), &pin).unwrap();
    assert_eq!(
        store.begin_import(&context, pin.domain, &pin, initial().accumulator),
        DurableCommitOutcome::Committed
    );
    let id: ObjectId = ObjectId::new([9; 32]);
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        id,
        DurableObjectVersion::new(17).unwrap(),
        digest(10),
        1,
        DurableObjectProvenance::new(pin.context.chain_id.clone(), pin.context.protocol_version),
        0,
        digest(11),
    );
    let current: ImportObjectHead = ImportObjectHead::Current {
        object_version: version.object_version(),
        digest: version.digest(),
        owner_projection: runtime::DurableObjectOwnerProjection::from_canonical_bytes(None)
            .unwrap(),
        routing_projection: runtime::DurableObjectRoutingProjection::new(Some(Vec::new())).unwrap(),
    };
    let bad: ImportBatch = batch(
        &pin,
        &initial(),
        vec![
            state(b"a", Some(b"must-rollback")),
            ImportRow::ObjectVersion(version.clone()),
            ImportRow::ObjectHead {
                object_id: id,
                head: ImportObjectHead::Tombstoned {
                    last_object_version: DurableObjectVersion::new(18).unwrap(),
                },
            },
        ],
    );
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &bad),
        DurableCommitOutcome::Rejected(DurableCommitRejection::ImportConflict)
    );
    assert_eq!(
        store.read_import_progress(&context, pin.domain).unwrap(),
        Some(initial())
    );
    assert!(
        store
            .get_object_version(&context, pin.domain, id, version.object_version())
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get_versioned_durable(&context, pin.domain, b"a")
            .unwrap()
            .value()
            .is_none()
    );
    let good: ImportBatch = batch(
        &pin,
        &initial(),
        vec![
            state(b"a", Some(b"original")),
            ImportRow::ObjectVersion(version.clone()),
            ImportRow::ObjectHead {
                object_id: id,
                head: current,
            },
        ],
    );
    let expired: DurableOperationContext = DurableOperationContext::new(
        context.writer_fence(),
        StorageDeadline::new(1).unwrap(),
        context.correlation_id(),
    );
    assert!(matches!(
        store.commit_import_batch(&expired, pin.domain, &good),
        DurableCommitOutcome::Rejected(_)
    ));
    assert_eq!(
        store.read_import_progress(&context, pin.domain).unwrap(),
        Some(initial())
    );
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &good),
        DurableCommitOutcome::Committed
    );
    assert!(
        matches!(store.get_object_head(&context, pin.domain, id).unwrap(), DurableObjectHead::Current { object_version, head_revision: runtime::ObjectHeadRevision::FIRST, routing_projection, .. }
        if object_version == version.object_version() && routing_projection.bytes() == Some([].as_slice()))
    );
}
impl SqlBackend for LostCommitBackend {
    fn transaction<T>(
        &self,
        budget: TransactionBudget,
        run: impl FnOnce(&mut dyn SqlSession, u64) -> Result<TransactionDecision<T>, SqlSessionError>,
    ) -> Result<T, SqlBackendError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            if self.land {
                let _result: T = self.inner.transaction(budget, run)?;
            }
            return Err(SqlBackendError::CommitIndeterminate);
        }
        self.inner.transaction(budget, run)
    }
}
#[test]
fn inactive_import_sqlite_indeterminate_landed_and_unlanded_batches_reconcile_exactly() {
    for land in [false, true] {
        let db: Database = Database::new();
        let pin: ImportBinding = binding(1);
        let context: DurableOperationContext = operation(7);
        let store =
            SqliteImportTarget::create(&db.0, namespace(&pin), context.writer_fence(), &pin)
                .unwrap();
        assert_eq!(
            store.begin_import(&context, pin.domain, &pin, initial().accumulator),
            DurableCommitOutcome::Committed
        );
        drop(store);
        let connection = Connection::open(&db.0).unwrap();
        crate::native_connection::configure_writable(&connection).unwrap();
        let engine = SqlDurableEngine::new(
            LostCommitBackend {
                inner: NativeSqlBackend::new(connection),
                armed: AtomicBool::new(true),
                land,
            },
            namespace(&pin),
        );
        let install: ImportBatch = batch(&pin, &initial(), vec![state(b"a", Some(b"exact"))]);
        assert_eq!(
            engine.commit_import_batch(&context, pin.domain, &install),
            DurableCommitOutcome::Indeterminate(runtime::IndeterminateCommitReason::ConnectionLost)
        );
        drop(engine);
        let reopened = SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).unwrap();
        assert_eq!(
            reopened.read_import_progress(&context, pin.domain).unwrap(),
            Some(if land {
                install.next().clone()
            } else {
                initial()
            })
        );
        assert_eq!(
            reopened.commit_import_batch(&context, pin.domain, &install),
            DurableCommitOutcome::Committed
        );
        assert_eq!(
            reopened
                .get_versioned_durable(&context, pin.domain, b"a")
                .unwrap()
                .value(),
            Some(b"exact".as_slice())
        );
    }
}
