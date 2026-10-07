//! Real file/transaction storage controls; these are not authenticated E votes.
use super::*;
use runtime::conditional_readiness::{encode_readiness_record, encode_readiness_slot};
use runtime_sql_durable::{SqlRows, SqlValue};
use rusqlite::params;
use std::sync::Arc;

fn complete(
    db: &Database,
) -> (
    SqliteImportTarget,
    ImportBinding,
    ImportProgress,
    PortableSnapshotToken,
) {
    let pin: ImportBinding = binding(4);
    let context: DurableOperationContext = operation(7);
    let store: SqliteImportTarget =
        SqliteImportTarget::create(&db.0, namespace(&pin), context.writer_fence(), &pin).unwrap();
    assert_eq!(
        store.begin_import(&context, pin.domain, &pin, initial().accumulator),
        DurableCommitOutcome::Committed
    );
    let id: ObjectId = ObjectId::new([0x71; 32]);
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_blob_reference(
        id,
        DurableObjectVersion::new(17).unwrap(),
        digest(10),
        1,
        DurableObjectProvenance::new(pin.context.chain_id.clone(), pin.context.protocol_version),
        0,
        digest(11),
    );
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x72; 32]).unwrap(),
        digest(12),
        vec![0x61; 72],
    )
    .unwrap();
    let install: ImportBatch = batch(
        &pin,
        &initial(),
        vec![
            state(b"business", Some(b"original")),
            ImportRow::ObjectVersion(version),
            ImportRow::ObjectHead {
                object_id: id,
                head: ImportObjectHead::Tombstoned {
                    last_object_version: DurableObjectVersion::new(17).unwrap(),
                },
            },
            ImportRow::Receipt(receipt),
        ],
    );
    assert_eq!(
        store.commit_import_batch(&context, pin.domain, &install),
        DurableCommitOutcome::Committed
    );
    let before: PortableSnapshotToken =
        store.begin_portable_snapshot(&context, pin.domain).unwrap();
    assert_eq!(
        store.finish_import(&context, pin.domain, &pin, install.next(), &before),
        DurableCommitOutcome::Committed
    );
    let token: PortableSnapshotToken = store.begin_portable_snapshot(&context, pin.domain).unwrap();
    (store, pin, install.next().clone(), token)
}
fn record(
    pin: &ImportBinding,
    progress: &ImportProgress,
    token: &PortableSnapshotToken,
    identity: u8,
) -> ReadinessRecord {
    ReadinessRecord {
        slot: ReadinessSlot {
            identity: digest(identity),
            signer: ValidatorId::new([9; 32]),
        },
        binding: pin.clone(),
        progress: progress.clone(),
        creation_token: token.clone(),
        vote_bytes: vec![0x42; 128],
    }
}
fn counts(db: &Database) -> [i64; 4] {
    let connection: Connection = Connection::open(&db.0).unwrap();
    [
        "durable_state",
        "durable_receipts",
        "durable_object_versions",
        "durable_object_heads",
    ]
    .map(|table: &str| {
        connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    })
}

#[test]
fn readiness_sqlite_insert_reopen_refence_exact_retry_preserves_four_business_collections() {
    let db: Database = Database::new();
    let (store, pin, progress, token) = complete(&db);
    let context: DurableOperationContext = operation(7);
    let value: ReadinessRecord = record(&pin, &progress, &token, 10);
    assert_eq!(counts(&db), [1, 1, 1, 1]);
    assert_eq!(
        store
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .unwrap(),
        ReadinessSlotObservation::Absent
    );
    assert_eq!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store.read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot),
        Err(PortableSnapshotError::Changed)
    );
    assert!(matches!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Present(value.clone()),
            &value
        ),
        DurableCommitOutcome::Rejected(_)
    ));
    drop(store);
    let reopened: SqliteImportTarget =
        SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).unwrap();
    assert_eq!(
        reopened
            .advance_writer_fence(
                context.writer_fence(),
                WriterFenceGeneration::new(8).unwrap()
            )
            .unwrap()
            .get(),
        8
    );
    let current: DurableOperationContext = operation(8);
    let fresh: PortableSnapshotToken = reopened
        .begin_portable_snapshot(&current, pin.domain)
        .unwrap();
    assert_eq!(fresh.mutation_sequence(), token.mutation_sequence() + 1);
    let observed: ReadinessSlotObservation = reopened
        .read_ready_slot_at(&current, pin.domain, &pin, &progress, &fresh, &value.slot)
        .unwrap();
    assert_eq!(observed, ReadinessSlotObservation::Present(value.clone()));
    assert_eq!(
        reopened.retain_ready_slot(
            &current, pin.domain, &pin, &progress, &fresh, &observed, &value
        ),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        reopened
            .begin_portable_snapshot(&current, pin.domain)
            .unwrap(),
        fresh
    );
    let corrected: ReadinessRecord = record(&pin, &progress, &fresh, 11);
    assert_eq!(
        reopened.retain_ready_slot(
            &current,
            pin.domain,
            &pin,
            &progress,
            &fresh,
            &ReadinessSlotObservation::Absent,
            &corrected
        ),
        DurableCommitOutcome::Committed
    );
    let latest: PortableSnapshotToken = reopened
        .begin_portable_snapshot(&current, pin.domain)
        .unwrap();
    assert_eq!(
        reopened
            .read_ready_slot_at(&current, pin.domain, &pin, &progress, &latest, &value.slot)
            .unwrap(),
        observed
    );
    assert_eq!(
        reopened
            .get_namespace_lifecycle(&current, pin.domain)
            .unwrap(),
        NamespaceLifecycle::CompleteInactive {
            binding: pin.clone(),
            progress: progress.clone()
        }
    );
    assert_eq!(
        reopened.commit_durable(&current, ordinary_write(pin.domain)),
        DurableCommitOutcome::Rejected(DurableCommitRejection::InactiveNamespace)
    );
    assert_eq!(
        reopened
            .get_versioned_durable(&current, pin.domain, b"business")
            .unwrap()
            .value(),
        Some(b"original".as_slice())
    );
    assert_eq!(
        reopened
            .get_request_receipt(
                &current,
                pin.domain,
                DurableRequestId::new([0x72; 32]).unwrap()
            )
            .unwrap()
            .unwrap()
            .canonical_bytes(),
        [0x61; 72]
    );
    assert!(
        matches!(reopened.get_object_head(&current, pin.domain, ObjectId::new([0x71; 32])).unwrap(), DurableObjectHead::Tombstoned { last_object_version, .. } if last_object_version.get() == 17)
    );
    assert_eq!(counts(&db), [1, 1, 1, 1]);
    assert!(matches!(
        SqliteDurableStore::open_existing(&db.0, namespace(&pin)),
        Err(SqliteDurableStoreError::InactiveNamespace)
    ));
}

#[test]
fn readiness_sqlite_two_handles_stale_token_and_conflicting_record_refuse() {
    let db: Database = Database::new();
    let (first, pin, progress, token) = complete(&db);
    let second: SqliteImportTarget =
        SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).unwrap();
    let context: DurableOperationContext = operation(7);
    let value: ReadinessRecord = record(&pin, &progress, &token, 10);
    assert_eq!(
        second
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .unwrap(),
        ReadinessSlotObservation::Absent
    );
    assert_eq!(
        first.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Committed
    );
    assert!(matches!(
        second.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Rejected(_)
    ));
    let current: PortableSnapshotToken = second
        .begin_portable_snapshot(&context, pin.domain)
        .unwrap();
    let observed: ReadinessSlotObservation = second
        .read_ready_slot_at(&context, pin.domain, &pin, &progress, &current, &value.slot)
        .unwrap();
    let mut conflict: ReadinessRecord = value.clone();
    conflict.vote_bytes[0] ^= 1;
    assert!(matches!(
        second.retain_ready_slot(
            &context, pin.domain, &pin, &progress, &current, &observed, &conflict
        ),
        DurableCommitOutcome::Rejected(_)
    ));
    assert_eq!(
        second
            .begin_portable_snapshot(&context, pin.domain)
            .unwrap(),
        current
    );
    assert_eq!(
        second
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &current, &value.slot)
            .unwrap(),
        observed
    );
}

#[test]
fn readiness_sqlite_is_scoped_to_destination_and_current_authority() {
    let db: Database = Database::new();
    let other_db: Database = Database::new();
    let (store, pin, progress, token) = complete(&db);
    let (other, _, _, other_token) = complete(&other_db);
    let context: DurableOperationContext = operation(7);
    let value: ReadinessRecord = record(&pin, &progress, &token, 10);
    assert!(
        other
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .is_err()
    );
    assert_eq!(
        other
            .read_ready_slot_at(
                &context,
                pin.domain,
                &pin,
                &progress,
                &other_token,
                &value.slot
            )
            .unwrap(),
        ReadinessSlotObservation::Absent
    );
    assert!(
        store
            .read_ready_slot_at(
                &operation(6),
                pin.domain,
                &pin,
                &progress,
                &token,
                &value.slot
            )
            .is_err()
    );
    let mut wrong: ImportBinding = pin.clone();
    wrong.package_digest = digest(11);
    assert!(
        store
            .read_ready_slot_at(&context, pin.domain, &wrong, &progress, &token, &value.slot)
            .is_err()
    );
    assert!(
        store
            .read_ready_slot_at(
                &context,
                AtomicityDomainId::new([0x55; 32]).unwrap(),
                &pin,
                &progress,
                &token,
                &value.slot
            )
            .is_err()
    );
    let expired: DurableOperationContext = DurableOperationContext::new(
        context.writer_fence(),
        StorageDeadline::new(1).unwrap(),
        context.correlation_id(),
    );
    assert!(matches!(
        store.retain_ready_slot(
            &expired,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Rejected(_)
    ));
    let fresh_db: Database = Database::new();
    let fresh: SqliteImportTarget =
        SqliteImportTarget::create(&fresh_db.0, namespace(&pin), context.writer_fence(), &pin)
            .unwrap();
    let fresh_token: PortableSnapshotToken =
        fresh.begin_portable_snapshot(&context, pin.domain).unwrap();
    assert!(
        fresh
            .read_ready_slot_at(
                &context,
                pin.domain,
                &pin,
                &progress,
                &fresh_token,
                &value.slot
            )
            .is_err()
    );
    assert_eq!(
        fresh.begin_import(&context, pin.domain, &pin, initial().accumulator),
        DurableCommitOutcome::Committed
    );
    let importing_token: PortableSnapshotToken =
        fresh.begin_portable_snapshot(&context, pin.domain).unwrap();
    assert!(
        fresh
            .read_ready_slot_at(
                &context,
                pin.domain,
                &pin,
                &progress,
                &importing_token,
                &value.slot
            )
            .is_err()
    );
}

#[test]
fn readiness_sqlite_landed_and_unlanded_commit_reply_loss_reconcile_exact_slot() {
    for land in [false, true] {
        let db: Database = Database::new();
        let (store, pin, progress, token) = complete(&db);
        let context: DurableOperationContext = operation(7);
        let value: ReadinessRecord = record(&pin, &progress, &token, 10);
        drop(store);
        let connection: Connection = Connection::open(&db.0).unwrap();
        crate::native_connection::configure_writable(&connection).unwrap();
        let engine: SqlDurableEngine<LostCommitBackend> = SqlDurableEngine::new(
            LostCommitBackend {
                inner: NativeSqlBackend::new(connection),
                armed: AtomicBool::new(true),
                land,
            },
            namespace(&pin),
        );
        assert_eq!(
            engine.retain_ready_slot(
                &context,
                pin.domain,
                &pin,
                &progress,
                &token,
                &ReadinessSlotObservation::Absent,
                &value
            ),
            DurableCommitOutcome::Indeterminate(runtime::IndeterminateCommitReason::ConnectionLost)
        );
        drop(engine);
        let reopened: SqliteImportTarget =
            SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).unwrap();
        let fresh: PortableSnapshotToken = reopened
            .begin_portable_snapshot(&context, pin.domain)
            .unwrap();
        let observed: ReadinessSlotObservation = reopened
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &fresh, &value.slot)
            .unwrap();
        assert_eq!(
            observed,
            if land {
                ReadinessSlotObservation::Present(value.clone())
            } else {
                ReadinessSlotObservation::Absent
            }
        );
        assert_eq!(
            fresh.mutation_sequence(),
            token.mutation_sequence() + u64::from(land)
        );
        assert_eq!(
            reopened.retain_ready_slot(
                &context, pin.domain, &pin, &progress, &fresh, &observed, &value
            ),
            DurableCommitOutcome::Committed
        );
        assert_eq!(counts(&db), [1, 1, 1, 1]);
    }
}

struct ProbeSession<'a> {
    inner: &'a mut dyn SqlSession,
    full_reads: &'a AtomicU64,
}
impl SqlSession for ProbeSession<'_> {
    fn exec(&mut self, statement: &str, params: &[SqlValue]) -> Result<SqlRows, SqlSessionError> {
        if statement.starts_with("SELECT record FROM durable_conditional_readiness") {
            self.full_reads.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.exec(statement, params)
    }
    fn now_unix_millis(&self) -> Result<u64, SqlSessionError> {
        self.inner.now_unix_millis()
    }
}
struct ProbeBackend {
    inner: NativeSqlBackend,
    full_reads: Arc<AtomicU64>,
}
impl SqlBackend for ProbeBackend {
    fn transaction<T>(
        &self,
        budget: TransactionBudget,
        run: impl FnOnce(&mut dyn SqlSession, u64) -> Result<TransactionDecision<T>, SqlSessionError>,
    ) -> Result<T, SqlBackendError> {
        self.inner.transaction(budget, |session, now| {
            run(
                &mut ProbeSession {
                    inner: session,
                    full_reads: self.full_reads.as_ref(),
                },
                now,
            )
        })
    }
}

#[test]
fn readiness_sqlite_length_first_corruption_tombstone_and_absent_recreation() {
    let db: Database = Database::new();
    let (store, pin, progress, token) = complete(&db);
    let context: DurableOperationContext = operation(7);
    let value: ReadinessRecord = record(&pin, &progress, &token, 10);
    let key: Vec<u8> = encode_readiness_slot(&value.slot).unwrap();
    let connection: Connection = Connection::open(&db.0).unwrap();
    connection
        .execute(
            "INSERT INTO durable_conditional_readiness (slot, status, record) VALUES (?1, 2, NULL)",
            params![key],
        )
        .unwrap();
    assert_eq!(
        store
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .unwrap(),
        ReadinessSlotObservation::Tombstoned
    );
    assert!(matches!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Tombstoned,
            &value
        ),
        DurableCommitOutcome::Rejected(_)
    ));
    connection
        .pragma_update(None, "ignore_check_constraints", "ON")
        .unwrap();
    connection.execute("UPDATE durable_conditional_readiness SET status = 1, record = zeroblob(16385) WHERE slot = ?1", params![key]).unwrap();
    let probe_connection: Connection = Connection::open(&db.0).unwrap();
    crate::native_connection::configure_writable(&probe_connection).unwrap();
    let full_reads: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let probe: ProbeBackend = ProbeBackend {
        inner: NativeSqlBackend::new(probe_connection),
        full_reads: Arc::clone(&full_reads),
    };
    let engine: SqlDurableEngine<ProbeBackend> = SqlDurableEngine::new(probe, namespace(&pin));
    assert!(
        engine
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .is_err()
    );
    assert_eq!(full_reads.load(Ordering::SeqCst), 0);
    connection
        .execute(
            "UPDATE durable_conditional_readiness SET record = zeroblob(100) WHERE slot = ?1",
            params![key],
        )
        .unwrap();
    assert!(
        store
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .is_err()
    );
    connection
        .execute(
            "DELETE FROM durable_conditional_readiness WHERE slot = ?1",
            params![key],
        )
        .unwrap();
    assert_eq!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Committed
    );
    connection
        .execute(
            "DELETE FROM durable_conditional_readiness WHERE slot = ?1",
            params![key],
        )
        .unwrap();
    let current: PortableSnapshotToken =
        store.begin_portable_snapshot(&context, pin.domain).unwrap();
    assert!(matches!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &current,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Rejected(_)
    ));
    let recreated: ReadinessRecord = record(&pin, &progress, &current, 10);
    assert_eq!(recreated.vote_bytes, value.vote_bytes);
    assert_eq!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &current,
            &ReadinessSlotObservation::Absent,
            &recreated
        ),
        DurableCommitOutcome::Committed
    );
}

#[test]
fn readiness_sqlite_missing_protected_table_and_older_schema_never_repair() {
    let db: Database = Database::new();
    let (store, pin, progress, token) = complete(&db);
    let context: DurableOperationContext = operation(7);
    let value: ReadinessRecord = record(&pin, &progress, &token, 10);
    let connection: Connection = Connection::open(&db.0).unwrap();
    connection
        .pragma_update(None, "user_version", 2_i64)
        .unwrap();
    assert!(SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).is_err());
    connection
        .pragma_update(None, "user_version", STRUCTURED_SCHEMA_VERSION)
        .unwrap();
    connection
        .execute(
            "UPDATE durable_metadata SET schema_identity = ?1 WHERE id = 1",
            params![b"sunrise-edge/sqlite/structured/schema/v3".as_slice()],
        )
        .unwrap();
    assert!(SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).is_err());
    connection
        .execute(
            "UPDATE durable_metadata SET schema_identity = ?1 WHERE id = 1",
            params![SQLITE_STRUCTURED_SCHEMA_IDENTITY],
        )
        .unwrap();
    connection
        .execute("DROP TABLE durable_conditional_readiness", [])
        .unwrap();
    assert!(
        store
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .is_err()
    );
    assert!(SqliteImportTarget::open_existing(&db.0, namespace(&pin), &pin).is_err());
    let exists: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'durable_conditional_readiness'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exists, 0);
    assert_eq!(counts(&db), [1, 1, 1, 1]);
}

#[test]
fn readiness_sqlite_present_creation_linkage_and_exact_vote_bound() {
    let db: Database = Database::new();
    let (store, pin, progress, token) = complete(&db);
    let context: DurableOperationContext = operation(7);
    let mut value: ReadinessRecord = record(&pin, &progress, &token, 10);
    value.vote_bytes = vec![0x42; runtime::conditional_readiness::MAX_READINESS_VOTE_BYTES];
    assert_eq!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Committed
    );
    let current: PortableSnapshotToken =
        store.begin_portable_snapshot(&context, pin.domain).unwrap();
    let key: Vec<u8> = encode_readiness_slot(&value.slot).unwrap();
    let connection: Connection = Connection::open(&db.0).unwrap();
    for bad_token in [
        current.clone(),
        PortableSnapshotToken::new(
            b"foreign-destination".to_vec(),
            pin.domain,
            context.writer_fence(),
            token.mutation_sequence(),
        )
        .unwrap(),
        PortableSnapshotToken::new(
            token.namespace().to_vec(),
            pin.domain,
            WriterFenceGeneration::new(8).unwrap(),
            token.mutation_sequence(),
        )
        .unwrap(),
    ] {
        let mut bad: ReadinessRecord = value.clone();
        bad.creation_token = bad_token;
        let bytes: Vec<u8> = encode_readiness_record(&bad).unwrap();
        connection
            .execute(
                "UPDATE durable_conditional_readiness SET record = ?1 WHERE slot = ?2",
                params![bytes, key],
            )
            .unwrap();
        assert!(
            store
                .read_ready_slot_at(&context, pin.domain, &pin, &progress, &current, &value.slot)
                .is_err()
        );
        assert!(matches!(
            store.retain_ready_slot(
                &context,
                pin.domain,
                &pin,
                &progress,
                &current,
                &ReadinessSlotObservation::Absent,
                &value
            ),
            DurableCommitOutcome::Rejected(_)
        ));
    }
    connection
        .execute(
            "UPDATE durable_conditional_readiness SET record = ?1 WHERE slot = ?2",
            params![encode_readiness_record(&value).unwrap(), key],
        )
        .unwrap();
    assert_eq!(
        store
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &current, &value.slot)
            .unwrap(),
        ReadinessSlotObservation::Present(value)
    );
}

#[test]
fn readiness_sqlite_ambiguous_protected_rows_refuse_without_loading_record() {
    let db: Database = Database::new();
    let (store, pin, progress, token) = complete(&db);
    let context: DurableOperationContext = operation(7);
    let value: ReadinessRecord = record(&pin, &progress, &token, 10);
    let key: Vec<u8> = encode_readiness_slot(&value.slot).unwrap();
    let connection: Connection = Connection::open(&db.0).unwrap();
    // Deliberately corrupt the protected schema so the bounded lookup must
    // reject ambiguity even if an attacker has bypassed the primary key.
    connection
        .execute("DROP TABLE durable_conditional_readiness", [])
        .unwrap();
    connection
        .execute(
            "CREATE TABLE durable_conditional_readiness
        (slot BLOB NOT NULL, status INTEGER NOT NULL, record BLOB)",
            [],
        )
        .unwrap();
    for _ in 0..2 {
        connection
            .execute(
                "INSERT INTO durable_conditional_readiness
            (slot, status, record) VALUES (?1, 1, ?2)",
                params![key, encode_readiness_record(&value).unwrap()],
            )
            .unwrap();
    }
    let probe_connection: Connection = Connection::open(&db.0).unwrap();
    crate::native_connection::configure_writable(&probe_connection).unwrap();
    let full_reads: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let engine: SqlDurableEngine<ProbeBackend> = SqlDurableEngine::new(
        ProbeBackend {
            inner: NativeSqlBackend::new(probe_connection),
            full_reads: Arc::clone(&full_reads),
        },
        namespace(&pin),
    );
    assert!(
        engine
            .read_ready_slot_at(&context, pin.domain, &pin, &progress, &token, &value.slot)
            .is_err()
    );
    assert_eq!(full_reads.load(Ordering::SeqCst), 0);
    assert!(matches!(
        store.retain_ready_slot(
            &context,
            pin.domain,
            &pin,
            &progress,
            &token,
            &ReadinessSlotObservation::Absent,
            &value
        ),
        DurableCommitOutcome::Rejected(_)
    ));
    assert_eq!(
        store.begin_portable_snapshot(&context, pin.domain).unwrap(),
        token
    );
    let rows: i64 = connection
        .query_row(
            "SELECT count(*) FROM durable_conditional_readiness",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 2);
    assert_eq!(counts(&db), [1, 1, 1, 1]);
}
