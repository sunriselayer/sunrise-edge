//! Real local process and attachment evidence, not power-loss qualification.
use super::*;
use crate::rusqlite_backend::CommitBoundary;
use hashing::{BuiltinHashFunction, HashFunction};
use objects::{Address, Object, Owner};
use protocol_types::{ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion, ValidatorId};
use runtime::{
    AtomicStateReadSet, DueOutboxClaimRequest, DurableCommitRejection, DurableObjectChanges,
    DurableObjectHeadRead, DurableObjectMutation, DurableObjectMutationEntry,
    DurableObjectOwnerProjection, DurableObjectProvenance, DurableObjectRoutingProjection,
    DurableOutboxBatch, DurableOutboxClaimOutcome, DurableOutboxLeaseId, DurableOutboxMessage,
    DurableStateTransaction, OutboxRequestId, PersistenceLayout, StateMutation, StateMutationEntry,
    StateReadAssertion, StateRevision, StorageCorrelationId, StorageDeadline,
};
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let nonce: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-native-ownership-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn database(&self) -> PathBuf {
        self.0.join("state.db")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn namespace() -> SqliteNamespace {
    SqliteNamespace::new(
        ChainId::new("native-ownership").unwrap(),
        ValidatorId::new([31; 32]),
        AtomicityDomainId::new([32; 32]).unwrap(),
    )
}
fn fence(value: u64) -> WriterFenceGeneration {
    WriterFenceGeneration::new(value).unwrap()
}
fn context(generation: u64) -> DurableOperationContext {
    let now: u64 = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    DurableOperationContext::new(
        fence(generation),
        StorageDeadline::new(now + 60_000).unwrap(),
        StorageCorrelationId::new([41; 16]).unwrap(),
    )
}
fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}
fn nonce_key() -> Vec<u8> {
    PersistenceLayout::new(namespace().chain_id().clone(), ProtocolVersion::new(1))
        .sender_nonce_key([51; 32], Epoch::new(7))
}

fn nonce_record_bytes() -> Vec<u8> {
    // Exact existing SenderNonceRecord oracle from
    // node-core/src/tests/core_and_nonce.rs, not another canonical encoder:
    // sender 0x33, epoch 7, next nonce 9. Storage transports these opaque bytes;
    // authentication and nonce-transition admission remain with node-core.
    const VECTOR: &str = concat!(
        "534e524506e001000300010020000000",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "0200080000000700000000000000",
        "0300080000000900000000000000"
    );
    let bytes: Vec<u8> = VECTOR
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    bytes
}
fn invocation() -> DurableInvocationTransaction {
    let ns: SqliteNamespace = namespace();
    let id: ObjectId = ObjectId::new([61; 32]);
    let object: Object = Object {
        id,
        version: 1,
        owner: Owner::Address(Address::new([62; 32])),
        type_hash: digest(63),
        schema_version: 1,
        data: vec![64],
    };
    let bytes: Vec<u8> = objects::encode_object(&object).unwrap();
    let object_digest: Digest32 = BuiltinHashFunction::new(HashAlgorithmId::Sha2_256)
        .hash(
            protocol_types::HashPurpose::Object,
            ProtocolVersion::new(1),
            ns.chain_id(),
            &bytes,
        )
        .unwrap();
    let version: DurableObjectVersionRecord = DurableObjectVersionRecord::from_inline_object(
        object,
        object_digest,
        DurableObjectProvenance::new(ns.chain_id().clone(), ProtocolVersion::new(1)),
        7,
    )
    .unwrap();
    let objects: DurableObjectChanges = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(id, DurableObjectHead::Absent)],
        vec![DurableObjectMutationEntry::new(
            id,
            DurableObjectMutation::Create {
                version,
                owner_projection: DurableObjectOwnerProjection::from_owner(Owner::Address(
                    Address::new([62; 32]),
                ))
                .unwrap(),
                routing_projection: DurableObjectRoutingProjection::new(None).unwrap(),
            },
        )],
    )
    .unwrap();
    // The storage slice transports an existing canonical nonce fixture atomically.
    let state: DurableStateTransaction = DurableStateTransaction::new(
        ns.domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(b"state".to_vec(), StateRevision::INITIAL).unwrap(),
            StateReadAssertion::new(nonce_key(), StateRevision::INITIAL).unwrap(),
        ])
        .unwrap(),
        vec![
            StateMutationEntry::new(b"state".to_vec(), StateMutation::Put(vec![71])).unwrap(),
            StateMutationEntry::new(nonce_key(), StateMutation::Put(nonce_record_bytes())).unwrap(),
        ],
    )
    .unwrap();
    let request: OutboxRequestId = OutboxRequestId::new([81; 32]).unwrap();
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(request, digest(82), vec![83, 84]).unwrap();
    let outbox: DurableOutboxBatch = DurableOutboxBatch::new(
        request,
        digest(82),
        vec![DurableOutboxMessage::new(digest(85), vec![86]).unwrap()],
    )
    .unwrap();
    DurableInvocationTransaction::new(ns.domain(), Some(state), objects, receipt, Some(outbox))
        .unwrap()
}

fn child_command(test: &str, path: &Path) -> Command {
    let mut command: Command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env("SUNRISE_SQLITE_TEST_PATH", path)
        .stdin(Stdio::null());
    command
}

#[test]
fn process_writer_probe() {
    let Some(path) = std::env::var_os("SUNRISE_SQLITE_TEST_PATH") else {
        return;
    };
    let expected: String = std::env::var("SUNRISE_SQLITE_EXPECT_LOCK").unwrap();
    let connection: Connection =
        Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
    connection.busy_timeout(Duration::from_millis(25)).unwrap();
    if std::env::var_os("SUNRISE_SQLITE_EXCLUSIVE_PROBE").is_some() {
        connection
            .execute_batch("PRAGMA locking_mode = EXCLUSIVE")
            .unwrap();
    }
    let result: rusqlite::Result<()> = connection.execute_batch("BEGIN IMMEDIATE; ROLLBACK");
    if expected == "busy" {
        assert!(
            matches!(result, Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::DatabaseBusy)
        );
    } else {
        assert_eq!(expected, "available");
        result.unwrap();
    }
}

fn probe_writer_mode(path: &Path, expected: &str, exclusive: bool) {
    let mut command: Command =
        child_command("structured::ownership_tests::process_writer_probe", path);
    command.env("SUNRISE_SQLITE_EXPECT_LOCK", expected);
    if exclusive {
        command.env("SUNRISE_SQLITE_EXCLUSIVE_PROBE", "1");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn probe_writer(path: &Path, expected: &str) {
    probe_writer_mode(path, expected, false);
}

fn probe_exclusion(path: &Path) {
    probe_writer_mode(path, "busy", false);
    // WAL's SHM writer lock alone does not prove that the main inode's
    // process-wide POSIX locks survived an independent identity guard Drop.
    probe_writer_mode(path, "busy", true);
}

fn assert_settings(backend: &NativeSqlBackend) {
    backend.inspect_test(|connection| {
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

#[test]
fn writable_settings_hold_on_fresh_development_existing_and_historical_constructors() {
    let directory: Directory = Directory::new();
    let path: PathBuf = directory.database();
    let created: SqliteDurableStore =
        SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap();
    assert_settings(created.engine.backend());
    drop(created);
    let development: SqliteDurableStore =
        SqliteDurableStore::open(&path, namespace(), fence(99)).unwrap();
    assert_settings(development.engine.backend());
    drop(development);
    let existing: SqliteDurableStore =
        SqliteDurableStore::open_existing(&path, namespace()).unwrap();
    assert_settings(existing.engine.backend());
    drop(existing);
    let historical: SqliteDurableStore =
        SqliteDurableStore::open_historical(&path, namespace()).unwrap();
    assert_settings(historical.engine.backend());
    assert_eq!(historical.writer_fence().unwrap(), fence(1));
    let development_path: PathBuf = directory.0.join("development.db");
    let development_fresh: SqliteDurableStore =
        SqliteDurableStore::open(&development_path, namespace(), fence(1)).unwrap();
    assert!(
        development_fresh.sync_created().is_err(),
        "development creation does not grant the fresh-only factory contract"
    );
}

#[test]
fn ordinary_and_historical_reopen_refuse_non_wal_without_repair() {
    let directory: Directory = Directory::new();
    let path: PathBuf = directory.database();
    drop(SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap());
    let connection: Connection = Connection::open(&path).unwrap();
    let mode: String = connection
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    drop(connection);
    assert!(
        matches!(SqliteDurableStore::open_existing(&path, namespace()), Err(SqliteDurableStoreError::UnsupportedJournalMode(mode)) if mode == "delete")
    );
    assert!(
        matches!(SqliteDurableStore::open_historical(&path, namespace()), Err(SqliteDurableStoreError::UnsupportedJournalMode(mode)) if mode == "delete")
    );
    let connection: Connection = Connection::open(&path).unwrap();
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    let count: i64 = connection
        .query_row("SELECT count(*) FROM durable_metadata", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn bootstrap_owner_lost_confirmation_preserves_metadata_but_returns_no_serving_success() {
    for after in [false, true] {
        let directory: Directory = Directory::new();
        let path: PathBuf = directory.database();
        let reserved: native_files::ImportFile = native_files::create_new(&path).unwrap();
        let backend: NativeSqlBackend = NativeSqlBackend::from_owned(
            NativeConnection::open_reserved(reserved, true, true).unwrap(),
        );
        backend.on_commit(
            if after {
                CommitBoundary::AfterCommit
            } else {
                CommitBoundary::BeforeDispatch
            },
            move || {
                Err(if after {
                    SqlBackendError::CommitIndeterminate
                } else {
                    SqlBackendError::Unavailable
                })
            },
        );
        let result: Result<(), SqliteDurableStoreError> =
            bootstrap_ordinary(&backend, &namespace(), fence(7));
        assert!(if after {
            matches!(result, Err(SqliteDurableStoreError::CommitIndeterminate))
        } else {
            matches!(result, Err(SqliteDurableStoreError::Unavailable))
        });
        drop(backend);
        if after {
            let store: SqliteDurableStore =
                SqliteDurableStore::open_existing(&path, namespace()).unwrap();
            assert_eq!(store.writer_fence().unwrap(), fence(7));
            assert!(store.object_store_is_empty().unwrap());
            assert!(
                store
                    .get_namespace_lifecycle(&context(7), namespace().domain())
                    .unwrap()
                    .is_ordinary()
            );
        } else {
            assert!(SqliteDurableStore::open_existing(&path, namespace()).is_err());
            let connection: Connection = Connection::open(&path).unwrap();
            let count: i64 = connection
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name='durable_metadata'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
        }
    }
}

#[test]
fn operator_commit_ambiguity_preserves_exact_fence_without_live_ownership_or_blind_retry() {
    let directory: Directory = Directory::new();
    let path: PathBuf = directory.database();
    let store: SqliteDurableStore =
        SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap();
    store
        .engine
        .backend()
        .on_commit(CommitBoundary::BeforeDispatch, || {
            Err(SqlBackendError::Unavailable)
        });
    assert!(matches!(
        store.advance_writer_fence(fence(1), fence(2)),
        Err(SqliteDurableStoreError::Unavailable)
    ));
    assert_eq!(store.writer_fence().unwrap(), fence(1));
    store
        .engine
        .backend()
        .on_commit(CommitBoundary::AfterCommit, || {
            Err(SqlBackendError::CommitIndeterminate)
        });
    assert!(matches!(
        store.advance_writer_fence(fence(1), fence(2)),
        Err(SqliteDurableStoreError::CommitIndeterminate)
    ));
    drop(store);
    // Exact existing inspection observes committed metadata. This observation
    // is not a claim that either competing operator owns a live writer.
    let reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(&path, namespace()).unwrap();
    assert_eq!(reopened.writer_fence().unwrap(), fence(2));
    assert!(
        reopened
            .get_namespace_lifecycle(&context(2), namespace().domain())
            .unwrap()
            .is_ordinary()
    );
    assert!(
        !reopened
            .get_outgoing_barrier(&context(2), namespace().domain())
            .unwrap()
            .is_sealed()
    );
    assert!(
        matches!(reopened.advance_writer_fence(fence(1), fence(2)), Err(SqliteDurableStoreError::WriterFenceMismatch { expected, actual }) if expected == fence(1) && actual == fence(2))
    );
}

#[test]
fn request_and_operator_precommit_identity_failure_are_definite_postcommit_is_indeterminate() {
    for operator in [false, true] {
        for after in [false, true] {
            let directory: Directory = Directory::new();
            let parent: PathBuf = directory.0.join("parent");
            let detached: PathBuf = directory.0.join("detached");
            fs::create_dir(&parent).unwrap();
            let path: PathBuf = parent.join("state.db");
            let store: SqliteDurableStore =
                SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap();
            let swapped: PathBuf = parent.clone();
            let retained: PathBuf = detached.clone();
            store.engine.backend().on_commit(
                if after {
                    CommitBoundary::AfterCommit
                } else {
                    CommitBoundary::BeforeDispatch
                },
                move || {
                    fs::rename(&swapped, &retained).unwrap();
                    fs::create_dir(&swapped).unwrap();
                    fs::write(swapped.join("state.db"), b"do not repair or bless").unwrap();
                    Ok(())
                },
            );
            if operator {
                let result = store.advance_writer_fence(fence(1), fence(2));
                assert!(if after {
                    matches!(result, Err(SqliteDurableStoreError::CommitIndeterminate))
                } else {
                    matches!(result, Err(SqliteDurableStoreError::Unavailable))
                });
            } else {
                let result: DurableCommitOutcome =
                    store.commit_invocation(&context(1), invocation());
                assert!(if after {
                    matches!(result, DurableCommitOutcome::Indeterminate(_))
                } else {
                    matches!(
                        result,
                        DurableCommitOutcome::Rejected(
                            DurableCommitRejection::UnavailableBeforeCommit
                        )
                    )
                });
            }
            assert!(store.writer_fence().is_err());
            drop(store);
            let reopened: SqliteDurableStore =
                SqliteDurableStore::open_existing(detached.join("state.db"), namespace()).unwrap();
            assert_eq!(
                reopened.writer_fence().unwrap(),
                fence(if operator && after { 2 } else { 1 })
            );
            let receipt: Option<DurableRequestReceipt> = reopened
                .get_request_receipt(
                    &context(if operator && after { 2 } else { 1 }),
                    namespace().domain(),
                    OutboxRequestId::new([81; 32]).unwrap(),
                )
                .unwrap();
            assert_eq!(receipt.is_some(), !operator && after);
            assert_eq!(fs::read(&path).unwrap(), b"do not repair or bless");
        }
    }
}

#[test]
fn structured_reopen_reads_and_snapshot_refuse_main_ancestor_and_sidecar_changes() {
    for changed in ["main", "ancestor", "wal", "shm", "journal"] {
        for symlink in [false, true] {
            let directory: Directory = Directory::new();
            let parent: PathBuf = directory.0.join("parent");
            fs::create_dir(&parent).unwrap();
            let path: PathBuf = parent.join("state.db");
            let original: SqliteDurableStore =
                SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap();
            let store: SqliteDurableStore =
                SqliteDurableStore::open_existing(&path, namespace()).unwrap();
            let ns: SqliteNamespace = namespace();
            let ctx: DurableOperationContext = context(1);
            store.begin_portable_snapshot(&ctx, ns.domain()).unwrap();
            if changed == "journal" {
                // Attach an observed sidecar while this already-open WAL
                // connection is active. Opening a cold pager with a fabricated
                // hot journal would test SQLite recovery refusal instead.
                store
                    .engine
                    .backend()
                    .transaction(TransactionBudget::OperatorDefault, |_session, _| {
                        fs::write(
                            PathBuf::from(format!("{}-journal", path.display())),
                            b"observed journal",
                        )
                        .unwrap();
                        Ok(TransactionDecision::Rollback(()))
                    })
                    .unwrap();
            }
            if changed == "ancestor" {
                let detached: PathBuf = parent.with_extension("detached");
                fs::rename(&parent, &detached).unwrap();
                if symlink {
                    std::os::unix::fs::symlink(&detached, &parent).unwrap();
                } else {
                    fs::create_dir(&parent).unwrap();
                    fs::hard_link(detached.join("state.db"), &path).unwrap();
                }
            } else {
                let target: PathBuf = if changed == "main" {
                    path.clone()
                } else {
                    PathBuf::from(format!("{}-{changed}", path.display()))
                };
                let retained: PathBuf = target.with_extension("retained");
                if target.exists() {
                    fs::rename(&target, &retained).unwrap();
                } else {
                    fs::write(&retained, b"journal control").unwrap();
                }
                if symlink {
                    std::os::unix::fs::symlink(&retained, &target).unwrap();
                } else {
                    fs::write(&target, b"replacement").unwrap();
                }
            }
            assert!(
                store
                    .get_versioned_durable(&ctx, ns.domain(), b"state")
                    .is_err(),
                "{changed}/{symlink}"
            );
            assert!(
                store.begin_portable_snapshot(&ctx, ns.domain()).is_err(),
                "{changed}/{symlink}"
            );
            assert!(store.writer_fence().is_err());
            assert!(store.sync_created().is_err());
            drop(store);
            drop(original);
        }
    }
}

#[test]
fn live_wal_and_shm_unlink_refuse_reads_and_commit_without_publication() {
    for suffix in ["wal", "shm"] {
        let directory: Directory = Directory::new();
        let path: PathBuf = directory.database();
        let store: SqliteDurableStore =
            SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap();
        fs::remove_file(PathBuf::from(format!("{}-{suffix}", path.display()))).unwrap();
        assert!(
            store
                .get_versioned_durable(&context(1), namespace().domain(), b"state")
                .is_err()
        );
        assert_eq!(
            store.commit_invocation(&context(1), invocation()),
            DurableCommitOutcome::Rejected(DurableCommitRejection::UnavailableBeforeCommit)
        );
        assert!(store.sync_created().is_err());
    }
}

#[test]
fn real_truncate_checkpoint_other_connection_close_and_final_reopen_remain_valid() {
    let directory: Directory = Directory::new();
    let path: PathBuf = directory.database();
    let store: SqliteDurableStore =
        SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap();
    let other: SqliteDurableStore = SqliteDurableStore::open_existing(&path, namespace()).unwrap();
    store
        .begin_portable_snapshot(&context(1), namespace().domain())
        .unwrap();
    let checkpoint: (i64, i64, i64) = other.engine.backend().inspect_test(|connection| {
        connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
    });
    assert_eq!(checkpoint, (0, 0, 0));
    drop(other);
    store
        .begin_portable_snapshot(&context(1), namespace().domain())
        .unwrap();
    assert_eq!(
        store.commit_invocation(&context(1), invocation()),
        DurableCommitOutcome::Committed
    );
    store.sync_created().unwrap();
    drop(store);
    let reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(&path, namespace()).unwrap();
    assert_eq!(
        reopened
            .get_request_receipt(
                &context(1),
                namespace().domain(),
                OutboxRequestId::new([81; 32]).unwrap()
            )
            .unwrap(),
        Some(
            DurableRequestReceipt::new(
                OutboxRequestId::new([81; 32]).unwrap(),
                digest(82),
                vec![83, 84]
            )
            .unwrap()
        )
    );
}

#[test]
fn existing_file_and_sidecar_symlink_or_hardlink_alias_are_refused_before_use() {
    for sidecar in [false, true] {
        for symlink in [false, true] {
            let directory: Directory = Directory::new();
            let path: PathBuf = directory.database();
            drop(SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap());
            let alias: PathBuf = if sidecar {
                PathBuf::from(format!("{}-wal", path.display()))
            } else {
                directory.0.join("alias.db")
            };
            if symlink {
                std::os::unix::fs::symlink(&path, &alias).unwrap();
            } else {
                fs::hard_link(&path, &alias).unwrap();
            }
            let target: &Path = if sidecar { &path } else { &alias };
            assert!(SqliteDurableStore::open_existing(target, namespace()).is_err());
            assert!(SqliteDurableStore::open_historical(target, namespace()).is_err());
        }
    }
}

#[test]
fn read_result_checks_identity_after_rollback_under_the_same_mutex() {
    let directory: Directory = Directory::new();
    let path: PathBuf = directory.database();
    let store: SqliteDurableStore =
        SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap();
    let result: Result<u64, SqlBackendError> =
        store
            .engine
            .backend()
            .transaction(TransactionBudget::OperatorDefault, |_session, _| {
                fs::rename(&path, path.with_extension("retained")).unwrap();
                fs::write(&path, b"replacement").unwrap();
                Ok(TransactionDecision::Rollback(123))
            });
    assert!(
        matches!(result, Err(SqlBackendError::Unavailable)),
        "changed read cannot release its value"
    );
}

#[test]
fn dropping_other_identity_and_failed_constructor_never_releases_external_writer_exclusion() {
    let directory: Directory = Directory::new();
    let path: PathBuf = directory.database();
    let store: SqliteDurableStore =
        SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap();
    store
        .engine
        .backend()
        .transaction(TransactionBudget::OperatorDefault, |_session, _| {
            probe_exclusion(&path);
            let other_identity: native_files::ImportFile =
                native_files::open_existing(&path).unwrap();
            drop(other_identity);
            probe_exclusion(&path);
            let other: NativeConnection = open_verified_connection(&path).unwrap();
            drop(other);
            probe_exclusion(&path);
            let foreign: SqliteNamespace = SqliteNamespace::new(
                ChainId::new("other").unwrap(),
                ValidatorId::new([31; 32]),
                namespace().domain(),
            );
            assert!(SqliteDurableStore::open_existing(&path, foreign).is_err());
            probe_exclusion(&path);
            Ok(TransactionDecision::Rollback(()))
        })
        .unwrap();
    probe_writer(&path, "available");
    drop(store);
    probe_writer_mode(&path, "available", true);
}

#[test]
fn process_commit_child() {
    let Some(path) = std::env::var_os("SUNRISE_SQLITE_TEST_PATH") else {
        return;
    };
    let path: PathBuf = PathBuf::from(path);
    let stage: String = std::env::var("SUNRISE_SQLITE_KILL_BOUNDARY").unwrap();
    let marker: PathBuf = path.with_extension("boundary");
    let boundary: CommitBoundary = if stage == "before" {
        CommitBoundary::BeforeDispatch
    } else {
        assert_eq!(stage, "after");
        CommitBoundary::AfterCommit
    };
    let store: SqliteDurableStore = SqliteDurableStore::open_existing(&path, namespace()).unwrap();
    store.engine.backend().on_commit(boundary, move || {
        fs::write(marker, stage.as_bytes()).unwrap();
        loop {
            std::thread::park();
        }
    });
    store.commit_invocation(&context(1), invocation());
    panic!("commit boundary child returned before it was killed");
}

struct KillChild(Child);
impl Drop for KillChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn kill_at_commit(path: &Path, stage: &str) {
    let mut child: KillChild = KillChild(
        child_command("structured::ownership_tests::process_commit_child", path)
            .env("SUNRISE_SQLITE_KILL_BOUNDARY", stage)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let marker: PathBuf = path.with_extension("boundary");
    let deadline: Instant = Instant::now() + Duration::from_secs(15);
    while !marker.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "boundary child exited early"
        );
        assert!(
            Instant::now() < deadline,
            "child did not reach real commit boundary"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fs::read(&marker).unwrap(), stage.as_bytes());
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
}

#[test]
fn real_process_kill_before_commit_publishes_none_after_commit_publishes_exact_write_set() {
    for stage in ["before", "after"] {
        let directory: Directory = Directory::new();
        let path: PathBuf = directory.database();
        drop(SqliteDurableStore::create_new(&path, namespace(), fence(1)).unwrap());
        kill_at_commit(&path, stage);
        let store: SqliteDurableStore =
            SqliteDurableStore::open_existing(&path, namespace()).unwrap();
        let ctx: DurableOperationContext = context(1);
        let domain: AtomicityDomainId = namespace().domain();
        let request: OutboxRequestId = OutboxRequestId::new([81; 32]).unwrap();
        let receipt: Option<DurableRequestReceipt> =
            store.get_request_receipt(&ctx, domain, request).unwrap();
        let state: VersionedStateValue =
            store.get_versioned_durable(&ctx, domain, b"state").unwrap();
        let nonce: VersionedStateValue = store
            .get_versioned_durable(&ctx, domain, &nonce_key())
            .unwrap();
        let head: DurableObjectHead = store
            .get_object_head(&ctx, domain, ObjectId::new([61; 32]))
            .unwrap();
        let version: Option<DurableObjectVersionRecord> = store
            .get_object_version(
                &ctx,
                domain,
                ObjectId::new([61; 32]),
                DurableObjectVersion::new(1).unwrap(),
            )
            .unwrap();
        if stage == "before" {
            assert!(receipt.is_none());
            assert!(version.is_none());
            assert_eq!(head, DurableObjectHead::Absent);
            assert_eq!(state.revision(), StateRevision::INITIAL);
            assert_eq!(state.value(), None);
            assert_eq!(nonce.revision(), StateRevision::INITIAL);
            assert_eq!(nonce.value(), None);
            assert_eq!(
                store.claim_due_outbox(
                    &ctx,
                    DueOutboxClaimRequest::new(
                        domain,
                        0,
                        DurableOutboxLeaseId::new([91; 32]).unwrap(),
                        1_000
                    )
                    .unwrap()
                ),
                DurableOutboxClaimOutcome::NoDueWork
            );
            assert_eq!(
                store.commit_invocation(&ctx, invocation()),
                DurableCommitOutcome::Committed
            );
        } else {
            assert_eq!(
                receipt.unwrap(),
                DurableRequestReceipt::new(request, digest(82), vec![83, 84]).unwrap()
            );
            assert_eq!(state.value(), Some(&[71][..]));
            assert_eq!(state.revision(), StateRevision::new(1));
            let expected_nonce: Vec<u8> = nonce_record_bytes();
            assert_eq!(nonce.value(), Some(expected_nonce.as_slice()));
            assert_eq!(nonce.revision(), StateRevision::new(1));
            assert!(
                matches!(head, DurableObjectHead::Current { head_revision, object_version, .. } if head_revision == runtime::ObjectHeadRevision::FIRST && object_version == DurableObjectVersion::new(1).unwrap())
            );
            let expected: DurableInvocationTransaction = invocation();
            let DurableObjectMutation::Create {
                version: expected_version,
                ..
            } = expected.object_changes().mutations()[0].mutation()
            else {
                panic!("test invocation must create an object");
            };
            assert_eq!(version.as_ref(), Some(expected_version));
            let before_replay: PortableSnapshotToken =
                store.begin_portable_snapshot(&ctx, domain).unwrap();
            assert_eq!(
                store.commit_invocation(&ctx, invocation()),
                DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
            );
            assert_eq!(
                store.begin_portable_snapshot(&ctx, domain).unwrap(),
                before_replay
            );
        }
        store.advance_writer_fence(fence(1), fence(2)).unwrap();
        assert!(matches!(
            store.commit_invocation(&ctx, invocation()),
            DurableCommitOutcome::Rejected(DurableCommitRejection::WriterFenced { .. })
        ));
        let fresh: DurableOperationContext = context(2);
        assert_eq!(
            store.commit_invocation(&fresh, invocation()),
            DurableCommitOutcome::Rejected(DurableCommitRejection::RequestAlreadyCommitted)
        );
        assert_eq!(
            store
                .get_versioned_durable(&fresh, domain, &nonce_key())
                .unwrap()
                .revision(),
            StateRevision::new(1)
        );
        assert!(
            matches!(store.get_object_head(&fresh, domain, ObjectId::new([61; 32])).unwrap(), DurableObjectHead::Current { head_revision, object_version, .. } if head_revision == runtime::ObjectHeadRevision::FIRST && object_version == DurableObjectVersion::new(1).unwrap())
        );
        assert!(
            store
                .get_object_version(
                    &fresh,
                    domain,
                    ObjectId::new([61; 32]),
                    DurableObjectVersion::new(2).unwrap()
                )
                .unwrap()
                .is_none()
        );
        let lease: DurableOutboxLeaseId = DurableOutboxLeaseId::new([92; 32]).unwrap();
        let claim = store.claim_due_outbox(
            &fresh,
            DueOutboxClaimRequest::new(domain, 0, lease, 1_000).unwrap(),
        );
        let DurableOutboxClaimOutcome::Claimed(message) = claim else {
            panic!("outbox missing after exact commit: {claim:?}");
        };
        assert_eq!(message.canonical_payload(), &[86]);
        assert_eq!(
            store.acknowledge_outbox(
                &fresh,
                DurableOutboxAcknowledgement::new(domain, request, 0, lease)
            ),
            runtime::DurableOutboxAcknowledgementOutcome::Acknowledged
        );
        assert_eq!(
            store.claim_due_outbox(
                &fresh,
                DueOutboxClaimRequest::new(
                    domain,
                    0,
                    DurableOutboxLeaseId::new([93; 32]).unwrap(),
                    1_000
                )
                .unwrap()
            ),
            DurableOutboxClaimOutcome::NoDueWork
        );
    }
}
