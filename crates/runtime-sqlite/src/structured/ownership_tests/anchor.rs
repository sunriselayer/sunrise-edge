//! Real store/lease/commit controls for the opt-in local anchor profile.
use super::*;
use crate::rusqlite_backend::{CommitBoundary, NativeSqlBackend};
use crate::{AnchorCheckpoint, enroll_independent_anchor, inspect_independent_anchor_inputs};
use runtime::BlobStore;
use rusqlite::params;

struct Fixture {
    directory: Directory,
    state: PathBuf,
    blobs: PathBuf,
    anchor: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory: Directory = Directory::new();
        let source: PathBuf = directory.0.join("source");
        let authority: PathBuf = directory.0.join("authority");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&authority).unwrap();
        let state: PathBuf = source.join("state.db");
        let blobs: PathBuf = source.join("bodies.db");
        let anchor: PathBuf = authority.join("anchor.db");
        drop(SqliteDurableStore::open(&state, namespace(), fence(1)).unwrap());
        let bodies: crate::SqliteBlobStore = crate::SqliteBlobStore::open(&blobs).unwrap();
        bodies
            .put_blob(digest(83), b"complete immutable body".to_vec())
            .unwrap();
        drop(bodies);
        Self {
            directory,
            state,
            blobs,
            anchor,
        }
    }
    fn inspect(&self) -> AnchorCheckpoint {
        inspect_independent_anchor_inputs(
            &self.state,
            &self.blobs,
            namespace().chain_id(),
            namespace().validator_id(),
            namespace().domain(),
        )
        .unwrap()
    }
    fn enroll(&self) -> AnchorCheckpoint {
        let expected: AnchorCheckpoint = self.inspect();
        enroll_independent_anchor(
            &self.state,
            &self.blobs,
            &self.anchor,
            namespace().chain_id(),
            namespace().validator_id(),
            namespace().domain(),
            expected.state_root,
            expected.body_manifest_root,
            true,
        )
        .unwrap()
    }
    fn open(&self) -> Result<SqliteDurableStore, SqliteDurableStoreError> {
        SqliteDurableStore::open_anchored(&self.state, &self.blobs, &self.anchor, namespace())
    }
    fn backend(&self) -> NativeSqlBackend {
        let owner =
            crate::anchor::IndependentAnchor::open(&self.anchor, &self.state, &self.blobs).unwrap();
        let connection: NativeConnection = open_verified_connection(&self.state).unwrap();
        NativeSqlBackend::anchored(connection, owner)
    }
}

#[test]
fn anchor_enrollment_requires_pins_stopped_owner_and_existing_separate_authority() {
    let f: Fixture = Fixture::new();
    let expected: AnchorCheckpoint = f.inspect();
    for (state, body, confirmed) in [
        ([99; 32], expected.body_manifest_root, true),
        (expected.state_root, [98; 32], true),
        (expected.state_root, expected.body_manifest_root, false),
    ] {
        assert!(
            enroll_independent_anchor(
                &f.state,
                &f.blobs,
                &f.anchor,
                namespace().chain_id(),
                namespace().validator_id(),
                namespace().domain(),
                state,
                body,
                confirmed
            )
            .is_err()
        );
        assert!(!f.anchor.exists());
        assert!(!f.anchor.with_file_name("anchor.db.lease").exists());
    }
    assert!(f.open().is_err());
    assert!(!f.anchor.exists());
    let initial: AnchorCheckpoint = f.enroll();
    assert_eq!(initial.sequence, 1);
    assert_eq!(initial.body_manifest_root, expected.body_manifest_root);
    assert_ne!(initial.state_root, expected.state_root); // explicit local profile transition
    assert!(
        enroll_independent_anchor(
            &f.state,
            &f.blobs,
            &f.anchor,
            namespace().chain_id(),
            namespace().validator_id(),
            namespace().domain(),
            expected.state_root,
            expected.body_manifest_root,
            true
        )
        .is_err()
    );
    let store: SqliteDurableStore = f.open().unwrap();
    assert_eq!(store.writer_fence().unwrap(), fence(1));
    store.advance_writer_fence(fence(1), fence(2)).unwrap();
    assert_eq!(store.writer_fence().unwrap(), fence(2));
    let published: AnchorCheckpoint = store.independent_anchor_checkpoint().unwrap();
    assert_eq!(published.sequence, 2);
    assert_ne!(published.state_root, initial.state_root);
    assert_eq!(published.body_manifest_root, initial.body_manifest_root);
}

#[test]
fn anchor_enrollment_excludes_already_open_baseline_store_and_keeps_historical_reading() {
    let f: Fixture = Fixture::new();
    let old: SqliteDurableStore = SqliteDurableStore::open_existing(&f.state, namespace()).unwrap();
    f.enroll();
    assert!(old.writer_fence().is_err());
    assert!(old.advance_writer_fence(fence(1), fence(2)).is_err());
    assert!(SqliteDurableStore::open_existing(&f.state, namespace()).is_err());
    let historical: SqliteDurableStore =
        SqliteDurableStore::open_historical(&f.state, namespace()).unwrap();
    assert_eq!(historical.writer_fence().unwrap(), fence(1));
    assert!(historical.advance_writer_fence(fence(1), fence(2)).is_err());
    drop(historical);
    drop(old);
    assert_eq!(f.open().unwrap().writer_fence().unwrap(), fence(1));
}

#[test]
fn anchor_excludes_concurrent_current_clone_and_accepts_exact_current_recovery_after_stop() {
    let f: Fixture = Fixture::new();
    f.enroll();
    let recovered: PathBuf = f.directory.0.join("recovered");
    fs::create_dir(&recovered).unwrap();
    let clone: PathBuf = recovered.join("clone.db");
    fs::copy(&f.state, &clone).unwrap();
    let current: SqliteDurableStore = f.open().unwrap();
    assert!(SqliteDurableStore::open_anchored(&clone, &f.blobs, &f.anchor, namespace()).is_err());
    assert_eq!(current.writer_fence().unwrap(), fence(1));
    drop(current);
    let restored: SqliteDurableStore =
        SqliteDurableStore::open_anchored(&clone, &f.blobs, &f.anchor, namespace()).unwrap();
    restored.advance_writer_fence(fence(1), fence(2)).unwrap();
    drop(restored);
    assert!(f.open().is_err()); // original is now the stale same-epoch copy
}

#[test]
fn anchor_refuses_in_place_owned_state_rollback_even_with_original_source_inode() {
    let f: Fixture = Fixture::new();
    f.enroll();
    let saved: PathBuf = f.directory.0.join("saved.db");
    fs::copy(&f.state, &saved).unwrap();
    let store: SqliteDurableStore = f.open().unwrap();
    store.advance_writer_fence(fence(1), fence(2)).unwrap();
    drop(store);
    let before = fs::metadata(&f.state).unwrap();
    fs::copy(&saved, &f.state).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(before.ino(), fs::metadata(&f.state).unwrap().ino());
    assert!(f.open().is_err());
}

#[test]
fn anchor_pending_before_source_commit_never_auto_clears_old_state() {
    let f: Fixture = Fixture::new();
    f.enroll();
    let backend: NativeSqlBackend = f.backend();
    backend.on_commit(CommitBoundary::BeforeDispatch, || {
        Err(SqlBackendError::Unavailable)
    });
    let store = SqlDurableEngine::new(backend, namespace());
    assert!(
        store
            .backend()
            .transaction(TransactionBudget::OperatorDefault, |session, _| {
                schema::advance_writer_fence(session, &namespace(), fence(1), fence(2)).map_err(
                    |_| runtime_sql_durable::SqlSessionError::Rejected("control".into()),
                )?;
                Ok(TransactionDecision::Commit(()))
            })
            .is_err()
    );
    drop(store);
    assert!(f.open().is_err());
    assert!(f.open().is_err());
    let c: Connection = Connection::open(&f.anchor).unwrap();
    let pending: i64 = c
        .query_row(
            "SELECT pending_state_root IS NOT NULL FROM anchor_head",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending, 1);
}

#[test]
fn anchor_pending_after_actual_source_commit_reconciles_only_exact_new_rows() {
    let f: Fixture = Fixture::new();
    f.enroll();
    let backend: NativeSqlBackend = f.backend();
    backend.on_commit(CommitBoundary::AfterCommit, || {
        Err(SqlBackendError::Unavailable)
    });
    let result = backend.transaction(TransactionBudget::OperatorDefault, |session, _| {
        schema::advance_writer_fence(session, &namespace(), fence(1), fence(2))
            .map_err(|_| runtime_sql_durable::SqlSessionError::Rejected("control".into()))?;
        Ok(TransactionDecision::Commit(()))
    });
    assert!(matches!(result, Err(SqlBackendError::CommitIndeterminate)));
    drop(backend);
    let reopened: SqliteDurableStore = f.open().unwrap();
    assert_eq!(reopened.writer_fence().unwrap(), fence(2));
    drop(reopened);
    let c: Connection = Connection::open(&f.anchor).unwrap();
    let (sequence, pending): (Vec<u8>, i64) = c
        .query_row(
            "SELECT sequence,pending_state_root IS NOT NULL FROM anchor_head",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(sequence, 2_u64.to_be_bytes());
    assert_eq!(pending, 0);
}

#[test]
fn anchor_refuses_missing_changed_body_and_copied_authority_or_replaced_lease() {
    for fault in ["body", "anchor", "lease"] {
        let f: Fixture = Fixture::new();
        f.enroll();
        let current: SqliteDurableStore = f.open().unwrap();
        if fault == "body" {
            let c: Connection = Connection::open(&f.blobs).unwrap();
            c.execute("UPDATE blobs SET content=zeroblob(length(content))", [])
                .unwrap();
        } else {
            let path: PathBuf = if fault == "anchor" {
                f.anchor.clone()
            } else {
                f.anchor.with_file_name("anchor.db.lease")
            };
            let moved: PathBuf = path.with_extension("old");
            fs::rename(&path, &moved).unwrap();
            fs::copy(&moved, &path).unwrap();
        }
        assert!(current.writer_fence().is_err(), "live {fault}");
        drop(current);
        assert!(f.open().is_err(), "{fault}");
    }
}

#[test]
fn anchor_borrowed_fixed_fields_refuse_oversized_persisted_values() {
    for (table, column) in [
        ("anchor_head", "state_root"),
        ("anchor_head", "sequence"),
        ("anchor_head", "device"),
        ("anchor_bodies", "digest"),
        ("anchor_bodies", "length"),
        ("anchor_bodies", "content_hash"),
    ] {
        let f: Fixture = Fixture::new();
        f.enroll();
        let c: Connection = Connection::open(&f.anchor).unwrap();
        c.pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        c.execute(
            &format!("UPDATE {table} SET {column}=zeroblob(1048576)"),
            [],
        )
        .unwrap();
        drop(c);
        assert!(f.open().is_err(), "{table}.{column}");
    }
}

#[test]
fn anchor_second_open_does_not_release_sqlite_main_or_wal_locks() {
    let f: Fixture = Fixture::new();
    f.enroll();
    let owner = crate::anchor::IndependentAnchor::open(&f.anchor, &f.state, &f.blobs).unwrap();
    owner.test_hold_transaction(|| {
        assert!(f.open().is_err());
        probe_exclusion(&f.anchor);
    });
    drop(owner);
    probe_writer(&f.anchor, "available");
}

#[test]
fn anchor_allows_immutable_staging_then_retains_new_bodies_at_next_commit() {
    let f: Fixture = Fixture::new();
    f.enroll();
    let current: SqliteDurableStore = f.open().unwrap();
    let blobs = crate::SqliteBlobStore::open_existing_writable(&f.blobs).unwrap();
    blobs
        .put_blob(digest(84), b"new immutable staged body".to_vec())
        .unwrap();
    drop(blobs);
    assert_eq!(current.writer_fence().unwrap(), fence(1));
    current.advance_writer_fence(fence(1), fence(2)).unwrap();
    drop(current);
    let c: Connection = Connection::open(&f.blobs).unwrap();
    c.execute(
        "DELETE FROM blobs WHERE digest_bytes=?1",
        [digest(84).bytes().as_slice()],
    )
    .unwrap();
    drop(c);
    assert!(f.open().is_err());
}

#[test]
fn anchor_selected_profile_refuses_oversized_body_before_authority_creation() {
    let f: Fixture = Fixture::new();
    let bodies = crate::SqliteBlobStore::open_existing_writable(&f.blobs).unwrap();
    bodies
        .put_blob(digest(85), vec![85; 16 * 1024 * 1024 + 1])
        .unwrap();
    drop(bodies);
    assert!(
        inspect_independent_anchor_inputs(
            &f.state,
            &f.blobs,
            namespace().chain_id(),
            namespace().validator_id(),
            namespace().domain()
        )
        .is_err()
    );
    assert!(!f.anchor.exists());
}

#[test]
fn anchor_selected_profile_refuses_excessive_complete_state_inventory() {
    let f: Fixture = Fixture::new();
    let mut c: Connection = Connection::open(&f.state).unwrap();
    let tx = c.transaction().unwrap();
    {
        let mut put = tx
            .prepare("INSERT INTO durable_state(key,revision,value) VALUES(?1,?2,?3)")
            .unwrap();
        for index in 0_u64..17_000 {
            put.execute(params![
                index.to_be_bytes().as_slice(),
                1_u64.to_be_bytes().as_slice(),
                [7_u8].as_slice()
            ])
            .unwrap();
        }
    }
    tx.commit().unwrap();
    drop(c);
    assert!(
        inspect_independent_anchor_inputs(
            &f.state,
            &f.blobs,
            namespace().chain_id(),
            namespace().validator_id(),
            namespace().domain()
        )
        .is_err()
    );
    assert!(!f.anchor.exists());
}

#[test]
fn anchor_logical_noop_commit_does_not_manufacture_indistinguishable_pending() {
    let f: Fixture = Fixture::new();
    let initial: AnchorCheckpoint = f.enroll();
    let backend: NativeSqlBackend = f.backend();
    backend.on_commit(CommitBoundary::BeforeDispatch, || {
        Err(SqlBackendError::Unavailable)
    });
    assert!(
        backend
            .transaction(TransactionBudget::OperatorDefault, |_session, _| Ok(
                TransactionDecision::Commit(())
            ))
            .is_err()
    );
    drop(backend);
    let current: SqliteDurableStore = f.open().unwrap();
    assert_eq!(current.independent_anchor_checkpoint().unwrap(), initial);
}
