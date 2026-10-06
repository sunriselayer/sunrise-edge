//! Fresh factories retain the reserved inode and refuse unsafe destinations.
//! These are real SQLite files; no operator/genesis authority is inferred.
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use runtime::WriterFenceGeneration;
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let sequence: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
        let time: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-fresh-files-{}-{time}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn namespace() -> SqliteNamespace {
    SqliteNamespace::new(
        ChainId::new("fresh-files-test").unwrap(),
        ValidatorId::new([31; 32]),
        AtomicityDomainId::new([32; 32]).unwrap(),
    )
}

fn refused(path: &Path) {
    assert!(
        SqliteDurableStore::create_new(path, namespace(), WriterFenceGeneration::new(1).unwrap())
            .is_err()
    );
    assert!(SqliteBlobStore::create_new_fresh(path).is_err());
}

#[test]
fn fresh_factories_refuse_each_existing_main_or_sidecar_without_repair() {
    let directory: Directory = Directory::new();
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path: PathBuf = directory.0.join(format!("existing-{suffix}.sqlite"));
        let mut occupied: OsString = path.as_os_str().to_owned();
        occupied.push(suffix);
        let occupied: PathBuf = occupied.into();
        fs::write(&occupied, b"keep unchanged").unwrap();
        refused(&path);
        assert_eq!(fs::read(&occupied).unwrap(), b"keep unchanged");
        if !suffix.is_empty() {
            assert!(!path.exists());
        }
    }
}

#[test]
fn both_fresh_factories_bind_and_flush_without_granting_reopened_ownership() {
    let directory: Directory = Directory::new();
    let state_path: PathBuf = directory.0.join("state.sqlite");
    let blob_path: PathBuf = directory.0.join("blob.sqlite");
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(7).unwrap();
    let state: SqliteDurableStore =
        SqliteDurableStore::create_new(&state_path, namespace(), fence).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::create_new_fresh(&blob_path).unwrap();
    state.sync_created().unwrap();
    blobs.sync_created().unwrap();
    assert_eq!(state.writer_fence().unwrap(), fence);
    assert_eq!(state.namespace(), &namespace());
    drop(state);
    drop(blobs);
    let reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_path, namespace()).unwrap();
    let reopened_blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_path).unwrap();
    assert_eq!(reopened.writer_fence().unwrap(), fence);
    assert!(reopened.sync_created().is_err());
    assert!(reopened_blobs.sync_created().is_err());
    let foreign: SqliteNamespace = SqliteNamespace::new(
        ChainId::new("foreign").unwrap(),
        ValidatorId::new([31; 32]),
        AtomicityDomainId::new([32; 32]).unwrap(),
    );
    assert!(SqliteDurableStore::open_existing(&state_path, foreign).is_err());
}

#[test]
fn unsafe_missing_and_non_directory_parents_never_create_a_main() {
    let directory: Directory = Directory::new();
    let missing: PathBuf = directory.0.join("missing/db.sqlite");
    refused(&missing);
    assert!(!missing.exists());
    let parent_file: PathBuf = directory.0.join("file");
    fs::write(&parent_file, b"parent stays a file").unwrap();
    refused(&parent_file.join("db.sqlite"));
    assert_eq!(fs::read(parent_file).unwrap(), b"parent stays a file");
    refused(&directory.0.join("../not-allowed.sqlite"));
    #[cfg(unix)]
    {
        let target: PathBuf = directory.0.join("target");
        fs::write(&target, b"leaf retained").unwrap();
        let leaf: PathBuf = directory.0.join("link");
        std::os::unix::fs::symlink(&target, &leaf).unwrap();
        refused(&leaf);
        assert_eq!(fs::read(&target).unwrap(), b"leaf retained");
        let parent: PathBuf = directory.0.join("parent-link");
        std::os::unix::fs::symlink(&directory.0, &parent).unwrap();
        refused(&parent.join("db.sqlite"));
        assert!(!directory.0.join("db.sqlite").exists());
    }
}

#[cfg(unix)]
#[test]
fn retained_factories_refuse_replaced_leaf_and_replaced_parent_even_for_original_inode() {
    let directory: Directory = Directory::new();
    for blob in [false, true] {
        for parent_swap in [false, true] {
            let parent: PathBuf = directory.0.join(format!("owner-{blob}-{parent_swap}"));
            fs::create_dir(&parent).unwrap();
            let path: PathBuf = parent.join("db.sqlite");
            let state: Option<SqliteDurableStore> = if blob {
                None
            } else {
                Some(
                    SqliteDurableStore::create_new(
                        &path,
                        namespace(),
                        WriterFenceGeneration::new(1).unwrap(),
                    )
                    .unwrap(),
                )
            };
            let blobs: Option<SqliteBlobStore> = if blob {
                Some(SqliteBlobStore::create_new_fresh(&path).unwrap())
            } else {
                None
            };
            if parent_swap {
                let detached: PathBuf = parent.with_extension("detached");
                fs::rename(&parent, &detached).unwrap();
                fs::create_dir(&parent).unwrap();
                fs::hard_link(detached.join("db.sqlite"), &path).unwrap();
            } else {
                fs::rename(&path, path.with_extension("detached")).unwrap();
                fs::write(&path, b"replacement must not be blessed").unwrap();
            }
            if let Some(store) = state {
                assert!(store.sync_created().is_err());
            }
            if let Some(store) = blobs {
                assert!(store.sync_created().is_err());
            }
        }
    }
}

#[test]
fn read_only_blob_reopen_refuses_missing_payload_columns_without_repair() {
    let directory: Directory = Directory::new();
    let path: PathBuf = directory.0.join("blob.sqlite");
    drop(SqliteBlobStore::create_new_fresh(&path).unwrap());
    let connection: rusqlite::Connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute("DROP TABLE blobs", []).unwrap();
    connection
        .execute("CREATE TABLE blobs (foreign_column INTEGER)", [])
        .unwrap();
    drop(connection);
    assert!(SqliteBlobStore::open_existing(&path).is_err());
    let connection: rusqlite::Connection = rusqlite::Connection::open(&path).unwrap();
    let columns: i64 = connection
        .query_row(
            "SELECT count(*) FROM pragma_table_info('blobs') WHERE name='foreign_column'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(columns, 1);
}
