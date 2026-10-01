//! Local-only, file-backed content-addressed [`BlobStore`] implementation.
//!
//! [`SqliteBlobStore`] uses its own SQLite `PRAGMA application_id`, schema,
//! and file, separate from both [`crate::SqliteStateStore`] (the opaque
//! legacy store) and [`crate::SqliteDurableStore`] (the structured store):
//! `application_id`/`user_version` are whole-file SQLite properties, so this
//! store cannot share a database file with either of them, and this module
//! never creates, reads, or migrates their tables. A blob is identified only
//! by its self-describing digest, never by a chain/validator/domain
//! namespace, so unlike [`crate::SqliteDurableStore`] this store binds no
//! namespace at open time.
//!
//! `put_blob` is atomic insert-if-absent: storing byte-identical content
//! under an already-present digest is an idempotent no-op success, storing
//! different content under an already-present digest fails closed with
//! [`RuntimeError::BlobDigestConflict`], and each `put_blob` call runs inside
//! its own `BEGIN IMMEDIATE` transaction. `get_blob` is a point query
//! against the connection. Portable descriptor and range reads project only
//! the stored length and requested chunk in one query under the connection
//! lock. This module defines no delete or garbage-collection operation;
//! GC/checkpoint manifest work that would reclaim blobs remains deferred.

use crate::native_files;
use protocol_types::Digest32;
use runtime::portable::{
    PortableBlobChunk, PortableBlobChunkOutcome, PortableBlobChunkRequest, PortableBlobDescriptor,
    PortableBlobRepository,
};
use runtime::{BlobStore, RuntimeError};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{
    error::Error,
    fmt,
    ops::Range,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

const BLOB_APPLICATION_ID: i64 = 0x5352_4245;
const BLOB_SCHEMA_VERSION: i64 = 1;
const BLOB_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Stable identity of the local-only content-addressed blob SQLite schema,
/// generation one.
///
/// A future additive migration bumps [`BLOB_SCHEMA_VERSION`] and this
/// identity together; a database claimed by an unsupported identity or
/// version fails closed rather than being silently reinterpreted.
pub const SQLITE_BLOB_SCHEMA_IDENTITY: &[u8] = b"sunrise-edge/sqlite/blob/schema/v1";

/// Fail-closed errors opening or bootstrapping a blob SQLite database, distinct
/// from the [`RuntimeError`] surface [`BlobStore`] methods return.
#[derive(Debug)]
pub enum SqliteBlobStoreError {
    /// Import file ownership failed; no existing path is replaced.
    File(std::io::Error),
    /// SQLite rejected an operation.
    Database(rusqlite::Error),
    /// The database could not enter WAL mode.
    UnsupportedJournalMode(String),
    /// The database belongs to another application.
    ApplicationId(i64),
    /// An unclaimed database already contained unrelated schema objects.
    UnclaimedDatabase,
    /// The database schema version is not supported by this binary.
    SchemaVersion(i64),
    /// The persisted schema identity does not match this binary.
    SchemaIdentityMismatch,
    /// The metadata row is missing or malformed.
    InvalidPersistedMetadata,
    /// Another thread panicked while holding the connection.
    ConnectionPoisoned,
}

impl fmt::Display for SqliteBlobStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(error) => write!(f, "SQLite blob file operation failed: {error}"),
            Self::Database(error) => write!(f, "SQLite operation failed: {error}"),
            Self::UnsupportedJournalMode(mode) => {
                write!(f, "SQLite journal mode is {mode}, expected wal")
            }
            Self::ApplicationId(id) => write!(
                f,
                "SQLite application id is {id:#x}, expected {BLOB_APPLICATION_ID:#x}"
            ),
            Self::UnclaimedDatabase => {
                f.write_str("unclaimed SQLite database already contains schema objects")
            }
            Self::SchemaVersion(version) => write!(
                f,
                "SQLite blob schema version is {version}, expected {BLOB_SCHEMA_VERSION}"
            ),
            Self::SchemaIdentityMismatch => {
                f.write_str("SQLite blob schema identity is unsupported")
            }
            Self::InvalidPersistedMetadata => {
                f.write_str("SQLite blob metadata row is missing or malformed")
            }
            Self::ConnectionPoisoned => f.write_str("SQLite connection lock is poisoned"),
        }
    }
}

impl Error for SqliteBlobStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::File(error) => Some(error),
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for SqliteBlobStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

/// A blocking, durable, content-addressed [`BlobStore`] backed by one SQLite
/// file.
///
/// Callers must run this synchronous interface behind bounded blocking
/// isolation when used from an asynchronous request runtime. See the module
/// documentation for its exact scope and limits.
#[derive(Debug)]
pub struct SqliteBlobStore {
    connection: Mutex<Connection>,
}

impl SqliteBlobStore {
    /// Creates only a new regular import artifact file. Existing files,
    /// including initialized source stores, are never overwritten or repaired.
    pub fn create_new(path: impl AsRef<Path>) -> Result<Self, SqliteBlobStoreError> {
        let path: &Path = path.as_ref();
        let held = native_files::create_new(path).map_err(SqliteBlobStoreError::File)?;
        let mut connection: Connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_writable(&connection)?;
        native_files::check_attached(path, &held).map_err(SqliteBlobStoreError::File)?;
        let journal: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(SqliteBlobStoreError::UnsupportedJournalMode(journal));
        }
        initialize_blob_schema(&mut connection)?;
        verify_writable_shape(&connection)?;
        native_files::sync_created(path, &held).map_err(SqliteBlobStoreError::File)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Opens an initialized writable destination without creating a file,
    /// schema or lost marker. Source `open_existing` remains read-only.
    pub fn open_existing_writable(path: impl AsRef<Path>) -> Result<Self, SqliteBlobStoreError> {
        let path: &Path = path.as_ref();
        let held = native_files::open_existing(path).map_err(SqliteBlobStoreError::File)?;
        let connection: Connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_writable(&connection)?;
        let application: i64 =
            connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        if application != BLOB_APPLICATION_ID {
            return Err(SqliteBlobStoreError::ApplicationId(application));
        }
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != BLOB_SCHEMA_VERSION {
            return Err(SqliteBlobStoreError::SchemaVersion(version));
        }
        let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(SqliteBlobStoreError::UnsupportedJournalMode(journal));
        }
        verify_schema_identity(&connection)?;
        verify_writable_shape(&connection)?;
        native_files::check_attached(path, &held).map_err(SqliteBlobStoreError::File)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Opens an already initialized blob file without creating or seeding it.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, SqliteBlobStoreError> {
        let connection: Connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(BLOB_BUSY_TIMEOUT)?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        let application_id: i64 =
            connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        if application_id != BLOB_APPLICATION_ID {
            return Err(SqliteBlobStoreError::ApplicationId(application_id));
        }
        let schema_version: i64 =
            connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if schema_version != BLOB_SCHEMA_VERSION {
            return Err(SqliteBlobStoreError::SchemaVersion(schema_version));
        }
        verify_schema_identity(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Opens or bootstraps a local content-addressed blob database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteBlobStoreError> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(BLOB_BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;

        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(SqliteBlobStoreError::UnsupportedJournalMode(journal_mode));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;

        initialize_blob_schema(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, SqliteBlobStoreError> {
        self.connection
            .lock()
            .map_err(|_| SqliteBlobStoreError::ConnectionPoisoned)
    }
}

fn configure_writable(connection: &Connection) -> Result<(), SqliteBlobStoreError> {
    connection.busy_timeout(BLOB_BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}
fn verify_writable_shape(connection: &Connection) -> Result<(), SqliteBlobStoreError> {
    connection.prepare("SELECT digest_algorithm, digest_bytes, content FROM blobs LIMIT 0")?;
    Ok(())
}

impl BlobStore for SqliteBlobStore {
    fn put_blob(&self, digest: Digest32, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        let mut connection = self.connection().map_err(runtime_failure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_failure)?;
        // An external descriptor observation can race another connection's
        // insertion. Recheck length under this writer transaction before
        // allocating any existing payload; the supplied bytes bound the read.
        let existing_length: Option<i64> = transaction
            .query_row(
                "SELECT length(content) FROM blobs WHERE digest_algorithm = ?1 AND digest_bytes = ?2",
                params![
                    i64::from(digest.algorithm().as_u16()),
                    digest.bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_failure)?;
        match existing_length {
            Some(length) => {
                let length: usize =
                    usize::try_from(length).map_err(|_| RuntimeError::InvalidPersistedState)?;
                if length != bytes.len() {
                    transaction.rollback().map_err(database_failure)?;
                    return Err(RuntimeError::BlobDigestConflict { digest });
                }
                let content: Vec<u8> = transaction
                    .query_row(
                        "SELECT content FROM blobs WHERE digest_algorithm = ?1 AND digest_bytes = ?2",
                        params![
                            i64::from(digest.algorithm().as_u16()),
                            digest.bytes().as_slice(),
                        ],
                        |row| row.get(0),
                    )
                    .map_err(database_failure)?;
                transaction.rollback().map_err(database_failure)?;
                if content == bytes {
                    Ok(())
                } else {
                    Err(RuntimeError::BlobDigestConflict { digest })
                }
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO blobs (digest_algorithm, digest_bytes, content)
                         VALUES (?1, ?2, ?3)",
                        params![
                            i64::from(digest.algorithm().as_u16()),
                            digest.bytes().as_slice(),
                            bytes,
                        ],
                    )
                    .map_err(database_failure)?;
                transaction.commit().map_err(database_failure)
            }
        }
    }

    fn get_blob(&self, digest: &Digest32) -> Result<Option<Vec<u8>>, RuntimeError> {
        let connection = self.connection().map_err(runtime_failure)?;
        connection
            .query_row(
                "SELECT content FROM blobs WHERE digest_algorithm = ?1 AND digest_bytes = ?2",
                params![
                    i64::from(digest.algorithm().as_u16()),
                    digest.bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_failure)
    }
}

impl PortableBlobRepository for SqliteBlobStore {
    fn read_portable_blob_descriptor(
        &self,
        digest: &Digest32,
    ) -> Result<Option<PortableBlobDescriptor>, RuntimeError> {
        let connection = self.connection().map_err(runtime_failure)?;
        let length: Option<i64> = connection
            .query_row(
                "SELECT length(content) FROM blobs WHERE digest_algorithm = ?1 AND digest_bytes = ?2",
                params![
                    i64::from(digest.algorithm().as_u16()),
                    digest.bytes().as_slice(),
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_failure)?;
        let Some(length) = length else {
            return Ok(None);
        };
        let length: usize =
            usize::try_from(length).map_err(|_| RuntimeError::InvalidPersistedState)?;
        Ok(Some(PortableBlobDescriptor::new(*digest, length)))
    }

    fn read_portable_blob_chunk(
        &self,
        request: &PortableBlobChunkRequest,
    ) -> Result<PortableBlobChunkOutcome, RuntimeError> {
        let descriptor: &PortableBlobDescriptor = request.descriptor();
        let range: Range<usize> = request.range();
        let start: i64 = i64::try_from(
            range
                .start
                .checked_add(1)
                .ok_or(RuntimeError::InvalidPersistedState)?,
        )
        .map_err(|_| RuntimeError::InvalidPersistedState)?;
        let chunk_length: i64 =
            i64::try_from(range.len()).map_err(|_| RuntimeError::InvalidPersistedState)?;
        let connection = self.connection().map_err(runtime_failure)?;
        if range.is_empty() {
            // SQLite returns NULL for substr(empty_blob, 1, 0), so confirm
            // presence and zero length without decoding a NULL as bytes.
            let current_length: Option<i64> = connection
                .query_row(
                    "SELECT length(content) FROM blobs WHERE digest_algorithm = ?1 AND digest_bytes = ?2",
                    params![
                        i64::from(descriptor.digest().algorithm().as_u16()),
                        descriptor.digest().bytes().as_slice(),
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(database_failure)?;
            return match current_length {
                Some(0) => PortableBlobChunk::new(request.clone(), Vec::new())
                    .map(|chunk| PortableBlobChunkOutcome::Chunk(Box::new(chunk))),
                _ => Ok(PortableBlobChunkOutcome::Corrupt),
            };
        }
        let row: Option<(i64, Vec<u8>)> = connection
            .query_row(
                "SELECT length(content), substr(content, ?1, ?2)
                 FROM blobs WHERE digest_algorithm = ?3 AND digest_bytes = ?4",
                params![
                    start,
                    chunk_length,
                    i64::from(descriptor.digest().algorithm().as_u16()),
                    descriptor.digest().bytes().as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_failure)?;
        let Some((current_length, bytes)) = row else {
            return Ok(PortableBlobChunkOutcome::Corrupt);
        };
        let current_length: usize =
            usize::try_from(current_length).map_err(|_| RuntimeError::InvalidPersistedState)?;
        if current_length != descriptor.length() {
            return Ok(PortableBlobChunkOutcome::Corrupt);
        }
        PortableBlobChunk::new(request.clone(), bytes)
            .map(|chunk| PortableBlobChunkOutcome::Chunk(Box::new(chunk)))
    }
}

fn blob_schema_ddl() -> String {
    format!(
        "CREATE TABLE blob_metadata (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             schema_identity BLOB NOT NULL
         );

         CREATE TABLE blobs (
             digest_algorithm INTEGER NOT NULL,
             digest_bytes BLOB NOT NULL CHECK(length(digest_bytes) = 32),
             content BLOB NOT NULL,
             PRIMARY KEY (digest_algorithm, digest_bytes)
         ) WITHOUT ROWID;

         PRAGMA application_id = {BLOB_APPLICATION_ID};
         PRAGMA user_version = {BLOB_SCHEMA_VERSION};"
    )
}

fn initialize_blob_schema(connection: &mut Connection) -> Result<(), SqliteBlobStoreError> {
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != 0 && application_id != BLOB_APPLICATION_ID {
        return Err(SqliteBlobStoreError::ApplicationId(application_id));
    }
    let schema_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version != 0 && schema_version != BLOB_SCHEMA_VERSION {
        return Err(SqliteBlobStoreError::SchemaVersion(schema_version));
    }

    if application_id == BLOB_APPLICATION_ID && schema_version == BLOB_SCHEMA_VERSION {
        return verify_schema_identity(connection);
    }
    if application_id != 0 {
        return Err(SqliteBlobStoreError::SchemaVersion(schema_version));
    }
    if schema_version != 0 {
        return Err(SqliteBlobStoreError::ApplicationId(application_id));
    }
    let schema_objects: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if schema_objects != 0 {
        return Err(SqliteBlobStoreError::UnclaimedDatabase);
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(&blob_schema_ddl())?;
    transaction.execute(
        "INSERT INTO blob_metadata (id, schema_identity) VALUES (1, ?1)",
        params![SQLITE_BLOB_SCHEMA_IDENTITY],
    )?;
    transaction.commit()?;
    verify_schema_identity(connection)
}

fn verify_schema_identity(connection: &Connection) -> Result<(), SqliteBlobStoreError> {
    let schema_identity: Option<Vec<u8>> = connection
        .query_row(
            "SELECT schema_identity FROM blob_metadata WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(schema_identity) = schema_identity else {
        return Err(SqliteBlobStoreError::InvalidPersistedMetadata);
    };
    if schema_identity != SQLITE_BLOB_SCHEMA_IDENTITY {
        return Err(SqliteBlobStoreError::SchemaIdentityMismatch);
    }
    Ok(())
}

fn database_failure(_error: rusqlite::Error) -> RuntimeError {
    RuntimeError::DurableStoreUnavailable
}

fn runtime_failure(_error: SqliteBlobStoreError) -> RuntimeError {
    RuntimeError::DurableStoreUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::HashAlgorithmId;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestDatabase {
        path: PathBuf,
    }

    impl TestDatabase {
        fn new() -> Self {
            let nonce = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "sunrise-edge-sqlite-blob-{}-{nanos}-{nonce}.db",
                std::process::id()
            ));
            Self { path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let mut path = self.path.as_os_str().to_owned();
                path.push(suffix);
                let path = PathBuf::from(path);
                if path.exists() {
                    fs::remove_file(path).unwrap();
                }
            }
        }
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
    }

    #[test]
    fn inactive_import_blob_create_and_writable_reopen_never_repair_or_overwrite() {
        let database: TestDatabase = TestDatabase::new();
        assert!(SqliteBlobStore::open_existing_writable(&database.path).is_err());
        assert!(!database.path.exists());
        let store: SqliteBlobStore = SqliteBlobStore::create_new(&database.path).unwrap();
        store.put_blob(digest(7), vec![1, 2, 3]).unwrap();
        assert!(SqliteBlobStore::create_new(&database.path).is_err());
        drop(store);
        let reopened: SqliteBlobStore =
            SqliteBlobStore::open_existing_writable(&database.path).unwrap();
        assert_eq!(reopened.get_blob(&digest(7)).unwrap(), Some(vec![1, 2, 3]));
        reopened.put_blob(digest(8), vec![4, 5, 6]).unwrap();
        assert_eq!(
            reopened.put_blob(digest(7), vec![9]),
            Err(RuntimeError::BlobDigestConflict { digest: digest(7) })
        );
        drop(reopened);
        let source: SqliteBlobStore = SqliteBlobStore::open_existing(&database.path).unwrap();
        assert!(
            source.put_blob(digest(9), vec![7]).is_err(),
            "existing source API stays read-only"
        );
        drop(source);
        let connection: Connection = Connection::open(&database.path).unwrap();
        connection.execute("DELETE FROM blob_metadata", []).unwrap();
        assert!(SqliteBlobStore::open_existing_writable(&database.path).is_err());
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM blob_metadata", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        connection.execute("DROP TABLE blob_metadata", []).unwrap();
        assert!(SqliteBlobStore::open_existing_writable(&database.path).is_err());
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name = 'blob_metadata'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn inactive_import_blob_symlinks_refuse_and_preserve_referenced_file() {
        let database: TestDatabase = TestDatabase::new();
        let link: TestDatabase = TestDatabase::new();
        let store: SqliteBlobStore = SqliteBlobStore::create_new(&database.path).unwrap();
        store.put_blob(digest(7), vec![1, 2, 3]).unwrap();
        drop(store);
        std::os::unix::fs::symlink(&database.path, &link.path).unwrap();
        assert!(SqliteBlobStore::create_new(&link.path).is_err());
        assert!(SqliteBlobStore::open_existing_writable(&link.path).is_err());
        assert_eq!(
            SqliteBlobStore::open_existing(&database.path)
                .unwrap()
                .get_blob(&digest(7))
                .unwrap(),
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn inactive_import_blob_missing_payload_table_is_not_recreated() {
        let database: TestDatabase = TestDatabase::new();
        drop(SqliteBlobStore::create_new(&database.path).unwrap());
        let connection: Connection = Connection::open(&database.path).unwrap();
        connection.execute("DROP TABLE blobs", []).unwrap();
        assert!(SqliteBlobStore::open_existing_writable(&database.path).is_err());
        assert_eq!(
            connection
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name = 'blobs'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn put_and_get_survive_reopen() {
        let database = TestDatabase::new();
        let content_digest = digest(0x01);
        {
            let store = SqliteBlobStore::open(&database.path).unwrap();
            store.put_blob(content_digest, vec![1, 2, 3]).unwrap();
            assert_eq!(
                store.get_blob(&content_digest).unwrap(),
                Some(vec![1, 2, 3])
            );
        }

        let reopened = SqliteBlobStore::open(&database.path).unwrap();
        assert_eq!(
            reopened.get_blob(&content_digest).unwrap(),
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn existing_read_only_open_reads_blob_with_wal_writer_still_open() {
        let database: TestDatabase = TestDatabase::new();
        assert!(SqliteBlobStore::open_existing(&database.path).is_err());
        assert!(!database.path.exists());
        let writer: SqliteBlobStore = SqliteBlobStore::open(&database.path).unwrap();
        let content_digest: Digest32 = digest(0x52);
        writer.put_blob(content_digest, vec![0xA1, 0xB2]).unwrap();
        let reader: SqliteBlobStore = SqliteBlobStore::open_existing(&database.path).unwrap();
        assert_eq!(
            reader.get_blob(&content_digest).unwrap(),
            Some(vec![0xA1, 0xB2]),
        );
        assert!(matches!(
            reader.put_blob(digest(0x53), vec![0xC3]),
            Err(RuntimeError::DurableStoreUnavailable),
        ));
        assert_eq!(writer.get_blob(&digest(0x53)).unwrap(), None);
    }

    #[test]
    fn get_missing_digest_is_none() {
        let database = TestDatabase::new();
        let store = SqliteBlobStore::open(&database.path).unwrap();
        assert_eq!(store.get_blob(&digest(0x02)).unwrap(), None);
    }

    #[test]
    fn put_is_idempotent_for_identical_content() {
        let database = TestDatabase::new();
        let store = SqliteBlobStore::open(&database.path).unwrap();
        let content_digest = digest(0x03);
        store.put_blob(content_digest, vec![9, 9]).unwrap();
        store.put_blob(content_digest, vec![9, 9]).unwrap();
        assert_eq!(store.get_blob(&content_digest).unwrap(), Some(vec![9, 9]));
    }

    #[test]
    fn put_rejects_conflicting_content_and_retains_original() {
        let database = TestDatabase::new();
        let store = SqliteBlobStore::open(&database.path).unwrap();
        let content_digest = digest(0x04);
        store.put_blob(content_digest, vec![1, 1]).unwrap();
        let error = store.put_blob(content_digest, vec![2, 2]).unwrap_err();
        assert_eq!(
            error,
            RuntimeError::BlobDigestConflict {
                digest: content_digest
            }
        );
        assert_eq!(store.get_blob(&content_digest).unwrap(), Some(vec![1, 1]));
    }

    #[test]
    fn put_rechecks_raced_length_inside_transaction_with_two_writable_handles() {
        let database: TestDatabase = TestDatabase::new();
        let target: SqliteBlobStore = SqliteBlobStore::create_new(&database.path).unwrap();
        let other: SqliteBlobStore =
            SqliteBlobStore::open_existing_writable(&database.path).unwrap();
        let oversized: Digest32 = digest(0x71);
        assert_eq!(
            target.read_portable_blob_descriptor(&oversized).unwrap(),
            None
        );
        // Deterministic race: another handle inserts after descriptor absence
        // was observed, before put starts its own writer transaction. SQLite
        // creates the legal generic blob without allocating it in Rust.
        let large_length: usize = 32 * 1024 * 1024 + 1;
        other
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO blobs (digest_algorithm, digest_bytes, content)
                 VALUES (?1, ?2, zeroblob(?3))",
                params![
                    i64::from(oversized.algorithm().as_u16()),
                    oversized.bytes().as_slice(),
                    i64::try_from(large_length).unwrap(),
                ],
            )
            .unwrap();
        assert_eq!(
            target.put_blob(oversized, vec![1, 2, 3]),
            Err(RuntimeError::BlobDigestConflict { digest: oversized })
        );
        let descriptor: PortableBlobDescriptor = other
            .read_portable_blob_descriptor(&oversized)
            .unwrap()
            .unwrap();
        assert_eq!(descriptor.length(), large_length);
        let request: PortableBlobChunkRequest =
            PortableBlobChunkRequest::new(descriptor, 0, std::num::NonZeroUsize::new(3).unwrap())
                .unwrap();
        let observed: PortableBlobChunkOutcome = other.read_portable_blob_chunk(&request).unwrap();
        let PortableBlobChunkOutcome::Chunk(chunk) = observed else {
            panic!("raced blob was modified or lost");
        };
        assert_eq!(chunk.bytes(), &[0, 0, 0]);

        let same_length: Digest32 = digest(0x72);
        assert_eq!(
            target.read_portable_blob_descriptor(&same_length).unwrap(),
            None
        );
        other.put_blob(same_length, vec![4, 5, 6]).unwrap();
        assert_eq!(
            target.put_blob(same_length, vec![7, 8, 9]),
            Err(RuntimeError::BlobDigestConflict {
                digest: same_length
            })
        );
        target.put_blob(same_length, vec![4, 5, 6]).unwrap();
        assert_eq!(other.get_blob(&same_length).unwrap(), Some(vec![4, 5, 6]));
    }

    #[test]
    fn put_refuses_equal_length_corrupt_content_without_repair() {
        let database: TestDatabase = TestDatabase::new();
        let target: SqliteBlobStore = SqliteBlobStore::create_new(&database.path).unwrap();
        let other: SqliteBlobStore =
            SqliteBlobStore::open_existing_writable(&database.path).unwrap();
        let content_digest: Digest32 = digest(0x73);
        target.put_blob(content_digest, vec![1, 2, 3]).unwrap();
        let before: PortableBlobDescriptor = target
            .read_portable_blob_descriptor(&content_digest)
            .unwrap()
            .unwrap();
        assert_eq!(before.length(), 3);
        other
            .connection()
            .unwrap()
            .execute(
                "UPDATE blobs SET content = 'abc'
                 WHERE digest_algorithm = ?1 AND digest_bytes = ?2",
                params![
                    i64::from(content_digest.algorithm().as_u16()),
                    content_digest.bytes().as_slice(),
                ],
            )
            .unwrap();
        assert_eq!(
            target.put_blob(content_digest, vec![1, 2, 3]),
            Err(RuntimeError::DurableStoreUnavailable)
        );
        let retained: (String, String) = other
            .connection()
            .unwrap()
            .query_row(
                "SELECT typeof(content), content FROM blobs
                 WHERE digest_algorithm = ?1 AND digest_bytes = ?2",
                params![
                    i64::from(content_digest.algorithm().as_u16()),
                    content_digest.bytes().as_slice(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(retained, ("text".to_owned(), "abc".to_owned()));
    }

    #[test]
    fn distinct_algorithms_over_the_same_bytes_are_distinct_keys() {
        let database = TestDatabase::new();
        let store = SqliteBlobStore::open(&database.path).unwrap();
        let sha2 = Digest32::new(HashAlgorithmId::Sha2_256, [0x05; 32]);
        let sha3 = Digest32::new(HashAlgorithmId::Sha3_256, [0x05; 32]);
        store.put_blob(sha2, vec![1]).unwrap();
        store.put_blob(sha3, vec![2]).unwrap();
        assert_eq!(store.get_blob(&sha2).unwrap(), Some(vec![1]));
        assert_eq!(store.get_blob(&sha3).unwrap(), Some(vec![2]));
    }

    #[test]
    fn journal_mode_is_wal_and_synchronous_is_full() {
        let database = TestDatabase::new();
        let store = SqliteBlobStore::open(&database.path).unwrap();
        let connection = store.connection().unwrap();
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert!(journal_mode.eq_ignore_ascii_case("wal"));
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        // SQLite reports synchronous=FULL as 2.
        assert_eq!(synchronous, 2);
    }

    #[test]
    fn unknown_application_id_fails_closed() {
        let database = TestDatabase::new();
        let connection = Connection::open(&database.path).unwrap();
        connection
            .pragma_update(None, "application_id", 0x1234_5678_i64)
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteBlobStore::open(&database.path),
            Err(SqliteBlobStoreError::ApplicationId(0x1234_5678))
        ));
    }

    #[test]
    fn unknown_schema_version_fails_closed() {
        let database = TestDatabase::new();
        let connection = Connection::open(&database.path).unwrap();
        connection
            .pragma_update(None, "application_id", BLOB_APPLICATION_ID)
            .unwrap();
        connection
            .pragma_update(None, "user_version", 99_i64)
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteBlobStore::open(&database.path),
            Err(SqliteBlobStoreError::SchemaVersion(99))
        ));
    }

    #[test]
    fn unclaimed_database_with_existing_schema_fails_closed() {
        let database = TestDatabase::new();
        let connection = Connection::open(&database.path).unwrap();
        connection
            .execute("CREATE TABLE foreign_data (id INTEGER)", [])
            .unwrap();
        drop(connection);

        assert!(matches!(
            SqliteBlobStore::open(&database.path),
            Err(SqliteBlobStoreError::UnclaimedDatabase)
        ));
    }

    #[test]
    fn cannot_share_a_file_with_the_structured_store() {
        use crate::{SqliteDurableStore, SqliteNamespace};
        use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
        use runtime::WriterFenceGeneration;

        let database = TestDatabase::new();
        let namespace = SqliteNamespace::new(
            ChainId::new("sunrise-test").unwrap(),
            ValidatorId::new([0x01; 32]),
            AtomicityDomainId::new([0x02; 32]).unwrap(),
        );
        SqliteDurableStore::open(
            &database.path,
            namespace,
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            SqliteBlobStore::open(&database.path),
            Err(SqliteBlobStoreError::ApplicationId(_))
        ));
    }

    #[test]
    fn portable_blob_reads_survive_close_reopen() {
        use runtime::portable::conformance::{self, BlobFixture};

        let database = TestDatabase::new();
        let store: SqliteBlobStore = SqliteBlobStore::open(&database.path).unwrap();
        let fixture: BlobFixture = conformance::seed_blob(&store);
        conformance::verify_blob(&store, &fixture);
        conformance::assert_blob_chunk_corrupt(&store, &fixture);
        drop(store);

        let reopened: SqliteBlobStore = SqliteBlobStore::open(&database.path).unwrap();
        conformance::verify_blob(&reopened, &fixture);
        conformance::assert_blob_chunk_corrupt(&reopened, &fixture);
    }

    #[test]
    fn portable_blob_descriptor_missing_and_chunk_offset_bounds() {
        use runtime::portable::{PortableBlobChunkRequest, PortableBlobDescriptor};
        use std::num::NonZeroUsize;

        let database = TestDatabase::new();
        let store: SqliteBlobStore = SqliteBlobStore::open(&database.path).unwrap();
        let missing: Digest32 = digest(0x60);
        assert_eq!(store.read_portable_blob_descriptor(&missing).unwrap(), None);

        let content_digest: Digest32 = digest(0x61);
        store.put_blob(content_digest, vec![9; 6]).unwrap();
        let descriptor: PortableBlobDescriptor = store
            .read_portable_blob_descriptor(&content_digest)
            .unwrap()
            .unwrap();
        assert_eq!(descriptor.length(), 6);
        assert!(
            PortableBlobChunkRequest::new(descriptor, 6, NonZeroUsize::new(1).unwrap()).is_err()
        );
        let request: PortableBlobChunkRequest =
            PortableBlobChunkRequest::new(descriptor, 2, NonZeroUsize::new(3).unwrap()).unwrap();
        assert_eq!(request.range(), 2..5);
    }
}
