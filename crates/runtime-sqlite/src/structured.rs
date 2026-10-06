//! Local-only, non-production SQLite implementation of the structured
//! durable runtime contracts.
//!
//! [`SqliteDurableStore`] implements [`StructuredDurableDomainStateStore`]
//! and [`IndexedOutboxRepository`] by forwarding every statement,
//! decoding rule, and commit decision to the backend-neutral
//! `runtime_sql_durable::engine::SqlDurableEngine`, driven through the
//! `NativeSqlBackend` rusqlite adapter in `crate::rusqlite_backend`. This
//! file therefore owns only what is genuinely native: opening the file,
//! `PRAGMA` setup (WAL, `application_id`, `user_version`, `busy_timeout`),
//! and the operator-only failover seams. It never duplicates the shared
//! engine's SQL text or validation rules.
//!
//! This adapter is for the single-node Developer MVP only. It is bound at
//! construction to exactly one trusted `(chain, validator, atomicity
//! domain)` namespace and serializes every operation behind one
//! process-local [`Mutex`] plus one SQLite transaction. It has none of
//! `runtime-postgres`'s connection pooling, serialization-conflict
//! retries, or live fault-injected evidence, and is not suitable for
//! multi-writer or production deployments.

use crate::native_files;
use crate::rusqlite_backend::NativeSqlBackend;
use runtime::outbox_guard::{StructuredOutboxExclusionGuard, StructuredOutboxInventory};
use runtime::portable::{
    DurablePortableRepository, DurablePortableSnapshotRepository, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordPage,
    DurableRecordScan, PortableSnapshotError, PortableSnapshotToken,
};
use runtime::successor_serving::SuccessorServingSlot;
use runtime::{
    AtomicStateTransaction, AtomicityDomainId, DueOutboxClaimRequest, DurableCommitOutcome,
    DurableDomainStateStore, DurableInvocationTransaction, DurableObjectHead, DurableObjectVersion,
    DurableObjectVersionRecord, DurableOperationContext, DurableOutboxAcknowledgement,
    DurableOutboxAcknowledgementOutcome, DurableOutboxClaimOutcome, DurableReadError,
    DurableRequestId, DurableRequestReceipt, DurableStateKeyScanner, IndexedOutboxRepository,
    ObjectId, RequestOutboxClaimRequest, StateKeyPage, StateKeyScan,
    StructuredDurableDomainStateStore, VersionedStateValue, WriterFenceGeneration,
};
use runtime_sql_durable::{
    SqlBackend, SqlDurableEngine, SqlDurableNamespace, TransactionBudget, TransactionDecision,
    schema,
};
use rusqlite::{Connection, OpenFlags};
use std::{error::Error, fmt, path::Path};

/// The exact trusted `(chain, validator, atomicity domain)` namespace one
/// local SQLite structured database file is bound to.
pub type SqliteNamespace = SqlDurableNamespace;

/// Stable identity of the local-only structured SQLite schema, generation
/// five, using the shared v6 SQL durable
/// origin/progress/readiness/barrier/successor-serving layout (DR-0189).
pub const SQLITE_STRUCTURED_SCHEMA_IDENTITY: &[u8] =
    runtime_sql_durable::SQL_DURABLE_SCHEMA_IDENTITY;

const STRUCTURED_APPLICATION_ID: i64 = 0x5352_4453;
const STRUCTURED_SCHEMA_VERSION: i64 = 5;
const STRUCTURED_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Fail-closed errors opening, bootstrapping, or operating a structured
/// SQLite database outside the request-path traits.
#[derive(Debug)]
pub enum SqliteDurableStoreError {
    /// Local file reservation failed; no existing file is replaced.
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
    /// The persisted namespace differs from the requested chain,
    /// validator, or domain.
    NamespaceMismatch,
    /// The namespace metadata row is missing or malformed.
    InvalidPersistedMetadata,
    /// The permanent origin does not permit ordinary serving/bootstrap.
    InactiveNamespace,
    /// The outgoing barrier is already Sealed; ordinary serving/bootstrap
    /// is refused, including a previously opened live handle.
    NamespaceSealed,
    /// The import-only namespace is bound to different immutable material.
    ImportBindingMismatch,
    /// A persisted writer fence was zero.
    ZeroWriterFence,
    /// The expected writer fence was no longer active when advancing it.
    WriterFenceMismatch {
        /// Generation the operator expected to replace.
        expected: WriterFenceGeneration,
        /// Generation actually persisted.
        actual: WriterFenceGeneration,
    },
    /// A requested writer generation did not strictly advance the active
    /// one.
    WriterFenceNotAdvanced {
        /// Current generation supplied by the operator.
        current: WriterFenceGeneration,
        /// Requested replacement generation.
        requested: WriterFenceGeneration,
    },
    /// The backend transaction was unavailable.
    Unavailable,
    /// The checked mutation sequence would overflow.
    MutationSequenceOverflow,
    /// The checked mutation sequence changed within the active transaction.
    MutationSequenceConflict,
}

impl fmt::Display for SqliteDurableStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(error) => write!(f, "SQLite file operation failed: {error}"),
            Self::Database(error) => write!(f, "SQLite operation failed: {error}"),
            Self::UnsupportedJournalMode(mode) => {
                write!(f, "SQLite journal mode is {mode}, expected wal")
            }
            Self::ApplicationId(id) => write!(
                f,
                "SQLite application id is {id:#x}, expected {STRUCTURED_APPLICATION_ID:#x}"
            ),
            Self::UnclaimedDatabase => {
                f.write_str("unclaimed SQLite database already contains schema objects")
            }
            Self::SchemaVersion(version) => write!(
                f,
                "SQLite structured schema version is {version}, expected {STRUCTURED_SCHEMA_VERSION}"
            ),
            Self::SchemaIdentityMismatch => {
                f.write_str("SQLite structured schema identity is unsupported")
            }
            Self::NamespaceMismatch => {
                f.write_str("SQLite database already has a different bound chain/validator/domain")
            }
            Self::InvalidPersistedMetadata => {
                f.write_str("SQLite structured metadata row is missing or malformed")
            }
            Self::InactiveNamespace => f.write_str("SQLite namespace is permanently import-only"),
            Self::NamespaceSealed => {
                f.write_str("SQLite namespace outgoing barrier is already Sealed")
            }
            Self::ImportBindingMismatch => f.write_str("SQLite import binding differs"),
            Self::ZeroWriterFence => f.write_str("SQLite writer fence must be non-zero"),
            Self::WriterFenceMismatch { expected, actual } => write!(
                f,
                "SQLite writer fence changed: expected {}, found {}",
                expected.get(),
                actual.get()
            ),
            Self::WriterFenceNotAdvanced { current, requested } => write!(
                f,
                "SQLite writer fence must advance: current {}, requested {}",
                current.get(),
                requested.get()
            ),
            Self::Unavailable => f.write_str("SQLite structured backend is unavailable"),
            Self::MutationSequenceOverflow => f.write_str("SQLite mutation sequence overflow"),
            Self::MutationSequenceConflict => f.write_str("SQLite mutation sequence conflict"),
        }
    }
}

impl Error for SqliteDurableStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::File(error) => Some(error),
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for SqliteDurableStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

impl From<schema::SchemaError> for SqliteDurableStoreError {
    fn from(value: schema::SchemaError) -> Self {
        match value {
            schema::SchemaError::Session(_) => Self::Unavailable,
            schema::SchemaError::SchemaIdentityMismatch => Self::SchemaIdentityMismatch,
            schema::SchemaError::NamespaceMismatch => Self::NamespaceMismatch,
            schema::SchemaError::InvalidPersistedMetadata => Self::InvalidPersistedMetadata,
            schema::SchemaError::InactiveNamespace => Self::InactiveNamespace,
            schema::SchemaError::NamespaceSealed => Self::NamespaceSealed,
            schema::SchemaError::ZeroWriterFence => Self::ZeroWriterFence,
            schema::SchemaError::WriterFenceMismatch { expected, actual } => {
                Self::WriterFenceMismatch { expected, actual }
            }
            schema::SchemaError::MutationSequenceOverflow => Self::MutationSequenceOverflow,
            schema::SchemaError::MutationSequenceConflict => Self::MutationSequenceConflict,
        }
    }
}

/// Local-only, single-writer structured durable store backed by one
/// SQLite file.
///
/// See the module documentation for the exact scope and limits. Callers
/// must run this synchronous interface behind bounded blocking isolation
/// when used from an asynchronous request runtime.
pub struct SqliteDurableStore {
    engine: SqlDurableEngine<NativeSqlBackend>,
    // Only a freshly created handle may flush its original file identity.
    // This is native ownership, never a persisted serving authorization.
    created_file: Option<native_files::ImportFile>,
}

impl fmt::Debug for SqliteDurableStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteDurableStore")
            .field("namespace", self.engine.namespace())
            .finish_non_exhaustive()
    }
}

/// Runs one operator-path transaction, mapping every backend failure to
/// `SqliteDurableStoreError::Unavailable` and every schema/namespace
/// failure through its own `From` conversion.
fn run_operator_step<T>(
    backend: &NativeSqlBackend,
    step: impl FnOnce(&mut dyn runtime_sql_durable::SqlSession, u64) -> Result<T, schema::SchemaError>,
) -> Result<T, SqliteDurableStoreError> {
    let outcome = backend.transaction(TransactionBudget::OperatorDefault, |session, now| {
        let result = step(session, now);
        match &result {
            Ok(_) => Ok(TransactionDecision::Commit(result)),
            Err(_) => Ok(TransactionDecision::Rollback(result)),
        }
    });
    outcome
        .map_err(|_| SqliteDurableStoreError::Unavailable)?
        .map_err(SqliteDurableStoreError::from)
}

/// Opens an existing file with the exact native connection checks live
/// serving requires: busy timeout, `foreign_keys` enforcement, distrust of
/// attached-schema triggers/views, the claimed `application_id`, the exact
/// supported `user_version`, and WAL journaling. Both `open_existing` and
/// `open_historical` share this so neither entry point can silently accept
/// a weaker-checked connection than the other.
fn open_verified_connection(path: impl AsRef<Path>) -> Result<Connection, SqliteDurableStoreError> {
    let connection: Connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(STRUCTURED_BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != STRUCTURED_APPLICATION_ID {
        return Err(SqliteDurableStoreError::ApplicationId(application_id));
    }
    let schema_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version != STRUCTURED_SCHEMA_VERSION {
        return Err(SqliteDurableStoreError::SchemaVersion(schema_version));
    }
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(SqliteDurableStoreError::UnsupportedJournalMode(
            journal_mode,
        ));
    }
    Ok(connection)
}

impl SqliteDurableStore {
    /// Opens an already initialized database for an operator operation.
    /// Unlike `open`, this never creates a file or bootstraps a schema.
    pub fn open_existing(
        path: impl AsRef<Path>,
        namespace: SqliteNamespace,
    ) -> Result<Self, SqliteDurableStoreError> {
        let connection: Connection = open_verified_connection(path)?;
        let backend = NativeSqlBackend::new(connection);
        run_operator_step(&backend, |session, _now| {
            let metadata = schema::verify_namespace(session, &namespace)?;
            if !metadata.lifecycle().is_ordinary() {
                return Err(schema::SchemaError::InactiveNamespace);
            }
            if metadata.barrier().is_sealed() {
                return Err(schema::SchemaError::NamespaceSealed);
            }
            Ok(metadata)
        })?;
        Ok(Self {
            engine: SqlDurableEngine::new(backend, namespace),
            created_file: None,
        })
    }

    /// Opens or bootstraps a local structured durable database.
    ///
    /// `initial_writer_fence` is used only the first time this namespace
    /// is bootstrapped; a later open with the same file ignores it and
    /// reads the persisted fence. This auto-bootstrap-on-open behavior
    /// (unlike `runtime-postgres`'s explicit operator-only bootstrap) is
    /// acceptable only because the file is local, single-tenant, and
    /// non-production.
    pub fn open(
        path: impl AsRef<Path>,
        namespace: SqliteNamespace,
        initial_writer_fence: WriterFenceGeneration,
    ) -> Result<Self, SqliteDurableStoreError> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(STRUCTURED_BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;

        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(SqliteDurableStoreError::UnsupportedJournalMode(
                journal_mode,
            ));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;

        let application_id: i64 =
            connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
        if application_id != 0 && application_id != STRUCTURED_APPLICATION_ID {
            return Err(SqliteDurableStoreError::ApplicationId(application_id));
        }
        let schema_version: i64 =
            connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if schema_version != 0 && schema_version != STRUCTURED_SCHEMA_VERSION {
            return Err(SqliteDurableStoreError::SchemaVersion(schema_version));
        }
        let already_claimed = application_id == STRUCTURED_APPLICATION_ID
            && schema_version == STRUCTURED_SCHEMA_VERSION;
        if !already_claimed {
            if application_id != 0 {
                return Err(SqliteDurableStoreError::SchemaVersion(schema_version));
            }
            if schema_version != 0 {
                return Err(SqliteDurableStoreError::ApplicationId(application_id));
            }
            let schema_objects: i64 = connection.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            if schema_objects != 0 {
                return Err(SqliteDurableStoreError::UnclaimedDatabase);
            }
        }

        let backend = NativeSqlBackend::new(connection);
        run_operator_step(&backend, |session, _now| {
            if already_claimed {
                let metadata = schema::verify_namespace(session, &namespace)?;
                if !metadata.lifecycle().is_ordinary() {
                    return Err(schema::SchemaError::InactiveNamespace);
                }
                if metadata.barrier().is_sealed() {
                    return Err(schema::SchemaError::NamespaceSealed);
                }
                return Ok(metadata);
            }
            session
                .exec(
                    &format!("PRAGMA application_id = {STRUCTURED_APPLICATION_ID}"),
                    &[],
                )
                .map_err(schema::SchemaError::from)?;
            session
                .exec(
                    &format!("PRAGMA user_version = {STRUCTURED_SCHEMA_VERSION}"),
                    &[],
                )
                .map_err(schema::SchemaError::from)?;
            schema::bootstrap_namespace(session, &namespace, initial_writer_fence)
        })?;
        Ok(Self {
            engine: SqlDurableEngine::new(backend, namespace),
            created_file: None,
        })
    }

    /// Opens an already initialized database for read-only historical
    /// inspection, export, or query. This grants no live composition or
    /// write exemption: every commit path on the returned handle still
    /// independently rechecks and rejects Sealed/inactive origin under its
    /// own lock/transaction, exactly like any other opened handle.
    pub fn open_historical(
        path: impl AsRef<Path>,
        namespace: SqliteNamespace,
    ) -> Result<Self, SqliteDurableStoreError> {
        let connection: Connection = open_verified_connection(path)?;
        let backend = NativeSqlBackend::new(connection);
        run_operator_step(&backend, |session, _now| {
            schema::open_namespace_historical(session, &namespace)
        })?;
        Ok(Self {
            engine: SqlDurableEngine::new(backend, namespace),
            created_file: None,
        })
    }

    /// Returns the exact namespace this database file is bound to.
    #[must_use]
    pub const fn namespace(&self) -> &SqliteNamespace {
        self.engine.namespace()
    }

    /// Reserves and initializes a genuinely fresh local structured database
    /// (DR-0195). Unlike [`Self::open`], an existing destination is refused
    /// before any schema or namespace content is written, using the same
    /// held-file/ancestor checks the import factory already uses.
    pub fn create_new(
        path: impl AsRef<Path>,
        namespace: SqliteNamespace,
        initial_writer_fence: WriterFenceGeneration,
    ) -> Result<Self, SqliteDurableStoreError> {
        let path: std::path::PathBuf =
            native_files::validate_fresh(path.as_ref()).map_err(SqliteDurableStoreError::File)?;
        let path: &Path = &path;
        let reserved: native_files::ImportFile =
            native_files::create_new(path).map_err(SqliteDurableStoreError::File)?;
        native_files::require_no_sidecars(path).map_err(SqliteDurableStoreError::File)?;
        let connection: Connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(STRUCTURED_BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        native_files::check_attached(path, &reserved).map_err(SqliteDurableStoreError::File)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(SqliteDurableStoreError::UnsupportedJournalMode(
                journal_mode,
            ));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;
        let backend = NativeSqlBackend::new(connection);
        run_operator_step(&backend, |session, _now| {
            session
                .exec(
                    &format!("PRAGMA application_id = {STRUCTURED_APPLICATION_ID}"),
                    &[],
                )
                .map_err(schema::SchemaError::from)?;
            session
                .exec(
                    &format!("PRAGMA user_version = {STRUCTURED_SCHEMA_VERSION}"),
                    &[],
                )
                .map_err(schema::SchemaError::from)?;
            schema::bootstrap_namespace(session, &namespace, initial_writer_fence)
        })?;
        native_files::check_attached(path, &reserved).map_err(SqliteDurableStoreError::File)?;
        native_files::sync_created(path, &reserved).map_err(SqliteDurableStoreError::File)?;
        Ok(Self {
            engine: SqlDurableEngine::new(backend, namespace),
            created_file: Some(reserved),
        })
    }

    /// Rechecks and flushes the original freshly reserved main file and
    /// directory identity. Reopened handles cannot claim fresh ownership.
    pub fn sync_created(&self) -> Result<(), SqliteDurableStoreError> {
        let held: &native_files::ImportFile = self.created_file.as_ref().ok_or_else(|| {
            SqliteDurableStoreError::File(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "store was not opened through the fresh-only factory",
            ))
        })?;
        native_files::sync_owned(held).map_err(SqliteDurableStoreError::File)
    }

    /// Atomically advances the persisted writer fence.
    ///
    /// This is an explicit operator-only failover seam, not part of any
    /// runtime trait. Request handling must never be able to reach it.
    pub fn advance_writer_fence(
        &self,
        expected: WriterFenceGeneration,
        next: WriterFenceGeneration,
    ) -> Result<WriterFenceGeneration, SqliteDurableStoreError> {
        if next.get() <= expected.get() {
            return Err(SqliteDurableStoreError::WriterFenceNotAdvanced {
                current: expected,
                requested: next,
            });
        }
        run_operator_step(self.engine.backend(), |session, _now| {
            schema::advance_writer_fence(session, self.engine.namespace(), expected, next)
        })
    }

    /// Reads the currently persisted writer fence.
    ///
    /// This is an explicit operator-only accessor, not part of any
    /// runtime trait; request handling must never be able to reach it.
    pub fn writer_fence(&self) -> Result<WriterFenceGeneration, SqliteDurableStoreError> {
        let metadata = run_operator_step(self.engine.backend(), |session, _now| {
            schema::verify_namespace(session, self.engine.namespace())
        })?;
        Ok(metadata.writer_fence())
    }

    /// Reports whether the normalized object-head table is empty.
    ///
    /// This is an operator-only startup accessor, not a request-path
    /// query.
    pub fn object_store_is_empty(&self) -> Result<bool, SqliteDurableStoreError> {
        run_operator_step(self.engine.backend(), |session, _now| {
            schema::verify_namespace(session, self.engine.namespace())?;
            schema::object_heads_is_empty(session).map_err(schema::SchemaError::from)
        })
    }
}

impl DurableDomainStateStore for SqliteDurableStore {
    fn get_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, DurableReadError> {
        self.engine.get_namespace_lifecycle(context, domain)
    }
    fn get_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, DurableReadError> {
        self.engine.get_outgoing_barrier(context, domain)
    }
    fn get_successor_serving(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<SuccessorServingSlot, DurableReadError> {
        self.engine.get_successor_serving(context, domain)
    }
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.engine.get_versioned_durable(context, domain, key)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.engine.commit_durable(context, transaction)
    }
}

mod inactive_import;
pub use inactive_import::SqliteImportTarget;

impl StructuredDurableDomainStateStore for SqliteDurableStore {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.engine.get_object_head(context, domain, object_id)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.engine
            .get_object_version(context, domain, object_id, object_version)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.engine.get_request_receipt(context, domain, request_id)
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        invocation: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.engine.commit_invocation(context, invocation)
    }

    fn outgoing_seal_repository(&self) -> Option<&dyn runtime::OutgoingSealRepository> {
        Some(self)
    }
}

impl DurableStateKeyScanner for SqliteDurableStore {
    fn scan_durable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &StateKeyScan,
    ) -> Result<StateKeyPage, DurableReadError> {
        self.engine.scan_durable_keys(context, domain, scan)
    }
}

impl DurablePortableRepository for SqliteDurableStore {
    fn scan_portable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.engine.scan_portable_keys(context, domain, scan)
    }
    fn read_portable_descriptor(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        self.engine.read_portable_descriptor(context, domain, key)
    }
    fn read_portable_chunk(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        self.engine.read_portable_chunk(context, domain, request)
    }
}

impl DurablePortableSnapshotRepository for SqliteDurableStore {
    fn begin_portable_snapshot(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<PortableSnapshotToken, PortableSnapshotError> {
        self.engine.begin_portable_snapshot(context, domain)
    }
    fn scan_portable_keys_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, PortableSnapshotError> {
        self.engine
            .scan_portable_keys_at(context, domain, token, scan)
    }
    fn read_portable_descriptor_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, PortableSnapshotError> {
        self.engine
            .read_portable_descriptor_at(context, domain, token, key)
    }
    fn read_portable_chunk_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, PortableSnapshotError> {
        self.engine
            .read_portable_chunk_at(context, domain, token, request)
    }
    fn check_portable_outbox_empty_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
    ) -> Result<(), PortableSnapshotError> {
        self.engine
            .check_portable_outbox_empty_at(context, domain, token)
    }
}

impl StructuredOutboxExclusionGuard for SqliteDurableStore {
    fn inspect_outbox_exclusion(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<StructuredOutboxInventory, DurableReadError> {
        self.engine.inspect_outbox_exclusion(context, domain)
    }
}

impl IndexedOutboxRepository for SqliteDurableStore {
    fn claim_request_outbox(
        &self,
        context: &DurableOperationContext,
        request: RequestOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        self.engine.claim_request_outbox(context, request)
    }

    fn claim_due_outbox(
        &self,
        context: &DurableOperationContext,
        request: DueOutboxClaimRequest,
    ) -> DurableOutboxClaimOutcome {
        self.engine.claim_due_outbox(context, request)
    }

    fn acknowledge_outbox(
        &self,
        context: &DurableOperationContext,
        acknowledgement: DurableOutboxAcknowledgement,
    ) -> DurableOutboxAcknowledgementOutcome {
        self.engine.acknowledge_outbox(context, acknowledgement)
    }
}

impl runtime::OutgoingSealRepository for SqliteDurableStore {
    fn commit_seal_retention(
        &self,
        context: &DurableOperationContext,
        token: &PortableSnapshotToken,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.engine
            .commit_seal_retention(context, token, transaction)
    }

    fn commit_seal_completion(
        &self,
        context: &DurableOperationContext,
        token: &PortableSnapshotToken,
        transaction: DurableInvocationTransaction,
        sealed: runtime::SealBarrier,
    ) -> DurableCommitOutcome {
        self.engine
            .commit_seal_completion(context, token, transaction, sealed)
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;
    use protocol_types::{ChainId, ValidatorId};
    use runtime::{
        AtomicStateMutationSet, AtomicStateReadSet, RuntimeError, StateMutation,
        StateMutationEntry, StateReadAssertion, StateRevision, StorageCorrelationId,
        StorageDeadline,
    };
    use std::{
        fs,
        num::NonZeroUsize,
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
                "sunrise-edge-sqlite-structured-scan-{}-{nanos}-{nonce}.db",
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

    fn scan_test_namespace(domain_byte: u8) -> SqliteNamespace {
        SqliteNamespace::new(
            ChainId::new("sunrise-edge-durable-scan-test").unwrap(),
            ValidatorId::new([0x10; 32]),
            AtomicityDomainId::new([domain_byte; 32]).unwrap(),
        )
    }

    fn live_context(fence: u64, correlation: u8) -> DurableOperationContext {
        let now: u64 = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        DurableOperationContext::new(
            WriterFenceGeneration::new(fence).unwrap(),
            StorageDeadline::new(now + 60_000).unwrap(),
            StorageCorrelationId::new([correlation; 16]).unwrap(),
        )
    }

    fn expired_context(fence: u64, correlation: u8) -> DurableOperationContext {
        DurableOperationContext::new(
            WriterFenceGeneration::new(fence).unwrap(),
            StorageDeadline::new(1).unwrap(),
            StorageCorrelationId::new([correlation; 16]).unwrap(),
        )
    }

    fn put_state(
        store: &SqliteDurableStore,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
        value: u8,
    ) {
        let transaction = AtomicStateTransaction::new(
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
        .unwrap();
        assert_eq!(
            store.commit_durable(context, transaction),
            DurableCommitOutcome::Committed
        );
    }

    #[test]
    fn scan_is_prefix_bounded_ordered_and_paginated_across_reopen() {
        let database = TestDatabase::new();
        let domain = AtomicityDomainId::new([3; 32]).unwrap();
        let store = SqliteDurableStore::open(
            &database.path,
            scan_test_namespace(3),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let context = live_context(1, 0x41);
        for (key, value) in [
            (b"outbox/c".as_slice(), 3u8),
            (b"other/a", 9),
            (b"outbox/a", 1),
            (b"outbox/b", 2),
        ] {
            put_state(&store, &context, domain, key, value);
        }

        let first_scan =
            StateKeyScan::new(b"outbox/".to_vec(), None, NonZeroUsize::new(2).unwrap()).unwrap();
        let first = store
            .scan_durable_keys(&context, domain, &first_scan)
            .unwrap();
        assert_eq!(first.keys(), &[b"outbox/a".to_vec(), b"outbox/b".to_vec()]);
        assert_eq!(first.continuation_cursor(), Some(b"outbox/b".as_slice()));
        drop(store);

        let reopened = SqliteDurableStore::open(
            &database.path,
            scan_test_namespace(3),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let second_scan = StateKeyScan::new(
            b"outbox/".to_vec(),
            first.continuation_cursor().map(<[u8]>::to_vec),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
        let second = reopened
            .scan_durable_keys(&context, domain, &second_scan)
            .unwrap();
        assert_eq!(second.keys(), &[b"outbox/c".to_vec()]);
        assert_eq!(second.continuation_cursor(), None);
    }

    #[test]
    fn scan_includes_tombstones_and_reports_empty_pages() {
        let database = TestDatabase::new();
        let domain = AtomicityDomainId::new([4; 32]).unwrap();
        let store = SqliteDurableStore::open(
            &database.path,
            scan_test_namespace(4),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let context = live_context(1, 0x42);
        put_state(&store, &context, domain, b"key/a", 1);
        let delete = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(b"key/a".to_vec(), StateRevision::new(1)).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(b"key/a".to_vec(), StateMutation::Delete).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            store.commit_durable(&context, delete),
            DurableCommitOutcome::Committed
        );

        let scan =
            StateKeyScan::new(b"key/".to_vec(), None, NonZeroUsize::new(4).unwrap()).unwrap();
        let page = store.scan_durable_keys(&context, domain, &scan).unwrap();
        assert_eq!(page.keys(), &[b"key/a".to_vec()]);
        assert_eq!(
            store
                .get_versioned_durable(&context, domain, b"key/a")
                .unwrap()
                .value(),
            None
        );

        let empty_scan =
            StateKeyScan::new(b"missing/".to_vec(), None, NonZeroUsize::new(4).unwrap()).unwrap();
        let empty_page = store
            .scan_durable_keys(&context, domain, &empty_scan)
            .unwrap();
        assert!(empty_page.keys().is_empty());
        assert_eq!(empty_page.continuation_cursor(), None);
    }

    #[test]
    fn scan_fails_closed_on_domain_fence_and_deadline() {
        let database = TestDatabase::new();
        let bound_domain = AtomicityDomainId::new([5; 32]).unwrap();
        let store = SqliteDurableStore::open(
            &database.path,
            scan_test_namespace(5),
            WriterFenceGeneration::new(4).unwrap(),
        )
        .unwrap();
        let scan =
            StateKeyScan::new(b"key/".to_vec(), None, NonZeroUsize::new(4).unwrap()).unwrap();

        let wrong_domain = AtomicityDomainId::new([6; 32]).unwrap();
        assert_eq!(
            store.scan_durable_keys(&live_context(4, 0x43), wrong_domain, &scan),
            Err(DurableReadError::InvalidRequest(
                RuntimeError::AtomicityDomainMismatch
            ))
        );

        assert_eq!(
            store.scan_durable_keys(&live_context(3, 0x44), bound_domain, &scan),
            Err(DurableReadError::WriterFenced {
                active_generation: WriterFenceGeneration::new(4).unwrap(),
            })
        );

        assert_eq!(
            store.scan_durable_keys(&expired_context(4, 0x45), bound_domain, &scan),
            Err(DurableReadError::DeadlineExceeded)
        );
    }
}
