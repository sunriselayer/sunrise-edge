//! Shared table DDL and namespace/metadata rules for every SQL durable
//! host.
//!
//! Native-only setup (SQLite `PRAGMA journal_mode`/`application_id`/
//! `user_version`, WAL, busy timeout) stays in `runtime-sqlite`: a
//! Durable Object has no such PRAGMAs, and this crate must not assume any
//! exist. What is shared is the table shape itself and the one
//! `durable_metadata` row every host bootstraps and re-verifies inside
//! the same transaction as every other read or write, so a database
//! claimed by an unexpected chain/validator/domain or an unsupported
//! schema generation fails closed identically on every host.

use crate::backend::{SqlSession, SqlSessionError, SqlValue};
use protocol_types::{ChainId, ValidatorId};
use runtime::inactive_import::{
    decode_import_binding, decode_import_progress, encode_import_binding,
};
use runtime::{AtomicityDomainId, ImportBinding, NamespaceLifecycle, WriterFenceGeneration};
use std::fmt;

/// Stable identity of the shared structured SQL schema.
///
/// A future additive migration bumps this identity together with any new
/// column; a database claimed by an unsupported identity fails closed
/// rather than being silently reinterpreted. `v3` requires an explicit,
/// immutable origin/binding and separate import progress. Older initialized
/// shapes are unsupported; opening never migrates, resets or repairs them.
pub const SQL_DURABLE_SCHEMA_IDENTITY: &[u8] = b"sunrise-edge/sqlite/structured/schema/v3";

pub(crate) const OBJECT_HEAD_STATUS_CURRENT: i64 = 1;
pub(crate) const OBJECT_HEAD_STATUS_TOMBSTONED: i64 = 2;

pub(crate) const OUTBOX_ATTEMPT_CLAIMED: i64 = 1;
pub(crate) const OUTBOX_ATTEMPT_ACKNOWLEDGED: i64 = 2;
pub(crate) const OUTBOX_ATTEMPT_EXPIRED: i64 = 3;

/// Encodes a `u64` as an order-preserving 8-byte big-endian value.
#[must_use]
pub const fn encode_u64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// Decodes an order-preserving 8-byte big-endian `u64`, if the length
/// matches.
#[must_use]
pub fn decode_u64(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_be_bytes(array))
}

/// The exact trusted (chain, validator, atomicity domain) namespace one
/// structured SQL database is bound to, shared by every host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlDurableNamespace {
    chain_id: ChainId,
    validator_id: ValidatorId,
    domain: AtomicityDomainId,
}

impl SqlDurableNamespace {
    /// Binds one trusted chain, validator identity, and logical
    /// atomicity domain.
    #[must_use]
    pub const fn new(
        chain_id: ChainId,
        validator_id: ValidatorId,
        domain: AtomicityDomainId,
    ) -> Self {
        Self {
            chain_id,
            validator_id,
            domain,
        }
    }

    /// Returns the trusted chain identity.
    #[must_use]
    pub const fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns the trusted validator identity this database serves.
    #[must_use]
    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// Returns the one logical atomicity domain this database serves.
    #[must_use]
    pub const fn domain(&self) -> AtomicityDomainId {
        self.domain
    }
}

/// Every `CREATE TABLE`/`CREATE INDEX` statement the shared schema needs,
/// in dependency order, each issued as its own statement so a backend
/// never has to split a batched multi-statement string itself.
///
/// This is literal SQLite DDL on both hosts in scope: the Cloudflare
/// Durable Object SQL storage API is itself SQLite, so no dialect
/// translation belongs here. Only file-level `PRAGMA` setup (WAL,
/// `application_id`, `user_version`), which has no Durable Object
/// analog, stays native-only.
pub const TABLE_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS durable_metadata (
         id INTEGER PRIMARY KEY CHECK (id = 1),
         schema_identity BLOB NOT NULL,
         chain_id TEXT NOT NULL,
         validator_id BLOB NOT NULL CHECK(length(validator_id) = 32),
         domain BLOB NOT NULL CHECK(length(domain) = 32),
         writer_fence BLOB NOT NULL CHECK(length(writer_fence) = 8),
         mutation_sequence BLOB NOT NULL CHECK(length(mutation_sequence) = 8),
         source_instance_id BLOB NOT NULL CHECK(length(source_instance_id) = 16),
         namespace_origin INTEGER NOT NULL CHECK(namespace_origin IN (1, 2)),
         import_binding BLOB NULL CHECK(import_binding IS NULL OR (typeof(import_binding) = 'blob' AND length(import_binding) <= 16384)),
         CHECK((namespace_origin = 1 AND import_binding IS NULL)
            OR (namespace_origin = 2 AND import_binding IS NOT NULL))
     )",
    "CREATE TABLE IF NOT EXISTS durable_import_progress (
         id INTEGER PRIMARY KEY CHECK(id = 1),
         phase INTEGER NOT NULL CHECK(phase IN (0, 1, 2)),
         progress BLOB NULL CHECK(progress IS NULL OR (typeof(progress) = 'blob' AND length(progress) <= 16384)),
         CHECK((phase = 0 AND progress IS NULL) OR (phase IN (1, 2) AND progress IS NOT NULL))
     )",
    "CREATE TABLE IF NOT EXISTS durable_state (
         key BLOB PRIMARY KEY NOT NULL,
         revision BLOB NOT NULL CHECK(length(revision) = 8),
         value BLOB NULL
     ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS durable_object_heads (
         object_id BLOB PRIMARY KEY NOT NULL CHECK(length(object_id) = 32),
         status INTEGER NOT NULL,
         head_revision BLOB NOT NULL CHECK(length(head_revision) = 8),
         object_version BLOB NULL CHECK(object_version IS NULL OR length(object_version) = 8),
         digest_algorithm INTEGER NULL,
         digest_bytes BLOB NULL CHECK(digest_bytes IS NULL OR length(digest_bytes) = 32),
         owner_projection BLOB NULL,
         routing_projection BLOB NULL
     ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS durable_object_versions (
         object_id BLOB NOT NULL CHECK(length(object_id) = 32),
         object_version BLOB NOT NULL CHECK(length(object_version) = 8),
         digest_algorithm INTEGER NOT NULL,
         digest_bytes BLOB NOT NULL CHECK(length(digest_bytes) = 32),
         schema_version INTEGER NOT NULL,
         type_id INTEGER NOT NULL,
         created_chain_id TEXT NOT NULL,
         created_protocol_version INTEGER NOT NULL,
         created_checkpoint BLOB NOT NULL CHECK(length(created_checkpoint) = 8),
         inline_canonical_bytes BLOB NULL,
         blob_digest_algorithm INTEGER NULL,
         blob_digest_bytes BLOB NULL CHECK(blob_digest_bytes IS NULL OR length(blob_digest_bytes) = 32),
         PRIMARY KEY (object_id, object_version)
     ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS durable_receipts (
         request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 32),
         event_digest_algorithm INTEGER NOT NULL,
         event_digest_bytes BLOB NOT NULL CHECK(length(event_digest_bytes) = 32),
         canonical_bytes BLOB NOT NULL
     ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS durable_outbox_messages (
         request_id BLOB NOT NULL CHECK(length(request_id) = 32),
         message_index INTEGER NOT NULL,
         payload_digest_algorithm INTEGER NOT NULL,
         payload_digest_bytes BLOB NOT NULL CHECK(length(payload_digest_bytes) = 32),
         canonical_payload BLOB NOT NULL,
         PRIMARY KEY (request_id, message_index)
     ) WITHOUT ROWID",
    "CREATE TABLE IF NOT EXISTS durable_outbox_delivery (
         request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 32),
         message_count INTEGER NOT NULL,
         next_message_index INTEGER NOT NULL,
         completed INTEGER NOT NULL,
         available_at_unix_millis BLOB NOT NULL CHECK(length(available_at_unix_millis) = 8),
         active_lease_id BLOB NULL CHECK(active_lease_id IS NULL OR length(active_lease_id) = 32),
         lease_expires_at_unix_millis BLOB NULL
             CHECK(lease_expires_at_unix_millis IS NULL OR length(lease_expires_at_unix_millis) = 8),
         attempt_count BLOB NOT NULL CHECK(length(attempt_count) = 8)
     ) WITHOUT ROWID",
    "CREATE INDEX IF NOT EXISTS durable_outbox_due_idx
         ON durable_outbox_delivery(available_at_unix_millis, request_id)
         WHERE completed = 0",
    "CREATE TABLE IF NOT EXISTS durable_outbox_attempts (
         lease_id BLOB PRIMARY KEY NOT NULL CHECK(length(lease_id) = 32),
         request_id BLOB NOT NULL CHECK(length(request_id) = 32),
         message_index INTEGER NOT NULL,
         lease_expires_at_unix_millis BLOB NOT NULL CHECK(length(lease_expires_at_unix_millis) = 8),
         status INTEGER NOT NULL
     ) WITHOUT ROWID",
];

/// Fail-closed errors bootstrapping or verifying the shared schema and
/// namespace metadata row.
#[derive(Debug)]
pub enum SchemaError {
    /// The underlying session failed.
    Session(SqlSessionError),
    /// The persisted schema identity does not match this binary.
    SchemaIdentityMismatch,
    /// The persisted namespace differs from the requested chain,
    /// validator, or domain.
    NamespaceMismatch,
    /// The namespace metadata row is missing or malformed.
    InvalidPersistedMetadata,
    /// A normal bootstrap/open attempted to serve an import-only namespace.
    InactiveNamespace,
    /// A persisted writer fence was zero.
    ZeroWriterFence,
    /// The expected writer fence was no longer active when advancing it.
    WriterFenceMismatch {
        /// Generation the caller expected to replace.
        expected: WriterFenceGeneration,
        /// Generation actually persisted.
        actual: WriterFenceGeneration,
    },
    /// The checked mutation sequence would overflow, so no covered write
    /// applied.
    MutationSequenceOverflow,
    /// The checked mutation sequence row did not match the value this same
    /// transaction already observed, so no covered write applied.
    MutationSequenceConflict,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => write!(f, "SQL session failed: {error}"),
            Self::SchemaIdentityMismatch => f.write_str("SQL schema identity is unsupported"),
            Self::NamespaceMismatch => {
                f.write_str("SQL database already has a different bound chain/validator/domain")
            }
            Self::InvalidPersistedMetadata => {
                f.write_str("SQL structured metadata row is missing or malformed")
            }
            Self::InactiveNamespace => f.write_str("SQL namespace is permanently import-only"),
            Self::ZeroWriterFence => f.write_str("SQL writer fence must be non-zero"),
            Self::WriterFenceMismatch { expected, actual } => write!(
                f,
                "SQL writer fence changed: expected {}, found {}",
                expected.get(),
                actual.get()
            ),
            Self::MutationSequenceOverflow => f.write_str("mutation sequence would overflow"),
            Self::MutationSequenceConflict => {
                f.write_str("mutation sequence changed mid-transaction")
            }
        }
    }
}

impl std::error::Error for SchemaError {}

impl From<SqlSessionError> for SchemaError {
    fn from(value: SqlSessionError) -> Self {
        Self::Session(value)
    }
}

/// The one persisted fact every commit/read must revalidate: the active
/// writer generation, plus this database's random bootstrap-time identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceMetadata {
    writer_fence: WriterFenceGeneration,
    mutation_sequence: u64,
    /// A random 16-byte identity persisted once at trusted bootstrap. It
    /// distinguishes two independently bootstrapped stores that otherwise
    /// share the same chain/validator/domain namespace tuple, so a portable
    /// snapshot token can never validate against the wrong physical source.
    /// It is a local source-identity bound, never a protocol fact, and does
    /// not survive a cloned/restored backup file being reattached as a new
    /// writer: an operator restore or failover still requires its own
    /// writer-refencing procedure, not this identity.
    source_instance_id: [u8; 16],
    lifecycle: NamespaceLifecycle,
}

impl NamespaceMetadata {
    /// Returns the persisted writer fence.
    #[must_use]
    pub const fn writer_fence(&self) -> WriterFenceGeneration {
        self.writer_fence
    }

    /// Returns the last checked mutation sequence this transaction observed.
    #[must_use]
    pub const fn mutation_sequence(&self) -> u64 {
        self.mutation_sequence
    }

    /// Returns the random bootstrap-time source instance identity.
    #[must_use]
    pub const fn source_instance_id(&self) -> [u8; 16] {
        self.source_instance_id
    }

    /// Returns the explicit origin and closed installation state.
    #[must_use]
    pub const fn lifecycle(&self) -> &NamespaceLifecycle {
        &self.lifecycle
    }
}

/// Issues every `CREATE TABLE`/`CREATE INDEX` statement in
/// `TABLE_STATEMENTS`, in order.
///
/// Idempotent: every statement is `IF NOT EXISTS`, so a host may call this
/// on every open rather than tracking whether it already ran.
pub fn ensure_schema(session: &mut dyn SqlSession) -> Result<(), SqlSessionError> {
    for statement in TABLE_STATEMENTS {
        session.exec(statement, &[])?;
    }
    Ok(())
}

/// Reads the one `durable_metadata` row and confirms it names exactly
/// `namespace` under the expected schema identity.
pub fn verify_namespace(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
) -> Result<NamespaceMetadata, SchemaError> {
    let rows = session.exec(
        "SELECT schema_identity, chain_id, validator_id, domain, writer_fence, mutation_sequence,
                source_instance_id, namespace_origin,
                CASE WHEN import_binding IS NULL OR length(import_binding) <= 16384 THEN import_binding ELSE NULL END
         FROM durable_metadata WHERE id = 1",
        &[],
    )?;
    let row = rows.one()?.ok_or(SchemaError::InvalidPersistedMetadata)?;
    let schema_identity = row.blob(0).map_err(SqlSessionError::from)?;
    if schema_identity != SQL_DURABLE_SCHEMA_IDENTITY {
        return Err(SchemaError::SchemaIdentityMismatch);
    }
    let chain_id = row.text(1).map_err(SqlSessionError::from)?;
    let validator_id = row.blob(2).map_err(SqlSessionError::from)?;
    let domain = row.blob(3).map_err(SqlSessionError::from)?;
    if chain_id != namespace.chain_id().as_str()
        || validator_id != namespace.validator_id().as_bytes().as_slice()
        || domain != namespace.domain().as_bytes().as_slice()
    {
        return Err(SchemaError::NamespaceMismatch);
    }
    let writer_fence_bytes = row.blob(4).map_err(SqlSessionError::from)?;
    let writer_fence = decode_u64(writer_fence_bytes)
        .and_then(WriterFenceGeneration::new)
        .ok_or(SchemaError::ZeroWriterFence)?;
    let mutation_sequence_bytes = row.blob(5).map_err(SqlSessionError::from)?;
    let mutation_sequence =
        decode_u64(mutation_sequence_bytes).ok_or(SchemaError::InvalidPersistedMetadata)?;
    let source_instance_id_bytes = row.blob(6).map_err(SqlSessionError::from)?;
    let source_instance_id: [u8; 16] = source_instance_id_bytes
        .try_into()
        .map_err(|_| SchemaError::InvalidPersistedMetadata)?;
    let origin: i64 = row.integer(7).map_err(SqlSessionError::from)?;
    let binding_bytes: Option<&[u8]> = row.opt_blob(8).map_err(SqlSessionError::from)?;
    let progress_rows = session.exec("SELECT phase, CASE WHEN progress IS NULL OR length(progress) <= 16384 THEN progress ELSE NULL END FROM durable_import_progress WHERE id = 1", &[])?;
    let progress_row = progress_rows.one()?;
    let lifecycle: NamespaceLifecycle = match (origin, binding_bytes, progress_row) {
        (1, None, None) => NamespaceLifecycle::Ordinary,
        (2, Some(bytes), Some(progress_row)) => {
            let binding: ImportBinding =
                decode_import_binding(bytes).map_err(|_| SchemaError::InvalidPersistedMetadata)?;
            if binding.domain != namespace.domain()
                || &binding.context.chain_id != namespace.chain_id()
            {
                return Err(SchemaError::NamespaceMismatch);
            }
            let phase: i64 = progress_row.integer(0).map_err(SqlSessionError::from)?;
            let progress: Option<&[u8]> =
                progress_row.opt_blob(1).map_err(SqlSessionError::from)?;
            match (phase, progress) {
                (0, None) if mutation_sequence == 0 => NamespaceLifecycle::FreshImport(binding),
                (1 | 2, Some(bytes)) => {
                    let progress = decode_import_progress(bytes)
                        .map_err(|_| SchemaError::InvalidPersistedMetadata)?;
                    if progress.next_ordinal > binding.row_count
                        || (phase == 2 && progress.next_ordinal != binding.row_count)
                    {
                        return Err(SchemaError::InvalidPersistedMetadata);
                    }
                    if phase == 1 {
                        NamespaceLifecycle::Importing { binding, progress }
                    } else {
                        NamespaceLifecycle::CompleteInactive { binding, progress }
                    }
                }
                _ => return Err(SchemaError::InvalidPersistedMetadata),
            }
        }
        _ => return Err(SchemaError::InvalidPersistedMetadata),
    };
    Ok(NamespaceMetadata {
        writer_fence,
        mutation_sequence,
        source_instance_id,
        lifecycle,
    })
}

/// Creates the shared tables if absent, installs `namespace`'s metadata
/// row the first time this database is bootstrapped, then re-reads and
/// verifies the persisted row in the same transaction the caller is
/// running.
///
/// `initial_writer_fence` is used only the very first time this namespace
/// is bootstrapped; a later call against an already-bootstrapped database
/// ignores it and returns the persisted fence instead.
pub fn bootstrap_namespace(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    initial_writer_fence: WriterFenceGeneration,
) -> Result<NamespaceMetadata, SchemaError> {
    // Reopening never repairs a missing metadata row or table. Recreating it
    // could silently rebind surviving state to another namespace/generation.
    let existing = session.exec(
        "SELECT name FROM sqlite_schema WHERE name = 'durable_metadata' LIMIT 1",
        &[],
    )?;
    if existing.one()?.is_some() {
        let metadata: NamespaceMetadata = verify_namespace(session, namespace)?;
        if !metadata.lifecycle().is_ordinary() {
            return Err(SchemaError::InactiveNamespace);
        }
        return Ok(metadata);
    }
    let surviving = session.exec(
        "SELECT name FROM sqlite_schema WHERE name GLOB 'durable_*' LIMIT 1",
        &[],
    )?;
    if surviving.one()?.is_some() {
        return Err(SchemaError::InvalidPersistedMetadata);
    }
    ensure_schema(session)?;
    session.exec(
        "INSERT OR IGNORE INTO durable_metadata
             (id, schema_identity, chain_id, validator_id, domain, writer_fence,
              mutation_sequence, source_instance_id, namespace_origin, import_binding)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, randomblob(16), 1, NULL)",
        &[
            SqlValue::Blob(SQL_DURABLE_SCHEMA_IDENTITY.to_vec()),
            SqlValue::Text(namespace.chain_id().as_str().to_owned()),
            SqlValue::Blob(namespace.validator_id().as_bytes().to_vec()),
            SqlValue::Blob(namespace.domain().as_bytes().to_vec()),
            SqlValue::Blob(encode_u64(initial_writer_fence.get()).to_vec()),
            SqlValue::Blob(encode_u64(0).to_vec()),
        ],
    )?;
    verify_namespace(session, namespace)
}

/// Initializes only a genuinely fresh, dedicated import target. Unlike an
/// ordinary bootstrap this refuses every surviving structured table, even
/// if its binding would match. Resume uses verification, never bootstrap.
pub fn bootstrap_import_namespace(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    own_writer_fence: WriterFenceGeneration,
    binding: &ImportBinding,
) -> Result<NamespaceMetadata, SchemaError> {
    if binding.domain != namespace.domain() || &binding.context.chain_id != namespace.chain_id() {
        return Err(SchemaError::NamespaceMismatch);
    }
    let bytes: Vec<u8> =
        encode_import_binding(binding).map_err(|_| SchemaError::InvalidPersistedMetadata)?;
    let surviving = session.exec(
        "SELECT name FROM sqlite_schema WHERE name GLOB 'durable_*' LIMIT 1",
        &[],
    )?;
    if surviving.one()?.is_some() {
        return Err(SchemaError::InvalidPersistedMetadata);
    }
    ensure_schema(session)?;
    session.exec(
        "INSERT INTO durable_metadata (id, schema_identity, chain_id, validator_id, domain,
             writer_fence, mutation_sequence, source_instance_id, namespace_origin, import_binding)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, randomblob(16), 2, ?7)",
        &[
            SqlValue::Blob(SQL_DURABLE_SCHEMA_IDENTITY.to_vec()),
            SqlValue::Text(namespace.chain_id().as_str().to_owned()),
            SqlValue::Blob(namespace.validator_id().as_bytes().to_vec()),
            SqlValue::Blob(namespace.domain().as_bytes().to_vec()),
            SqlValue::Blob(encode_u64(own_writer_fence.get()).to_vec()),
            SqlValue::Blob(encode_u64(0).to_vec()),
            SqlValue::Blob(bytes),
        ],
    )?;
    session.exec(
        "INSERT INTO durable_import_progress (id, phase, progress) VALUES (1, 0, NULL)",
        &[],
    )?;
    verify_namespace(session, namespace)
}

/// Atomically advances the persisted mutation sequence by exactly one.
///
/// `current` must be the exact value this same active transaction already
/// observed via [`verify_namespace`]; a mismatch (a concurrent writer already
/// advanced it, which cannot happen inside one exclusive SQL write
/// transaction but is still checked defensively) or an overflow leaves the
/// row untouched and every covered write in the same transaction must then
/// roll back rather than apply.
pub fn advance_mutation_sequence(
    session: &mut dyn SqlSession,
    current: u64,
) -> Result<u64, SchemaError> {
    let next = current
        .checked_add(1)
        .ok_or(SchemaError::MutationSequenceOverflow)?;
    let rows = session.exec(
        "UPDATE durable_metadata SET mutation_sequence = ?1
         WHERE id = 1 AND mutation_sequence = ?2",
        &[
            SqlValue::Blob(encode_u64(next).to_vec()),
            SqlValue::Blob(encode_u64(current).to_vec()),
        ],
    )?;
    if rows.rows_affected() != 1 {
        return Err(SchemaError::MutationSequenceConflict);
    }
    Ok(next)
}

/// Atomically advances the persisted writer fence from `expected` to
/// `next`.
///
/// This is an explicit operator-only failover seam, not part of any
/// runtime trait; request handling must never be able to reach it.
pub fn advance_writer_fence(
    session: &mut dyn SqlSession,
    namespace: &SqlDurableNamespace,
    expected: WriterFenceGeneration,
    next: WriterFenceGeneration,
) -> Result<WriterFenceGeneration, SchemaError> {
    let metadata = verify_namespace(session, namespace)?;
    if metadata.writer_fence() != expected {
        return Err(SchemaError::WriterFenceMismatch {
            expected,
            actual: metadata.writer_fence(),
        });
    }
    let rows = session.exec(
        "UPDATE durable_metadata SET writer_fence = ?1 WHERE id = 1",
        &[SqlValue::Blob(encode_u64(next.get()).to_vec())],
    )?;
    if rows.rows_affected() != 1 {
        return Err(SchemaError::InvalidPersistedMetadata);
    }
    Ok(next)
}

/// Reports whether the normalized object-head table is empty.
///
/// This is an operator-only startup accessor, not a request-path query.
pub fn object_heads_is_empty(session: &mut dyn SqlSession) -> Result<bool, SqlSessionError> {
    let rows = session.exec(
        "SELECT EXISTS(SELECT 1 FROM durable_object_heads LIMIT 1)",
        &[],
    )?;
    let row = rows.one()?.ok_or(SqlSessionError::Unavailable)?;
    Ok(row.integer(0)? == 0)
}
