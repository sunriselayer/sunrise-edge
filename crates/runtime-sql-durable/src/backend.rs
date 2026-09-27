//! Backend-neutral synchronous SQL seam shared by every durable SQL host.
//!
//! [SqlSession] and [SqlBackend] are the only two traits a storage host must
//! implement to reuse the shared engine in `crate::engine`. Neither trait
//! names SQLite, rusqlite, or any Cloudflare/JavaScript type: a native
//! process implements them with a local file connection, and a Durable
//! Object implements them with safe wasm-bindgen calls into
//! `storage.transactionSync`/`sql.exec`. Keep this file the first thing a
//! new backend author reads.

use std::fmt;

/// One dynamically typed SQL parameter or column value.
///
/// This is intentionally the smallest set every backend in scope can
/// represent without native extensions: SQLite dynamic typing and the
/// Cloudflare Durable Object SQL API both map cleanly onto these four
/// cases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SqlValue {
    /// SQL `NULL`.
    Null,
    /// A signed 64-bit integer column or parameter.
    Integer(i64),
    /// A UTF-8 text column or parameter.
    Text(String),
    /// An opaque byte-string column or parameter.
    Blob(Vec<u8>),
}

impl SqlValue {
    /// Returns the blob bytes, or `None` if this value is not a blob.
    #[must_use]
    pub fn as_blob(&self) -> Option<&[u8]> {
        match self {
            Self::Blob(bytes) => Some(bytes.as_slice()),
            _ => None,
        }
    }

    /// Returns the integer, or `None` if this value is not an integer.
    #[must_use]
    pub const fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the text, or `None` if this value is not text.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value.as_str()),
            _ => None,
        }
    }

    /// Returns whether this value is SQL `NULL`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl From<i64> for SqlValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<Vec<u8>> for SqlValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Blob(value)
    }
}

impl From<String> for SqlValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for SqlValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl<T: Into<SqlValue>> From<Option<T>> for SqlValue {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}

/// One decoded output row, addressed positionally by the same column order
/// named in the `SELECT` list that produced it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SqlRow(Vec<SqlValue>);

impl SqlRow {
    /// Wraps one row of already-decoded column values.
    #[must_use]
    pub const fn new(values: Vec<SqlValue>) -> Self {
        Self(values)
    }

    /// Returns the number of columns in this row.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether this row has no columns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the raw value at `index`, if the row is wide enough.
    #[must_use]
    pub fn value(&self, index: usize) -> Option<&SqlValue> {
        self.0.get(index)
    }

    /// Decodes column `index` as a required blob.
    pub fn blob(&self, index: usize) -> Result<&[u8], SqlDecodeError> {
        match self.value(index) {
            Some(SqlValue::Blob(bytes)) => Ok(bytes.as_slice()),
            Some(_) => Err(SqlDecodeError::WrongType { index }),
            None => Err(SqlDecodeError::MissingColumn { index }),
        }
    }

    /// Decodes column `index` as an optional blob, treating `NULL` as
    /// absent.
    pub fn opt_blob(&self, index: usize) -> Result<Option<&[u8]>, SqlDecodeError> {
        match self.value(index) {
            Some(SqlValue::Blob(bytes)) => Ok(Some(bytes.as_slice())),
            Some(SqlValue::Null) => Ok(None),
            Some(_) => Err(SqlDecodeError::WrongType { index }),
            None => Err(SqlDecodeError::MissingColumn { index }),
        }
    }

    /// Decodes column `index` as a required integer.
    pub fn integer(&self, index: usize) -> Result<i64, SqlDecodeError> {
        match self.value(index) {
            Some(SqlValue::Integer(value)) => Ok(*value),
            Some(_) => Err(SqlDecodeError::WrongType { index }),
            None => Err(SqlDecodeError::MissingColumn { index }),
        }
    }

    /// Decodes column `index` as an optional integer, treating `NULL` as
    /// absent.
    pub fn opt_integer(&self, index: usize) -> Result<Option<i64>, SqlDecodeError> {
        match self.value(index) {
            Some(SqlValue::Integer(value)) => Ok(Some(*value)),
            Some(SqlValue::Null) => Ok(None),
            Some(_) => Err(SqlDecodeError::WrongType { index }),
            None => Err(SqlDecodeError::MissingColumn { index }),
        }
    }

    /// Decodes column `index` as required text.
    pub fn text(&self, index: usize) -> Result<&str, SqlDecodeError> {
        match self.value(index) {
            Some(SqlValue::Text(value)) => Ok(value.as_str()),
            Some(_) => Err(SqlDecodeError::WrongType { index }),
            None => Err(SqlDecodeError::MissingColumn { index }),
        }
    }
}

/// A column value existed but was not the type or presence the caller
/// required, or the row was narrower than the requested column index.
///
/// This is always persisted-state corruption from the perspective of the
/// shared engine: the DDL in `crate::schema` fixes every column type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlDecodeError {
    /// The row has no column at this index.
    MissingColumn { index: usize },
    /// The column exists but is not the requested variant.
    WrongType { index: usize },
}

impl fmt::Display for SqlDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingColumn { index } => write!(f, "SQL row has no column {index}"),
            Self::WrongType { index } => write!(f, "SQL column {index} has an unexpected type"),
        }
    }
}

impl std::error::Error for SqlDecodeError {}

/// The bounded result of one `exec` call: at most the rows the statement
/// text itself limited (for example an explicit `LIMIT`), plus the number
/// of rows a write statement inserted, updated, or deleted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SqlRows {
    rows: Vec<SqlRow>,
    rows_affected: u64,
}

impl SqlRows {
    /// Wraps a bounded row set and its affected-row count.
    #[must_use]
    pub const fn new(rows: Vec<SqlRow>, rows_affected: u64) -> Self {
        Self {
            rows,
            rows_affected,
        }
    }

    /// Returns the decoded rows, in the order the backend produced them.
    #[must_use]
    pub fn rows(&self) -> &[SqlRow] {
        &self.rows
    }

    /// Returns the number of rows a write statement affected.
    #[must_use]
    pub const fn rows_affected(&self) -> u64 {
        self.rows_affected
    }

    /// Returns the single row a point query produced, or `None`.
    ///
    /// Returns `SqlSessionError::UnexpectedRowCount` instead of silently
    /// picking a row if the statement text did not in fact bound the
    /// result to at most one row.
    pub fn one(mut self) -> Result<Option<SqlRow>, SqlSessionError> {
        match self.rows.len() {
            0 => Ok(None),
            1 => Ok(Some(self.rows.remove(0))),
            found => Err(SqlSessionError::UnexpectedRowCount { found }),
        }
    }
}

/// A definite failure executing one statement inside an active
/// transaction.
///
/// This is always a backend/session-level failure (a rejected statement, a
/// closed connection, a decode mismatch against the fixed DDL); it is
/// never used to represent a business decision such as a revision
/// conflict, which the engine expresses through its own typed outcome
/// instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SqlSessionError {
    /// The backend rejected the statement or parameters.
    Rejected(String),
    /// The session is no longer usable, for example a poisoned connection.
    Unavailable,
    /// A row had an unexpected shape.
    Decode(SqlDecodeError),
    /// A query bounded to at most one row returned more than one.
    UnexpectedRowCount { found: usize },
}

impl fmt::Display for SqlSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(message) => write!(f, "SQL statement rejected: {message}"),
            Self::Unavailable => f.write_str("SQL session is unavailable"),
            Self::Decode(error) => write!(f, "SQL row decode failed: {error}"),
            Self::UnexpectedRowCount { found } => {
                write!(f, "SQL query returned {found} rows, expected at most one")
            }
        }
    }
}

impl std::error::Error for SqlSessionError {}

impl From<SqlDecodeError> for SqlSessionError {
    fn from(value: SqlDecodeError) -> Self {
        Self::Decode(value)
    }
}

/// One synchronous SQL statement executor inside an active host
/// transaction.
///
/// Every statement the shared engine issues is a single, complete,
/// bounded statement: no cursors are kept open across calls, and every
/// multi-row query supplies its own `LIMIT`. A backend may implement this
/// by preparing and stepping a native SQLite statement, or by forwarding
/// the text and parameters directly to one `sql.exec` call inside
/// `storage.transactionSync`.
pub trait SqlSession {
    /// Executes one statement and returns its bounded rows and
    /// affected-row count.
    fn exec(&mut self, statement: &str, params: &[SqlValue]) -> Result<SqlRows, SqlSessionError>;

    /// Returns a freshly read, host-owned trusted Unix-millisecond clock
    /// reading, taken at the moment of this call.
    ///
    /// The engine calls this a second time immediately before finalizing
    /// a commit decision, rather than reusing the `now` `SqlBackend::
    /// transaction` supplied when the transaction began: a native
    /// backend samples that initial value only after it already holds
    /// its file lock, so real time can still advance past the caller's
    /// deadline while an earlier `BEGIN`/`sql.exec` call was blocked on a
    /// contended lock. A WASM/Durable Object implementation must supply
    /// this from the same host-owned clock source it uses for the
    /// `now` argument to `SqlBackend::transaction` (for example a scoped
    /// `Date.now()` import), never a value cached from when the
    /// transaction began, and never `std::time`, which has no source on
    /// `wasm32-unknown-unknown`.
    fn now_unix_millis(&self) -> Result<u64, SqlSessionError>;
}

/// The engine's decision at the end of one transaction callback.
///
/// Returning this from `SqlBackend::transaction`'s callback, rather than a
/// thrown/propagated error, keeps every definite, well-understood
/// decision (including a deliberate rollback such as a revision
/// conflict) inside the host's normal control flow. A Rust `Err` from the
/// callback is reserved for a genuinely unexpected failure and is
/// translated into an aborting exception at a JavaScript host boundary
/// instead of an ordinary rollback.
#[derive(Debug)]
pub enum TransactionDecision<T> {
    /// Commit the transaction and yield `value`.
    Commit(T),
    /// Roll back the transaction and yield `value`; `value` typically
    /// carries a definite, already fully explained rejection.
    Rollback(T),
}

/// The caller's remaining wall-clock budget for acquiring one
/// transaction.
///
/// This is a lock-acquisition/backend hint, not a substitute for the
/// engine's own deadline check against trusted time inside the
/// transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionBudget {
    /// Fail to acquire the transaction once this absolute
    /// Unix-millisecond deadline has passed, rather than waiting on the
    /// backend's own default.
    Deadline(u64),
    /// Use the backend's fixed operator-path default budget.
    OperatorDefault,
}

/// A failure opening or completing one host transaction, distinct from
/// any business rejection the engine itself decided on.
#[derive(Debug)]
pub enum SqlBackendError {
    /// The transaction could not be started at all; nothing was
    /// attempted.
    Unavailable,
    /// The callback reported a definite session failure before reaching
    /// a commit/rollback decision.
    SessionFailed(SqlSessionError),
    /// The callback requested `Commit`, but the backend cannot confirm
    /// whether the underlying storage commit took effect.
    CommitIndeterminate,
}

impl fmt::Display for SqlBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("SQL backend transaction is unavailable"),
            Self::SessionFailed(error) => write!(f, "SQL backend session failed: {error}"),
            Self::CommitIndeterminate => f.write_str("SQL backend commit outcome is indeterminate"),
        }
    }
}

impl std::error::Error for SqlBackendError {}

/// One host-owned synchronous SQL transaction provider.
///
/// A native process implements this over a local file connection and its
/// own locking; a Durable Object implements this over
/// `storage.transactionSync`/`sql.exec` through safe wasm-bindgen
/// bindings. Both share every statement text and every decision in
/// `crate::engine`; this trait is the only seam between them.
pub trait SqlBackend {
    /// Runs `run` inside one new host transaction and returns its
    /// outcome.
    ///
    /// `run` receives the active session and a trusted, host-supplied
    /// `now_unix_millis` reading it must use for every time-dependent
    /// decision instead of reading a platform clock itself, so the same
    /// engine code runs unchanged on a host with no local wall clock.
    fn transaction<T>(
        &self,
        budget: TransactionBudget,
        run: impl FnOnce(&mut dyn SqlSession, u64) -> Result<TransactionDecision<T>, SqlSessionError>,
    ) -> Result<T, SqlBackendError>;
}
