//! Bounded rusqlite-compat `SqlSession`/`SqlBackend` adapter.
//!
//! This is the sole place `rusqlite` meets the portable
//! `runtime-sql-durable` engine: everything here is mechanical
//! translation between `SqlValue`/`SqlRows` and rusqlite's own row/value
//! types, never business logic. `runtime-sql-durable` itself never
//! depends on `rusqlite`.

use runtime_sql_durable::{
    SqlBackend, SqlBackendError, SqlRow, SqlRows, SqlSession, SqlSessionError, SqlValue,
    TransactionBudget, TransactionDecision,
};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, Transaction, TransactionBehavior, types::Value as RusqliteValue};
use std::{
    sync::{Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_BUSY_TIMEOUT_MILLIS: u64 = 5_000;
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_millis(MAX_BUSY_TIMEOUT_MILLIS);

fn now_unix_millis() -> Option<u64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(elapsed.as_millis()).ok()
}

fn remaining_busy_timeout(deadline_unix_millis: u64, now: u64) -> Duration {
    let remaining = deadline_unix_millis.saturating_sub(now);
    Duration::from_millis(remaining.clamp(1, MAX_BUSY_TIMEOUT_MILLIS))
}

fn sql_value_to_rusqlite(value: &SqlValue) -> RusqliteValue {
    match value {
        SqlValue::Null => RusqliteValue::Null,
        SqlValue::Integer(value) => RusqliteValue::Integer(*value),
        SqlValue::Text(value) => RusqliteValue::Text(value.clone()),
        SqlValue::Blob(value) => RusqliteValue::Blob(value.clone()),
    }
}

fn rejected(error: impl std::fmt::Display) -> SqlSessionError {
    SqlSessionError::Rejected(error.to_string())
}

fn value_ref_to_sql_value(value: ValueRef<'_>) -> Result<SqlValue, SqlSessionError> {
    match value {
        ValueRef::Null => Ok(SqlValue::Null),
        ValueRef::Integer(value) => Ok(SqlValue::Integer(value)),
        ValueRef::Blob(bytes) => Ok(SqlValue::Blob(bytes.to_vec())),
        ValueRef::Text(bytes) => String::from_utf8(bytes.to_vec())
            .map(SqlValue::Text)
            .map_err(rejected),
        ValueRef::Real(_) => Err(SqlSessionError::Rejected(
            "unexpected SQL REAL column in structured schema".to_owned(),
        )),
    }
}

/// One synchronous [`SqlSession`] backed by an active rusqlite
/// transaction.
///
/// This is the bounded rusqlite-compat helper the shared engine calls
/// through: every statement is prepared and stepped once, with no cursor
/// kept open across `exec` calls.
pub(crate) struct RusqliteSession<'a> {
    transaction: &'a Transaction<'a>,
}

impl SqlSession for RusqliteSession<'_> {
    fn exec(&mut self, statement: &str, params: &[SqlValue]) -> Result<SqlRows, SqlSessionError> {
        let mut prepared = self.transaction.prepare(statement).map_err(rejected)?;
        let bound: Vec<RusqliteValue> = params.iter().map(sql_value_to_rusqlite).collect();
        if prepared.column_count() == 0 {
            let rows_affected = prepared
                .execute(rusqlite::params_from_iter(bound))
                .map_err(rejected)?;
            return Ok(SqlRows::new(Vec::new(), rows_affected as u64));
        }
        let mut rows = prepared
            .query(rusqlite::params_from_iter(bound))
            .map_err(rejected)?;
        let mut decoded = Vec::new();
        while let Some(row) = rows.next().map_err(rejected)? {
            let mut values = Vec::new();
            let mut index = 0usize;
            loop {
                match row.get_ref(index) {
                    Ok(value_ref) => values.push(value_ref_to_sql_value(value_ref)?),
                    Err(rusqlite::Error::InvalidColumnIndex(_)) => break,
                    Err(error) => return Err(rejected(error)),
                }
                index += 1;
            }
            decoded.push(SqlRow::new(values));
        }
        Ok(SqlRows::new(decoded, 0))
    }

    fn now_unix_millis(&self) -> Result<u64, SqlSessionError> {
        now_unix_millis()
            .ok_or_else(|| SqlSessionError::Rejected("system clock unavailable".to_owned()))
    }
}

/// Native `SqlBackend`: one process-local rusqlite connection behind a
/// mutex, matching this crate's original single-writer transaction
/// model. `busy_timeout` is reset immediately before every transaction
/// from `budget`, so a blocked write fails closed near the caller's own
/// deadline instead of always waiting the fixed operator default.
pub(crate) struct NativeSqlBackend {
    connection: Mutex<Connection>,
}

impl NativeSqlBackend {
    pub(crate) const fn new(connection: Connection) -> Self {
        Self {
            connection: Mutex::new(connection),
        }
    }

    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>, SqlBackendError> {
        self.connection
            .lock()
            .map_err(|_| SqlBackendError::Unavailable)
    }
}

impl SqlBackend for NativeSqlBackend {
    fn transaction<T>(
        &self,
        budget: TransactionBudget,
        run: impl FnOnce(&mut dyn SqlSession, u64) -> Result<TransactionDecision<T>, SqlSessionError>,
    ) -> Result<T, SqlBackendError> {
        let mut connection = self.lock()?;
        let Some(pre_lock_now) = now_unix_millis() else {
            return Err(SqlBackendError::Unavailable);
        };
        let timeout = match budget {
            TransactionBudget::Deadline(deadline) => remaining_busy_timeout(deadline, pre_lock_now),
            TransactionBudget::OperatorDefault => DEFAULT_BUSY_TIMEOUT,
        };
        if connection.busy_timeout(timeout).is_err() {
            return Err(SqlBackendError::Unavailable);
        }
        // `BEGIN IMMEDIATE` itself can block up to `timeout` waiting on a
        // contended file lock, so the caller's deadline must be checked
        // against a clock read taken after that wait, not the value used
        // only to size the wait itself.
        let Ok(transaction) = connection.transaction_with_behavior(TransactionBehavior::Immediate)
        else {
            return Err(SqlBackendError::Unavailable);
        };
        let Some(now) = now_unix_millis() else {
            let _ = transaction.rollback();
            return Err(SqlBackendError::Unavailable);
        };
        let mut session = RusqliteSession {
            transaction: &transaction,
        };
        match run(&mut session, now) {
            Err(error) => {
                let _ = transaction.rollback();
                Err(SqlBackendError::SessionFailed(error))
            }
            Ok(TransactionDecision::Rollback(value)) => {
                if transaction.rollback().is_err() {
                    return Err(SqlBackendError::Unavailable);
                }
                Ok(value)
            }
            Ok(TransactionDecision::Commit(value)) => {
                if transaction.commit().is_err() {
                    return Err(SqlBackendError::CommitIndeterminate);
                }
                Ok(value)
            }
        }
    }
}
