//! `runtime_sql_durable::SqlBackend`/`SqlSession` over `host::SqlHost`.
//!
//! See `host` for why the transaction callback returns
//! `Result<JsValue, JsValue>` and never calls `wasm_bindgen::throw_val`.
//! This module is the one place that interprets what a thrown value from
//! `SqlHost::transaction` means: the exact rollback sentinel this same
//! module threw (a deliberate `TransactionDecision::Rollback`, whose
//! value was already saved locally before the throw), the exact session-
//! failure sentinel this module threw (a definite `SqlSessionError` the
//! callback observed), or anything else, which is indeterminate: it was
//! either thrown by the backend itself outside the callback body (for
//! example after a successful callback return, during the host own
//! commit step) or is not a value this module ever produced, so this
//! module cannot tell whether the underlying SQL commit took effect.

use std::cell::Cell;

use js_sys::{Array, Number, Object, Reflect, Uint8Array};
use runtime_sql_durable::backend::{
    SqlBackend, SqlBackendError, SqlRow, SqlRows, SqlSession, SqlSessionError, SqlValue,
    TransactionBudget, TransactionDecision,
};
use wasm_bindgen::closure::ScopedClosure;
use wasm_bindgen::{JsCast, JsValue};

use crate::host::{MAX_SQL_ROW_LIMIT, SqlHost};

/// Reads the host clock and validates it is a safe, non-negative
/// integer. Never cached: every caller re-invokes this to get a fresh
/// reading, since a `SqlSession`-held value from transaction start is
/// exactly the stale reading the shared engine own deadline recheck
/// immediately before commit must not rely on.
pub(crate) fn read_now_millis(sql: &SqlHost) -> Result<u64, SqlSessionError> {
    match sql.now_millis() {
        Ok(value) if value >= 0.0 && Number::is_safe_integer(&JsValue::from_f64(value)) => {
            Ok(value as u64)
        }
        _ => Err(SqlSessionError::Rejected(
            "host nowMillis was unavailable or not a safe non-negative integer".to_owned(),
        )),
    }
}

fn safe_i64_to_js(value: i64) -> Result<JsValue, SqlSessionError> {
    let as_f64 = value as f64;
    let candidate = JsValue::from_f64(as_f64);
    if as_f64 as i64 != value || !Number::is_safe_integer(&candidate) {
        return Err(SqlSessionError::Rejected(
            "integer parameter exceeds the JS safe-integer range".to_owned(),
        ));
    }
    Ok(candidate)
}

fn sql_value_to_js(value: &SqlValue) -> Result<JsValue, SqlSessionError> {
    match value {
        SqlValue::Null => Ok(JsValue::NULL),
        SqlValue::Integer(value) => safe_i64_to_js(*value),
        SqlValue::Text(text) => Ok(JsValue::from_str(text)),
        SqlValue::Blob(bytes) => Ok(Uint8Array::from(bytes.as_slice()).into()),
    }
}

/// Decodes one JS row column. Accepts only `null` as SQL `NULL` -- a
/// real stored column is never JS `undefined`, so an `undefined` column
/// is rejected exactly like an unsafe-range number, an object, or a
/// boolean, rather than silently treated the same as `null`. Accepts a
/// JS string as SQL text, a safe-integer JS number as a signed 64-bit
/// integer, and a `Uint8Array` or `ArrayBuffer` as a blob.
fn js_to_sql_value(value: &JsValue) -> Result<SqlValue, SqlSessionError> {
    if value.is_undefined() {
        return Err(SqlSessionError::Rejected(
            "row column was undefined, not null".to_owned(),
        ));
    }
    if value.is_null() {
        return Ok(SqlValue::Null);
    }
    if let Some(text) = value.as_string() {
        return Ok(SqlValue::Text(text));
    }
    if value.as_f64().is_some() {
        if !Number::is_safe_integer(value) {
            return Err(SqlSessionError::Rejected(
                "row column number is not a safe integer".to_owned(),
            ));
        }
        // Safety of the round trip is exactly what `is_safe_integer` above
        // just confirmed: no fractional part and within +/-(2^53 - 1).
        return Ok(SqlValue::Integer(value.as_f64().unwrap_or_default() as i64));
    }
    if let Some(array) = value.dyn_ref::<Uint8Array>() {
        return Ok(SqlValue::Blob(array.to_vec()));
    }
    if let Some(buffer) = value.dyn_ref::<js_sys::ArrayBuffer>() {
        return Ok(SqlValue::Blob(Uint8Array::new(buffer).to_vec()));
    }
    Err(SqlSessionError::Rejected(
        "row column had an unsupported JS type".to_owned(),
    ))
}

struct DoSqlSession<'a> {
    sql: &'a SqlHost,
}

impl SqlSession for DoSqlSession<'_> {
    /// Fresh host clock reading, taken at the moment of this call --
    /// never a value cached from transaction start. The shared engine
    /// calls this a second time immediately before finalizing a commit
    /// decision, exactly per this trait method own documented contract.
    fn now_unix_millis(&self) -> Result<u64, SqlSessionError> {
        read_now_millis(self.sql)
    }

    fn exec(&mut self, statement: &str, params: &[SqlValue]) -> Result<SqlRows, SqlSessionError> {
        let params_array = Array::new();
        for value in params {
            params_array.push(&sql_value_to_js(value)?);
        }
        let result = self
            .sql
            .exec(statement, &params_array.into(), MAX_SQL_ROW_LIMIT)
            .map_err(|_| SqlSessionError::Unavailable)?;
        let rows_value = Reflect::get(&result, &JsValue::from_str("rows"))
            .map_err(|_| SqlSessionError::Rejected("exec result has no rows field".to_owned()))?;
        let rows_array: Array = rows_value.dyn_into().map_err(|_| {
            SqlSessionError::Rejected("exec result rows was not an array".to_owned())
        })?;
        let mut rows = Vec::with_capacity(rows_array.length() as usize);
        for row_value in rows_array.iter() {
            let row_array: Array = row_value.dyn_into().map_err(|_| {
                SqlSessionError::Rejected("exec result row was not an array".to_owned())
            })?;
            let mut columns = Vec::with_capacity(row_array.length() as usize);
            for column_value in row_array.iter() {
                columns.push(js_to_sql_value(&column_value)?);
            }
            rows.push(SqlRow::new(columns));
        }
        let rows_affected_value = Reflect::get(&result, &JsValue::from_str("rowsAffected"))
            .map_err(|_| {
                SqlSessionError::Rejected("exec result has no rowsAffected field".to_owned())
            })?;
        if !Number::is_safe_integer(&rows_affected_value) {
            return Err(SqlSessionError::Rejected(
                "exec result rowsAffected was not a safe integer".to_owned(),
            ));
        }
        let rows_affected = rows_affected_value.as_f64().unwrap_or(-1.0);
        if rows_affected < 0.0 {
            return Err(SqlSessionError::Rejected(
                "exec result rowsAffected was negative".to_owned(),
            ));
        }
        Ok(SqlRows::new(rows, rows_affected as u64))
    }
}

/// `SqlBackend` over one Durable Object own `SqlHost`.
pub struct DoSqlBackend {
    sql: SqlHost,
    in_transaction: Cell<bool>,
}

impl DoSqlBackend {
    #[must_use]
    pub const fn new(sql: SqlHost) -> Self {
        Self {
            sql,
            in_transaction: Cell::new(false),
        }
    }

    /// Returns the bound host bridge, for callers (namespace bootstrap)
    /// that need to run a transaction through this same backend before
    /// `SqlDurableEngine` exists yet.
    #[must_use]
    pub const fn sql(&self) -> &SqlHost {
        &self.sql
    }
}

impl SqlBackend for DoSqlBackend {
    fn transaction<T>(
        &self,
        // The Durable Object own event loop already serializes every
        // request into this actor, so there is never a concurrent lock
        // holder to wait out; `budget` has nothing to queue behind here.
        // It is still honored as a genuine admission gate below (checked
        // against a fresh clock read before the callback ever runs), not
        // merely documented and ignored. The shared engine separately
        // re-reads `DoSqlSession::now_unix_millis` for its own deadline
        // check immediately before commit; this method never assumes the
        // single reading it passes to `run` still suffices by then.
        budget: TransactionBudget,
        run: impl FnOnce(&mut dyn SqlSession, u64) -> Result<TransactionDecision<T>, SqlSessionError>,
    ) -> Result<T, SqlBackendError> {
        if self.in_transaction.replace(true) {
            return Err(SqlBackendError::Unavailable);
        }
        struct ReleaseGuard<'a>(&'a Cell<bool>);
        impl Drop for ReleaseGuard<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let _release = ReleaseGuard(&self.in_transaction);

        if let TransactionBudget::Deadline(deadline) = budget {
            let now_before = read_now_millis(&self.sql).map_err(SqlBackendError::SessionFailed)?;
            if now_before >= deadline {
                return Err(SqlBackendError::Unavailable);
            }
        }

        // Unique per-call sentinel objects, not strings: a thrown value
        // is matched by JS object identity (`===`) below, never by
        // content, so nothing a statement, row, or host error could ever
        // itself throw can be mistaken for one of these.
        let rollback_sentinel = JsValue::from(Object::new());
        let session_failure_sentinel = JsValue::from(Object::new());
        let reentrant_sentinel = JsValue::from(Object::new());

        let mut run = Some(run);
        let mut decision: Option<TransactionDecision<T>> = None;
        let mut session_failure: Option<SqlSessionError> = None;

        let mut callback = || -> Result<JsValue, JsValue> {
            if decision.is_some() || session_failure.is_some() {
                return Err(reentrant_sentinel.clone());
            }
            let Some(run) = run.take() else {
                return Err(reentrant_sentinel.clone());
            };
            let mut session = DoSqlSession { sql: &self.sql };
            // Fresh read through the session, not a value captured
            // earlier in this closure: this is exactly the reading
            // `DoSqlSession::now_unix_millis` also exposes for the
            // shared engine own immediately-before-commit recheck.
            let now_unix_millis = match session.now_unix_millis() {
                Ok(value) => value,
                Err(error) => {
                    session_failure = Some(error);
                    return Err(session_failure_sentinel.clone());
                }
            };
            match run(&mut session, now_unix_millis) {
                Ok(TransactionDecision::Commit(value)) => {
                    decision = Some(TransactionDecision::Commit(value));
                    Ok(JsValue::TRUE)
                }
                Ok(TransactionDecision::Rollback(value)) => {
                    decision = Some(TransactionDecision::Rollback(value));
                    Err(rollback_sentinel.clone())
                }
                Err(error) => {
                    session_failure = Some(error);
                    Err(session_failure_sentinel.clone())
                }
            }
        };

        let scoped = ScopedClosure::borrow_mut_assert_unwind_safe(&mut callback);
        let outcome = self.sql.transaction(&scoped);
        drop(scoped);

        match outcome {
            Ok(_) => match decision {
                Some(TransactionDecision::Commit(value)) => Ok(value),
                _ => Err(SqlBackendError::CommitIndeterminate),
            },
            Err(thrown) => {
                // Matched by object identity, never by content: only
                // one of these three specific heap objects (created
                // fresh above, never reused across calls) can equal
                // `thrown` here. A rollback/session-failure verdict is
                // trusted only when this module also actually saved
                // the corresponding local state before throwing;
                // anything else -- including a sentinel match with no
                // saved state, which should never happen but is not
                // trusted blindly -- is indeterminate.
                if thrown == rollback_sentinel {
                    match decision {
                        Some(TransactionDecision::Rollback(value)) => Ok(value),
                        _ => Err(SqlBackendError::CommitIndeterminate),
                    }
                } else if thrown == session_failure_sentinel {
                    match session_failure {
                        Some(error) => Err(SqlBackendError::SessionFailed(error)),
                        None => Err(SqlBackendError::CommitIndeterminate),
                    }
                } else if thrown == reentrant_sentinel {
                    Err(SqlBackendError::SessionFailed(SqlSessionError::Rejected(
                        "host called the transaction callback more than once".to_owned(),
                    )))
                } else {
                    Err(SqlBackendError::CommitIndeterminate)
                }
            }
        }
    }
}
