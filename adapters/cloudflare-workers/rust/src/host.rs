//! JS-side host bridge imported by the embedded validator.
//!
//! This is the exact interface the parent Durable Object wrapper must
//! implement and pass into ValidatorHost::new. Publishing this module
//! early lets the TypeScript side compile and unit-test its own SqlHost
//! and BlobHost implementations before the durable state-store wiring
//! (runtime-sql-durable::SqlBackend) lands on the Rust side.
//!
//! SqlHost::transaction takes a borrowed, non-static, FnMut callback via
//! wasm_bindgen::closure::ScopedClosure::borrow_mut_assert_unwind_safe
//! rather than an owned wasm_bindgen::closure::Closure: the callback only
//! needs to live for the duration of one synchronous
//! storage.transactionSync call, so it borrows this call stack state
//! (never a global) and is dropped the moment transaction returns.
//!
//! The callback itself returns `Result<JsValue, JsValue>`, never calls
//! `wasm_bindgen::throw_val`, and never panics: `throw_val` unwinds
//! immediately through the generated glue and skips Rust destructors
//! (including whatever the callback body itself would otherwise have
//! dropped), which is exactly the unsound shortcut DR-0152 forbids. The
//! `wasm-bindgen`-generated JS wrapper around an `FnMut() -> Result<T, E>`
//! closure instead calls the Rust closure, lets it return normally (so
//! every Rust destructor for that call already ran before any JS control
//! flow resumes), and only then -- back in JS, after the Rust call frame
//! is gone -- throws `E` if the closure returned `Err`. `sql_backend`
//! relies on exactly that ordering: it saves its own decided
//! [`runtime_sql_durable::TransactionDecision`] value into a local
//! variable *before* returning `Err(rollback_sentinel)`, so the value is
//! already safely stored on the Rust side by the time
//! `storage.transactionSync` sees the thrown sentinel and rolls the SQL
//! transaction back.

use wasm_bindgen::JsValue;
use wasm_bindgen::closure::ScopedClosure;
use wasm_bindgen::prelude::wasm_bindgen;

/// Upper bound this crate ever passes as `exec`'s `row_limit`: one more
/// than the largest page `runtime_sql_durable::engine` statement text
/// itself bounds with an explicit `LIMIT`, mirroring the
/// `runtime::StateKeyPage` lookahead-row convention (request one extra
/// row to detect truncation, never expose it). This is a resource-safety
/// ceiling on the value this crate supplies, not a claim about what any
/// particular statement text requests.
pub const MAX_SQL_ROW_LIMIT: u32 = 1025;

#[wasm_bindgen]
extern "C" {
    /// One trusted, single-actor synchronous SQL session.
    ///
    /// The parent DO wrapper constructs exactly one SqlHost per Durable
    /// Object instance, backed by that instance own state.storage.sql.
    /// Nothing about this type selects a namespace, actor id, or domain:
    /// that binding happens once, out of band, when the DO wrapper itself
    /// is constructed from trusted deployment configuration.
    #[wasm_bindgen(js_name = SqlHost)]
    pub type SqlHost;

    /// Executes one bounded SQL statement and returns its rows as an
    /// opaque JsValue (an array of row objects or arrays; this crate does
    /// not prescribe the exact JS row shape, only that it is bounded by
    /// row_limit). Thrown JS exceptions are caught and surfaced as Err,
    /// never as an unwind through this boundary.
    #[wasm_bindgen(method, catch, js_name = exec)]
    pub fn exec(
        this: &SqlHost,
        sql: &str,
        params: &JsValue,
        row_limit: u32,
    ) -> Result<JsValue, JsValue>;

    /// Runs `callback` inside one host-owned synchronous SQL transaction
    /// (`storage.transactionSync` on a Durable Object). `callback` is
    /// called at most once, synchronously, before this method returns:
    /// this crate never registers it for later/async/reentrant
    /// invocation. Returns whatever `callback` returned on success;
    /// propagates a thrown JS exception (including the deliberate
    /// rollback sentinel `sql_backend` throws) as `Err`.
    #[wasm_bindgen(method, catch, js_name = transaction)]
    pub fn transaction(
        this: &SqlHost,
        callback: &ScopedClosure<dyn FnMut() -> Result<JsValue, JsValue>>,
    ) -> Result<JsValue, JsValue>;

    /// Returns the current wall-clock time in Unix milliseconds.
    ///
    /// Explicit rather than a Rust-side SystemTime read: the DO notion of
    /// now is the one the host callback observes at the exact instant it
    /// is asked, matching the deterministic-input discipline the rest of
    /// the protocol already requires.
    #[wasm_bindgen(method, catch, js_name = nowMillis)]
    pub fn now_millis(this: &SqlHost) -> Result<f64, JsValue>;

    /// Content-addressed, insert-if-absent blob storage bound to one
    /// Durable Object own bounded SQL-backed blob table.
    #[wasm_bindgen(js_name = DoBlobStore)]
    pub type DoBlobStore;

    /// Stores bytes under digest_hex if absent. Returns Ok(true) when the
    /// digest was newly stored, Ok(false) when it was already present
    /// with byte-identical content (idempotent no-op), and throws
    /// (surfaced as Err) on an exact digest/content conflict.
    #[wasm_bindgen(method, catch, js_name = putIfAbsent)]
    pub fn put_if_absent(
        this: &DoBlobStore,
        digest_hex: &str,
        bytes: &[u8],
    ) -> Result<bool, JsValue>;

    /// Loads a previously stored blob, or undefined if absent.
    #[wasm_bindgen(method, catch, js_name = getBlob)]
    pub fn get_blob(this: &DoBlobStore, digest_hex: &str) -> Result<JsValue, JsValue>;
}
