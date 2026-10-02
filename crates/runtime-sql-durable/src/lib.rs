#![forbid(unsafe_code)]

//! Backend-neutral structured durable SQL engine.
//!
//! This crate extracts the SQL statement text, decoding, and commit rules
//! `runtime-sqlite` previously implemented directly against `rusqlite` so
//! a Cloudflare Durable Object host can reuse the exact same rules through
//! its own `SqlBackend` implementation. It depends only on `runtime` and
//! `protocol-types` and builds for `wasm32-unknown-unknown`; it must never
//! gain a dependency on `rusqlite` or any other native-only or
//! JavaScript-only crate.
//!
//! See `backend` for the two traits a new host implements, and `engine`
//! for the shared statements and rules built on top of them.

pub mod backend;
pub mod engine;
pub mod schema;

pub use backend::{
    SqlBackend, SqlBackendError, SqlDecodeError, SqlRow, SqlRows, SqlSession, SqlSessionError,
    SqlValue, TransactionBudget, TransactionDecision,
};
pub use engine::SqlDurableEngine;
pub use schema::{
    NamespaceMetadata, SQL_DURABLE_SCHEMA_IDENTITY, SchemaError, SqlDurableNamespace,
    advance_writer_fence, bootstrap_namespace, ensure_schema, object_heads_is_empty,
    open_namespace_historical, verify_namespace,
};
