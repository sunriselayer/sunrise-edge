//! Private test-only observation mechanics shared by fee, lifecycle, slash
//! and registration preparation tests: a reader-only capability, a counted
//! immutable publication port and exact portable capture. See
//! `docs/architecture/test-observation-contracts.md` and
//! `docs/architecture/decisions/0183-test-observation-ownership.md`.
//!
//! This module owns observation mechanics only. It never generates a
//! committee, trusted genesis, certificate or accepted business result;
//! genuine fixtures and the counting WASM engine stay with their owning
//! tests.

pub(crate) mod capture;
pub(crate) mod counted_blobs;
pub(crate) mod reader_view;
