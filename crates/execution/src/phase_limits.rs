//! DR-0124 first-profile reserve/settle phase ceilings.
//!
//! These are the single crate-internal copy of the fixed per-phase resource
//! budgets. Both the paid policy wire boundary (`crate::paid_execution`,
//! which binds them as `PaidFeePolicy` fields 17..22) and the private VM
//! phase coordinator (`crate::local_wasm::coordinator`, which enforces them)
//! read them from here, so committing to a phase cap never makes the
//! private coordinator module a public prerequisite of the wire boundary.
//!
//! Changing any value here changes committed `PaidFeePolicy` bytes and is a
//! protocol-critical change.

/// Maximum nested calls one reserve or settle phase may make.
pub(crate) const PHASE_CALLS: u32 = 8;
/// Maximum object handles one reserve or settle phase may hold.
pub(crate) const PHASE_HANDLES: usize = 16;
/// Maximum objects one reserve or settle phase may create.
pub(crate) const PHASE_CREATIONS: u32 = 4;
/// Maximum events one reserve or settle phase may emit.
pub(crate) const PHASE_EVENTS: usize = 16;
/// Maximum cumulative linear-memory allocation for one reserve or settle phase.
pub(crate) const PHASE_MEMORY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum encoded-effect allowance for one reserve or settle phase.
pub(crate) const PHASE_OUTPUT_BYTES: usize = 1024 * 1024;
