//! Read-only outbox-exclusion inventory for the initial epoch-handoff profile.
//!
//! DR-0154 and docs/architecture/epoch-handoff.md name outbox batch,
//! message, delivery and attempt rows as excluded families that
//! crate::portable never enumerates. Exclusion is conditional: a fresh
//! handoff profile must verify that no nonempty or pending outbound
//! obligation exists, including in the legacy outbox/ state-key prefix,
//! before excluding those rows, and must fail closed on any such
//! obligation. This module is that separate check.
//!
//! This is a probe, not a fence: a clear report proves only that one read
//! observed no pending outbound obligation at that instant. It carries no
//! lock, quorum, or admission-marker authority, is not atomic with any
//! later decision, and a concurrent writer may commit a new obligation
//! immediately afterward. The epoch-handoff protocol's own
//! Freeze/DrainSet/Seal chain is the only mechanism that may actually close
//! admission. Neither type here may be used to claim a handoff is ready.
//!
//! Empty-batch normalization: an outbox batch may be explicitly empty; its
//! delivery cursor is created already completed. Both SQL profiles still
//! persist batch/delivery rows for an explicitly empty batch. A nonempty
//! message family blocks this initial profile even after local acknowledgement:
//! cross-epoch delivery and deterministic reconstruction are not yet proven.
//! Batch/delivery/attempt row presence alone is not an obligation.

use crate::{
    AtomicityDomainId, DurableOperationContext, DurableReadError, MemoryDurableStateStore,
    PersistenceLayout, RuntimeError, StateKeyScan, StateKeyScanner,
    StructuredDurableDomainStateStore, validate_memory_durable_read_authority,
    validate_memory_durable_read_domain,
};
use std::num::NonZeroUsize;

/// Presence-only observation of every outbox family this guard
/// recognizes for one structured backend, at one read.
///
/// Every field is a presence check, never a full-table count. SQL backends
/// use `LIMIT 1`; the in-memory implementation may scan the domain to find
/// a nonempty batch or incomplete delivery. A backend that has no separate physical batch-header table
/// (see the SQLite/`runtime-sql-durable` engine, whose `durable_outbox_delivery`
/// row already carries the batch's message count) still reports
/// `batch_present` from that same row, since the logical batch family is
/// what matters, not the physical table layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StructuredOutboxInventory {
    batch_present: bool,
    message_present: bool,
    delivery_present: bool,
    pending_delivery_present: bool,
    attempt_present: bool,
}

impl StructuredOutboxInventory {
    /// Constructs an inventory from exact per-family presence observations.
    #[must_use]
    pub const fn new(
        batch_present: bool,
        message_present: bool,
        delivery_present: bool,
        pending_delivery_present: bool,
        attempt_present: bool,
    ) -> Self {
        Self {
            batch_present,
            message_present,
            delivery_present,
            pending_delivery_present,
            attempt_present,
        }
    }

    /// Returns whether any outbox batch (or batch-equivalent delivery) row
    /// was observed. Not, by itself, an obligation: see
    /// [`Self::blocks_exclusion`].
    #[must_use]
    pub const fn batch_present(&self) -> bool {
        self.batch_present
    }

    /// Returns whether any outbox message, nonempty-batch descriptor, or
    /// nonzero delivery cursor was
    /// observed. This initial profile refuses it even after local
    /// acknowledgement, including when message rows are unexpectedly absent.
    #[must_use]
    pub const fn message_present(&self) -> bool {
        self.message_present
    }

    /// Returns whether any delivery-cursor row was observed, completed or
    /// not. Not, by itself, an obligation: see [`Self::blocks_exclusion`].
    #[must_use]
    pub const fn delivery_present(&self) -> bool {
        self.delivery_present
    }

    /// Returns whether any delivery cursor is not yet fully acknowledged.
    #[must_use]
    pub const fn pending_delivery_present(&self) -> bool {
        self.pending_delivery_present
    }

    /// Returns whether any replica-local lease/attempt row was observed.
    /// Attempt rows persist after acknowledgement and after lease
    /// expiry; this is reported for completeness but never blocks
    /// exclusion by itself (see [`Self::blocks_exclusion`]). Per DR-0154,
    /// delivery leases, errors and attempt counts must never be imported
    /// even when exclusion is otherwise clear.
    #[must_use]
    pub const fn attempt_present(&self) -> bool {
        self.attempt_present
    }

    /// The DR-0154 exclusion rule for this one read: any nonempty batch or
    /// uncompleted delivery blocks handoff. An explicitly empty batch does
    /// not block merely because its header/delivery rows exist. Delivered
    /// messages remain blocked until cross-epoch behavior is specified.
    #[must_use]
    pub const fn blocks_exclusion(&self) -> bool {
        self.message_present || self.pending_delivery_present
    }
}

/// Read-only, presence-bounded probe across the outbox batch, message,
/// delivery and attempt families for one domain, at one read.
///
/// See the module documentation for the exact limits of what a clear
/// report proves. Implementations must enforce the same namespace/domain,
/// writer-fence and deadline authority as their other structured reads.
pub trait StructuredOutboxExclusionGuard: StructuredDurableDomainStateStore {
    /// Probes every recognized outbox family for one domain.
    fn inspect_outbox_exclusion(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<StructuredOutboxInventory, DurableReadError>;
}

/// Presence-only observation of the legacy generic `outbox/` state-key
/// prefix (see [`PersistenceLayout::outbox_prefix`]).
///
/// Unlike [`StructuredOutboxInventory`], this cannot normalize an explicit
/// empty batch to "no obligation": decoding the canonical `NodeOutboxBatch`/
/// `NodeOutboxDelivery` records stored under these keys requires
/// `node-core`'s codec, which is outside this crate's dependency graph and
/// this guard's scope. Any key observed under the prefix is therefore
/// conservatively treated as blocking, even though some of those keys may
/// in fact belong to an already-fully-delivered or explicitly empty batch.
/// This is a documented precision gap that can only over-refuse, never
/// silently admit a real obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyOutboxInventory {
    any_key_present: bool,
}

impl LegacyOutboxInventory {
    /// Returns whether any key under the legacy `outbox/` prefix was
    /// observed.
    #[must_use]
    pub const fn any_key_present(&self) -> bool {
        self.any_key_present
    }

    /// Always equal to [`Self::any_key_present`]; see the type-level
    /// documentation for why this cannot normalize empty batches the way
    /// [`StructuredOutboxInventory::blocks_exclusion`] does.
    #[must_use]
    pub const fn blocks_exclusion(&self) -> bool {
        self.any_key_present
    }
}

/// Probes the legacy `outbox/` state-key prefix for presence only, bounded
/// to a single one-key page: existence, not enumeration, is all this check
/// needs. Supported for any backend that implements [`StateKeyScanner`]
/// (currently the in-memory and local-SQLite plain state stores in this
/// workspace); PostgreSQL has no plain `StateStore`/[`StateKeyScanner`]
/// implementation here, so this legacy check does not apply to it.
pub fn inspect_legacy_outbox_prefix<S: StateKeyScanner>(
    store: &S,
    layout: &PersistenceLayout,
) -> Result<LegacyOutboxInventory, RuntimeError> {
    let scan = StateKeyScan::new(layout.outbox_prefix(), None, NonZeroUsize::new(1).unwrap())?;
    let page = store.scan_keys(&scan)?;
    Ok(LegacyOutboxInventory {
        any_key_present: !page.keys().is_empty(),
    })
}

impl StructuredOutboxExclusionGuard for MemoryDurableStateStore {
    fn inspect_outbox_exclusion(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<StructuredOutboxInventory, DurableReadError> {
        let data = self
            .inner
            .read()
            .map_err(|_| DurableReadError::Unavailable)?;
        validate_memory_durable_read_domain(&data, domain)?;
        validate_memory_durable_read_authority(&data, context)?;
        let domain_bytes: [u8; 32] = *domain.as_bytes();
        let lower = (domain_bytes, [0u8; 32]);
        let upper = (domain_bytes, [0xffu8; 32]);
        let batch_present: bool = data.outboxes.range(lower..=upper).next().is_some();
        let message_present: bool = data
            .outboxes
            .range(lower..=upper)
            .any(|(_, batch)| !batch.messages().is_empty())
            || data
                .deliveries
                .range(lower..=upper)
                .any(|(_, delivery)| delivery.next_index != 0);
        let delivery_present: bool = data.deliveries.range(lower..=upper).next().is_some();
        let pending_delivery_present: bool = data
            .deliveries
            .range(lower..=upper)
            .any(|(_, delivery)| !delivery.completed);
        let attempt_present: bool = data
            .delivery_attempts
            .values()
            .any(|attempt| attempt.domain == domain);
        Ok(StructuredOutboxInventory::new(
            batch_present,
            message_present,
            delivery_present,
            pending_delivery_present,
            attempt_present,
        ))
    }
}

#[cfg(test)]
mod tests;

/// Shared test-only contract exercise used by memory, SQLite and PostgreSQL.
#[cfg(any(test, feature = "durable-conformance"))]
pub mod conformance;
