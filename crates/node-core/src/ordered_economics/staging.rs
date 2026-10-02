//! The private staging-store adapter DR-0153 calls for: it lets an ordered
//! economics leg run an *existing, unmodified* handler (`handle_fee_claim`,
//! `handle_bond_lifecycle`, `bond_lifecycle::slash::handle_bond_slash`, or
//! one `equivocation::submit_*` function) against the real durable store's
//! reads, while capturing the exact atomic transaction that handler would
//! have committed instead of publishing it. The caller then merges that
//! captured transaction with the order/consensus-state writes and commits
//! once, so a semantically refused candidate -- which never reaches this
//! adapter's `commit_invocation`/`commit_durable` -- can never move value or
//! advance a nonce: there is nothing staged to merge.
//!
//! This is a compatibility adapter for handlers which still commit through
//! runtime traits. A `Committed` return from either intercepted method is
//! only a capture acknowledgement to that handler, never evidence of durable
//! completion. Only [`StagingStore::finish`] returns a prepared contribution;
//! the real completion assembler must publish it to an actual store before
//! exposing output. This adapter cannot issue a confirmed completion.
//!
//! This adapter grants no additional storage authority: every read is
//! forwarded unchanged to the wrapped store under the same
//! [`DurableOperationContext`] and [`AtomicityDomainId`] the caller already
//! holds. It masks no value already durable; it only defers one write.
//!
//! It also **records every state read it forwards**. The typed preflight and
//! the staged handler both decide their answer from those rows, so the merged
//! final commit must assert each one at exactly the revision that was
//! observed. Without that, a deterministic refusal decided against a healthy
//! row could still be retained after the row moved: the refusal would be
//! recorded against state that no longer justifies it. Object heads, object
//! versions and provenance stay handler-owned and are deliberately not
//! recorded here.
use super::*;
use runtime::DurableDomainStateStore;
use runtime::{
    DurableObjectHead, DurableObjectVersion, DurableObjectVersionRecord, DurableReadError,
    DurableRequestId,
};
use std::cell::RefCell;

/// Wraps `store` for the lifetime of one staged leg attempt. At most one of
/// [`commit_durable`]/[`commit_invocation`] may ever be captured per
/// instance: a second attempt is a caller bug (an existing handler commits
/// at most once) and fails closed rather than silently discarding the first
/// capture.
pub(crate) struct StagingStore<'a, S: StructuredDurableDomainStateStore> {
    inner: &'a S,
    captured: RefCell<Option<PreparedHandlerWrite>>,
    repeated_capture: RefCell<bool>,
    finished: RefCell<bool>,
    observed_reads: RefCell<BTreeMap<Vec<u8>, StateRevision>>,
    inconsistent_read: RefCell<bool>,
}

/// A handler's proposed write, not a durable outcome. Keeping the two commit
/// paths in one slot makes their mutual exclusion explicit.
pub(super) enum PreparedHandlerWrite {
    State(AtomicStateTransaction),
    Invocation(Box<DurableInvocationTransaction>),
}

/// Complete observations and at most one proposed handler write.
pub(super) struct HandlerPreparation {
    pub(super) reads: BTreeMap<Vec<u8>, StateRevision>,
    pub(super) write: Option<PreparedHandlerWrite>,
}

impl<'a, S: StructuredDurableDomainStateStore> StagingStore<'a, S> {
    pub(crate) fn new(inner: &'a S) -> Self {
        Self {
            inner,
            captured: RefCell::new(None),
            repeated_capture: RefCell::new(false),
            finished: RefCell::new(false),
            observed_reads: RefCell::new(BTreeMap::new()),
            inconsistent_read: RefCell::new(false),
        }
    }

    /// Ends preparation. Conflicting observations or a second commit attempt
    /// are preparation invariants, not a fabricated storage deadline. Even a
    /// handler which ignores the second attempt cannot publish the first.
    pub(super) fn finish(&self) -> Result<HandlerPreparation, OrderedEconomicsError> {
        if *self.finished.borrow() {
            return Err(OrderedEconomicsError::Prerequisite(
                "ordered handler preparation was already consumed",
            ));
        }
        if *self.repeated_capture.borrow() {
            return Err(OrderedEconomicsError::Prerequisite(
                "ordered handler attempted more than one prepared completion",
            ));
        }
        if self.had_inconsistent_read() {
            return Err(NodeCoreError::StateConflict.into());
        }
        *self.finished.borrow_mut() = true;
        Ok(HandlerPreparation {
            reads: self.observed_reads(),
            write: self.captured.borrow_mut().take(),
        })
    }

    /// Every state row this staged attempt read, at the revision it observed.
    /// The caller merges these into the one final transaction as CAS read
    /// assertions.
    pub(crate) fn observed_reads(&self) -> BTreeMap<Vec<u8>, StateRevision> {
        self.observed_reads.borrow().clone()
    }

    /// Whether the same key was read twice at two different revisions during
    /// this one staged attempt.
    ///
    /// A durable invocation observes one stable snapshot, so this can only mean
    /// concurrent interference. It is never a semantic outcome: the caller must
    /// stop rather than retain a decision derived from two disagreeing views of
    /// one row.
    pub(crate) fn had_inconsistent_read(&self) -> bool {
        *self.inconsistent_read.borrow()
    }
}

impl<'a, S: StructuredDurableDomainStateStore> DurableDomainStateStore for StagingStore<'a, S> {
    fn get_namespace_lifecycle(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, runtime::DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        let observed: VersionedStateValue =
            self.inner.get_versioned_durable(context, domain, key)?;
        if let Some(previous) = self
            .observed_reads
            .borrow_mut()
            .insert(key.to_vec(), observed.revision())
            && previous != observed.revision()
        {
            *self.inconsistent_read.borrow_mut() = true;
        }
        Ok(observed)
    }

    fn commit_durable(
        &self,
        _context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        let mut slot = self.captured.borrow_mut();
        if slot.is_some() || *self.finished.borrow() {
            *self.repeated_capture.borrow_mut() = true;
            // Definite private adapter rejection: no commit was dispatched.
            // The evaluator must check `finish` even if the handler propagates
            // this sentinel, so it escapes only as a preparation invariant.
            return DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState);
        }
        *slot = Some(PreparedHandlerWrite::State(transaction));
        DurableCommitOutcome::Committed
    }
}

impl<'a, S: StructuredDurableDomainStateStore> StructuredDurableDomainStateStore
    for StagingStore<'a, S>
{
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }

    fn commit_invocation(
        &self,
        _context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        let mut slot = self.captured.borrow_mut();
        if slot.is_some() || *self.finished.borrow() {
            *self.repeated_capture.borrow_mut() = true;
            // Definite private adapter rejection, never backend ambiguity.
            return DurableCommitOutcome::Rejected(DurableCommitRejection::InvalidPersistedState);
        }
        *slot = Some(PreparedHandlerWrite::Invocation(Box::new(transaction)));
        DurableCommitOutcome::Committed
    }
}

#[cfg(test)]
mod tests;
