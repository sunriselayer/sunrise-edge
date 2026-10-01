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
    captured_durable: RefCell<Option<AtomicStateTransaction>>,
    captured_invocation: RefCell<Option<DurableInvocationTransaction>>,
    observed_reads: RefCell<BTreeMap<Vec<u8>, StateRevision>>,
    inconsistent_read: RefCell<bool>,
}

impl<'a, S: StructuredDurableDomainStateStore> StagingStore<'a, S> {
    pub(crate) fn new(inner: &'a S) -> Self {
        Self {
            inner,
            captured_durable: RefCell::new(None),
            captured_invocation: RefCell::new(None),
            observed_reads: RefCell::new(BTreeMap::new()),
            inconsistent_read: RefCell::new(false),
        }
    }

    /// Takes the captured plain state transaction, if any handler committed
    /// through [`DurableDomainStateStore::commit_durable`] rather than
    /// [`StructuredDurableDomainStateStore::commit_invocation`].
    pub(crate) fn take_durable(&self) -> Option<AtomicStateTransaction> {
        self.captured_durable.borrow_mut().take()
    }

    /// Takes the captured structured invocation transaction, if any handler
    /// committed.
    pub(crate) fn take_invocation(&self) -> Option<DurableInvocationTransaction> {
        self.captured_invocation.borrow_mut().take()
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
        let mut slot = self.captured_durable.borrow_mut();
        if slot.is_some() || self.captured_invocation.borrow().is_some() {
            return DurableCommitOutcome::Indeterminate(
                IndeterminateCommitReason::DeadlineExceeded,
            );
        }
        *slot = Some(transaction);
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
        let mut slot = self.captured_invocation.borrow_mut();
        if slot.is_some() || self.captured_durable.borrow().is_some() {
            return DurableCommitOutcome::Indeterminate(
                IndeterminateCommitReason::DeadlineExceeded,
            );
        }
        *slot = Some(transaction);
        DurableCommitOutcome::Committed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime::{
        MemoryDurableStateStore, StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
    };

    fn store_context() -> (
        MemoryDurableStateStore,
        DurableOperationContext,
        AtomicityDomainId,
    ) {
        let generation: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        let store: MemoryDurableStateStore = MemoryDurableStateStore::new(generation);
        let context: DurableOperationContext = DurableOperationContext::new(
            generation,
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([1; 16]).unwrap(),
        );
        let domain: AtomicityDomainId = AtomicityDomainId::new([2; 32]).unwrap();
        (store, context, domain)
    }

    #[test]
    fn staging_store_forwards_reads_and_never_publishes_a_captured_commit() {
        let (store, context, domain) = store_context();
        let key: Vec<u8> = b"ordered-economics-staging-probe".to_vec();
        let real_before: VersionedStateValue =
            store.get_versioned_durable(&context, domain, &key).unwrap();
        let staging: StagingStore<'_, MemoryDurableStateStore> = StagingStore::new(&store);
        let observed: VersionedStateValue = staging
            .get_versioned_durable(&context, domain, &key)
            .unwrap();
        assert_eq!(observed.revision(), real_before.revision());

        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key.clone(), StateMutation::Put(vec![9, 9, 9])).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            staging.commit_durable(&context, transaction),
            DurableCommitOutcome::Committed
        );

        // The real store never saw the write: the staged transaction was
        // captured, not published.
        let real_after: VersionedStateValue =
            store.get_versioned_durable(&context, domain, &key).unwrap();
        assert_eq!(real_after.revision(), real_before.revision());
        assert_eq!(real_after.value(), None);

        let captured: AtomicStateTransaction =
            staging.take_durable().expect("captured transaction");
        assert_eq!(
            store.commit_durable(&context, captured),
            DurableCommitOutcome::Committed
        );
        let real_committed: VersionedStateValue =
            store.get_versioned_durable(&context, domain, &key).unwrap();
        assert_eq!(real_committed.value(), Some(vec![9, 9, 9].as_slice()));
    }
}
