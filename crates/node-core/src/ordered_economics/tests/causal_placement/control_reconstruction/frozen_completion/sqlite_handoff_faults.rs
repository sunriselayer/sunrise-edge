//! Test-owned import/readiness faults over the actual SQLite target.
//! Undispatched ambiguity never writes; reply loss only hides an actual commit.
//! Source execution, expected results and restart assertions belong to callers.
use protocol_types::Digest32;
use runtime::portable::{
    DurablePortableRepository, DurablePortableSnapshotRepository, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordPage,
    DurableRecordScan, PortableSnapshotError, PortableSnapshotToken,
};
use runtime::{
    AtomicStateTransaction, AtomicityDomainId, DurableCommitOutcome, DurableDomainStateStore,
    DurableInvocationTransaction, DurableObjectHead, DurableObjectVersion,
    DurableObjectVersionRecord, DurableOperationContext, DurableReadError, DurableRequestId,
    DurableRequestReceipt, ImportBatch, ImportBinding, ImportProgress, InactiveImportRepository,
    IndeterminateCommitReason, NamespaceLifecycle, ObjectId, ReadinessRecord,
    ReadinessRetentionRepository, ReadinessSlot, ReadinessSlotObservation,
    StructuredDurableDomainStateStore, VersionedStateValue, WriterFenceGeneration,
};
use runtime_sqlite::SqliteImportTarget;
use std::cell::{RefCell, RefMut};

/// Closed plans select only the fault combinations used by owning tests.
#[derive(Clone, Copy, Debug)]
pub(super) enum HandoffFaultPlan {
    LoseCommittedImportReplies,
    ImportBatchUndispatchedAmbiguity,
    AdvanceFenceBeforeImportFinish,
    LoseCommittedReadinessReply,
    ReadinessRetentionUndispatchedAmbiguity,
    AdvanceFenceAfterReadinessSlotRead,
}

/// Observational fault identities, not a mutable configuration interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PendingHandoffFault {
    ImportBeginCommittedReplyLoss,
    ImportBatchCommittedReplyLoss,
    ImportFinishCommittedReplyLoss,
    ImportBatchUndispatchedAmbiguity,
    AdvanceFenceBeforeImportFinish,
    ReadinessRetentionCommittedReplyLoss,
    ReadinessRetentionUndispatchedAmbiguity,
    AdvanceFenceAfterReadinessSlotRead,
}

pub(super) struct SqliteHandoffFaults<'a> {
    inner: &'a SqliteImportTarget,
    pending: RefCell<Vec<PendingHandoffFault>>,
}

impl<'a> SqliteHandoffFaults<'a> {
    pub(super) fn new(inner: &'a SqliteImportTarget, plan: HandoffFaultPlan) -> Self {
        let pending: Vec<PendingHandoffFault> = match plan {
            HandoffFaultPlan::LoseCommittedImportReplies => vec![
                PendingHandoffFault::ImportBeginCommittedReplyLoss,
                PendingHandoffFault::ImportBatchCommittedReplyLoss,
                PendingHandoffFault::ImportFinishCommittedReplyLoss,
            ],
            HandoffFaultPlan::ImportBatchUndispatchedAmbiguity => {
                vec![PendingHandoffFault::ImportBatchUndispatchedAmbiguity]
            }
            HandoffFaultPlan::AdvanceFenceBeforeImportFinish => {
                vec![PendingHandoffFault::AdvanceFenceBeforeImportFinish]
            }
            HandoffFaultPlan::LoseCommittedReadinessReply => {
                vec![PendingHandoffFault::ReadinessRetentionCommittedReplyLoss]
            }
            HandoffFaultPlan::ReadinessRetentionUndispatchedAmbiguity => {
                vec![PendingHandoffFault::ReadinessRetentionUndispatchedAmbiguity]
            }
            HandoffFaultPlan::AdvanceFenceAfterReadinessSlotRead => {
                vec![PendingHandoffFault::AdvanceFenceAfterReadinessSlotRead]
            }
        };
        Self {
            inner,
            pending: RefCell::new(pending),
        }
    }

    pub(super) fn pending_faults(&self) -> Vec<PendingHandoffFault> {
        self.pending.borrow().clone()
    }

    fn consume(&self, fault: PendingHandoffFault) -> bool {
        let mut pending: RefMut<'_, Vec<PendingHandoffFault>> = self.pending.borrow_mut();
        let position: Option<usize> = pending
            .iter()
            .position(|candidate: &PendingHandoffFault| *candidate == fault);
        match position {
            Some(index) => {
                pending.remove(index);
                true
            }
            None => false,
        }
    }

    fn lose_committed_reply(
        &self,
        fault: PendingHandoffFault,
        actual: DurableCommitOutcome,
    ) -> DurableCommitOutcome {
        if actual == DurableCommitOutcome::Committed && self.consume(fault) {
            DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
        } else {
            actual
        }
    }

    fn advance_writer_fence(&self, operation: &DurableOperationContext) {
        let next: WriterFenceGeneration =
            WriterFenceGeneration::new(operation.writer_fence().get().checked_add(1).unwrap())
                .unwrap();
        self.inner
            .advance_writer_fence(operation.writer_fence(), next)
            .unwrap();
    }
}

impl DurableDomainStateStore for SqliteHandoffFaults<'_> {
    fn get_namespace_lifecycle(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.inner.get_namespace_lifecycle(c, d)
    }
    fn get_versioned_durable(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        k: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.inner.get_versioned_durable(c, d, k)
    }
    fn commit_durable(
        &self,
        c: &DurableOperationContext,
        tx: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_durable(c, tx)
    }
}
impl StructuredDurableDomainStateStore for SqliteHandoffFaults<'_> {
    fn get_object_head(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        o: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(c, d, o)
    }
    fn get_object_version(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        o: ObjectId,
        v: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner.get_object_version(c, d, o, v)
    }
    fn get_request_receipt(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        r: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(c, d, r)
    }
    fn commit_invocation(
        &self,
        c: &DurableOperationContext,
        tx: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_invocation(c, tx)
    }
}
impl DurablePortableRepository for SqliteHandoffFaults<'_> {
    fn scan_portable_keys(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.inner.scan_portable_keys(c, d, scan)
    }
    fn read_portable_descriptor(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        k: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        self.inner.read_portable_descriptor(c, d, k)
    }
    fn read_portable_chunk(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        req: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        self.inner.read_portable_chunk(c, d, req)
    }
}
impl DurablePortableSnapshotRepository for SqliteHandoffFaults<'_> {
    fn begin_portable_snapshot(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
    ) -> Result<PortableSnapshotToken, PortableSnapshotError> {
        self.inner.begin_portable_snapshot(c, d)
    }
    fn scan_portable_keys_at(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        t: &PortableSnapshotToken,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, PortableSnapshotError> {
        self.inner.scan_portable_keys_at(c, d, t, scan)
    }
    fn read_portable_descriptor_at(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        t: &PortableSnapshotToken,
        k: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, PortableSnapshotError> {
        self.inner.read_portable_descriptor_at(c, d, t, k)
    }
    fn read_portable_chunk_at(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        t: &PortableSnapshotToken,
        req: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, PortableSnapshotError> {
        self.inner.read_portable_chunk_at(c, d, t, req)
    }
    fn check_portable_outbox_empty_at(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        t: &PortableSnapshotToken,
    ) -> Result<(), PortableSnapshotError> {
        self.inner.check_portable_outbox_empty_at(c, d, t)
    }
}
impl InactiveImportRepository for SqliteHandoffFaults<'_> {
    fn begin_import(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        b: &ImportBinding,
        a: Digest32,
    ) -> DurableCommitOutcome {
        let actual: DurableCommitOutcome = self.inner.begin_import(c, d, b, a);
        self.lose_committed_reply(PendingHandoffFault::ImportBeginCommittedReplyLoss, actual)
    }
    fn read_import_progress(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
    ) -> Result<Option<ImportProgress>, DurableReadError> {
        self.inner.read_import_progress(c, d)
    }
    fn commit_import_batch(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        b: &ImportBatch,
    ) -> DurableCommitOutcome {
        if self.consume(PendingHandoffFault::ImportBatchUndispatchedAmbiguity) {
            return DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost);
        }
        let actual: DurableCommitOutcome = self.inner.commit_import_batch(c, d, b);
        self.lose_committed_reply(PendingHandoffFault::ImportBatchCommittedReplyLoss, actual)
    }
    fn finish_import(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        b: &ImportBinding,
        p: &ImportProgress,
        t: &PortableSnapshotToken,
    ) -> DurableCommitOutcome {
        if self.consume(PendingHandoffFault::AdvanceFenceBeforeImportFinish) {
            self.advance_writer_fence(c);
        }
        let actual: DurableCommitOutcome = self.inner.finish_import(c, d, b, p, t);
        self.lose_committed_reply(PendingHandoffFault::ImportFinishCommittedReplyLoss, actual)
    }
}
impl ReadinessRetentionRepository for SqliteHandoffFaults<'_> {
    fn read_ready_slot_at(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        token: &PortableSnapshotToken,
        slot: &ReadinessSlot,
    ) -> Result<ReadinessSlotObservation, PortableSnapshotError> {
        let observed: ReadinessSlotObservation = self
            .inner
            .read_ready_slot_at(operation, domain, binding, progress, token, slot)?;
        if self.consume(PendingHandoffFault::AdvanceFenceAfterReadinessSlotRead) {
            self.advance_writer_fence(operation);
        }
        Ok(observed)
    }
    fn retain_ready_slot(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        token: &PortableSnapshotToken,
        observed: &ReadinessSlotObservation,
        record: &ReadinessRecord,
    ) -> DurableCommitOutcome {
        if self.consume(PendingHandoffFault::ReadinessRetentionUndispatchedAmbiguity) {
            return DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost);
        }
        let actual: DurableCommitOutcome = self.inner.retain_ready_slot(
            operation, domain, binding, progress, token, observed, record,
        );
        self.lose_committed_reply(
            PendingHandoffFault::ReadinessRetentionCommittedReplyLoss,
            actual,
        )
    }
}
