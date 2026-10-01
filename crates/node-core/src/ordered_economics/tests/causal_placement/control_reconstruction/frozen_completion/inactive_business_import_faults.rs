//! Test-only loss of real SQLite replies. Never fabricates committed rows,
//! outcomes or a successful storage result.
use runtime::portable::*;
use runtime::*;
use runtime_sqlite::SqliteImportTarget;
use std::cell::Cell;

pub(super) struct ReplyLoss<'a> {
    pub(super) inner: &'a SqliteImportTarget,
    pub(super) hide_stages: Cell<u8>,
    pub(super) abort_batch: Cell<bool>,
    pub(super) fence_finish: Cell<bool>,
}
impl ReplyLoss<'_> {
    fn hide(&self, stage: u8, actual: DurableCommitOutcome) -> DurableCommitOutcome {
        if actual == DurableCommitOutcome::Committed && self.hide_stages.get() & stage != 0 {
            self.hide_stages.set(self.hide_stages.get() & !stage);
            DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
        } else {
            actual
        }
    }
}
impl DurableDomainStateStore for ReplyLoss<'_> {
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
impl StructuredDurableDomainStateStore for ReplyLoss<'_> {
    fn get_object_head(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        o: objects::ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(c, d, o)
    }
    fn get_object_version(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        o: objects::ObjectId,
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
impl DurablePortableRepository for ReplyLoss<'_> {
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
impl DurablePortableSnapshotRepository for ReplyLoss<'_> {
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
impl InactiveImportRepository for ReplyLoss<'_> {
    fn begin_import(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        b: &ImportBinding,
        a: protocol_types::Digest32,
    ) -> DurableCommitOutcome {
        self.hide(1, self.inner.begin_import(c, d, b, a))
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
        if self.abort_batch.replace(false) {
            return DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost);
        }
        self.hide(2, self.inner.commit_import_batch(c, d, b))
    }
    fn finish_import(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
        b: &ImportBinding,
        p: &ImportProgress,
        t: &PortableSnapshotToken,
    ) -> DurableCommitOutcome {
        if self.fence_finish.replace(false) {
            let next: WriterFenceGeneration =
                WriterFenceGeneration::new(c.writer_fence().get().checked_add(1).unwrap()).unwrap();
            self.inner
                .advance_writer_fence(c.writer_fence(), next)
                .unwrap();
        }
        self.hide(4, self.inner.finish_import(c, d, b, p, t))
    }
}
