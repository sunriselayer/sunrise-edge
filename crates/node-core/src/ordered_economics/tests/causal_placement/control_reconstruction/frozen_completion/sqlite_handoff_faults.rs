//! Test-owned import, readiness, activation and Seal faults on real SQLite.
//! Undispatched ambiguity never writes; reply loss only hides an actual commit.
//! Source execution, expected results and restart assertions belong to callers.
use crate::business_reconstruction::SourceBusinessSnapshot;
use protocol_types::{Digest32, ValidatorId};
use runtime::portable::{
    DurablePortableRepository, DurablePortableSnapshotRepository, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordPage,
    DurableRecordScan, PortableSnapshotError, PortableSnapshotToken,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicityDomainId,
    DurableCommitOutcome, DurableDomainStateStore, DurableInvocationTransaction, DurableObjectHead,
    DurableObjectVersion, DurableObjectVersionRecord, DurableOperationContext, DurableReadError,
    DurableRequestId, DurableRequestReceipt, ImportBatch, ImportBinding, ImportProgress,
    InactiveImportRepository, IndeterminateCommitReason, NamespaceLifecycle, ObjectId,
    OutgoingSealRepository, ReadinessRecord, ReadinessRetentionRepository, ReadinessSlot,
    ReadinessSlotObservation, SealBarrier, StateMutation, StateMutationEntry, StateReadAssertion,
    StructuredDurableDomainStateStore, SuccessorServingObservation, SuccessorServingRepository,
    VersionedStateValue, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteImportTarget};
use std::cell::{Cell, RefCell, RefMut};

/// Closed plans select only the fault combinations used by owning tests.
#[derive(Clone, Copy, Debug)]
pub(super) enum HandoffFaultPlan {
    LoseCommittedImportReplies,
    ImportBatchUndispatchedAmbiguity,
    AdvanceFenceBeforeImportFinish,
    LoseCommittedReadinessReply,
    ReadinessRetentionUndispatchedAmbiguity,
    AdvanceFenceAfterReadinessSlotRead,
    SuccessorRetentionReplyLoss,
    SuccessorCompletionReplyLoss,
    SuccessorCompletionLiveRace,
    LoseCommittedActivationReply,
    ActivationUndispatchedAmbiguity,
    CompetingActivationBeforeCommit,
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
    SuccessorRetentionCommittedReplyLoss,
    SuccessorCompletionCommittedReplyLoss,
    SuccessorCompletionLiveRace,
    ActivationCommittedReplyLoss,
    ActivationUndispatchedAmbiguity,
    CompetingActivationBeforeCommit,
}

type ActivationCompetitor<'a> =
    Box<dyn FnOnce(&DurableOperationContext) -> SourceBusinessSnapshot + 'a>;

pub(super) struct SqliteHandoffFaults<'a> {
    inner: &'a SqliteImportTarget,
    pending: RefCell<Vec<PendingHandoffFault>>,
    race_blobs: Option<&'a SqliteBlobStore>,
    race_key: Option<Vec<u8>>,
    activation_competitor: RefCell<Option<ActivationCompetitor<'a>>>,
    pub(super) outgoing_getter_calls: Cell<usize>,
    pub(super) ordinary_durable_calls: Cell<usize>,
    pub(super) ordinary_invocation_calls: Cell<usize>,
    pub(super) successor_retention_calls: Cell<usize>,
    pub(super) successor_completion_calls: Cell<usize>,
    pub(super) successor_activation_calls: Cell<usize>,
    pub(super) live_race_calls: Cell<usize>,
    pub(super) competing_activation_calls: Cell<usize>,
    pub(super) after_race: RefCell<Option<SourceBusinessSnapshot>>,
    pub(super) after_competing_activation: RefCell<Option<SourceBusinessSnapshot>>,
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
            HandoffFaultPlan::SuccessorRetentionReplyLoss => {
                vec![PendingHandoffFault::SuccessorRetentionCommittedReplyLoss]
            }
            HandoffFaultPlan::SuccessorCompletionReplyLoss => {
                vec![PendingHandoffFault::SuccessorCompletionCommittedReplyLoss]
            }
            HandoffFaultPlan::SuccessorCompletionLiveRace => {
                vec![PendingHandoffFault::SuccessorCompletionLiveRace]
            }
            HandoffFaultPlan::LoseCommittedActivationReply => {
                vec![PendingHandoffFault::ActivationCommittedReplyLoss]
            }
            HandoffFaultPlan::ActivationUndispatchedAmbiguity => {
                vec![PendingHandoffFault::ActivationUndispatchedAmbiguity]
            }
            HandoffFaultPlan::CompetingActivationBeforeCommit => {
                vec![PendingHandoffFault::CompetingActivationBeforeCommit]
            }
        };
        Self {
            inner,
            pending: RefCell::new(pending),
            race_blobs: None,
            race_key: None,
            activation_competitor: RefCell::new(None),
            outgoing_getter_calls: Cell::new(0),
            ordinary_durable_calls: Cell::new(0),
            ordinary_invocation_calls: Cell::new(0),
            successor_retention_calls: Cell::new(0),
            successor_completion_calls: Cell::new(0),
            successor_activation_calls: Cell::new(0),
            live_race_calls: Cell::new(0),
            competing_activation_calls: Cell::new(0),
            after_race: RefCell::new(None),
            after_competing_activation: RefCell::new(None),
        }
    }

    pub(super) fn completion_live_race(
        inner: &'a SqliteImportTarget,
        blobs: &'a SqliteBlobStore,
        applied_height_key: Vec<u8>,
    ) -> Self {
        let mut faults: Self = Self::new(inner, HandoffFaultPlan::SuccessorCompletionLiveRace);
        faults.race_blobs = Some(blobs);
        faults.race_key = Some(applied_height_key);
        faults
    }

    /// A single genuine core activation runs on a second handle before the
    /// challenged activation reaches the owning SQLite compare-and-swap.
    pub(super) fn competing_activation<F>(inner: &'a SqliteImportTarget, competitor: F) -> Self
    where
        F: FnOnce(&DurableOperationContext) -> SourceBusinessSnapshot + 'a,
    {
        let faults: Self = Self::new(inner, HandoffFaultPlan::CompetingActivationBeforeCommit);
        *faults.activation_competitor.borrow_mut() = Some(Box::new(competitor));
        faults
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

    fn apply_successor_live_race(
        &self,
        operation: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        domain: AtomicityDomainId,
    ) {
        assert_eq!(self.live_race_calls.get(), 0);
        let key: Vec<u8> = self.race_key.as_ref().unwrap().clone();
        let value: VersionedStateValue = self
            .inner
            .get_versioned_durable(operation, domain, &key)
            .unwrap();
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), value.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key, StateMutation::Put(value.value().unwrap().to_vec()))
                    .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            self.inner
                .commit_successor_durable(operation, observation, transaction),
            DurableCommitOutcome::Committed,
            "the competing live invocation uses the actual protected successor port"
        );
        self.live_race_calls.set(1);
        *self.after_race.borrow_mut() = Some(crate::test_support::capture::captured_source(
            self.inner,
            self.race_blobs.unwrap(),
            operation,
            domain,
        ));
    }
}

impl DurableDomainStateStore for SqliteHandoffFaults<'_> {
    fn get_outgoing_barrier(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, DurableReadError> {
        self.inner.get_outgoing_barrier(c, d)
    }

    fn get_namespace_lifecycle(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.inner.get_namespace_lifecycle(c, d)
    }
    fn get_successor_serving(
        &self,
        c: &DurableOperationContext,
        d: AtomicityDomainId,
    ) -> Result<runtime::SuccessorServingSlot, DurableReadError> {
        self.inner.get_successor_serving(c, d)
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
        self.ordinary_durable_calls
            .set(self.ordinary_durable_calls.get().checked_add(1).unwrap());
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
        self.ordinary_invocation_calls
            .set(self.ordinary_invocation_calls.get().checked_add(1).unwrap());
        self.inner.commit_invocation(c, tx)
    }
    fn outgoing_seal_repository(&self) -> Option<&dyn OutgoingSealRepository> {
        self.outgoing_getter_calls
            .set(self.outgoing_getter_calls.get().checked_add(1).unwrap());
        None
    }
    fn successor_serving_repository(&self) -> Option<&dyn SuccessorServingRepository> {
        Some(self)
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

impl SuccessorServingRepository for SqliteHandoffFaults<'_> {
    fn read_namespace_validator(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<ValidatorId, DurableReadError> {
        self.inner.read_namespace_validator(operation, domain)
    }

    fn commit_successor_activation(
        &self,
        operation: &DurableOperationContext,
        domain: AtomicityDomainId,
        binding: &ImportBinding,
        progress: &ImportProgress,
        fresh_token: &PortableSnapshotToken,
        record: &[u8],
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.successor_activation_calls.set(
            self.successor_activation_calls
                .get()
                .checked_add(1)
                .unwrap(),
        );
        if self.consume(PendingHandoffFault::ActivationUndispatchedAmbiguity) {
            return DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost);
        }
        if self.consume(PendingHandoffFault::CompetingActivationBeforeCommit) {
            let competitor: ActivationCompetitor<'_> =
                self.activation_competitor.borrow_mut().take().unwrap();
            let after: SourceBusinessSnapshot = competitor(operation);
            self.competing_activation_calls.set(1);
            *self.after_competing_activation.borrow_mut() = Some(after);
        }
        let actual: DurableCommitOutcome = self.inner.commit_successor_activation(
            operation,
            domain,
            binding,
            progress,
            fresh_token,
            record,
            transaction,
        );
        self.lose_committed_reply(PendingHandoffFault::ActivationCommittedReplyLoss, actual)
    }

    fn commit_successor_durable(
        &self,
        operation: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.inner
            .commit_successor_durable(operation, observation, transaction)
    }

    fn commit_successor_invocation(
        &self,
        operation: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner
            .commit_successor_invocation(operation, observation, transaction)
    }

    fn commit_successor_seal_retention(
        &self,
        operation: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        token: &PortableSnapshotToken,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.successor_retention_calls
            .set(self.successor_retention_calls.get().checked_add(1).unwrap());
        let actual: DurableCommitOutcome =
            self.inner
                .commit_successor_seal_retention(operation, observation, token, transaction);
        self.lose_committed_reply(
            PendingHandoffFault::SuccessorRetentionCommittedReplyLoss,
            actual,
        )
    }

    fn commit_successor_seal_completion(
        &self,
        operation: &DurableOperationContext,
        observation: &SuccessorServingObservation,
        token: &PortableSnapshotToken,
        transaction: DurableInvocationTransaction,
        sealed: SealBarrier,
    ) -> DurableCommitOutcome {
        self.successor_completion_calls.set(
            self.successor_completion_calls
                .get()
                .checked_add(1)
                .unwrap(),
        );
        if self.consume(PendingHandoffFault::SuccessorCompletionLiveRace) {
            self.apply_successor_live_race(operation, observation, transaction.domain());
        }
        let actual: DurableCommitOutcome = self.inner.commit_successor_seal_completion(
            operation,
            observation,
            token,
            transaction,
            sealed,
        );
        self.lose_committed_reply(
            PendingHandoffFault::SuccessorCompletionCommittedReplyLoss,
            actual,
        )
    }
}
