//! Completion-only warrant read faults over the actual SQLite Seal store.
//! The underlying rows, snapshot owner and Seal commit capability stay real.

use execution::{LocalWasmExecutionEngine, local_execution::LocalExecutionPolicy};
use node_core::NodeCoreError;
use node_core::business_reconstruction::SourceBusinessSnapshot;
use node_core::fast_path::records::{
    FastPathBondRecord, FastPathBondState, decode_fastpath_bond_record, encode_fastpath_bond_record,
};
use node_core::local_instance_state::fastpath_bond_record_key;
use node_core::ordered_economics::{
    AdmissionClosureRecord, DrainSetRecord, OrderedCandidate, OrderedEconomicsEnvironment,
    OrderedEconomicsError, OrderedEconomicsPolicy, OrderedOperationKind, OrderedStatus,
    decode_admission_closure_record, decode_drain_set_record, decode_ordered_candidate,
    query_status,
};
use objects::ObjectId;
use protocol_types::AtomicityDomainId;
use runtime::portable::DurableRecordKey;
use runtime::portable::{
    DurablePortableRepository, DurablePortableSnapshotRepository, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordPage, DurableRecordScan,
    PortableSnapshotError, PortableSnapshotToken,
};
use runtime::{
    AtomicStateTransaction, DurableCommitOutcome, DurableDomainStateStore,
    DurableInvocationTransaction, DurableObjectHead, DurableObjectVersion,
    DurableObjectVersionRecord, DurableOperationContext, DurableReadError, DurableRequestId,
    DurableRequestReceipt, IndeterminateCommitReason, NamespaceLifecycle, OutgoingBarrier,
    OutgoingSealRepository, SealBarrier, StateRevision, StructuredDurableDomainStateStore,
    VersionedStateValue,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore};
use std::{
    collections::BTreeSet,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use sunrise_edge_operator::business_snapshot::capture_source_business_snapshot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SealWarrantFault {
    Healthy,
    MissingFreeze,
    MissingDrain,
    IneligibleSuccessor,
}

/// A closed test plan, enabled only at the real persisted prior Seal tip.
pub(super) struct SealWarrantFaultStore {
    inner: Arc<SqliteDurableStore>,
    policy: OrderedEconomicsPolicy,
    local_policy: LocalExecutionPolicy,
    engine: Arc<LocalWasmExecutionEngine>,
    blobs: Arc<SqliteBlobStore>,
    prior_height: u64,
    fault: SealWarrantFault,
    fault_key: Option<Vec<u8>>,
    active: AtomicBool,
    fault_hits: AtomicUsize,
    before_fault: Mutex<Option<SourceBusinessSnapshot>>,
    ordinary_commit_attempts_after_fault: AtomicUsize,
}

impl SealWarrantFaultStore {
    /// `source` is the parent's truthful capture of this exact inner store.
    /// Fault keys are resolved once from public owners, never guessed prefixes.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        inner: Arc<SqliteDurableStore>,
        policy: OrderedEconomicsPolicy,
        local_policy: LocalExecutionPolicy,
        engine: Arc<LocalWasmExecutionEngine>,
        blobs: Arc<SqliteBlobStore>,
        prior_height: u64,
        fault: SealWarrantFault,
        source: &SourceBusinessSnapshot,
    ) -> Result<Self, DurableReadError> {
        if prior_height == 0
            || source.token.domain() != policy.domain()
            || local_policy.context() != policy.context()
        {
            return Err(DurableReadError::InvalidPersistedState);
        }
        source
            .validate()
            .map_err(|_| DurableReadError::InvalidPersistedState)?;
        let fault_key: Option<Vec<u8>> = resolve_fault_key(&policy, fault, source)?;
        Ok(Self {
            inner,
            policy,
            local_policy,
            engine,
            blobs,
            prior_height,
            fault,
            fault_key,
            active: AtomicBool::new(fault != SealWarrantFault::Healthy),
            fault_hits: AtomicUsize::new(0),
            before_fault: Mutex::new(None),
            ordinary_commit_attempts_after_fault: AtomicUsize::new(0),
        })
    }

    pub(super) fn inner(&self) -> &Arc<SqliteDurableStore> {
        &self.inner
    }

    pub(super) fn disable_fault(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    pub(super) fn fault_hits(&self) -> usize {
        self.fault_hits.load(Ordering::SeqCst)
    }

    pub(super) fn before_fault(&self) -> Option<SourceBusinessSnapshot> {
        self.before_fault
            .lock()
            .expect("completion fault capture lock")
            .clone()
    }

    pub(super) fn ordinary_commit_attempts_after_fault(&self) -> usize {
        self.ordinary_commit_attempts_after_fault
            .load(Ordering::SeqCst)
    }

    fn at_completion_tip(
        &self,
        context: &DurableOperationContext,
    ) -> Result<bool, DurableReadError> {
        let environment: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
            policy: &self.policy,
            history: &[],
            leg_policy: &self.local_policy,
            engine: self.engine.as_ref(),
            blobs: self.blobs.as_ref(),
            seal: None,
        };
        // The real inner reader avoids recursion through the fault wrapper.
        let status: OrderedStatus = query_status(self.inner.as_ref(), context, &environment)
            .map_err(|error: OrderedEconomicsError| match error {
                OrderedEconomicsError::Node(NodeCoreError::DurableRead(error)) => error,
                _ => DurableReadError::InvalidPersistedState,
            })?;
        Ok(status.committed_height == self.prior_height)
    }

    fn capture_before_fault(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<(), DurableReadError> {
        let mut before: MutexGuard<'_, Option<SourceBusinessSnapshot>> =
            self.before_fault
                .lock()
                .map_err(|_| DurableReadError::Unavailable)?;
        if before.is_none() {
            let page_size: NonZeroUsize =
                NonZeroUsize::new(128).ok_or(DurableReadError::InvalidPersistedState)?;
            let snapshot: SourceBusinessSnapshot = capture_source_business_snapshot(
                self.inner.as_ref(),
                self.blobs.as_ref(),
                context,
                domain,
                page_size,
            )
            .map_err(|_| DurableReadError::InvalidPersistedState)?;
            *before = Some(snapshot);
        }
        Ok(())
    }

    fn count_ordinary_commit_attempt(&self) {
        if !self.active.load(Ordering::SeqCst) {
            return;
        }
        // Release the capture mutex before forwarding the real commit.
        let captured: bool = {
            let before: MutexGuard<'_, Option<SourceBusinessSnapshot>> = self
                .before_fault
                .lock()
                .expect("completion fault capture lock");
            before.is_some()
        };
        if captured && self.active.load(Ordering::SeqCst) {
            self.ordinary_commit_attempts_after_fault
                .fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn resolve_fault_key(
    policy: &OrderedEconomicsPolicy,
    fault: SealWarrantFault,
    source: &SourceBusinessSnapshot,
) -> Result<Option<Vec<u8>>, DurableReadError> {
    if fault == SealWarrantFault::Healthy {
        return Ok(None);
    }
    let first_member: &validator_set::ValidatorInfo = policy
        .engine()
        .validator_set()
        .validators()
        .first()
        .ok_or(DurableReadError::InvalidPersistedState)?;
    let bond_key: Vec<u8> = fastpath_bond_record_key(policy.context().chain_id(), &first_member.id)
        .map_err(|_| DurableReadError::InvalidPersistedState)?;
    // AdmissionClosureRecord has no chain field. Link its request to the
    // captured original Freeze candidate under the exact pinned context.
    let mut freeze_requests: BTreeSet<[u8; 32]> = BTreeSet::new();
    if fault == SealWarrantFault::MissingFreeze {
        for record in &source.records {
            if !matches!(record.descriptor.key(), DurableRecordKey::State(_)) {
                continue;
            }
            let Some(bytes) = record.value.as_deref() else {
                continue;
            };
            let decoded: Result<OrderedCandidate, NodeCoreError> = decode_ordered_candidate(bytes);
            let Ok(candidate) = decoded else {
                continue;
            };
            if candidate.kind == OrderedOperationKind::Freeze
                && candidate.context == *policy.context()
                && policy.authenticate_candidate(&candidate).is_ok()
            {
                freeze_requests.insert(candidate.request_id);
            }
        }
    }
    let mut selected_key: Option<Vec<u8>> = None;
    for record in &source.records {
        let DurableRecordKey::State(key) = record.descriptor.key() else {
            continue;
        };
        let Some(bytes) = record.value.as_deref() else {
            continue;
        };
        let matches: bool = match fault {
            SealWarrantFault::Healthy => false,
            SealWarrantFault::MissingFreeze => decode_admission_closure_record(bytes).is_ok_and(
                |closure: AdmissionClosureRecord| {
                    closure.closed_epoch == policy.context().epoch()
                        && freeze_requests.contains(&closure.request_id)
                },
            ),
            SealWarrantFault::MissingDrain => {
                decode_drain_set_record(bytes).is_ok_and(|drain: DrainSetRecord| {
                    let identity: &consensus::DrainUnionIdentity = &drain.drain_union_identity;
                    drain.closed_epoch == policy.context().epoch()
                        && identity.chain_id == *policy.context().chain_id()
                        && identity.protocol_version == policy.context().protocol_version()
                        && identity.epoch == policy.context().epoch()
                        && identity.domain == policy.domain()
                })
            }
            SealWarrantFault::IneligibleSuccessor => {
                key == &bond_key
                    && decode_fastpath_bond_record(bytes).is_ok_and(|bond: FastPathBondRecord| {
                        bond.context.chain_id() == policy.context().chain_id()
                            && bond.validator_id == first_member.id
                            && bond.authorization_scheme == first_member.signature_scheme
                            && bond.authorization_key.as_slice()
                                == first_member.public_key.as_slice()
                            && bond.state == FastPathBondState::Active
                    })
            }
        };
        if matches && selected_key.replace(key.clone()).is_some() {
            return Err(DurableReadError::InvalidPersistedState);
        }
    }
    selected_key
        .map(Some)
        .ok_or(DurableReadError::InvalidPersistedState)
}

impl DurableDomainStateStore for SealWarrantFaultStore {
    fn get_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }

    fn get_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<OutgoingBarrier, DurableReadError> {
        self.inner.get_outgoing_barrier(context, domain)
    }

    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        let actual: VersionedStateValue = self.inner.get_versioned_durable(context, domain, key)?;
        if !self.active.load(Ordering::SeqCst)
            || domain != self.policy.domain()
            || self.fault_key.as_deref() != Some(key)
            || !self.at_completion_tip(context)?
        {
            return Ok(actual);
        }
        let actual_bytes: &[u8] = actual
            .value()
            .ok_or(DurableReadError::InvalidPersistedState)?;
        let faulted: VersionedStateValue = match self.fault {
            SealWarrantFault::Healthy => return Ok(actual),
            SealWarrantFault::MissingFreeze | SealWarrantFault::MissingDrain => {
                VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None)
            }
            SealWarrantFault::IneligibleSuccessor => {
                let mut bond: FastPathBondRecord = decode_fastpath_bond_record(actual_bytes)
                    .map_err(|_| DurableReadError::InvalidPersistedState)?;
                // Exited is a valid historical bond state. Retain all actual
                // identity, custody, authorization, amount and generation fields.
                bond.state = FastPathBondState::Exited;
                let bytes: Vec<u8> = encode_fastpath_bond_record(&bond)
                    .map_err(|_| DurableReadError::InvalidPersistedState)?;
                VersionedStateValue::from_persisted_parts(actual.revision(), Some(bytes))
            }
        }
        .map_err(DurableReadError::InvalidRequest)?;
        self.capture_before_fault(context, domain)?;
        self.fault_hits.fetch_add(1, Ordering::SeqCst);
        Ok(faulted)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.count_ordinary_commit_attempt();
        self.inner.commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for SealCompletionReplyLossStore {
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
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_invocation(context, transaction)
    }

    fn outgoing_seal_repository(&self) -> Option<&dyn OutgoingSealRepository> {
        Some(self)
    }
}

impl DurablePortableRepository for SealCompletionReplyLossStore {
    fn scan_portable_keys(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, DurableReadError> {
        self.inner.scan_portable_keys(context, domain, scan)
    }

    fn read_portable_descriptor(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, DurableReadError> {
        self.inner.read_portable_descriptor(context, domain, key)
    }

    fn read_portable_chunk(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, DurableReadError> {
        self.inner.read_portable_chunk(context, domain, request)
    }
}

impl DurablePortableSnapshotRepository for SealCompletionReplyLossStore {
    fn begin_portable_snapshot(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<PortableSnapshotToken, PortableSnapshotError> {
        self.inner.begin_portable_snapshot(context, domain)
    }

    fn scan_portable_keys_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        scan: &DurableRecordScan,
    ) -> Result<DurableRecordPage, PortableSnapshotError> {
        self.inner
            .scan_portable_keys_at(context, domain, token, scan)
    }

    fn read_portable_descriptor_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        key: &DurableRecordKey,
    ) -> Result<Option<DurableRecordDescriptor>, PortableSnapshotError> {
        self.inner
            .read_portable_descriptor_at(context, domain, token, key)
    }

    fn read_portable_chunk_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
        request: &DurableRecordChunkRequest,
    ) -> Result<DurableRecordChunkOutcome, PortableSnapshotError> {
        self.inner
            .read_portable_chunk_at(context, domain, token, request)
    }

    fn check_portable_outbox_empty_at(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        token: &PortableSnapshotToken,
    ) -> Result<(), PortableSnapshotError> {
        self.inner
            .check_portable_outbox_empty_at(context, domain, token)
    }
}

impl OutgoingSealRepository for SealCompletionReplyLossStore {
    fn commit_seal_retention(
        &self,
        context: &DurableOperationContext,
        token: &PortableSnapshotToken,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.delegate()
            .commit_seal_retention(context, token, transaction)
    }

    fn commit_seal_completion(
        &self,
        context: &DurableOperationContext,
        token: &PortableSnapshotToken,
        transaction: DurableInvocationTransaction,
        sealed: SealBarrier,
    ) -> DurableCommitOutcome {
        match self.current_mode() {
            SealCompletionReplyLossMode::Healthy => {
                self.delegate()
                    .commit_seal_completion(context, token, transaction, sealed)
            }
            SealCompletionReplyLossMode::LandedIndeterminate => {
                let landed: DurableCommitOutcome =
                    self.delegate()
                        .commit_seal_completion(context, token, transaction, sealed);
                assert_eq!(landed, DurableCommitOutcome::Committed);
                self.hits.fetch_add(1, Ordering::SeqCst);
                DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
            }
            SealCompletionReplyLossMode::UnlandedIndeterminate => {
                self.hits.fetch_add(1, Ordering::SeqCst);
                DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
            }
        }
    }
}

impl StructuredDurableDomainStateStore for SealWarrantFaultStore {
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
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.count_ordinary_commit_attempt();
        self.inner.commit_invocation(context, transaction)
    }

    fn outgoing_seal_repository(&self) -> Option<&dyn OutgoingSealRepository> {
        // The capability belongs to the same actual SQLite store used by
        // every read and write above; no test writer or portable facade exists.
        self.inner.outgoing_seal_repository()
    }
}

/// Genuine landed-versus-unlanded reply-loss fault at the exact same-store
/// `OutgoingSealRepository::commit_seal_completion` port. Every other port
/// (reads, retention, portable enumeration) delegates unchanged to the real
/// inner store; no production behavior is replaced outside this one method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SealCompletionReplyLossMode {
    /// Passthrough: the real inner completion commits and reports normally.
    Healthy,
    /// The real inner completion commits for real; only the reply is lost.
    LandedIndeterminate,
    /// The reply is lost before any real inner completion commit.
    UnlandedIndeterminate,
}

pub(super) struct SealCompletionReplyLossStore {
    inner: Arc<SqliteDurableStore>,
    fault_state: AtomicUsize,
    hits: AtomicUsize,
}

impl SealCompletionReplyLossStore {
    pub(super) fn new(
        inner: Arc<SqliteDurableStore>,
        initial: SealCompletionReplyLossMode,
    ) -> Self {
        let store: Self = Self {
            inner,
            fault_state: AtomicUsize::new(0),
            hits: AtomicUsize::new(0),
        };
        store.reconfigure(initial);
        store
    }

    pub(super) fn reconfigure(&self, next: SealCompletionReplyLossMode) {
        let encoded: usize = match next {
            SealCompletionReplyLossMode::Healthy => 0,
            SealCompletionReplyLossMode::LandedIndeterminate => 1,
            SealCompletionReplyLossMode::UnlandedIndeterminate => 2,
        };
        self.fault_state.store(encoded, Ordering::SeqCst);
    }

    pub(super) fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn current_mode(&self) -> SealCompletionReplyLossMode {
        match self.fault_state.load(Ordering::SeqCst) {
            0 => SealCompletionReplyLossMode::Healthy,
            1 => SealCompletionReplyLossMode::LandedIndeterminate,
            _ => SealCompletionReplyLossMode::UnlandedIndeterminate,
        }
    }

    fn delegate(&self) -> &dyn OutgoingSealRepository {
        self.inner.outgoing_seal_repository().unwrap()
    }
}

impl DurableDomainStateStore for SealCompletionReplyLossStore {
    fn get_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }

    fn get_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<OutgoingBarrier, DurableReadError> {
        self.inner.get_outgoing_barrier(context, domain)
    }

    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.inner.get_versioned_durable(context, domain, key)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.inner.commit_durable(context, transaction)
    }
}
