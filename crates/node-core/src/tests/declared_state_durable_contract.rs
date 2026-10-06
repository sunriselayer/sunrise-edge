//! DR-0203 pre-change controls for the actual structured durable handler.
//!
//! These tests pin handle_resolved_durable_idempotent_event's existing
//! sorted application-read ordering, corrupt-value fail-closed behavior,
//! canonical mixed-update refusal priority, and point-read error mapping,
//! strictly as implemented today (before any state_transition extraction).
//! They exist only to give an independent, pre-change baseline; they are not
//! production code and authorize no migration by themselves.

use super::*;

type RecordedDurableRead = (Vec<u8>, AtomicityDomainId, DurableOperationContext);

#[derive(Clone, Debug, PartialEq, Eq)]
enum RecordedOperation {
    State(RecordedDurableRead),
    ObjectHead(ObjectId),
    ObjectVersion(ObjectId, DurableObjectVersion),
}

const CHAIN: &str = "sunrise-test";
const KEY_APP_ABSENT: &[u8] = b"state/app-absent";
const KEY_APP_TOMBSTONE: &[u8] = b"state/app-tombstone";
const KEY_APP_A: &[u8] = b"state/app-a";
const KEY_APP_B: &[u8] = b"state/app-b";
const KEY_MIX_Z_READONLY: &[u8] = b"state/mix-z-readonly";
const KEY_MIX_A_UNDECLARED: &[u8] = b"state/mix-a-undeclared";
const KEY_MIX_A_READONLY: &[u8] = b"state/mix-a-readonly";
const KEY_MIX_Z_UNDECLARED: &[u8] = b"state/mix-z-undeclared";
const KEY_MIX_RW: &[u8] = b"state/mix-rw";
const KEY_DURABLE_READ_FAIL: &[u8] = b"state/durable-read-fail";

/// Records every DurableDomainStateStore::get_versioned_durable call's
/// exact key, domain and context in call order, and can be scripted to fail
/// one exact key with a fixed DurableReadError. Every other call and every
/// other trait method is forwarded unchanged to the owned
/// ScriptedDurableStore, so that fixture's existing behavior (including its
/// own state_reads counter and genesis-epoch preload) is fully preserved
/// for every other test.
struct RecordingDurableStore {
    inner: ScriptedDurableStore,
    calls: Mutex<Vec<RecordedOperation>>,
    fail_key: Mutex<Option<(Vec<u8>, DurableReadError)>>,
}

impl RecordingDurableStore {
    fn new(commit_outcome: DurableCommitOutcome) -> Self {
        Self {
            inner: ScriptedDurableStore::new(commit_outcome),
            calls: Mutex::new(Vec::new()),
            fail_key: Mutex::new(None),
        }
    }

    /// Returns the owned fixture store, so a test can preload fixed
    /// revisions/values or inspect committed invocations.
    fn inner(&self) -> &ScriptedDurableStore {
        &self.inner
    }

    /// Scripts the next and every subsequent read of key to fail with
    /// error instead of being forwarded to the owned store.
    fn fail_on(&self, key: Vec<u8>, error: DurableReadError) {
        *self.fail_key.lock().unwrap() = Some((key, error));
    }

    /// Returns every recorded call in order, exactly as observed.
    fn calls(&self) -> Vec<RecordedDurableRead> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter_map(|operation: &RecordedOperation| match operation {
                RecordedOperation::State(read) => Some(read.clone()),
                RecordedOperation::ObjectHead(_) | RecordedOperation::ObjectVersion(_, _) => None,
            })
            .collect()
    }

    fn trace(&self) -> Vec<RecordedOperation> {
        self.calls.lock().unwrap().clone()
    }

    /// Returns only the recorded keys, in call order.
    fn recorded_keys(&self) -> Vec<Vec<u8>> {
        self.calls().iter().map(|entry| entry.0.clone()).collect()
    }
}

impl DurableDomainStateStore for RecordingDurableStore {
    fn get_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, DurableReadError> {
        self.inner.get_outgoing_barrier(context, domain)
    }

    fn get_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }

    fn get_successor_serving(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::SuccessorServingSlot, DurableReadError> {
        self.inner.get_successor_serving(context, domain)
    }

    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.calls
            .lock()
            .unwrap()
            .push(RecordedOperation::State((key.to_vec(), domain, *context)));
        let failing: Option<(Vec<u8>, DurableReadError)> = self.fail_key.lock().unwrap().clone();
        if let Some(failing_entry) = failing {
            if failing_entry.0 == key {
                return Err(failing_entry.1);
            }
        }
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

impl StructuredDurableDomainStateStore for RecordingDurableStore {
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

    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.calls
            .lock()
            .unwrap()
            .push(RecordedOperation::ObjectHead(object_id));
        self.inner.get_object_head(context, domain, object_id)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.calls
            .lock()
            .unwrap()
            .push(RecordedOperation::ObjectVersion(object_id, object_version));
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }
}

/// Declares two ReadOnly keys and asserts one response, never mutating
/// either key. Used to exercise the sorted application-read loop without
/// also exercising the writable-update checker.
struct TwoKeyReadOnlyMachine {
    first_key: Vec<u8>,
    second_key: Vec<u8>,
    calls: AtomicUsize,
    snapshot: Mutex<Option<NodeStateSnapshot>>,
}

impl TwoKeyReadOnlyMachine {
    fn new(first_key: &[u8], second_key: &[u8]) -> Self {
        Self {
            first_key: first_key.to_vec(),
            second_key: second_key.to_vec(),
            calls: AtomicUsize::new(0),
            snapshot: Mutex::new(None),
        }
    }
}

impl TransactionalNodeStateMachine for TwoKeyReadOnlyMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![
            NodeStateAccess::new(self.first_key.clone(), NodeStateAccessMode::ReadOnly)?,
            NodeStateAccess::new(self.second_key.clone(), NodeStateAccessMode::ReadOnly)?,
        ])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.snapshot.lock().unwrap() = Some(state.clone());
        Ok(TransactionalNodeTransition::read_only(NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?))
    }
}

/// Declares one ReadOnly key and counts every transition call. Used to
/// prove a scripted point-read failure stops before the machine ever runs.
struct SingleKeyCountingMachine {
    key: Vec<u8>,
    calls: AtomicUsize,
}

impl TransactionalNodeStateMachine for SingleKeyCountingMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            self.key.clone(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(TransactionalNodeTransition::read_only(NodeOutput::new(
            vec![NodeResponse::new(
                event.request_id(),
                NodeResponseStatus::Accepted,
                None,
            )?],
            Vec::new(),
        )?))
    }
}

/// One outbound message addressed back to event's own chain/protocol
/// version/epoch, matching validate_output_event_context's requirement.
fn matching_outbound_message(event: &NodeEvent, byte: u8) -> OutboundMessage {
    OutboundMessage::new(
        NodeEvent::new(
            event.chain_id().clone(),
            event.protocol_version(),
            event.epoch(),
            request(byte),
            NodeEventKind::Tick,
            canonical(TEST_PAYLOAD_TYPE_ID, u64::from(byte)),
        )
        .unwrap(),
    )
}

/// DR-0203 control 1: the sorted application-read loop runs strictly after
/// the existing direct-admission epoch and profile reads, and keeps the
/// exact observed revision for both a read-only absent key and a read-only
/// tombstoned key in the committed durable read set.
#[test]
fn durable_sorted_application_reads_follow_profile_and_epoch_and_keep_exact_revisions() {
    let recording: RecordingDurableStore =
        RecordingDurableStore::new(DurableCommitOutcome::Committed);
    let tombstone_revision: StateRevision = StateRevision::new(5);
    recording
        .inner()
        .preload_tombstone(KEY_APP_TOMBSTONE.to_vec(), tombstone_revision);
    let machine: TwoKeyReadOnlyMachine = TwoKeyReadOnlyMachine {
        first_key: KEY_APP_ABSENT.to_vec(),
        second_key: KEY_APP_TOMBSTONE.to_vec(),
        calls: AtomicUsize::new(0),
        snapshot: Mutex::new(None),
    };
    let chain_id: ChainId = ChainId::new(CHAIN).unwrap();
    let event_epoch: Epoch = Epoch::new(7);

    let result: ResolvedNodeOutput = handle_resolved_durable_idempotent_event(
        &recording,
        &durable_context(),
        &placement(0xD1, 7),
        &config(CHAIN),
        &resolver(CHAIN),
        event(CHAIN, request(0xD1)),
        &machine,
    )
    .unwrap();
    assert_eq!(result.domain(), domain(0xD1));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let recorded_snapshot: NodeStateSnapshot = machine.snapshot.lock().unwrap().clone().unwrap();
    let observed_keys: Vec<&[u8]> = recorded_snapshot.iter().map(|(key, _)| key).collect();
    assert_eq!(observed_keys, vec![KEY_APP_ABSENT, KEY_APP_TOMBSTONE]);
    assert_eq!(
        recorded_snapshot.get(KEY_APP_ABSENT).unwrap().revision(),
        StateRevision::INITIAL
    );
    assert_eq!(
        recorded_snapshot.get(KEY_APP_TOMBSTONE).unwrap().revision(),
        tombstone_revision
    );
    assert!(
        recorded_snapshot
            .get(KEY_APP_ABSENT)
            .unwrap()
            .value()
            .is_none()
    );
    assert!(
        recorded_snapshot
            .get(KEY_APP_TOMBSTONE)
            .unwrap()
            .value()
            .is_none()
    );
    assert!(recorded_snapshot.resolved_objects().is_empty());

    let epoch_key: Vec<u8> = local_instance_state::fastpath_epoch_record_key(&chain_id).unwrap();
    let profile_key: Vec<u8> = logical_generation::logical_profile_key(&chain_id).unwrap();
    let admission_context: execution::publication::PublicationContext =
        execution::publication::PublicationContext::new(
            chain_id,
            ProtocolVersion::new(3),
            event_epoch,
        )
        .unwrap();
    let manifest_key: Vec<u8> = genesis::genesis_manifest_key(&admission_context).unwrap();
    let marker_key: Vec<u8> = genesis::genesis_marker_key(&admission_context).unwrap();

    let calls: Vec<RecordedDurableRead> = recording.calls();
    let keys: Vec<Vec<u8>> = calls.iter().map(|entry| entry.0.clone()).collect();
    let epoch_index = keys.iter().position(|key| *key == epoch_key).unwrap();
    let profile_index = keys.iter().position(|key| *key == profile_key).unwrap();
    let manifest_index = keys.iter().position(|key| *key == manifest_key).unwrap();
    let marker_index = keys.iter().position(|key| *key == marker_key).unwrap();
    let absent_index = keys
        .iter()
        .position(|key| key.as_slice() == KEY_APP_ABSENT)
        .unwrap();
    let tombstone_index = keys
        .iter()
        .position(|key| key.as_slice() == KEY_APP_TOMBSTONE)
        .unwrap();

    // Epoch is read first; profile/manifest/marker admission reads, however
    // many there are, all precede both application reads; the two
    // application reads themselves stay in canonical sorted-key order.
    assert_eq!(epoch_index, 0);
    assert!(profile_index < absent_index);
    assert!(manifest_index < absent_index);
    assert!(marker_index < absent_index);
    assert!(absent_index < tombstone_index);
    for application_key in [KEY_APP_ABSENT, KEY_APP_TOMBSTONE] {
        assert_eq!(
            keys.iter()
                .filter(|key| key.as_slice() == application_key)
                .count(),
            1,
            "each declared application key is read exactly once"
        );
    }

    // Every recorded call shares the one invocation context and domain: the
    // application loop never substitutes a different backend/context/domain
    // than the admission reads that preceded it.
    for recorded in &calls {
        assert_eq!(recorded.1, domain(0xD1));
        assert_eq!(recorded.2, durable_context());
    }

    let commits = recording.inner().commits.lock().unwrap();
    assert_eq!(commits.len(), 1);
    let state = commits[0].state().unwrap();
    let absent_read = state
        .reads()
        .iter()
        .find(|read| read.key() == KEY_APP_ABSENT)
        .unwrap();
    assert_eq!(absent_read.expected_revision(), StateRevision::INITIAL);
    let tombstone_read = state
        .reads()
        .iter()
        .find(|read| read.key() == KEY_APP_TOMBSTONE)
        .unwrap();
    assert_eq!(tombstone_read.expected_revision(), tombstone_revision);
    assert!(
        state.mutations().is_empty(),
        "read-only observations are not mutations"
    );
}

/// DR-0203 control 2 (negative): a corrupt value at the first sorted
/// application key is rejected before the second application key is ever
/// read, before the machine's transition ever runs, and before any
/// commit is attempted.
#[test]
fn durable_corrupt_first_sorted_application_value_stops_before_later_read_transition_or_commit() {
    let recording = RecordingDurableStore::new(DurableCommitOutcome::Committed);
    recording.inner().preload(
        KEY_APP_A.to_vec(),
        StateRevision::new(3),
        vec![0xFF, 0x00, 0x01],
    );
    recording.inner().preload(
        KEY_APP_B.to_vec(),
        StateRevision::new(1),
        canonical(TEST_STATE_TYPE_ID, 1),
    );
    let original_state: ScriptedStateReads = recording.inner().preloaded.lock().unwrap().clone();
    let machine = TwoKeyReadOnlyMachine {
        first_key: KEY_APP_A.to_vec(),
        second_key: KEY_APP_B.to_vec(),
        calls: AtomicUsize::new(0),
        snapshot: Mutex::new(None),
    };

    let error = handle_resolved_durable_idempotent_event(
        &recording,
        &durable_context(),
        &placement(0xD2, 7),
        &config(CHAIN),
        &resolver(CHAIN),
        event(CHAIN, request(0xD2)),
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::CanonicalDecoding(canonical_encoding::CanonicalDecodingError::Truncated {
            offset: 0,
            needed: 4,
            remaining: 3,
        })
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(
        !recording
            .recorded_keys()
            .iter()
            .any(|key| key.as_slice() == KEY_APP_B)
    );
    assert!(recording.inner().commits.lock().unwrap().is_empty());
    assert!(recording.inner().receipt.lock().unwrap().is_none());
    assert_eq!(*recording.inner().preloaded.lock().unwrap(), original_state);
}

/// DR-0203 control 2 (positive control): the same owning path and the same
/// two-key setup, with both values valid, commits normally. Pairs with
/// durable_corrupt_first_sorted_application_value_stops_before_later_read_transition_or_commit.
#[test]
fn durable_two_valid_sorted_application_values_both_read_and_commit() {
    let recording = RecordingDurableStore::new(DurableCommitOutcome::Committed);
    recording.inner().preload(
        KEY_APP_A.to_vec(),
        StateRevision::new(3),
        canonical(TEST_STATE_TYPE_ID, 9),
    );
    recording.inner().preload(
        KEY_APP_B.to_vec(),
        StateRevision::new(1),
        canonical(TEST_STATE_TYPE_ID, 1),
    );
    let machine = TwoKeyReadOnlyMachine {
        first_key: KEY_APP_A.to_vec(),
        second_key: KEY_APP_B.to_vec(),
        calls: AtomicUsize::new(0),
        snapshot: Mutex::new(None),
    };

    handle_resolved_durable_idempotent_event(
        &recording,
        &durable_context(),
        &placement(0xD3, 7),
        &config(CHAIN),
        &resolver(CHAIN),
        event(CHAIN, request(0xD3)),
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let observed: NodeStateSnapshot = machine.snapshot.lock().unwrap().clone().unwrap();
    assert_eq!(
        observed.get(KEY_APP_A).unwrap().value(),
        Some(canonical(TEST_STATE_TYPE_ID, 9).as_slice())
    );
    assert_eq!(
        observed.get(KEY_APP_B).unwrap().value(),
        Some(canonical(TEST_STATE_TYPE_ID, 1).as_slice())
    );
    assert!(
        recording
            .recorded_keys()
            .iter()
            .any(|key| key.as_slice() == KEY_APP_B)
    );
    assert_eq!(recording.inner().commits.lock().unwrap().len(), 1);
}

/// A real signed read-only object manifest, using the established test signer
/// and authentication helper. Loading/authentication is left to the public core.
fn object_submission(
    recording: &RecordingDurableStore,
    owner: Owner,
    request_byte: u8,
) -> (AuthenticatedSubmitTransaction, ObjectId, DurableObjectHead) {
    let key: SigningKey = dev_signing_key(0xB7);
    let object_id: ObjectId = ObjectId::new([0x87; 32]);
    let (object_ref, head): (ObjectRef, DurableObjectHead) =
        preload_inline_object(recording.inner(), CHAIN, object_id, owner, 0x87);
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        CHAIN,
        request(request_byte),
        &key,
        Epoch::new(7),
        0,
        manifest,
        &config(CHAIN),
        &active_protocol_config(0xE7),
    );
    (submission, object_id, head)
}

#[test]
fn authenticated_nonce_fences_and_object_load_precede_each_application_read_and_commit() {
    let recording: RecordingDurableStore =
        RecordingDurableStore::new(DurableCommitOutcome::Committed);
    let sender: Address = dev_sender_address(&dev_signing_key(0xB7));
    let (submission, object_id, head): (
        AuthenticatedSubmitTransaction,
        ObjectId,
        DurableObjectHead,
    ) = object_submission(&recording, Owner::Address(sender), 0xE7);
    recording.inner().preload(
        KEY_APP_A.to_vec(),
        StateRevision::new(3),
        canonical(TEST_STATE_TYPE_ID, 9),
    );
    let machine: TwoKeyReadOnlyMachine = TwoKeyReadOnlyMachine::new(KEY_APP_B, KEY_APP_A);
    let result: ResolvedNodeOutput = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &recording,
        &durable_context(),
        &resolver(CHAIN),
        submission,
        &machine,
    )
    .unwrap();
    assert_eq!(result.domain(), domain(0xE7));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let snapshot: NodeStateSnapshot = machine.snapshot.lock().unwrap().clone().unwrap();
    assert_eq!(snapshot.resolved_objects().len(), 1);
    assert_eq!(
        snapshot.get(KEY_APP_A).unwrap().revision(),
        StateRevision::new(3)
    );
    assert_eq!(
        snapshot.get(KEY_APP_B).unwrap().revision(),
        StateRevision::INITIAL
    );

    let chain: ChainId = ChainId::new(CHAIN).unwrap();
    let nonce_key: Vec<u8> = PersistenceLayout::new(chain.clone(), ProtocolVersion::new(3))
        .sender_nonce_key(*sender.as_bytes(), Epoch::new(7));
    let nonce_lock_key: Vec<u8> =
        local_instance_state::fastpath_nonce_lock_key(&chain, sender.as_bytes(), Epoch::new(7))
            .unwrap();
    let epoch_key: Vec<u8> = local_instance_state::fastpath_epoch_record_key(&chain).unwrap();
    let trace: Vec<RecordedOperation> = recording.trace();
    let state_index = |key: &[u8]| -> usize {
        trace.iter().position(|operation: &RecordedOperation| {
            matches!(operation, RecordedOperation::State((actual, _, _)) if actual.as_slice() == key)
        }).unwrap()
    };
    let head_index: usize = trace
        .iter()
        .position(|operation: &RecordedOperation| {
            *operation == RecordedOperation::ObjectHead(object_id)
        })
        .unwrap();
    let version_index: usize = trace
        .iter()
        .position(|operation: &RecordedOperation| {
            *operation == RecordedOperation::ObjectVersion(object_id, DurableObjectVersion::FIRST)
        })
        .unwrap();
    assert!(state_index(&nonce_key) < state_index(&nonce_lock_key));
    assert!(state_index(&nonce_lock_key) < head_index);
    assert!(head_index < version_index);
    assert!(version_index < state_index(KEY_APP_A));
    assert!(state_index(KEY_APP_A) < state_index(KEY_APP_B));
    let epoch_reads: Vec<usize> = trace
        .iter()
        .enumerate()
        .filter_map(|(index, operation)| {
            matches!(operation, RecordedOperation::State((actual, _, _)) if *actual == epoch_key)
                .then_some(index)
        })
        .collect();
    assert!(
        epoch_reads.len() >= 2,
        "direct admission and current-epoch fencing both run"
    );
    assert!(epoch_reads.iter().all(|index| *index < head_index));
    let keys: Vec<Vec<u8>> = recording.recorded_keys();
    for key in [KEY_APP_A, KEY_APP_B] {
        assert_eq!(
            keys.iter()
                .filter(|actual| actual.as_slice() == key)
                .count(),
            1
        );
    }
    let commits = recording.inner().commits.lock().unwrap();
    assert_eq!(commits.len(), 1);
    assert_eq!(
        commits[0].object_changes().reads(),
        &[DurableObjectHeadRead::new(object_id, head)]
    );
    let state: &runtime::DurableStateTransaction = commits[0].state().unwrap();
    let nonce: &StateMutationEntry = state
        .mutations()
        .iter()
        .find(|mutation| mutation.key() == nonce_key)
        .unwrap();
    let StateMutation::Put(bytes) = nonce.mutation() else {
        panic!("nonce must advance atomically");
    };
    assert_eq!(SenderNonceRecord::decode(bytes).unwrap().next_nonce, 1);
}

#[test]
fn authenticated_object_owner_refusal_wins_over_corrupt_declared_state_without_application_io() {
    let recording: RecordingDurableStore =
        RecordingDurableStore::new(DurableCommitOutcome::Committed);
    let wrong_owner: Address = Address::new([0xEE; 32]);
    assert_ne!(wrong_owner, dev_sender_address(&dev_signing_key(0xB7)));
    let (submission, object_id, _): (AuthenticatedSubmitTransaction, ObjectId, DurableObjectHead) =
        object_submission(&recording, Owner::Address(wrong_owner), 0xE8);
    recording
        .inner()
        .preload(KEY_APP_A.to_vec(), StateRevision::new(3), vec![0xFF]);
    let original: ScriptedStateReads = recording.inner().preloaded.lock().unwrap().clone();
    let machine: TwoKeyReadOnlyMachine = TwoKeyReadOnlyMachine::new(KEY_APP_A, KEY_APP_B);
    let error: NodeCoreError = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &recording,
        &durable_context(),
        &resolver(CHAIN),
        submission,
        &machine,
    )
    .unwrap_err();
    assert_eq!(error, NodeCoreError::ObjectOwnerMismatch { object_id });
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(machine.snapshot.lock().unwrap().is_none());
    let keys: Vec<Vec<u8>> = recording.recorded_keys();
    assert!(
        !keys
            .iter()
            .any(|key| [KEY_APP_A, KEY_APP_B].contains(&key.as_slice()))
    );
    assert_eq!(
        recording.inner().object_head_reads.load(Ordering::SeqCst),
        1
    );
    assert!(recording.inner().commits.lock().unwrap().is_empty());
    assert!(recording.inner().receipt.lock().unwrap().is_none());
    assert_eq!(*recording.inner().preloaded.lock().unwrap(), original);
}

#[test]
fn authenticated_correct_owner_reaches_the_corrupt_state_refusal_after_real_object_load() {
    let recording: RecordingDurableStore =
        RecordingDurableStore::new(DurableCommitOutcome::Committed);
    let sender: Address = dev_sender_address(&dev_signing_key(0xB7));
    let (submission, object_id, _): (AuthenticatedSubmitTransaction, ObjectId, DurableObjectHead) =
        object_submission(&recording, Owner::Address(sender), 0xE9);
    recording
        .inner()
        .preload(KEY_APP_A.to_vec(), StateRevision::new(3), vec![0xFF]);
    let original: ScriptedStateReads = recording.inner().preloaded.lock().unwrap().clone();
    let machine: TwoKeyReadOnlyMachine = TwoKeyReadOnlyMachine::new(KEY_APP_A, KEY_APP_B);
    let error: NodeCoreError = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &recording,
        &durable_context(),
        &resolver(CHAIN),
        submission,
        &machine,
    )
    .unwrap_err();
    assert_eq!(
        error,
        NodeCoreError::CanonicalDecoding(canonical_encoding::CanonicalDecodingError::Truncated {
            offset: 0,
            needed: 4,
            remaining: 1,
        })
    );
    let trace: Vec<RecordedOperation> = recording.trace();
    assert!(trace.contains(&RecordedOperation::ObjectVersion(
        object_id,
        DurableObjectVersion::FIRST
    )));
    let application_reads: Vec<Vec<u8>> = recording
        .recorded_keys()
        .into_iter()
        .filter(|key| [KEY_APP_A, KEY_APP_B].contains(&key.as_slice()))
        .collect();
    assert_eq!(application_reads, vec![KEY_APP_A.to_vec()]);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(recording.inner().commits.lock().unwrap().is_empty());
    assert!(recording.inner().receipt.lock().unwrap().is_none());
    assert_eq!(*recording.inner().preloaded.lock().unwrap(), original);
}

/// Declares one ReadOnly key, so any returned update to it is a read-only
/// violation, and returns exactly the two updates (and the one outbound
/// message) the caller supplies, in the caller's own literal order.
struct MixedUpdateMachine {
    declared_key: Vec<u8>,
    first_update_key: Vec<u8>,
    second_update_key: Vec<u8>,
}

impl TransactionalNodeStateMachine for MixedUpdateMachine {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            self.declared_key.clone(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        _state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        let response = NodeResponse::new(event.request_id(), NodeResponseStatus::Accepted, None)?;
        let outbound = matching_outbound_message(event, 0xFE);
        TransactionalNodeTransition::new(
            vec![
                NodeStateUpdate::put(
                    self.first_update_key.clone(),
                    canonical(TEST_STATE_TYPE_ID, 1),
                )?,
                NodeStateUpdate::put(
                    self.second_update_key.clone(),
                    canonical(TEST_STATE_TYPE_ID, 2),
                )?,
            ],
            NodeOutput::new(vec![response], vec![outbound])?,
        )
    }
}

/// DR-0203 control 3 (negative, undeclared wins): the machine's own
/// access_plan declares only KEY_MIX_Z_READONLY. Its transition returns a
/// read-only-violating update for that key and an undeclared-key update
/// for KEY_MIX_A_UNDECLARED, supplied to TransactionalNodeTransition::new
/// in the literal order [z-readonly, a-undeclared]. Because that
/// constructor canonically sorts updates by key before the durable
/// handler ever inspects them, KEY_MIX_A_UNDECLARED sorts first and its
/// UndeclaredStateUpdate refusal is the one actually returned, not the
/// caller's own input order and not the read-only violation. The
/// transition itself (which builds a real response and a real outbound
/// message, exercising the handler's original receipt/outbox
/// construction) still runs exactly once; nothing is committed.
#[test]
fn durable_undeclared_update_wins_canonical_priority_over_read_only_when_it_sorts_first() {
    let store: RecordingDurableStore = RecordingDurableStore::new(DurableCommitOutcome::Committed);
    let original_state: ScriptedStateReads = store.inner().preloaded.lock().unwrap().clone();
    let machine = MixedUpdateMachine {
        declared_key: KEY_MIX_Z_READONLY.to_vec(),
        first_update_key: KEY_MIX_Z_READONLY.to_vec(),
        second_update_key: KEY_MIX_A_UNDECLARED.to_vec(),
    };

    let error = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xD4, 7),
        &config(CHAIN),
        &resolver(CHAIN),
        event(CHAIN, request(0xD4)),
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::UndeclaredStateUpdate(KEY_MIX_A_UNDECLARED.to_vec())
    );
    assert_post_application_profile_read(&store, KEY_MIX_Z_READONLY);
    assert!(store.inner().commits.lock().unwrap().is_empty());
    assert!(store.inner().receipt.lock().unwrap().is_none());
    assert_eq!(*store.inner().preloaded.lock().unwrap(), original_state);
}

/// DR-0203 control 3 (negative, read-only wins): mirrors
/// durable_undeclared_update_wins_canonical_priority_over_read_only_when_it_sorts_first
/// with the alphabetical order reversed: access_plan declares only
/// KEY_MIX_A_READONLY, and transition supplies
/// [z-undeclared, a-readonly]. After canonical sorting,
/// KEY_MIX_A_READONLY is inspected first, so ReadOnlyStateUpdate is the
/// refusal actually returned, again with the same real
/// response/outbound-message construction and no commit.
#[test]
fn durable_read_only_update_wins_canonical_priority_over_undeclared_when_it_sorts_first() {
    let store: RecordingDurableStore = RecordingDurableStore::new(DurableCommitOutcome::Committed);
    let original_state: ScriptedStateReads = store.inner().preloaded.lock().unwrap().clone();
    let machine = MixedUpdateMachine {
        declared_key: KEY_MIX_A_READONLY.to_vec(),
        first_update_key: KEY_MIX_Z_UNDECLARED.to_vec(),
        second_update_key: KEY_MIX_A_READONLY.to_vec(),
    };

    let error = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xD5, 7),
        &config(CHAIN),
        &resolver(CHAIN),
        event(CHAIN, request(0xD5)),
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ReadOnlyStateUpdate(KEY_MIX_A_READONLY.to_vec())
    );
    assert_post_application_profile_read(&store, KEY_MIX_A_READONLY);
    assert!(store.inner().commits.lock().unwrap().is_empty());
    assert!(store.inner().receipt.lock().unwrap().is_none());
    assert_eq!(*store.inner().preloaded.lock().unwrap(), original_state);
}

fn assert_post_application_profile_read(store: &RecordingDurableStore, application_key: &[u8]) {
    let keys: Vec<Vec<u8>> = store.recorded_keys();
    let app_index: usize = keys
        .iter()
        .position(|key: &Vec<u8>| key.as_slice() == application_key)
        .unwrap();
    let profile_key: Vec<u8> =
        logical_generation::logical_profile_key(&ChainId::new(CHAIN).unwrap()).unwrap();
    assert!(
        keys.iter()
            .skip(app_index + 1)
            .any(|key: &Vec<u8>| *key == profile_key),
        "the late logical-profile fence still precedes writable-update refusal"
    );
}

/// DR-0203 control 3 (positive control): the same owning path, the same
/// single-declared-key shape, and the same real response/outbound-message
/// construction as the two mixed-priority refusals above, but with a
/// declared ReadWrite key and no undeclared key, so the transition
/// actually commits its state, receipt and outbox.
#[test]
fn durable_declared_read_write_update_commits_state_receipt_and_outbox() {
    struct ValidUpdateMachine;

    impl TransactionalNodeStateMachine for ValidUpdateMachine {
        fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
            NodeStateAccessPlan::new(vec![NodeStateAccess::new(
                KEY_MIX_RW.to_vec(),
                NodeStateAccessMode::ReadWrite,
            )?])
        }

        fn transition(
            &self,
            _state: &NodeStateSnapshot,
            event: &NodeEvent,
        ) -> Result<TransactionalNodeTransition, NodeCoreError> {
            let response =
                NodeResponse::new(event.request_id(), NodeResponseStatus::Accepted, None)?;
            let outbound = matching_outbound_message(event, 0xFD);
            TransactionalNodeTransition::new(
                vec![NodeStateUpdate::put(
                    KEY_MIX_RW.to_vec(),
                    canonical(TEST_STATE_TYPE_ID, 1),
                )?],
                NodeOutput::new(vec![response], vec![outbound])?,
            )
        }
    }

    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let result = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xD6, 7),
        &config(CHAIN),
        &resolver(CHAIN),
        event(CHAIN, request(0xD6)),
        &ValidUpdateMachine,
    )
    .unwrap();

    assert_eq!(result.output().outbound_messages().len(), 1);
    let commits = store.commits.lock().unwrap();
    assert_eq!(commits.len(), 1);
    let state = commits[0].state().unwrap();
    assert_eq!(state.mutations().len(), 1);
    assert_eq!(state.mutations()[0].key(), KEY_MIX_RW);
    assert_eq!(
        commits[0].receipt().request_id(),
        DurableRequestId::new([0xD6; 32]).unwrap()
    );
    assert!(commits[0].outbox().is_some());
}

/// DR-0203 control 4 (negative): a scripted failure on the application
/// point-read maps to NodeCoreError::DurableRead, not
/// NodeCoreError::Runtime (the legacy TransactionalStateStore/
/// DomainTransactionalStateStore mapping, unchanged by this slice and
/// pinned by the explicit injected-failure legacy dispatch matrix). The
/// machine's transition never runs and nothing is committed.
#[test]
fn durable_application_point_read_failure_maps_to_durable_read_not_runtime() {
    let recording = RecordingDurableStore::new(DurableCommitOutcome::Committed);
    let original_state: ScriptedStateReads = recording.inner().preloaded.lock().unwrap().clone();
    recording.fail_on(
        KEY_DURABLE_READ_FAIL.to_vec(),
        DurableReadError::Unavailable,
    );
    let machine = SingleKeyCountingMachine {
        key: KEY_DURABLE_READ_FAIL.to_vec(),
        calls: AtomicUsize::new(0),
    };

    let error = handle_resolved_durable_idempotent_event(
        &recording,
        &durable_context(),
        &placement(0xD7, 7),
        &config(CHAIN),
        &resolver(CHAIN),
        event(CHAIN, request(0xD7)),
        &machine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::DurableRead(DurableReadError::Unavailable)
    );
    assert!(!matches!(error, NodeCoreError::Runtime(_)));
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
    assert!(recording.inner().commits.lock().unwrap().is_empty());
    assert!(recording.inner().receipt.lock().unwrap().is_none());
    assert_eq!(*recording.inner().preloaded.lock().unwrap(), original_state);
}

/// DR-0203 control 4 (positive control): the same owning path, the same
/// recording wrapper, and the same declared key, with no failure
/// scripted, succeeds and actually reads the key.
#[test]
fn durable_application_point_read_without_failure_succeeds() {
    let recording = RecordingDurableStore::new(DurableCommitOutcome::Committed);
    let machine = SingleKeyCountingMachine {
        key: KEY_DURABLE_READ_FAIL.to_vec(),
        calls: AtomicUsize::new(0),
    };

    handle_resolved_durable_idempotent_event(
        &recording,
        &durable_context(),
        &placement(0xD8, 7),
        &config(CHAIN),
        &resolver(CHAIN),
        event(CHAIN, request(0xD8)),
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert!(
        recording
            .recorded_keys()
            .iter()
            .any(|key| key.as_slice() == KEY_DURABLE_READ_FAIL)
    );
    assert_eq!(recording.inner().commits.lock().unwrap().len(), 1);
}
