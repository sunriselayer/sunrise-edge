//! Independent pre-change public-library transactional preparation controls.
//! Legacy public HTTP is closed; these are not network-acceptance claims.
//! Builders create untrusted input; expected errors and I/O remain test-owned.

use canonical_encoding::{CanonicalDecodingError, CanonicalStruct, decode_canonical_frame};
use hashing::HashSuiteResolver;
use node_core::{
    NodeConfig, NodeCoreError, NodeDedupRecord, NodeEvent, NodeEventKind, NodeOutboxBatch,
    NodeOutput, NodeResponse, NodeResponseStatus, NodeStateAccess, NodeStateAccessMode,
    NodeStateAccessPlan, NodeStateSnapshot, NodeStateUpdate, OutboundMessage, RequestId,
    TransactionalNodeStateMachine, TransactionalNodeTransition, handle_domain_idempotent_event,
    handle_domain_transactional_event, handle_idempotent_event, handle_transactional_event,
};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicStateWriteResult,
    AtomicStateWriteSet, AtomicityDomainId, CompareAndSwapResult, ComposedRuntime,
    DomainTransactionalStateStore, ManualClock, MemoryBlobStore, MemoryScheduler, MemorySigner,
    MemoryStateStore, MemoryTransport, PersistenceLayout, Runtime, RuntimeError, StateMutation,
    StateMutationEntry, StateReadAssertion, StateStore, StateWrite, TransactionalStateStore,
    ValidatorId, VersionedStateValue,
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Copy, Debug)]
enum Scope {
    Unscoped,
    Domain,
}

impl Scope {
    fn domain(self) -> Option<AtomicityDomainId> {
        match self {
            Self::Unscoped => None,
            Self::Domain => Some(AtomicityDomainId::new([0x4e; 32]).unwrap()),
        }
    }
}

type ReadTrace = Vec<(Option<AtomicityDomainId>, Vec<u8>)>;

#[derive(Default)]
struct RecordingStore {
    inner: MemoryStateStore,
    reads: Mutex<ReadTrace>,
    commits: AtomicUsize,
    write_sets: Mutex<Vec<AtomicStateWriteSet>>,
    transactions: Mutex<Vec<AtomicStateTransaction>>,
}

impl RecordingStore {
    fn raw_read(&self, scope: Scope, key: &[u8]) -> VersionedStateValue {
        match scope.domain() {
            None => self.inner.get_versioned(key).unwrap(),
            Some(domain) => self.inner.get_versioned_in_domain(domain, key).unwrap(),
        }
    }

    fn seed(&self, scope: Scope, key: Vec<u8>, value: Vec<u8>) {
        self.seed_mutation(scope, key, StateMutation::Put(value));
    }

    fn seed_mutation(&self, scope: Scope, key: Vec<u8>, mutation: StateMutation) {
        let observed: VersionedStateValue = self.raw_read(scope, &key);
        match scope.domain() {
            None => {
                let writes: AtomicStateWriteSet = AtomicStateWriteSet::new(vec![
                    StateWrite::new(key, observed.revision(), mutation).unwrap(),
                ])
                .unwrap();
                assert_eq!(
                    self.inner.commit_atomic(writes).unwrap(),
                    AtomicStateWriteResult::Committed
                );
            }
            Some(domain) => {
                let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
                    domain,
                    AtomicStateReadSet::new(vec![
                        StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
                    ])
                    .unwrap(),
                    AtomicStateMutationSet::new(vec![
                        StateMutationEntry::new(key, mutation).unwrap(),
                    ])
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    self.inner.commit_transaction(transaction).unwrap(),
                    AtomicStateWriteResult::Committed
                );
            }
        }
    }
}

impl StateStore for RecordingStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.inner.get(key)
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), RuntimeError> {
        self.inner.put(key, value)
    }

    fn compare_and_swap(
        &self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        value: Vec<u8>,
    ) -> Result<CompareAndSwapResult, RuntimeError> {
        self.inner.compare_and_swap(key, expected, value)
    }
}

impl TransactionalStateStore for RecordingStore {
    fn get_versioned(&self, key: &[u8]) -> Result<VersionedStateValue, RuntimeError> {
        self.reads.lock().unwrap().push((None, key.to_vec()));
        self.inner.get_versioned(key)
    }

    fn commit_atomic(
        &self,
        writes: AtomicStateWriteSet,
    ) -> Result<AtomicStateWriteResult, RuntimeError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.write_sets.lock().unwrap().push(writes.clone());
        self.inner.commit_atomic(writes)
    }
}

impl DomainTransactionalStateStore for RecordingStore {
    fn get_versioned_in_domain(
        &self,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, RuntimeError> {
        self.reads
            .lock()
            .unwrap()
            .push((Some(domain), key.to_vec()));
        self.inner.get_versioned_in_domain(domain, key)
    }

    fn commit_transaction(
        &self,
        transaction: AtomicStateTransaction,
    ) -> Result<AtomicStateWriteResult, RuntimeError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.transactions.lock().unwrap().push(transaction.clone());
        self.inner.commit_transaction(transaction)
    }
}

type TestRuntime = ComposedRuntime<
    RecordingStore,
    MemoryBlobStore,
    MemorySigner,
    MemoryTransport,
    ManualClock,
    MemoryScheduler,
>;

fn runtime() -> TestRuntime {
    ComposedRuntime::new(
        RecordingStore::default(),
        MemoryBlobStore::default(),
        MemorySigner::new(ValidatorId::new([0x52; 32])),
        MemoryTransport::default(),
        ManualClock::default(),
        MemoryScheduler::default(),
    )
}

fn frame(type_id: u16, value: u64) -> Vec<u8> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(type_id, 1);
    frame.field_u64(1, value).unwrap();
    frame.finish().unwrap()
}

fn chain() -> ChainId {
    ChainId::new("legacy-invocation-control").unwrap()
}

fn config() -> NodeConfig {
    NodeConfig::new(
        chain(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        b"node/control".to_vec(),
    )
    .unwrap()
}

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        chain(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}

fn event() -> NodeEvent {
    NodeEvent::new(
        chain(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        RequestId::new([0x31; 32]).unwrap(),
        NodeEventKind::ReceiveVote,
        frame(0xef02, 9),
    )
    .unwrap()
}

struct ProbeMachine {
    keys: Vec<Vec<u8>>,
    plans: AtomicUsize,
    transitions: AtomicUsize,
    snapshots: Mutex<Vec<Vec<(Vec<u8>, VersionedStateValue)>>>,
}

impl ProbeMachine {
    fn new(keys: Vec<Vec<u8>>) -> Self {
        Self {
            keys,
            plans: AtomicUsize::new(0),
            transitions: AtomicUsize::new(0),
            snapshots: Mutex::new(Vec::new()),
        }
    }
}

impl TransactionalNodeStateMachine for ProbeMachine {
    fn access_plan(&self, _: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        self.plans.fetch_add(1, Ordering::SeqCst);
        let accesses: Vec<NodeStateAccess> = self
            .keys
            .iter()
            .map(|key: &Vec<u8>| {
                NodeStateAccess::new(key.clone(), NodeStateAccessMode::ReadWrite).unwrap()
            })
            .collect();
        NodeStateAccessPlan::new(accesses)
    }

    fn transition(
        &self,
        snapshot: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.transitions.fetch_add(1, Ordering::SeqCst);
        let observed: Vec<(Vec<u8>, VersionedStateValue)> = snapshot
            .iter()
            .map(|(key, value)| (key.to_vec(), value.clone()))
            .collect();
        self.snapshots.lock().unwrap().push(observed);
        assert!(snapshot.resolved_objects().is_empty());
        TransactionalNodeTransition::new(
            vec![NodeStateUpdate::put(
                self.keys[0].clone(),
                frame(0xef01, 99),
            )?],
            NodeOutput::new(
                vec![NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Accepted,
                    Some(frame(0xef02, 99)),
                )?],
                Vec::new(),
            )?,
        )
    }
}

fn invoke(
    scope: Scope,
    runtime: &TestRuntime,
    machine: &ProbeMachine,
) -> Result<NodeOutput, NodeCoreError> {
    match scope.domain() {
        None => handle_idempotent_event(runtime, &config(), &resolver(), event(), machine),
        Some(domain) => handle_domain_idempotent_event(
            runtime,
            domain,
            &config(),
            &resolver(),
            event(),
            machine,
        ),
    }
}

#[derive(Clone, Copy, Debug)]
enum MetadataCase {
    OrphanOutbox,
    OrphanDelivery,
    InvalidDedup,
    DedupRequest,
    DedupDigest,
    MissingOutbox,
    InvalidOutbox,
    OutboxRequest,
    OutboxDigest,
    OutboundChain,
    MissingDelivery,
    InvalidDelivery,
    DeliveryRequest,
    DeliveryDigest,
    Valid,
}

fn metadata(case: MetadataCase) -> [Option<Vec<u8>>; 3] {
    let event: NodeEvent = event();
    let request: RequestId = event.request_id();
    let other: RequestId = RequestId::new([0x32; 32]).unwrap();
    let digest: Digest32 = event.digest(&resolver()).unwrap();
    let wrong_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0xa7; 32]);
    let dedup_request: RequestId = if matches!(case, MetadataCase::DedupRequest) {
        other
    } else {
        request
    };
    let dedup_digest: Digest32 = if matches!(case, MetadataCase::DedupDigest) {
        wrong_digest
    } else {
        digest
    };
    let response: NodeResponse = NodeResponse::new(
        dedup_request,
        NodeResponseStatus::Accepted,
        Some(frame(0xef02, 7)),
    )
    .unwrap();
    let mut dedup: Option<Vec<u8>> = Some(
        NodeDedupRecord::new(dedup_request, dedup_digest, vec![response])
            .unwrap()
            .encode()
            .unwrap(),
    );
    let outbound_chain: ChainId = if matches!(case, MetadataCase::OutboundChain) {
        ChainId::new("foreign-replay").unwrap()
    } else {
        chain()
    };
    let outbound: NodeEvent = NodeEvent::new(
        outbound_chain,
        ProtocolVersion::new(3),
        Epoch::new(7),
        other,
        NodeEventKind::Tick,
        frame(0xef02, 10),
    )
    .unwrap();
    let outbox_request: RequestId = if matches!(case, MetadataCase::OutboxRequest) {
        other
    } else {
        request
    };
    let outbox_digest: Digest32 = if matches!(case, MetadataCase::OutboxDigest) {
        wrong_digest
    } else {
        digest
    };
    let mut outbox: Option<Vec<u8>> = Some(
        NodeOutboxBatch::new(
            outbox_request,
            outbox_digest,
            vec![OutboundMessage::new(outbound)],
        )
        .unwrap()
        .encode()
        .unwrap(),
    );
    // Independent raw E005 input, not the private production pending producer.
    let mut cursor: CanonicalStruct = CanonicalStruct::new(0xe005, 1);
    let delivery_request: RequestId = if matches!(case, MetadataCase::DeliveryRequest) {
        other
    } else {
        request
    };
    let delivery_digest: Digest32 = if matches!(case, MetadataCase::DeliveryDigest) {
        wrong_digest
    } else {
        digest
    };
    cursor
        .field_bytes(1, delivery_request.as_bytes().to_vec())
        .unwrap();
    cursor
        .field_u16(2, delivery_digest.algorithm().as_u16())
        .unwrap();
    cursor.field_bytes(3, delivery_digest.bytes()).unwrap();
    cursor.field_u32(4, 0).unwrap();
    cursor.field_u32(5, 0).unwrap();
    let mut delivery: Option<Vec<u8>> = Some(cursor.finish().unwrap());
    match case {
        MetadataCase::OrphanOutbox => {
            dedup = None;
            delivery = None;
        }
        MetadataCase::OrphanDelivery => {
            dedup = None;
            outbox = None;
        }
        MetadataCase::InvalidDedup => {
            dedup = Some(vec![0]);
            outbox = Some(vec![0]);
            delivery = Some(vec![0]);
        }
        MetadataCase::DedupRequest | MetadataCase::DedupDigest => {
            outbox = Some(vec![0]);
            delivery = Some(vec![0]);
        }
        MetadataCase::MissingOutbox => {
            outbox = None;
            delivery = None;
        }
        MetadataCase::InvalidOutbox => {
            outbox = Some(vec![0]);
            delivery = None;
        }
        MetadataCase::OutboxRequest
        | MetadataCase::OutboxDigest
        | MetadataCase::OutboundChain
        | MetadataCase::MissingDelivery => {
            delivery = None;
        }
        MetadataCase::InvalidDelivery => {
            delivery = Some(vec![0]);
        }
        MetadataCase::DeliveryRequest | MetadataCase::DeliveryDigest | MetadataCase::Valid => {}
    }
    [dedup, outbox, delivery]
}

fn metadata_keys() -> [Vec<u8>; 3] {
    let layout: PersistenceLayout = PersistenceLayout::new(chain(), ProtocolVersion::new(3));
    let request: [u8; 32] = *event().request_id().as_bytes();
    [
        layout.request_dedup_key(request),
        layout.outbox_batch_key(request),
        layout.outbox_delivery_key(request),
    ]
}

#[test]
fn legacy_replay_refusals_preserve_metadata_read_order_without_application_io() {
    let cases: [(MetadataCase, NodeCoreError); 14] = [
        (
            MetadataCase::OrphanOutbox,
            NodeCoreError::PersistenceInvariant("outbox state exists without dedup"),
        ),
        (
            MetadataCase::OrphanDelivery,
            NodeCoreError::PersistenceInvariant("outbox state exists without dedup"),
        ),
        (
            MetadataCase::InvalidDedup,
            NodeCoreError::PersistenceInvariant("invalid dedup record"),
        ),
        (MetadataCase::DedupRequest, NodeCoreError::RequestIdReuse),
        (MetadataCase::DedupDigest, NodeCoreError::RequestIdReuse),
        (
            MetadataCase::MissingOutbox,
            NodeCoreError::PersistenceInvariant("dedup exists without outbox"),
        ),
        (
            MetadataCase::InvalidOutbox,
            NodeCoreError::PersistenceInvariant("invalid outbox batch"),
        ),
        (
            MetadataCase::OutboxRequest,
            NodeCoreError::PersistenceInvariant("dedup and outbox identities differ"),
        ),
        (
            MetadataCase::OutboxDigest,
            NodeCoreError::PersistenceInvariant("dedup and outbox identities differ"),
        ),
        (
            MetadataCase::OutboundChain,
            NodeCoreError::ChainMismatch {
                expected: chain(),
                actual: ChainId::new("foreign-replay").unwrap(),
            },
        ),
        (
            MetadataCase::MissingDelivery,
            NodeCoreError::PersistenceInvariant("dedup exists without outbox delivery state"),
        ),
        (
            MetadataCase::InvalidDelivery,
            NodeCoreError::PersistenceInvariant("invalid outbox delivery state"),
        ),
        (
            MetadataCase::DeliveryRequest,
            NodeCoreError::PersistenceInvariant("dedup and outbox delivery identities differ"),
        ),
        (
            MetadataCase::DeliveryDigest,
            NodeCoreError::PersistenceInvariant("dedup and outbox delivery identities differ"),
        ),
    ];
    for scope in [Scope::Unscoped, Scope::Domain] {
        for (case, expected) in &cases {
            let runtime: TestRuntime = runtime();
            let store: &RecordingStore = runtime.state_store();
            let keys: [Vec<u8>; 3] = metadata_keys();
            for (key, value) in keys.iter().zip(metadata(*case)) {
                if let Some(value) = value {
                    store.seed(scope, key.clone(), value);
                }
            }
            store.seed(scope, b"state/application".to_vec(), frame(0xef01, 12));
            let before: Vec<VersionedStateValue> =
                keys.iter().map(|key| store.raw_read(scope, key)).collect();
            let application: VersionedStateValue = store.raw_read(scope, b"state/application");
            let machine: ProbeMachine = ProbeMachine::new(vec![b"state/application".to_vec()]);
            assert_eq!(
                invoke(scope, &runtime, &machine),
                Err(expected.clone()),
                "{scope:?} {case:?}"
            );
            let expected_reads: ReadTrace = keys
                .iter()
                .map(|key| (scope.domain(), key.clone()))
                .collect();
            assert_eq!(
                *store.reads.lock().unwrap(),
                expected_reads,
                "{scope:?} {case:?}"
            );
            assert_eq!(machine.plans.load(Ordering::SeqCst), 1);
            assert_eq!(machine.transitions.load(Ordering::SeqCst), 0);
            assert_eq!(store.commits.load(Ordering::SeqCst), 0);
            assert_eq!(
                keys.iter()
                    .map(|key| store.raw_read(scope, key))
                    .collect::<Vec<VersionedStateValue>>(),
                before
            );
            assert_eq!(store.raw_read(scope, b"state/application"), application);
        }
    }
}

#[test]
fn legacy_exact_replay_returns_retained_response_without_reenqueue_or_mutation() {
    for scope in [Scope::Unscoped, Scope::Domain] {
        let runtime: TestRuntime = runtime();
        let store: &RecordingStore = runtime.state_store();
        let keys: [Vec<u8>; 3] = metadata_keys();
        for (key, value) in keys.iter().zip(metadata(MetadataCase::Valid)) {
            store.seed(scope, key.clone(), value.unwrap());
        }
        store.seed(scope, b"state/application".to_vec(), frame(0xef01, 12));
        let before: Vec<VersionedStateValue> =
            keys.iter().map(|key| store.raw_read(scope, key)).collect();
        let application: VersionedStateValue = store.raw_read(scope, b"state/application");
        let machine: ProbeMachine = ProbeMachine::new(vec![b"state/application".to_vec()]);
        let output: NodeOutput = invoke(scope, &runtime, &machine).unwrap();
        assert_eq!(output.responses().len(), 1);
        assert_eq!(output.responses()[0].request_id(), event().request_id());
        assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);
        assert_eq!(
            decode_canonical_frame(output.responses()[0].payload().unwrap())
                .unwrap()
                .required_u64(1),
            Ok(7)
        );
        assert!(output.outbound_messages().is_empty());
        assert_eq!(machine.plans.load(Ordering::SeqCst), 1);
        assert_eq!(machine.transitions.load(Ordering::SeqCst), 0);
        assert_eq!(store.commits.load(Ordering::SeqCst), 0);
        assert_eq!(
            *store.reads.lock().unwrap(),
            keys.iter()
                .map(|key| (scope.domain(), key.clone()))
                .collect::<ReadTrace>()
        );
        assert_eq!(
            keys.iter()
                .map(|key| store.raw_read(scope, key))
                .collect::<Vec<VersionedStateValue>>(),
            before
        );
        assert_eq!(store.raw_read(scope, b"state/application"), application);
    }
}

#[test]
fn legacy_metadata_and_nonce_reservations_fail_before_any_record_io() {
    let layout: PersistenceLayout = PersistenceLayout::new(chain(), ProtocolVersion::new(3));
    let mut reserved: Vec<Vec<u8>> = metadata_keys().into_iter().collect();
    let mut nonce: Vec<u8> = layout.sender_nonce_prefix();
    nonce.extend_from_slice(b"test-only");
    reserved.push(nonce);
    for scope in [Scope::Unscoped, Scope::Domain] {
        for key in &reserved {
            let runtime: TestRuntime = runtime();
            let machine: ProbeMachine = ProbeMachine::new(vec![key.clone()]);
            assert_eq!(
                invoke(scope, &runtime, &machine),
                Err(NodeCoreError::ReservedStateAccess(key.clone()))
            );
            assert!(runtime.state_store().reads.lock().unwrap().is_empty());
            assert_eq!(machine.transitions.load(Ordering::SeqCst), 0);
            assert_eq!(runtime.state_store().commits.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn legacy_slot_limit_precedes_metadata_collision_but_not_nonce_namespace() {
    let maximum: usize = core::cmp::min(
        runtime::MAX_ATOMIC_STATE_READS,
        runtime::MAX_ATOMIC_STATE_WRITES,
    ) - 3;
    let count: usize = maximum + 1;
    let layout: PersistenceLayout = PersistenceLayout::new(chain(), ProtocolVersion::new(3));
    let mut nonce: Vec<u8> = layout.sender_nonce_prefix();
    nonce.extend_from_slice(b"test-only");
    for scope in [Scope::Unscoped, Scope::Domain] {
        let mut oversized: Vec<Vec<u8>> = (0..count - 1)
            .map(|index: usize| format!("state/application/{index:04}").into_bytes())
            .collect();
        oversized.push(metadata_keys()[0].clone());
        let runtime: TestRuntime = runtime();
        let machine: ProbeMachine = ProbeMachine::new(oversized.clone());
        assert_eq!(
            invoke(scope, &runtime, &machine),
            Err(NodeCoreError::TooManyStateAccesses { count, maximum })
        );
        assert!(runtime.state_store().reads.lock().unwrap().is_empty());
        assert_eq!(machine.transitions.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.state_store().commits.load(Ordering::SeqCst), 0);

        oversized[0] = nonce.clone();
        let runtime: TestRuntime = self::runtime();
        let machine: ProbeMachine = ProbeMachine::new(oversized);
        assert_eq!(
            invoke(scope, &runtime, &machine),
            Err(NodeCoreError::ReservedStateAccess(nonce.clone()))
        );
        assert!(runtime.state_store().reads.lock().unwrap().is_empty());
        assert_eq!(machine.transitions.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.state_store().commits.load(Ordering::SeqCst), 0);
    }
}

#[derive(Clone, Copy, Debug)]
enum Dispatch {
    Transactional,
    DomainTransactional,
    Idempotent,
    DomainIdempotent,
}

impl Dispatch {
    fn scope(self) -> Scope {
        match self {
            Self::Transactional | Self::Idempotent => Scope::Unscoped,
            Self::DomainTransactional | Self::DomainIdempotent => Scope::Domain,
        }
    }

    fn has_metadata(self) -> bool {
        matches!(self, Self::Idempotent | Self::DomainIdempotent)
    }

    fn invoke(
        self,
        runtime: &TestRuntime,
        machine: &ProbeMachine,
    ) -> Result<NodeOutput, NodeCoreError> {
        match self {
            Self::Transactional => handle_transactional_event(runtime, &config(), event(), machine),
            Self::DomainTransactional => handle_domain_transactional_event(
                runtime,
                self.scope().domain().unwrap(),
                &config(),
                event(),
                machine,
            ),
            Self::Idempotent | Self::DomainIdempotent => invoke(self.scope(), runtime, machine),
        }
    }
}

const DISPATCHES: [Dispatch; 4] = [
    Dispatch::Transactional,
    Dispatch::DomainTransactional,
    Dispatch::Idempotent,
    Dispatch::DomainIdempotent,
];

fn expected_application_reads(dispatch: Dispatch, keys: &[&[u8]]) -> ReadTrace {
    let mut expected: ReadTrace = Vec::new();
    if dispatch.has_metadata() {
        expected.extend(
            metadata_keys()
                .into_iter()
                .map(|key| (dispatch.scope().domain(), key)),
        );
    }
    expected.extend(
        keys.iter()
            .map(|key| (dispatch.scope().domain(), key.to_vec())),
    );
    expected
}

#[test]
fn declared_reads_stay_sorted_complete_and_assert_absence_and_tombstones() {
    for dispatch in DISPATCHES {
        let runtime: TestRuntime = runtime();
        let store: &RecordingStore = runtime.state_store();
        let scope: Scope = dispatch.scope();
        store.seed(scope, b"state/a".to_vec(), frame(0xef01, 12));
        store.seed(scope, b"state/c".to_vec(), frame(0xef01, 13));
        store.seed_mutation(scope, b"state/c".to_vec(), StateMutation::Delete);
        let keys: [&[u8]; 3] = [b"state/a", b"state/b", b"state/c"];
        let observations: Vec<VersionedStateValue> =
            keys.iter().map(|key| store.raw_read(scope, key)).collect();
        assert_eq!(observations[1].revision(), runtime::StateRevision::INITIAL);
        assert!(observations[1].value().is_none());
        assert_eq!(observations[2].revision(), runtime::StateRevision::new(2));
        assert!(observations[2].value().is_none());
        let machine: ProbeMachine = ProbeMachine::new(vec![
            b"state/c".to_vec(),
            b"state/b".to_vec(),
            b"state/a".to_vec(),
        ]);
        let _output: NodeOutput = dispatch.invoke(&runtime, &machine).unwrap();
        assert_eq!(
            *store.reads.lock().unwrap(),
            expected_application_reads(dispatch, &keys),
            "{dispatch:?}"
        );
        assert_eq!(machine.transitions.load(Ordering::SeqCst), 1);
        assert_eq!(
            machine.snapshots.lock().unwrap().as_slice(),
            &[keys
                .iter()
                .zip(&observations)
                .map(|(key, value)| (key.to_vec(), value.clone()))
                .collect::<Vec<(Vec<u8>, VersionedStateValue)>>()]
        );
        assert_eq!(store.commits.load(Ordering::SeqCst), 1);
        match scope {
            Scope::Unscoped => {
                let writes = store.write_sets.lock().unwrap();
                assert_eq!(writes.len(), 1);
                assert!(store.transactions.lock().unwrap().is_empty());
                for (key, observed) in keys.iter().zip(&observations) {
                    let actual: &StateWrite = writes[0]
                        .writes()
                        .iter()
                        .find(|write| write.key() == *key)
                        .unwrap();
                    assert_eq!(actual.expected_revision(), observed.revision());
                    if *key != b"state/c" {
                        assert_eq!(actual.mutation(), &StateMutation::Assert);
                    }
                }
            }
            Scope::Domain => {
                let transactions = store.transactions.lock().unwrap();
                assert_eq!(transactions.len(), 1);
                assert!(store.write_sets.lock().unwrap().is_empty());
                assert_eq!(transactions[0].domain(), scope.domain().unwrap());
                for (key, observed) in keys.iter().zip(&observations) {
                    let actual: &StateReadAssertion = transactions[0]
                        .reads()
                        .iter()
                        .find(|read| read.key() == *key)
                        .unwrap();
                    assert_eq!(actual.expected_revision(), observed.revision());
                    if *key != b"state/c" {
                        assert!(
                            transactions[0]
                                .mutations()
                                .iter()
                                .all(|mutation| mutation.key() != *key)
                        );
                    }
                }
            }
        }
        assert_eq!(store.raw_read(scope, b"state/a"), observations[0]);
        assert_eq!(store.raw_read(scope, b"state/b"), observations[1]);
        assert_eq!(
            store.raw_read(scope, b"state/c").revision(),
            runtime::StateRevision::new(3)
        );
    }
}

#[test]
fn corrupt_declared_state_stops_at_first_sorted_key_without_transition_or_commit() {
    for dispatch in DISPATCHES {
        let runtime: TestRuntime = runtime();
        let store: &RecordingStore = runtime.state_store();
        let scope: Scope = dispatch.scope();
        store.seed(scope, b"state/a".to_vec(), vec![0]);
        store.seed(scope, b"state/c".to_vec(), frame(0xef01, 13));
        let before: VersionedStateValue = store.raw_read(scope, b"state/a");
        let machine: ProbeMachine = ProbeMachine::new(vec![
            b"state/c".to_vec(),
            b"state/b".to_vec(),
            b"state/a".to_vec(),
        ]);
        assert_eq!(
            dispatch.invoke(&runtime, &machine),
            Err(NodeCoreError::CanonicalDecoding(
                CanonicalDecodingError::Truncated {
                    offset: 0,
                    needed: 4,
                    remaining: 1
                }
            )),
            "{dispatch:?}"
        );
        assert_eq!(
            *store.reads.lock().unwrap(),
            expected_application_reads(dispatch, &[b"state/a"])
        );
        assert_eq!(machine.transitions.load(Ordering::SeqCst), 0);
        assert_eq!(store.commits.load(Ordering::SeqCst), 0);
        assert_eq!(store.raw_read(scope, b"state/a"), before);
        assert!(store.transactions.lock().unwrap().is_empty());
        assert!(store.write_sets.lock().unwrap().is_empty());
        for key in metadata_keys() {
            assert!(store.raw_read(scope, &key).value().is_none());
        }
    }
}
