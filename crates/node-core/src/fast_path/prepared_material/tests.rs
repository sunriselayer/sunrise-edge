use super::*;
use crate::fast_path::tests::{RetentionReplica, logical_replica, transfer_bytes};
use crate::logical_generation::{LogicalDerivation, LogicalObservation, ReadObservation};
use crate::paid_execution::tests::{
    CountingEngine, FIRST_PAID_NONCE, Fixture, PaidCall, base_policy, context, domain, entry,
    memory_store, paid_call_with_access, protocol, resolver, set_state,
};
use execution::paid_execution::ReservationAccessKind;
use execution::paid_execution::encode_paid_execution_result;
use protocol_types::{ExecutionGeneration, HashAlgorithmId};
use runtime::{
    DurableDomainStateStore, DurableObjectHead, DurableRequestId, DurableRequestReceipt,
    IndeterminateCommitReason, MemoryBlobStore, MemoryDurableStateStore,
};
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;

const REQUEST: u8 = 0xE4;

/// Real, canonical `0x6415/v1` `PaidExecutionResult` bytes from one genuine
/// handoff-capable prepare (`crate::fast_path::tests::logical_replica`), so
/// every synthetic witness built below decodes under the same strict field-2
/// validation [`commitment::decode_witness`] applies to a real prepare/apply.
/// Only the read-operand list around it is synthetic.
fn real_v2_result_bytes() -> Vec<u8> {
    let replica = logical_replica();
    replica
        .prepare_transfer(REQUEST, crate::paid_execution::tests::FIRST_PAID_NONCE)
        .unwrap();
    let witness_key: Vec<u8> =
        fastpath_prepared_witness_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    let witness_bytes: Vec<u8> = replica
        .row(&witness_key)
        .expect("a handoff-capable prepare retains its own witness");
    let decoded: commitment::DecodedCommitmentWitness =
        commitment::decode_witness(&witness_bytes).unwrap();
    encode_paid_execution_result(&decoded.paid_execution_result).unwrap()
}

/// Builds a synthetic handoff-capable (`0x6424/v2`) witness whose generic
/// state-read operand list carries exactly `count` distinct present reads,
/// each a required [`ArtifactKind::StateValue`] artifact under a distinct
/// identity, all sharing `content_digest`. Real admission never produces this
/// many reads in one request; this exists solely to exercise the retention-
/// size bound deterministically and cheaply, mirroring `commitment.rs`'s own
/// envelope encoder rather than reimplementing it. `result_bytes` must be
/// real, valid `0x6415/v1` bytes (see [`real_v2_result_bytes`]): only the
/// read-operand list is synthetic.
fn synthetic_witness_with_state_reads(
    result_bytes: &[u8],
    count: usize,
    content_digest: Digest32,
) -> (Vec<u8>, BTreeMap<Vec<u8>, StateRevision>) {
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let mut observations: BTreeMap<Vec<u8>, ReadObservation> = BTreeMap::new();
    for index in 0..count {
        let key: Vec<u8> = format!("synthetic-artifact-key-{index:06}").into_bytes();
        reads.insert(key.clone(), StateRevision::new(1));
        observations.insert(
            key,
            ReadObservation {
                observed: Some(LogicalObservation::StatePresent { content_digest }),
                generation: Some(ExecutionGeneration::new(1)),
            },
        );
    }
    let derived: LogicalDerivation = LogicalDerivation {
        generation: ExecutionGeneration::new(2),
        reads: observations,
        inputs: BTreeMap::new(),
    };
    let witness: Vec<u8> = commitment::encode_envelope(
        Digest32::new(HashAlgorithmId::Sha2_256, [0xaa; 32]),
        result_bytes,
        &[],
        &[],
        &[],
        &reads,
        &[],
        b"synthetic-nonce-key",
        StateRevision::new(1),
        &crate::SenderNonceRecord::new([0x31; 32], protocol().epoch(), FIRST_PAID_NONCE + 1)
            .encode()
            .unwrap(),
        Some(&derived),
    )
    .unwrap();
    (witness, reads)
}

#[test]
fn stage_prepared_material_refuses_an_over_bound_closure_before_any_write() {
    let store: MemoryDurableStateStore = memory_store();
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();
    let result_bytes: Vec<u8> = real_v2_result_bytes();
    let content_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x7a; 32]);
    let (witness, _reads) = synthetic_witness_with_state_reads(
        &result_bytes,
        MAX_RETAINED_ARTIFACTS + 1,
        content_digest,
    );
    let request_id: [u8; 32] = [0x33; 32];

    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let mut mutations: Vec<StateMutationEntry> = Vec::new();
    let error: FastPathError = stage_prepared_material(
        &store,
        &blob_store,
        &context(),
        domain(),
        &resolver(),
        protocol().chain_id(),
        &request_id,
        protocol().epoch(),
        &witness,
        &mut reads,
        &mut mutations,
    )
    .expect_err("a closure over the retention bound must be refused");
    assert!(
        matches!(
            &error,
            FastPathError::Publication(inner) if matches!(inner.as_ref(), PublicationRetentionError::ClosureTooLarge {
                actual,
                max,
            } if *actual == MAX_RETAINED_ARTIFACTS + 1 && *max == MAX_RETAINED_ARTIFACTS)
        ),
        "unexpected error: {error:?}"
    );
    assert!(reads.is_empty());
    assert!(mutations.is_empty());

    // Nothing was staged or written: neither the witness row nor any
    // artifact row exists.
    let witness_key: Vec<u8> =
        fastpath_prepared_witness_key(protocol().chain_id(), &request_id).unwrap();
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &witness_key)
            .unwrap()
            .value(),
        None
    );
}

#[test]
fn stage_prepared_material_accepts_a_closure_at_exactly_the_bound_without_writing() {
    let store: MemoryDurableStateStore = memory_store();
    let result_bytes: Vec<u8> = real_v2_result_bytes();
    // `MAX_RETAINED_ARTIFACTS` distinct identities (state keys) all holding
    // byte-identical content: the closure has exactly `MAX_RETAINED_ARTIFACTS`
    // *required* `(kind, identity)` entries (proving the bound is measured
    // against distinct identities, not distinct content), even though they
    // content-address down to one physical storage row.
    let content: Vec<u8> = b"shared retained content".to_vec();
    let content_digest: Digest32 = resolver()
        .hash_for_purpose(protocol().epoch(), HashPurpose::ExecutionEffects, &content)
        .unwrap();
    let (witness, reads) =
        synthetic_witness_with_state_reads(&result_bytes, MAX_RETAINED_ARTIFACTS, content_digest);

    let mut mutations: Vec<StateMutationEntry> = Vec::with_capacity(MAX_RETAINED_ARTIFACTS);
    let mut assertions: Vec<StateReadAssertion> = Vec::with_capacity(MAX_RETAINED_ARTIFACTS);
    for key in reads.keys() {
        let observed: VersionedStateValue = store
            .get_versioned_durable(&context(), domain(), key)
            .unwrap();
        assertions.push(StateReadAssertion::new(key.clone(), observed.revision()).unwrap());
        mutations.push(
            StateMutationEntry::new(key.clone(), StateMutation::Put(content.clone())).unwrap(),
        );
    }
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(assertions).unwrap(),
        AtomicStateMutationSet::new(mutations).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );

    let request_id: [u8; 32] = [0x44; 32];
    let mut retained_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let mut retained_mutations: Vec<StateMutationEntry> = Vec::new();
    stage_prepared_material(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        protocol().chain_id(),
        &request_id,
        protocol().epoch(),
        &witness,
        &mut retained_reads,
        &mut retained_mutations,
    )
    .expect("a closure of exactly MAX_RETAINED_ARTIFACTS required identities is accepted");

    let witness_key: Vec<u8> =
        fastpath_prepared_witness_key(protocol().chain_id(), &request_id).unwrap();
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &witness_key)
            .unwrap()
            .value(),
        None,
        "staging never performs its own material commit"
    );
    let assertions: Vec<StateReadAssertion> = retained_reads
        .into_iter()
        .map(|(key, revision)| StateReadAssertion::new(key, revision).unwrap())
        .collect();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(assertions).unwrap(),
        AtomicStateMutationSet::new(retained_mutations).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &witness_key)
            .unwrap()
            .value(),
        Some(witness.as_slice())
    );
    let artifact_key: Vec<u8> = fastpath_prepared_artifact_key(
        protocol().chain_id(),
        &request_id,
        ArtifactKind::StateValue,
        &content_digest.bytes(),
    )
    .unwrap();
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &artifact_key)
            .unwrap()
            .value(),
        Some(content.as_slice()),
        "MAX_RETAINED_ARTIFACTS identical-content identities content-address to one row"
    );
}

/// Read and commit hooks model a second invocation at the exact boundaries
/// of a real prepare, while every observation and successful commit uses the
/// production in-memory durable store. No transaction implementation is mocked.
type ReadHook<'a> = &'a dyn Fn(&[u8]);

struct ControlledPrepareStore<'a> {
    inner: &'a MemoryDurableStateStore,
    before_read: Option<ReadHook<'a>>,
    before_commit: Option<&'a dyn Fn()>,
    outcome: Option<DurableCommitOutcome>,
    commit_before_outcome: bool,
    state_commits: Cell<usize>,
    invocation_commits: Cell<usize>,
}

impl<'a> ControlledPrepareStore<'a> {
    fn new(inner: &'a MemoryDurableStateStore) -> Self {
        Self {
            inner,
            before_read: None,
            before_commit: None,
            outcome: None,
            commit_before_outcome: false,
            state_commits: Cell::new(0),
            invocation_commits: Cell::new(0),
        }
    }
}

impl DurableDomainStateStore for ControlledPrepareStore<'_> {
    fn get_outgoing_barrier(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, runtime::DurableReadError> {
        self.inner.get_outgoing_barrier(context, domain)
    }

    fn get_namespace_lifecycle(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, runtime::DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }

    fn get_successor_serving(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::SuccessorServingSlot, runtime::DurableReadError> {
        self.inner.get_successor_serving(context, domain)
    }
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        if let Some(hook) = self.before_read {
            hook(key);
        }
        self.inner.get_versioned_durable(context, domain, key)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.state_commits.set(self.state_commits.get() + 1);
        self.inner.commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for ControlledPrepareStore<'_> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object: ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object, version)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request)
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.invocation_commits
            .set(self.invocation_commits.get() + 1);
        if let Some(hook) = self.before_commit {
            hook();
        }
        if self.commit_before_outcome {
            assert_eq!(
                self.inner.commit_invocation(context, transaction),
                DurableCommitOutcome::Committed
            );
            return self.outcome.clone().unwrap();
        }
        match &self.outcome {
            Some(outcome) => outcome.clone(),
            None => self.inner.commit_invocation(context, transaction),
        }
    }
}

fn prepare_signed<S: StructuredDurableDomainStateStore, C: ConsensusSigner>(
    store: &S,
    fixture: &Fixture,
    signer: &C,
    signed: &[u8],
) -> FastPathResult<FastVote> {
    prepare(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &fixture.policy,
        &CountingEngine::new(),
        signer,
        signed,
        10,
    )
}

fn material_keys(witness: &[u8], request: u8) -> Vec<Vec<u8>> {
    let (_, required): (Digest32, publication::RequiredArtifacts) =
        required_artifacts(witness).unwrap();
    let mut keys: BTreeSet<Vec<u8>> = BTreeSet::new();
    keys.insert(fastpath_prepared_witness_key(protocol().chain_id(), &[request; 32]).unwrap());
    for ((kind_tag, _identity), digest) in required.iter() {
        keys.insert(
            fastpath_prepared_artifact_key(
                protocol().chain_id(),
                &[request; 32],
                ArtifactKind::from_u16(*kind_tag).unwrap(),
                digest,
            )
            .unwrap(),
        );
    }
    keys.into_iter().collect()
}

fn reference_material_keys(request: u8) -> Vec<Vec<u8>> {
    let reference: RetentionReplica = logical_replica();
    reference
        .prepare_transfer(request, FIRST_PAID_NONCE)
        .unwrap();
    let witness_key: Vec<u8> =
        fastpath_prepared_witness_key(protocol().chain_id(), &[request; 32]).unwrap();
    material_keys(&reference.row(&witness_key).unwrap(), request)
}

fn assert_no_prepare_rows(replica: &RetentionReplica, request: u8, material: &[Vec<u8>]) {
    for key in material {
        assert_eq!(replica.row(key), None, "unexpected material at {key:?}");
    }
    assert!(replica.lock_rows().iter().all(Option::is_none));
    let prepared_key: Vec<u8> =
        fastpath_prepared_record_key(protocol().chain_id(), &[request; 32]).unwrap();
    assert_eq!(replica.row(&prepared_key), None);
    let synthetic_id: [u8; 32] =
        fastpath_synthetic_prepare_request_id(&resolver(), protocol().epoch(), &[request; 32])
            .unwrap();
    assert_eq!(replica.request_receipt(synthetic_id), None);
}

#[test]
fn rejected_or_indeterminate_prepare_retains_no_partial_material() {
    const REQUEST: u8 = 0xB1;
    let material: Vec<Vec<u8>> = reference_material_keys(REQUEST);
    for outcome in [
        DurableCommitOutcome::Rejected(DurableCommitRejection::Conflict {
            key: b"injected-conflict".to_vec(),
            current_revision: StateRevision::new(1),
        }),
        DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost),
    ] {
        let replica: RetentionReplica = logical_replica();
        let mut store: ControlledPrepareStore<'_> = ControlledPrepareStore::new(&replica.store);
        store.outcome = Some(outcome.clone());
        let signed: Vec<u8> = transfer_bytes(&replica.fixture, REQUEST, FIRST_PAID_NONCE);
        let error: FastPathError =
            prepare_signed(&store, &replica.fixture, &replica.signer, &signed).unwrap_err();
        match outcome {
            DurableCommitOutcome::Rejected(_) => {
                assert!(matches!(
                    error,
                    FastPathError::Node(NodeCoreError::StateConflict)
                ));
            }
            DurableCommitOutcome::Indeterminate(_) => {
                assert!(matches!(
                    error,
                    FastPathError::Node(NodeCoreError::DurableCommitIndeterminate(_))
                ));
            }
            DurableCommitOutcome::Committed => unreachable!(),
        }
        assert_eq!(store.state_commits.get(), 0, "no separate material commit");
        assert_eq!(store.invocation_commits.get(), 1);
        assert_no_prepare_rows(&replica, REQUEST, &material);
    }
}

#[test]
fn indeterminate_committed_prepare_replays_only_its_matching_atomic_material() {
    const REQUEST: u8 = 0xB6;
    let replica: RetentionReplica = logical_replica();
    let signed: Vec<u8> = transfer_bytes(&replica.fixture, REQUEST, FIRST_PAID_NONCE);
    let mut store: ControlledPrepareStore<'_> = ControlledPrepareStore::new(&replica.store);
    store.outcome = Some(DurableCommitOutcome::Indeterminate(
        IndeterminateCommitReason::ConnectionLost,
    ));
    store.commit_before_outcome = true;
    let error: FastPathError =
        prepare_signed(&store, &replica.fixture, &replica.signer, &signed).unwrap_err();
    assert!(matches!(
        error,
        FastPathError::Node(NodeCoreError::DurableCommitIndeterminate(_))
    ));
    assert_eq!(store.state_commits.get(), 0);
    assert_eq!(store.invocation_commits.get(), 1);
    let prepared_key: Vec<u8> =
        fastpath_prepared_record_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    let prepared: FastPathPreparedRecord =
        records::decode_fastpath_prepared_record(&replica.row(&prepared_key).unwrap()).unwrap();
    let witness_key: Vec<u8> =
        fastpath_prepared_witness_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    let witness: Vec<u8> = replica.row(&witness_key).unwrap();
    assert_eq!(
        commitment::hash_witness_bytes(&resolver(), protocol().epoch(), &witness).unwrap(),
        prepared.commitment
    );
    let material: Vec<Vec<u8>> = material_keys(&witness, REQUEST);
    let before: Vec<VersionedStateValue> = material
        .iter()
        .map(|key| {
            replica
                .store
                .get_versioned_durable(&context(), domain(), key)
                .unwrap()
        })
        .collect();
    assert!(before.iter().all(|observed| observed.value().is_some()));
    let replay: FastVote =
        prepare_signed(&store, &replica.fixture, &replica.signer, &signed).unwrap();
    assert_eq!(consensus::encode_fast_vote(&replay).unwrap(), prepared.vote);
    assert_eq!(
        store.invocation_commits.get(),
        1,
        "replay performs no commit"
    );
    let after: Vec<VersionedStateValue> = material
        .iter()
        .map(|key| {
            replica
                .store
                .get_versioned_durable(&context(), domain(), key)
                .unwrap()
        })
        .collect();
    assert_eq!(
        after, before,
        "replay preserves every retained byte and revision"
    );
}

struct BadSignatureSigner {
    validator: ValidatorId,
    calls: Cell<usize>,
}

impl ConsensusSigner for BadSignatureSigner {
    fn validator_id(&self) -> ValidatorId {
        self.validator
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, _framed: &[u8]) -> Result<Vec<u8>, String> {
        self.calls.set(self.calls.get() + 1);
        Ok(vec![0; 64])
    }
}

#[test]
fn logical_prepare_bad_signer_retains_no_partial_material() {
    const REQUEST: u8 = 0xB2;
    let material: Vec<Vec<u8>> = reference_material_keys(REQUEST);
    let replica: RetentionReplica = logical_replica();
    let store: ControlledPrepareStore<'_> = ControlledPrepareStore::new(&replica.store);
    let signer: BadSignatureSigner = BadSignatureSigner {
        validator: replica.signer.validator_id(),
        calls: Cell::new(0),
    };
    let signed: Vec<u8> = transfer_bytes(&replica.fixture, REQUEST, FIRST_PAID_NONCE);
    let error: FastPathError =
        prepare_signed(&store, &replica.fixture, &signer, &signed).unwrap_err();
    assert!(matches!(error, FastPathError::Consensus(_)));
    assert_eq!(signer.calls.get(), 1);
    assert_eq!(store.state_commits.get(), 0);
    assert_eq!(store.invocation_commits.get(), 0);
    assert_no_prepare_rows(&replica, REQUEST, &material);
}

#[test]
fn mismatched_retained_destination_is_never_overwritten_by_prepare() {
    const REQUEST: u8 = 0xB3;
    let material: Vec<Vec<u8>> = reference_material_keys(REQUEST);
    let witness_key: Vec<u8> =
        fastpath_prepared_witness_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
    let artifact_key: Vec<u8> = material
        .iter()
        .find(|key| **key != witness_key)
        .unwrap()
        .clone();
    for destination in [witness_key, artifact_key] {
        let replica: RetentionReplica = logical_replica();
        let old_bytes: Vec<u8> = b"mismatched retained bytes".to_vec();
        set_state(
            &replica.store,
            destination.clone(),
            StateMutation::Put(old_bytes.clone()),
        );
        let store: ControlledPrepareStore<'_> = ControlledPrepareStore::new(&replica.store);
        let signer: BadSignatureSigner = BadSignatureSigner {
            validator: replica.signer.validator_id(),
            calls: Cell::new(0),
        };
        let signed: Vec<u8> = transfer_bytes(&replica.fixture, REQUEST, FIRST_PAID_NONCE);
        let error: FastPathError =
            prepare_signed(&store, &replica.fixture, &signer, &signed).unwrap_err();
        assert!(matches!(
            error,
            FastPathError::Invalid("fast-path retained prepare material mismatch")
        ));
        assert_eq!(replica.row(&destination), Some(old_bytes));
        assert_eq!(signer.calls.get(), 0);
        assert_eq!(store.state_commits.get(), 0);
        assert_eq!(store.invocation_commits.get(), 0);
        let absent_material: Vec<Vec<u8>> = material
            .iter()
            .filter(|key| **key != destination)
            .cloned()
            .collect();
        assert_no_prepare_rows(&replica, REQUEST, &absent_material);
    }
}

/// B passes the absent-prepared check and executes a different valid signed
/// intent under the same request ID. A then commits before B reads the witness
/// destination (the original overwrite-then-reject race), or before B's final
/// invocation commit (the destination CAS race). Neither schedule can replace
/// the witness backing A's exposed vote.
#[test]
fn interleaved_conflicting_prepares_preserve_the_committed_votes_exact_material() {
    const REQUEST: u8 = 0xB4;
    for before_destination_read in [true, false] {
        let replica: RetentionReplica = logical_replica();
        let signed_a: Vec<u8> = transfer_bytes(&replica.fixture, REQUEST, FIRST_PAID_NONCE);
        let signed_b: Vec<u8> = paid_call_with_access(
            PaidCall {
                fixture: &replica.fixture,
                policy: &replica.fixture.policy,
                request: REQUEST,
                nonce: FIRST_PAID_NONCE,
                source: &replica.fixture.coin,
                entrypoint: "transfer",
                arguments: public_standard_asset::transfer_arguments(&[0x77; 32]).unwrap(),
                access: vec![entry(&replica.fixture.coin, objects::AccessMode::Write)],
            },
            ReservationAccessKind::Write,
        );
        assert_ne!(signed_a, signed_b);
        let witness_key: Vec<u8> =
            fastpath_prepared_witness_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
        let prepared_key: Vec<u8> =
            fastpath_prepared_record_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
        let triggered: Cell<bool> = Cell::new(false);
        let b_observed_absent: Cell<bool> = Cell::new(false);
        let vote_a: RefCell<Option<FastVote>> = RefCell::new(None);
        let first_witness: RefCell<Option<Vec<u8>>> = RefCell::new(None);
        let commit_a = || {
            assert!(
                b_observed_absent.get(),
                "B already passed prepared reconciliation"
            );
            assert!(!triggered.replace(true));
            assert_eq!(replica.row(&prepared_key), None);
            let vote: FastVote =
                prepare_signed(&replica.store, &replica.fixture, &replica.signer, &signed_a)
                    .unwrap();
            *vote_a.borrow_mut() = Some(vote);
            *first_witness.borrow_mut() = Some(replica.row(&witness_key).unwrap());
        };
        let read_hook = |key: &[u8]| {
            if key == prepared_key && !triggered.get() {
                assert_eq!(replica.row(key), None);
                b_observed_absent.set(true);
            }
            if before_destination_read && key == witness_key && !triggered.get() {
                commit_a();
            }
        };
        let mut store: ControlledPrepareStore<'_> = ControlledPrepareStore::new(&replica.store);
        store.before_read = Some(&read_hook);
        if !before_destination_read {
            store.before_commit = Some(&commit_a);
        }
        let error: FastPathError =
            prepare_signed(&store, &replica.fixture, &replica.signer, &signed_b).unwrap_err();
        assert!(triggered.get());
        if before_destination_read {
            assert!(matches!(
                error,
                FastPathError::Invalid("fast-path retained prepare material mismatch")
            ));
            assert_eq!(store.invocation_commits.get(), 0);
        } else {
            assert!(matches!(
                error,
                FastPathError::Node(NodeCoreError::StateConflict)
            ));
            assert_eq!(store.invocation_commits.get(), 1);
        }
        assert_eq!(store.state_commits.get(), 0);
        let retained_witness: Vec<u8> = replica.row(&witness_key).unwrap();
        assert_eq!(Some(retained_witness.clone()), *first_witness.borrow());
        let committed_vote: FastVote = vote_a.borrow().clone().unwrap();
        assert_eq!(
            commitment::hash_witness_bytes(&resolver(), protocol().epoch(), &retained_witness)
                .unwrap(),
            committed_vote.execution_effects_hash
        );
        let replay: FastVote =
            prepare_signed(&replica.store, &replica.fixture, &replica.signer, &signed_a).unwrap();
        assert_eq!(replay, committed_vote);
        assert_eq!(replica.row(&witness_key), Some(retained_witness));
    }
}

#[test]
fn logical_prepare_replay_refuses_missing_or_corrupt_material_without_repair() {
    const REQUEST: u8 = 0xB5;
    for (witness_target, missing) in [(true, true), (true, false), (false, true), (false, false)] {
        let replica: RetentionReplica = logical_replica();
        replica.prepare_transfer(REQUEST, FIRST_PAID_NONCE).unwrap();
        let witness_key: Vec<u8> =
            fastpath_prepared_witness_key(protocol().chain_id(), &[REQUEST; 32]).unwrap();
        let material: Vec<Vec<u8>> = material_keys(&replica.row(&witness_key).unwrap(), REQUEST);
        let key: Vec<u8> = if witness_target {
            witness_key
        } else {
            material
                .iter()
                .find(|key| **key != witness_key)
                .unwrap()
                .clone()
        };
        let mutation: StateMutation = if missing {
            StateMutation::Delete
        } else {
            StateMutation::Put(b"corrupt retained bytes".to_vec())
        };
        set_state(&replica.store, key, mutation);
        let before: Vec<Option<Vec<u8>>> = material.iter().map(|key| replica.row(key)).collect();
        let store: ControlledPrepareStore<'_> = ControlledPrepareStore::new(&replica.store);
        let signed: Vec<u8> = transfer_bytes(&replica.fixture, REQUEST, FIRST_PAID_NONCE);
        let error: FastPathError =
            prepare_signed(&store, &replica.fixture, &replica.signer, &signed).unwrap_err();
        assert!(matches!(error, FastPathError::Invalid(_)));
        assert_eq!(store.state_commits.get(), 0);
        assert_eq!(store.invocation_commits.get(), 0);
        let after: Vec<Option<Vec<u8>>> = material.iter().map(|key| replica.row(key)).collect();
        assert_eq!(after, before, "replay does not rewrite retained material");
    }
}
