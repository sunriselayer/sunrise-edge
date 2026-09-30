//! U7 regressions: a real four-validator quorum, a genuine drain union
//! reconstructed on a fourth replica that never locally prepared the
//! certified operation, and a genuine conflicting local partial prepare that
//! `apply_drain_member` must resolve atomically with the certified effects.
use super::*;
use crate::fast_path::drain_publication::retain_drain_publication;
use crate::fast_path::tests::{
    AmbiguousCommitStore, RetentionReplica, TestSigner, four_validators, full_snapshot,
    installed_validator_set, logical_replica, transfer_bundle_bytes,
};
use crate::ordered_economics::{
    self, DrainSetRecord, confirm_drain_signer_entry, drain_set_record_key,
    encode_drain_set_record, import_staged_drain_publication, ingest_drain_signer_page,
};
use crate::paid_execution::tests::{
    CountingEngine, FIRST_PAID_NONCE, base_policy, context, domain, protocol, resolver, sender,
};
use consensus::bundle::{PublicationBundle, encode_publication_bundle, verify_publication_bundle};
use consensus::{
    AvailabilityIdentity, ConsensusSigner, DrainUnionAccumulator, FastPathCertifier,
    FrozenFrontierAccumulator, FrozenFrontierCertifier, FrozenFrontierPage, FrozenFrontierVote,
};
use runtime::MemoryBlobStore;
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableDomainStateStore,
};

const CLOSURE_REQUEST_ID: [u8; 32] = [0x77; 32];
const CLOSURE_HEIGHT: u64 = 4;
const X_REQUEST: u8 = 0xC1;
const Y_REQUEST: u8 = 0xC2;

#[test]
fn drain_lock_resolution_has_a_stable_strict_canonical_vector() {
    let record: FastPathDrainLockResolutionRecord = FastPathDrainLockResolutionRecord {
        epoch: Epoch::new(9),
        resolving_request_id: [0x31; 32],
        displaced_request_id: [0x32; 32],
        resolved_key: b"lock".to_vec(),
    };
    let encoded: Vec<u8> = encode_drain_lock_resolution_record(&record).unwrap();
    let hex: String = encoded.iter().map(|byte| format!("{byte:02x}")).collect();
    let expected: String = format!(
        "534e52455064010004000100080000000900000000000000020020000000{}030020000000{}0400040000006c6f636b",
        "31".repeat(32),
        "32".repeat(32),
    );
    assert_eq!(hex, expected);
    assert_eq!(
        decode_drain_lock_resolution_record(&encoded).unwrap(),
        record
    );
    let mut invalid: FastPathDrainLockResolutionRecord = record.clone();
    invalid.displaced_request_id = invalid.resolving_request_id;
    assert!(encode_drain_lock_resolution_record(&invalid).is_err());
    invalid.displaced_request_id = [0; 32];
    assert!(encode_drain_lock_resolution_record(&invalid).is_err());
    invalid = record;
    invalid.resolved_key.clear();
    assert!(encode_drain_lock_resolution_record(&invalid).is_err());
}

fn close(replica: &RetentionReplica) {
    let record = ordered_economics::AdmissionClosureRecord {
        closed_epoch: protocol().epoch(),
        request_id: CLOSURE_REQUEST_ID,
        closed_at_block_height: CLOSURE_HEIGHT,
    };
    let key: Vec<u8> =
        ordered_economics::admission_closure_key(protocol().chain_id(), protocol().epoch())
            .unwrap();
    replica.put_row(
        key,
        ordered_economics::encode_admission_closure_record(&record).unwrap(),
    );
}

fn remove_closure(replica: &RetentionReplica) {
    let key: Vec<u8> =
        ordered_economics::admission_closure_key(protocol().chain_id(), protocol().epoch())
            .unwrap();
    let observed: VersionedStateValue = replica
        .store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        replica.store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}

fn identity(bundle: &PublicationBundle) -> AvailabilityIdentity {
    let certifier: FastPathCertifier = FastPathCertifier::new(
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        installed_validator_set(),
    )
    .unwrap();
    verify_publication_bundle(
        bundle,
        &certifier,
        &FastPathEd25519Verifier,
        &resolver(),
        &[],
    )
    .unwrap()
    .identity
}

fn import_into(
    replica: &RetentionReplica,
    bundle: &PublicationBundle,
    identity: &AvailabilityIdentity,
) {
    retain_drain_publication(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        identity,
        &encode_publication_bundle(bundle).unwrap(),
    )
    .unwrap();
}

fn cast_vote(signer: &TestSigner, entries: &[AvailabilityIdentity]) -> FrozenFrontierVote {
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        installed_validator_set(),
    )
    .unwrap();
    let mut accumulator: FrozenFrontierAccumulator = FrozenFrontierAccumulator::new(
        &resolver(),
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        domain(),
        CLOSURE_REQUEST_ID,
        CLOSURE_HEIGHT,
    )
    .unwrap();
    for entry in entries {
        accumulator.push(&resolver(), entry).unwrap();
    }
    certifier
        .cast_vote(accumulator.into_identity(), signer)
        .unwrap()
}

fn one_page(entries: &[AvailabilityIdentity]) -> FrozenFrontierPage {
    FrozenFrontierPage {
        after_request_id: None,
        entries: entries.to_vec(),
        terminal: true,
    }
}

fn sorted(mut votes: Vec<FrozenFrontierVote>) -> Vec<FrozenFrontierVote> {
    votes.sort_by_key(|vote| vote.validator);
    votes
}

/// Fully drives one signer's single-member frontier over `id` to completion
/// on `replica`, importing the real bundle along the way.
fn complete_signer(
    replica: &RetentionReplica,
    signer: &TestSigner,
    id: &AvailabilityIdentity,
    bundle: &PublicationBundle,
) -> FrozenFrontierVote {
    let vote: FrozenFrontierVote = cast_vote(signer, std::slice::from_ref(id));
    ingest_drain_signer_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
        vote.clone(),
        one_page(std::slice::from_ref(id)),
    )
    .unwrap();
    import_staged_drain_publication(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        signer.validator_id(),
        &encode_publication_bundle(bundle).unwrap(),
    )
    .unwrap();
    assert_eq!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
            id.request_id,
        )
        .unwrap(),
        *id
    );
    vote
}

fn advance_to_ready(
    replica: &RetentionReplica,
    selected: &[FrozenFrontierVote],
) -> consensus::DrainUnionIdentity {
    loop {
        match ordered_economics::advance_drain_union(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            selected,
        )
        .unwrap()
        {
            ordered_economics::DrainUnionStep::Ready(identity) => return *identity,
            ordered_economics::DrainUnionStep::Advanced { .. } => {}
        }
    }
}

/// The standard fixture: a fresh replica D that never locally prepares the
/// certified transfer X, a genuine 3-of-4 quorum of validators each
/// attesting a complete single-member frontier over X, the resulting drain
/// union reconstructed to readiness, and a coherent committed
/// [`DrainSetRecord`] installed directly (test-only, mirroring `close()`'s
/// own direct write of the committed Freeze -- exercising
/// `apply_drain_member`'s own independent re-verification of storage, not
/// the ordered-economics consensus wiring DR-0159's own tests already
/// cover).
fn drain_ready_fixture(prepared_request: Option<u8>) -> (RetentionReplica, AvailabilityIdentity) {
    let d: RetentionReplica = logical_replica();
    if let Some(request) = prepared_request {
        // Any local prepare reserves its locks while the old epoch is open.
        // Freeze must prohibit new prepares afterward.
        d.prepare_transfer(request, FIRST_PAID_NONCE).unwrap();
    }
    close(&d);
    let (bundle, _certificate) = transfer_bundle_bytes(X_REQUEST, FIRST_PAID_NONCE);
    let x_identity: AvailabilityIdentity = commit_ready_bundle(&d, &bundle);
    (d, x_identity)
}

fn commit_ready_bundle(d: &RetentionReplica, bundle: &PublicationBundle) -> AvailabilityIdentity {
    let x_identity: AvailabilityIdentity = identity(bundle);
    import_into(d, bundle, &x_identity);

    let (signers, _entries) = four_validators();
    let vote_a: FrozenFrontierVote = complete_signer(d, &signers[0], &x_identity, bundle);
    let vote_b: FrozenFrontierVote = complete_signer(d, &signers[1], &x_identity, bundle);
    let vote_c: FrozenFrontierVote = complete_signer(d, &signers[2], &x_identity, bundle);
    let selected: Vec<FrozenFrontierVote> = sorted(vec![vote_a, vote_b, vote_c]);
    let ready_identity: consensus::DrainUnionIdentity = advance_to_ready(d, &selected);

    let record: DrainSetRecord = DrainSetRecord {
        closed_epoch: protocol().epoch(),
        request_id: [0xDD; 32],
        committed_at_block_height: CLOSURE_HEIGHT + 1,
        drain_union_identity: ready_identity,
        selected_votes: selected,
    };
    let key: Vec<u8> = drain_set_record_key(protocol().chain_id(), protocol().epoch()).unwrap();
    d.put_row(key, encode_drain_set_record(&record).unwrap());

    x_identity
}

#[test]
fn a_certified_application_trap_applies_only_its_fee_and_replays_without_a_second_charge() {
    let replicas: Vec<RetentionReplica> = (0..3).map(|_| logical_replica()).collect();
    let (signers, _) = four_validators();
    let signed: Vec<u8> = crate::paid_execution::tests::trapping_mint_call(
        &replicas[0].fixture,
        X_REQUEST,
        FIRST_PAID_NONCE,
    );
    let votes: Vec<FastVote> = replicas
        .iter()
        .enumerate()
        .map(|(index, replica)| {
            crate::fast_path::prepare(
                &replica.store,
                &MemoryBlobStore::default(),
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                &base_policy(),
                &replica.fixture.policy,
                &CountingEngine::new(),
                &signers[index],
                &signed,
                10,
            )
            .unwrap()
        })
        .collect();
    let certifier: FastPathCertifier = FastPathCertifier::new(
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        installed_validator_set(),
    )
    .unwrap();
    let certificate: FastCertificate = certifier
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let bundle: PublicationBundle = crate::fast_path::publication::assemble_publication_bundle(
        &replicas[0].store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &signed,
        &consensus::encode_fast_certificate(&certificate).unwrap(),
    )
    .unwrap();
    let d: RetentionReplica = logical_replica();
    close(&d);
    let member: AvailabilityIdentity = commit_ready_bundle(&d, &bundle);
    let before_cap: DurableObjectHead = d
        .store
        .get_object_head(&context(), domain(), d.fixture.cap.id)
        .unwrap();
    let output: NodeOutput = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        member.request_id,
        999,
    )
    .unwrap();
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Rejected);
    let result: execution::paid_execution::PaidExecutionResult =
        execution::paid_execution::decode_paid_execution_result(
            output.responses()[0].payload().unwrap(),
        )
        .unwrap();
    let (event, certified_result) =
        crate::fast_path::publication::decode_certified_execution_witness(&bundle.witness).unwrap();
    assert_eq!(event, certificate.tx_hash);
    assert_eq!(result, certified_result);
    assert_eq!(
        result.status,
        execution::paid_execution::PaidExecutionStatus::ApplicationFailed
    );
    assert!(result.charged.as_ref().unwrap().actual.get() > 0);
    assert_eq!(
        d.store
            .get_object_head(&context(), domain(), d.fixture.cap.id)
            .unwrap(),
        before_cap
    );
    assert_eq!(
        crate::paid_execution::tests::next_nonce(&d.store),
        FIRST_PAID_NONCE + 1
    );
    let committed = full_snapshot(&d.store);
    let replay_engine: CountingEngine = CountingEngine::new();
    let replay: NodeOutput = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &replay_engine,
        member.request_id,
        999,
    )
    .unwrap();
    assert_eq!(replay, output);
    assert_eq!(replay_engine.calls.get(), 0);
    assert_eq!(full_snapshot(&d.store), committed);
}

#[test]
fn apply_drain_member_resolves_conflicting_partial_prepare_lock_and_applies_the_certificate() {
    let (d, x_identity) = drain_ready_fixture(Some(Y_REQUEST));

    // Y: a genuine local partial prepare on d, over the same fee-source coin
    // and sender/epoch nonce X's own certified inputs require. It can never
    // itself be certified: X's own quorum already reserved that exact
    // object/nonce lock.
    let before: Vec<Option<Vec<u8>>> = d.lock_rows();
    assert!(before[0].is_some(), "Y's object lock must exist");
    assert!(before[1].is_some(), "Y's nonce lock must exist");
    let unrelated_key: Vec<u8> =
        fastpath_lock_key(protocol().chain_id(), ObjectId::new([0xEE; 32])).unwrap();
    d.put_row(unrelated_key.clone(), vec![0xA5]);

    let output: NodeOutput = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        x_identity.request_id,
        10,
    )
    .unwrap();
    assert_eq!(output.responses().len(), 1);
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);

    // Y's conflicting locks are gone, atomically with X's own effects.
    let after: Vec<Option<Vec<u8>>> = d.lock_rows();
    assert!(after[0].is_none(), "Y's object lock must be resolved");
    assert!(after[1].is_none(), "Y's nonce lock must be resolved");
    assert_eq!(d.row(&unrelated_key), Some(vec![0xA5]));
    assert!(d.request_receipt(x_identity.request_id).is_some());

    // The certificate/settlement/commitment-witness rows exist.
    let certificate_key: Vec<u8> =
        fastpath_certificate_key(protocol().chain_id(), &x_identity.request_id).unwrap();
    assert!(d.row(&certificate_key).is_some());
    let settlement_key: Vec<u8> =
        fastpath_settlement_key(protocol().chain_id(), &x_identity.request_id).unwrap();
    assert!(d.row(&settlement_key).is_some());

    // A durable audit row exists for the resolved object lock and names Y as
    // the displaced request and X as the resolving one.
    let object_lock_key: Vec<u8> =
        fastpath_lock_key(protocol().chain_id(), d.fixture.coin.id).unwrap();
    let audit_key: Vec<u8> = drain_lock_resolution_key(
        protocol().chain_id(),
        protocol().epoch(),
        &x_identity.request_id,
        &object_lock_key,
    )
    .unwrap();
    let audit_bytes: Vec<u8> = d.row(&audit_key).expect("lock resolution audit row");
    let audit_record: FastPathDrainLockResolutionRecord =
        decode_drain_lock_resolution_record(&audit_bytes).unwrap();
    assert_eq!(audit_record.resolving_request_id, x_identity.request_id);
    assert_eq!(audit_record.displaced_request_id, [Y_REQUEST; 32]);
    assert_eq!(audit_record.resolved_key, object_lock_key);

    // Exact replay is receipt-first even if the old local ready marker is
    // unavailable after application. It neither re-runs execution nor
    // re-resolves Y's locks.
    let record_key: Vec<u8> =
        drain_set_record_key(protocol().chain_id(), protocol().epoch()).unwrap();
    let record: DrainSetRecord =
        ordered_economics::decode_drain_set_record(&d.row(&record_key).unwrap()).unwrap();
    let selected_pairs: Vec<(ValidatorId, consensus::FrozenFrontierIdentity)> = record
        .selected_votes
        .iter()
        .map(|vote| (vote.validator, vote.identity.clone()))
        .collect();
    let selection_seed: DrainUnionAccumulator = DrainUnionAccumulator::new(
        &resolver(),
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        domain(),
        record.selected_votes[0].identity.closure_request_id,
        record.selected_votes[0].identity.closure_height,
        &selected_pairs,
    )
    .unwrap();
    let selection_digest: Digest32 = selection_seed.identity().entries_digest;
    assert_ne!(selection_digest, record.drain_union_identity.entries_digest);
    let ready_key: Vec<u8> = ordered_economics::drain_union_ready_key(
        protocol().chain_id(),
        protocol().epoch(),
        &selection_digest,
    )
    .unwrap();
    assert!(d.row(&ready_key).is_some());
    d.put_row(ready_key.clone(), vec![0xFF]);
    let applied_head: DurableObjectHead = d.coin_head();
    let replay: NodeOutput = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        x_identity.request_id,
        10,
    )
    .unwrap();
    assert_eq!(
        replay.responses()[0].status(),
        output.responses()[0].status()
    );
    assert_eq!(d.coin_head(), applied_head);
    assert_eq!(d.lock_rows(), after);
    assert_eq!(d.row(&ready_key), Some(vec![0xFF]));
}

#[test]
fn apply_drain_member_never_deletes_a_lock_without_its_matching_partial_prepare() {
    let (d, x_identity) = drain_ready_fixture(Some(Y_REQUEST));
    let y_request_id: [u8; 32] = [Y_REQUEST; 32];
    let prepared_key: Vec<u8> =
        fastpath_prepared_record_key(protocol().chain_id(), &y_request_id).unwrap();
    let mut prepared: records::FastPathPreparedRecord =
        records::decode_fastpath_prepared_record(&d.row(&prepared_key).unwrap()).unwrap();
    prepared.locked_objects.clear();
    d.put_row(
        prepared_key,
        records::encode_fastpath_prepared_record(&prepared).unwrap(),
    );
    let locks_before: Vec<Option<Vec<u8>>> = d.lock_rows();
    let head_before: DurableObjectHead = d.coin_head();
    let result: FastPathResult<NodeOutput> = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        x_identity.request_id,
        10,
    );
    assert!(result.is_err());
    assert_eq!(d.lock_rows(), locks_before);
    assert_eq!(d.coin_head(), head_before);
    assert!(d.request_receipt(x_identity.request_id).is_none());
}

#[test]
fn a_forged_partial_prepare_vote_cannot_authorize_lock_resolution_or_a_receipt() {
    let (d, member) = drain_ready_fixture(Some(Y_REQUEST));
    let key: Vec<u8> =
        fastpath_prepared_record_key(protocol().chain_id(), &[Y_REQUEST; 32]).unwrap();
    let mut prepared: records::FastPathPreparedRecord =
        records::decode_fastpath_prepared_record(&d.row(&key).unwrap()).unwrap();
    let mut vote: FastVote = consensus::decode_fast_vote(&prepared.vote).unwrap();
    vote.signature[0] ^= 1;
    prepared.vote = consensus::encode_fast_vote(&vote).unwrap();
    d.put_row(
        key,
        records::encode_fastpath_prepared_record(&prepared).unwrap(),
    );
    let before = full_snapshot(&d.store);
    assert!(
        apply_drain_member(
            &d.store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &d.fixture.policy,
            &CountingEngine::new(),
            member.request_id,
            999,
        )
        .is_err()
    );
    assert!(d.request_receipt(member.request_id).is_none());
    assert_eq!(full_snapshot(&d.store), before);
}

#[test]
fn apply_drain_member_rejects_a_foreign_nonce_lock_for_a_different_nonce() {
    let (d, x_identity) = drain_ready_fixture(Some(Y_REQUEST));
    let nonce_key: Vec<u8> =
        fastpath_nonce_lock_key(protocol().chain_id(), &sender(), protocol().epoch()).unwrap();
    let mut lock: FastPathNonceLockRecord =
        local_instance_state::decode_fastpath_nonce_lock_record(&d.row(&nonce_key).unwrap())
            .unwrap();
    lock.nonce += 1;
    d.put_row(
        nonce_key,
        local_instance_state::encode_fastpath_nonce_lock_record(&lock).unwrap(),
    );
    let locks_before: Vec<Option<Vec<u8>>> = d.lock_rows();
    let head_before: DurableObjectHead = d.coin_head();
    let result: FastPathResult<NodeOutput> = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        x_identity.request_id,
        10,
    );
    assert!(result.is_err());
    assert_eq!(d.lock_rows(), locks_before);
    assert_eq!(d.coin_head(), head_before);
    assert!(d.request_receipt(x_identity.request_id).is_none());
}

#[test]
fn apply_drain_member_clears_its_own_local_prepare_locks_without_foreign_audit() {
    let (d, x_identity) = drain_ready_fixture(Some(X_REQUEST));
    assert!(d.lock_rows().iter().all(Option::is_some));
    let output: NodeOutput = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        x_identity.request_id,
        10,
    )
    .unwrap();
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);
    assert!(d.lock_rows().iter().all(Option::is_none));
    assert!(d.request_receipt(x_identity.request_id).is_some());
    let object_lock_key: Vec<u8> =
        fastpath_lock_key(protocol().chain_id(), d.fixture.coin.id).unwrap();
    let audit_key: Vec<u8> = drain_lock_resolution_key(
        protocol().chain_id(),
        protocol().epoch(),
        &x_identity.request_id,
        &object_lock_key,
    )
    .unwrap();
    assert!(d.row(&audit_key).is_none());
}

#[test]
fn apply_drain_member_applies_without_any_conflicting_local_lock() {
    let (d, x_identity) = drain_ready_fixture(None);
    assert!(d.lock_rows().iter().all(Option::is_none));

    let output: NodeOutput = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        x_identity.request_id,
        999,
    )
    .unwrap();
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);
    assert!(d.request_receipt(x_identity.request_id).is_some());
}

#[test]
fn ambiguous_member_commit_returns_no_success_then_exact_retry_executes_and_charges_nothing() {
    let (d, member) = drain_ready_fixture(Some(Y_REQUEST));
    let ambiguous: AmbiguousCommitStore<'_> = AmbiguousCommitStore {
        inner: &d.store,
        state: std::cell::Cell::new(false),
        invocation: std::cell::Cell::new(true),
        land_before_outcome: true,
    };
    let engine: CountingEngine = CountingEngine::new();
    let result: FastPathResult<NodeOutput> = apply_drain_member(
        &ambiguous,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &engine,
        member.request_id,
        999,
    );
    assert!(matches!(
        result,
        Err(FastPathError::Node(
            NodeCoreError::DurableCommitIndeterminate(_)
        ))
    ));
    assert!(engine.calls.get() > 0);
    assert!(d.request_receipt(member.request_id).is_some());
    let committed = full_snapshot(&d.store);
    let replay_engine: CountingEngine = CountingEngine::new();
    let replay: NodeOutput = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &replay_engine,
        member.request_id,
        999,
    )
    .unwrap();
    assert_eq!(replay.responses()[0].status(), NodeResponseStatus::Accepted);
    assert_eq!(replay_engine.calls.get(), 0);
    assert_eq!(full_snapshot(&d.store), committed);
}

#[test]
fn missing_application_prerequisite_stops_without_execution_fee_nonce_or_receipt() {
    let (d, member) = drain_ready_fixture(None);
    let key: Vec<u8> = local_instance_state::instance_record_key(
        protocol().chain_id(),
        &d.fixture.instance.creator,
        &d.fixture.instance.seed,
    )
    .unwrap();
    let observed: VersionedStateValue = d
        .store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        d.store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
    let before = full_snapshot(&d.store);
    let engine: CountingEngine = CountingEngine::new();
    assert!(
        apply_drain_member(
            &d.store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &base_policy(),
            &d.fixture.policy,
            &engine,
            member.request_id,
            999,
        )
        .is_err()
    );
    assert_eq!(engine.calls.get(), 0);
    assert!(d.request_receipt(member.request_id).is_none());
    assert_eq!(full_snapshot(&d.store), before);
}

#[test]
fn apply_drain_member_rejects_a_request_id_absent_from_the_committed_union() {
    let (d, _x_identity) = drain_ready_fixture(None);
    let foreign_request_id: [u8; 32] = [0xEE; 32];
    let result = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        foreign_request_id,
        10,
    );
    assert!(matches!(result, Err(FastPathError::Invalid(_))));
}

#[test]
fn apply_drain_member_rejects_when_no_drain_set_is_committed() {
    let d: RetentionReplica = logical_replica();
    close(&d);
    let (bundle, _certificate) = transfer_bundle_bytes(X_REQUEST, FIRST_PAID_NONCE);
    let x_identity: AvailabilityIdentity = identity(&bundle);
    import_into(&d, &bundle, &x_identity);
    // No DrainSetRecord is ever installed.
    let result = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        x_identity.request_id,
        10,
    );
    assert!(matches!(result, Err(FastPathError::Invalid(_))));
}

#[test]
fn apply_drain_member_rejects_a_union_identity_disagreeing_with_local_readiness() {
    let (d, x_identity) = drain_ready_fixture(None);

    // Corrupt the committed record's union digest (structurally still a
    // valid record: `validate_drain_set_record_structure` never checks that
    // `entries_digest` is the *correct* reconstruction, only its bookkeeping
    // fields) so it no longer matches this replica's own re-verified
    // `drain-union-ready/` marker: readiness re-verification must fail
    // closed rather than trusting the record's self-reported identity.
    let key: Vec<u8> = drain_set_record_key(protocol().chain_id(), protocol().epoch()).unwrap();
    let bytes: Vec<u8> = d.row(&key).unwrap();
    let mut record: DrainSetRecord = ordered_economics::decode_drain_set_record(&bytes).unwrap();
    let mut digest_bytes: [u8; 32] = record.drain_union_identity.entries_digest.bytes();
    digest_bytes[0] ^= 1;
    record.drain_union_identity.entries_digest = Digest32::new(
        record.drain_union_identity.entries_digest.algorithm(),
        digest_bytes,
    );
    d.put_row(key, encode_drain_set_record(&record).unwrap());

    let result = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        x_identity.request_id,
        10,
    );
    assert!(matches!(result, Err(FastPathError::Invalid(_))));
}

#[test]
fn apply_drain_member_refuses_to_displace_a_prepare_with_a_local_certificate_outcome() {
    let (d, x_identity) = drain_ready_fixture(Some(Y_REQUEST));
    let head_before: DurableObjectHead = d.coin_head();
    let locks_before: Vec<Option<Vec<u8>>> = d.lock_rows();
    let y_certificate_key: Vec<u8> =
        fastpath_certificate_key(protocol().chain_id(), &[Y_REQUEST; 32]).unwrap();
    // A certificate outcome next to a still-held local prepare is inconsistent
    // state. It must never be papered over by the drain's lock resolution.
    d.put_row(y_certificate_key, vec![0xA5]);

    let result: FastPathResult<NodeOutput> = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        x_identity.request_id,
        10,
    );
    assert!(result.is_err());
    assert_eq!(d.coin_head(), head_before);
    assert_eq!(d.lock_rows(), locks_before);
    assert!(d.request_receipt(x_identity.request_id).is_none());
}

#[test]
fn apply_drain_member_refuses_when_the_committed_freeze_disappears() {
    let (d, x_identity) = drain_ready_fixture(None);
    let head_before: DurableObjectHead = d.coin_head();
    remove_closure(&d);
    let result: FastPathResult<NodeOutput> = apply_drain_member(
        &d.store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &base_policy(),
        &d.fixture.policy,
        &CountingEngine::new(),
        x_identity.request_id,
        10,
    );
    assert!(result.is_err());
    assert_eq!(d.coin_head(), head_before);
    assert!(d.request_receipt(x_identity.request_id).is_none());
}
