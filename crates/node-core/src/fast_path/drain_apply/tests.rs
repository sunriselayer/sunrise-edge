//! U7 regressions: a real four-validator quorum, a genuine drain union
//! reconstructed on a fourth replica that never locally prepared the
//! certified operation, and a genuine conflicting local partial prepare that
//! `apply_drain_member` must resolve atomically with the certified effects.
use super::*;
use crate::fast_path::drain_publication::retain_drain_publication;
use crate::fast_path::tests::{
    RetentionReplica, TestSigner, four_validators, installed_validator_set, logical_replica,
    transfer_bundle_bytes,
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
    AvailabilityIdentity, ConsensusSigner, FastPathCertifier, FrozenFrontierAccumulator,
    FrozenFrontierCertifier, FrozenFrontierPage, FrozenFrontierVote,
};
use runtime::MemoryBlobStore;

const CLOSURE_REQUEST_ID: [u8; 32] = [0x77; 32];
const CLOSURE_HEIGHT: u64 = 4;
const X_REQUEST: u8 = 0xC1;
const Y_REQUEST: u8 = 0xC2;

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
    let x_identity: AvailabilityIdentity = identity(&bundle);
    import_into(&d, &bundle, &x_identity);

    let (signers, _entries) = four_validators();
    let vote_a: FrozenFrontierVote = complete_signer(&d, &signers[0], &x_identity, &bundle);
    let vote_b: FrozenFrontierVote = complete_signer(&d, &signers[1], &x_identity, &bundle);
    let vote_c: FrozenFrontierVote = complete_signer(&d, &signers[2], &x_identity, &bundle);
    let selected: Vec<FrozenFrontierVote> = sorted(vec![vote_a, vote_b, vote_c]);
    let ready_identity: consensus::DrainUnionIdentity = advance_to_ready(&d, &selected);

    let record: DrainSetRecord = DrainSetRecord {
        closed_epoch: protocol().epoch(),
        request_id: [0xDD; 32],
        committed_at_block_height: CLOSURE_HEIGHT + 1,
        drain_union_identity: ready_identity,
        selected_votes: selected,
    };
    let key: Vec<u8> = drain_set_record_key(protocol().chain_id(), protocol().epoch()).unwrap();
    d.put_row(key, encode_drain_set_record(&record).unwrap());

    (d, x_identity)
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
    let ready_key: Vec<u8> = ordered_economics::drain_union_ready_key(
        protocol().chain_id(),
        protocol().epoch(),
        &record.drain_union_identity.entries_digest,
    )
    .unwrap();
    d.put_row(ready_key, vec![0xFF]);
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
