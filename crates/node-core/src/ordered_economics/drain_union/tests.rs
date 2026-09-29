use super::*;
use crate::fast_path::FastPathEd25519Verifier;
use crate::fast_path::drain_publication::retain_drain_publication;
use crate::fast_path::tests::{
    RetentionReplica, TestSigner, four_validators, installed_validator_set, logical_replica,
    transfer_bundle_bytes,
};
use crate::ordered_economics::{AdmissionClosureRecord, encode_admission_closure_record};
use crate::paid_execution::tests::{FIRST_PAID_NONCE, context, domain, protocol, resolver};
use consensus::bundle::{PublicationBundle, encode_publication_bundle, verify_publication_bundle};
use consensus::{ConsensusSigner, FastPathCertifier};
use runtime::{DurableDomainStateStore, MemoryDurableStateStore};

const REQUEST: u8 = 0xE5;
const CLOSURE_REQUEST_ID: [u8; 32] = [0x66; 32];
const CLOSURE_HEIGHT: u64 = 4;

fn close(store: &MemoryDurableStateStore) {
    let record = AdmissionClosureRecord {
        closed_epoch: protocol().epoch(),
        request_id: CLOSURE_REQUEST_ID,
        closed_at_block_height: CLOSURE_HEIGHT,
    };
    let key: Vec<u8> = admission_closure_key(protocol().chain_id(), protocol().epoch()).unwrap();
    put_row(
        store,
        key,
        encode_admission_closure_record(&record).unwrap(),
    );
}

fn put_row(store: &MemoryDurableStateStore, key: Vec<u8>, value: Vec<u8>) {
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Put(value)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );
}

fn delete_row(store: &MemoryDurableStateStore, key: Vec<u8>) {
    let revision: StateRevision = store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap()
        .revision();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), revision).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(key, StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
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
    store: &MemoryDurableStateStore,
    bundle: &PublicationBundle,
    identity: &AvailabilityIdentity,
) {
    retain_drain_publication(
        store,
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

/// Builds one signer's real signed complete-frontier vote over exactly
/// `entries`, in ascending order.
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

/// Selection requires ascending, unique validator IDs; a `TestSigner`'s
/// Ed25519-derived ID has no relation to its construction seed's order.
fn sorted(mut votes: Vec<FrozenFrontierVote>) -> Vec<FrozenFrontierVote> {
    votes.sort_by_key(|vote| vote.validator);
    votes
}

fn one_page(entries: &[AvailabilityIdentity]) -> FrozenFrontierPage {
    FrozenFrontierPage {
        after_request_id: None,
        entries: entries.to_vec(),
        terminal: true,
    }
}

#[test]
fn ingest_confirm_and_import_round_trip_across_two_pages_and_reject_replay_and_gaps() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let (bundle2, _) = transfer_bundle_bytes(REQUEST + 1, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let id2: AvailabilityIdentity = identity(&bundle2);
    let (signers, _entries) = four_validators();
    let signer: &TestSigner = &signers[0];
    let vote: FrozenFrontierVote = cast_vote(signer, &[id1.clone(), id2.clone()]);

    let page1: FrozenFrontierPage = FrozenFrontierPage {
        after_request_id: None,
        entries: vec![id1.clone()],
        terminal: false,
    };
    let page2: FrozenFrontierPage = FrozenFrontierPage {
        after_request_id: Some(id1.request_id),
        entries: vec![id2.clone()],
        terminal: true,
    };

    // A gap (skipping straight to page2) is refused before any staging.
    assert!(
        ingest_drain_signer_page(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
            vote.clone(),
            page2.clone(),
        )
        .is_err()
    );

    ingest_drain_signer_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
        vote.clone(),
        page1.clone(),
    )
    .unwrap();
    // Staging a second page before the first is fully confirmed is refused.
    assert!(
        ingest_drain_signer_page(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
            vote.clone(),
            page2.clone(),
        )
        .is_err()
    );

    assert_eq!(
        staged_drain_signer_identity(
            &replica.store,
            &context(),
            domain(),
            &protocol(),
            signer.validator_id()
        )
        .unwrap(),
        id1
    );
    // Confirming before the proof is imported fails closed.
    assert!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
        )
        .is_err()
    );
    assert_eq!(
        import_staged_drain_publication(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
            &encode_publication_bundle(&bundle1).unwrap(),
        )
        .unwrap(),
        id1
    );
    assert_eq!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
        )
        .unwrap(),
        id1
    );
    // Exact replay after confirmation must not error, and must not advance
    // past the already-confirmed entry a second time.
    assert!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
        )
        .is_err()
    );

    ingest_drain_signer_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
        vote.clone(),
        page2,
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
        &encode_publication_bundle(&bundle2).unwrap(),
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
        )
        .unwrap(),
        id2
    );

    // The signer's frontier is now complete: no further ingest or confirm.
    assert!(
        ingest_drain_signer_page(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
            vote,
            one_page(&[]),
        )
        .is_err()
    );
    assert!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
        )
        .is_err()
    );
}

#[test]
fn ingest_rejects_wrong_vote_mixed_freeze_forged_signature_and_foreign_signer() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let (signers, _entries) = four_validators();
    let signer: &TestSigner = &signers[0];
    let vote: FrozenFrontierVote = cast_vote(signer, std::slice::from_ref(&id1));
    let page: FrozenFrontierPage = one_page(std::slice::from_ref(&id1));

    let mut mixed_freeze: FrozenFrontierVote = vote.clone();
    mixed_freeze.identity.closure_height += 1;
    assert!(
        ingest_drain_signer_page(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
            mixed_freeze,
            page.clone(),
        )
        .is_err()
    );

    let mut forged: FrozenFrontierVote = vote.clone();
    forged.signature[0] ^= 1;
    assert!(
        ingest_drain_signer_page(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
            forged,
            page.clone(),
        )
        .is_err()
    );

    // The vote really is validator 0's, but the caller claims it belongs to
    // validator 1.
    assert!(
        ingest_drain_signer_page(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signers[1].validator_id(),
            vote.clone(),
            page,
        )
        .is_err()
    );
}

#[test]
fn confirm_fails_closed_on_missing_and_tombstoned_proof_and_marker() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let (signers, _entries) = four_validators();
    let signer: &TestSigner = &signers[0];
    let vote: FrozenFrontierVote = cast_vote(signer, std::slice::from_ref(&id1));
    ingest_drain_signer_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
        vote,
        one_page(std::slice::from_ref(&id1)),
    )
    .unwrap();

    // Missing proof.
    assert!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
        )
        .is_err()
    );

    import_into(&replica.store, &bundle1, &id1);
    let marker_key: Vec<u8> = crate::fast_path::drain_publication::drain_possession_key(
        protocol().chain_id(),
        protocol().epoch(),
        &id1.request_id,
    )
    .unwrap();
    delete_row(&replica.store, marker_key);
    // Tombstoned possession marker.
    assert!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
        )
        .is_err()
    );
}

#[test]
fn empty_frontier_completes_on_ingest_without_any_confirmation() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (signers, _entries) = four_validators();
    let signer: &TestSigner = &signers[0];
    let vote: FrozenFrontierVote = cast_vote(signer, &[]);
    ingest_drain_signer_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
        vote,
        one_page(&[]),
    )
    .unwrap();
    assert!(
        staged_drain_signer_identity(
            &replica.store,
            &context(),
            domain(),
            &protocol(),
            signer.validator_id()
        )
        .is_err()
    );
    assert!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
        )
        .is_err()
    );
}

/// Fully drives one signer's frontier of exactly `entries` to completion on
/// `store`, importing every real bundle along the way.
fn complete_signer(
    store: &MemoryDurableStateStore,
    signer: &TestSigner,
    entries: &[(AvailabilityIdentity, PublicationBundle)],
) -> FrozenFrontierVote {
    let identities: Vec<AvailabilityIdentity> = entries.iter().map(|(id, _)| id.clone()).collect();
    let vote: FrozenFrontierVote = cast_vote(signer, &identities);
    ingest_drain_signer_page(
        store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
        vote.clone(),
        one_page(&identities),
    )
    .unwrap();
    for (id, bundle) in entries {
        import_staged_drain_publication(
            store,
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
                store,
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                signer.validator_id()
            )
            .unwrap(),
            *id
        );
    }
    vote
}

#[test]
fn union_dedupes_shared_entries_reaches_ready_and_replays_exactly() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let (bundle2, _) = transfer_bundle_bytes(REQUEST + 1, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let id2: AvailabilityIdentity = identity(&bundle2);
    let (signers, _entries) = four_validators();

    let vote_a: FrozenFrontierVote = complete_signer(
        &replica.store,
        &signers[0],
        &[
            (id1.clone(), bundle1.clone()),
            (id2.clone(), bundle2.clone()),
        ],
    );
    let vote_b: FrozenFrontierVote = complete_signer(
        &replica.store,
        &signers[1],
        &[(id1.clone(), bundle1.clone())],
    );
    let vote_c: FrozenFrontierVote = complete_signer(
        &replica.store,
        &signers[2],
        &[(id2.clone(), bundle2.clone())],
    );
    let selected: Vec<FrozenFrontierVote> = sorted(vec![vote_a, vote_b, vote_c]);

    let step1: DrainUnionStep = advance_drain_union(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        &selected,
    )
    .unwrap();
    assert_eq!(step1, DrainUnionStep::Advanced { member_count: 1 });
    let step2: DrainUnionStep = advance_drain_union(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        &selected,
    )
    .unwrap();
    assert_eq!(step2, DrainUnionStep::Advanced { member_count: 2 });
    let step3: DrainUnionStep = advance_drain_union(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        &selected,
    )
    .unwrap();
    let ready_identity: DrainUnionIdentity = match step3 {
        DrainUnionStep::Ready(identity) => *identity,
        DrainUnionStep::Advanced { .. } => panic!("expected the union to be ready"),
    };
    assert_eq!(ready_identity.member_count, 2);
    assert_eq!(ready_identity.signer_count, 3);

    // Exact replay after readiness returns the same identity without
    // rescanning or re-merging anything.
    let replay: DrainUnionStep = advance_drain_union(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        &selected,
    )
    .unwrap();
    assert_eq!(
        replay,
        DrainUnionStep::Ready(Box::new(ready_identity.clone()))
    );

    let verified: DrainUnionIdentity = verify_drain_ready(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        &selected,
    )
    .unwrap();
    assert_eq!(verified, ready_identity);

    // A changed selection disagrees with the committed ready marker.
    let changed_selection: Vec<FrozenFrontierVote> = selected[..2].to_vec();
    assert!(
        verify_drain_ready(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            &changed_selection,
        )
        .is_err()
    );
}

#[test]
fn union_refuses_underquorum_forged_and_incomplete_selection() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let (signers, _entries) = four_validators();

    let vote_a: FrozenFrontierVote = complete_signer(
        &replica.store,
        &signers[0],
        &[(id1.clone(), bundle1.clone())],
    );
    let vote_b: FrozenFrontierVote =
        complete_signer(&replica.store, &signers[1], &[(id1.clone(), bundle1)]);

    // Below the 3-of-4 quorum.
    assert!(
        advance_drain_union(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            &[vote_a.clone(), vote_b.clone()],
        )
        .is_err()
    );

    // Validator 2 was never ingested/confirmed at all.
    let vote_c: FrozenFrontierVote = cast_vote(&signers[2], std::slice::from_ref(&id1));
    assert!(
        advance_drain_union(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            &sorted(vec![vote_a.clone(), vote_b.clone(), vote_c]),
        )
        .is_err()
    );

    // A forged signature on an otherwise-selected vote.
    let mut forged: FrozenFrontierVote = vote_b;
    forged.signature[0] ^= 1;
    assert!(
        advance_drain_union(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            &sorted(vec![vote_a, forged]),
        )
        .is_err()
    );
}

#[test]
fn union_detects_a_cross_signer_conflict_at_the_same_request_id() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let (bundle3, _) = transfer_bundle_bytes(REQUEST + 2, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let id3: AvailabilityIdentity = identity(&bundle3);
    let mut conflicting: AvailabilityIdentity = id1.clone();
    conflicting.signed_intent_digest = id1.execution_commitment;
    let (signers, _entries) = four_validators();

    let vote_a: FrozenFrontierVote =
        complete_signer(&replica.store, &signers[0], &[(id1.clone(), bundle1)]);
    let vote_c: FrozenFrontierVote =
        complete_signer(&replica.store, &signers[2], &[(id3.clone(), bundle3)]);
    // Signer B's own local complete frontier legitimately differs; this
    // simulates a Byzantine or corrupted signer whose confirmed entry
    // disagrees with signer A's for the exact same request ID. In the
    // ordinary pipeline this is already refused earlier, at
    // `import_staged_drain_publication`'s shared content-addressed dedup
    // (two different identities can never both be durably retained for one
    // request ID); this test exercises `advance_drain_union`'s own
    // defense-in-depth conflict check directly against a hand-placed row.
    let vote_b: FrozenFrontierVote = cast_vote(&signers[1], &[conflicting.clone()]);
    let entry_key: Vec<u8> = drain_signer_entry_key(
        protocol().chain_id(),
        protocol().epoch(),
        signers[1].validator_id(),
        &conflicting.request_id,
    )
    .unwrap();
    put_row(
        &replica.store,
        entry_key,
        encode_availability_identity(&conflicting).unwrap(),
    );
    let progress_key: Vec<u8> = drain_signer_progress_key(
        protocol().chain_id(),
        protocol().epoch(),
        signers[1].validator_id(),
    )
    .unwrap();
    let fake_progress = SignerProgressRecord {
        vote: vote_b.clone(),
        confirmed_identity: vote_b.identity.clone(),
        confirmed_last_request_id: Some(conflicting.request_id),
        staged_page: None,
        complete: true,
    };
    put_row(
        &replica.store,
        progress_key,
        encode_signer_progress(&fake_progress).unwrap(),
    );

    assert!(
        advance_drain_union(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            &sorted(vec![vote_a, vote_b, vote_c]),
        )
        .is_err()
    );
}

#[test]
fn crash_between_import_and_confirm_leaves_only_a_harmless_extra_proof() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let (signers, _entries) = four_validators();
    let signer: &TestSigner = &signers[0];
    let vote: FrozenFrontierVote = cast_vote(signer, std::slice::from_ref(&id1));
    ingest_drain_signer_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
        vote,
        one_page(std::slice::from_ref(&id1)),
    )
    .unwrap();
    let progress_key: Vec<u8> = drain_signer_progress_key(
        protocol().chain_id(),
        protocol().epoch(),
        signer.validator_id(),
    )
    .unwrap();
    let before: Vec<u8> = replica.row(&progress_key).unwrap();

    // The import commits (a real, separate, atomic commit)...
    import_staged_drain_publication(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        signer.validator_id(),
        &encode_publication_bundle(&bundle1).unwrap(),
    )
    .unwrap();
    // ...but a crash before confirm leaves signer progress completely
    // unchanged: only a harmless extra retained proof exists.
    assert_eq!(replica.row(&progress_key).unwrap(), before);

    // A later retry confirms normally, re-verifying the already-retained
    // proof from storage.
    assert_eq!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
        )
        .unwrap(),
        id1
    );
}
