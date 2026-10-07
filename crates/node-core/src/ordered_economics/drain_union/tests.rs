use super::*;
use crate::fast_path::drain_publication::{
    drain_possession_key, drain_publication_artifact_key, drain_publication_key,
    retain_drain_publication,
};
use crate::fast_path::publication::{
    FastPathPublicationRecord, PublicationRetentionError, encode_fastpath_publication_record,
};
use crate::fast_path::tests::{
    RetentionReplica, TestSigner, four_validators, full_snapshot, installed_validator_set,
    logical_replica, logical_replica_bound, seal_namespace, transfer_bundle_bytes,
};
use crate::ordered_economics::{AdmissionClosureRecord, encode_admission_closure_record};
use crate::paid_execution::tests::{FIRST_PAID_NONCE, context, domain, protocol, resolver};
use consensus::bundle::{
    PublicationBundle, encode_artifact_manifest, encode_publication_bundle,
    verify_publication_bundle,
};
use consensus::{ConsensusSigner, FastPathCertifier, encode_fast_certificate};
use protocol_types::{HashAlgorithmId, SignatureSchemeId};
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
        &consensus::Ed25519ConsensusVerifier::new(
            consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
        ),
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

/// Writes the exact `drain-publication/`+`drain-publication-artifact/` rows
/// [`retain_drain_publication`] would have written, but deliberately leaves
/// the `drain-possession/` marker key completely untouched (pristine,
/// `StateRevision::INITIAL`) -- simulating a same-epoch restore that carried
/// the authenticated proof/artifact history without importing the local
/// marker, per DR-0156's own closing paragraph.
fn stage_proof_without_marker(
    store: &MemoryDurableStateStore,
    bundle: &PublicationBundle,
    identity: &AvailabilityIdentity,
) {
    let chain = protocol().chain_id().clone();
    let epoch = protocol().epoch();
    let record = FastPathPublicationRecord {
        context: protocol(),
        request_id: bundle.request_id,
        identity: encode_availability_identity(identity).unwrap(),
        signed_intent: bundle.signed_intent.clone(),
        certificate: encode_fast_certificate(&bundle.certificate).unwrap(),
        witness: bundle.witness.clone(),
        manifest: encode_artifact_manifest(&bundle.manifest).unwrap(),
    };
    for (entry, content) in bundle.manifest.entries.iter().zip(bundle.contents.iter()) {
        let key = drain_publication_artifact_key(&chain, epoch, &bundle.request_id, entry).unwrap();
        put_row(store, key, content.clone());
    }
    let key = drain_publication_key(&chain, epoch, &bundle.request_id).unwrap();
    put_row(
        store,
        key,
        encode_fastpath_publication_record(&record).unwrap(),
    );
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
fn ingest_drain_signer_page_stops_before_commit_once_sealed() {
    let unsealed: RetentionReplica = logical_replica();
    close(&unsealed.store);
    let (signers, _entries) = four_validators();
    let vote: FrozenFrontierVote = cast_vote(&signers[0], &[]);
    let page: FrozenFrontierPage = one_page(&[]);
    ingest_drain_signer_page(
        &unsealed.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signers[0].validator_id(),
        vote.clone(),
        page.clone(),
    )
    .unwrap();

    let sealed: RetentionReplica = logical_replica_bound();
    close(&sealed.store);
    seal_namespace(&sealed.store, domain());
    let before: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&sealed.store);
    let result: Result<(), DrainSignerError> = ingest_drain_signer_page(
        &sealed.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signers[0].validator_id(),
        vote,
        page,
    );
    assert!(
        matches!(
            &result,
            Err(DrainSignerError::Node(NodeCoreError::PersistenceInvariant(
                "outgoing epoch is sealed; live work is forbidden"
            )))
        ),
        "unexpected sealed ingest result: {result:?}"
    );
    let progress_key: Vec<u8> = drain_signer_progress_key(
        protocol().chain_id(),
        protocol().epoch(),
        signers[0].validator_id(),
    )
    .unwrap();
    assert!(
        sealed
            .store
            .get_versioned_durable(&context(), domain(), &progress_key)
            .unwrap()
            .value()
            .is_none()
    );
    let after: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&sealed.store);
    assert_eq!(
        before, after,
        "a sealed ingest must write nothing at all, not merely the named progress row"
    );
}

fn complete_empty_signers(
    store: &MemoryDurableStateStore,
    signers: &[TestSigner],
) -> Vec<FrozenFrontierVote> {
    let votes: Vec<FrozenFrontierVote> = signers
        .iter()
        .map(|signer| {
            let vote: FrozenFrontierVote = cast_vote(signer, &[]);
            ingest_drain_signer_page(
                store,
                &context(),
                domain(),
                &resolver(),
                &protocol(),
                signer.validator_id(),
                vote.clone(),
                one_page(&[]),
            )
            .unwrap();
            vote
        })
        .collect();
    sorted(votes)
}

#[test]
fn advance_drain_union_stops_before_commit_once_sealed() {
    let unsealed: RetentionReplica = logical_replica();
    close(&unsealed.store);
    let (signers, _entries) = four_validators();
    let votes: Vec<FrozenFrontierVote> = complete_empty_signers(&unsealed.store, &signers[..3]);
    let step: DrainUnionStep = advance_drain_union(
        &unsealed.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &votes,
    )
    .unwrap();
    assert!(matches!(step, DrainUnionStep::Ready(_)));

    let sealed: RetentionReplica = logical_replica_bound();
    close(&sealed.store);
    let (sealed_signers, _entries) = four_validators();
    let sealed_votes: Vec<FrozenFrontierVote> =
        complete_empty_signers(&sealed.store, &sealed_signers[..3]);
    seal_namespace(&sealed.store, domain());
    let before: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&sealed.store);
    let result: Result<DrainUnionStep, DrainSignerError> = advance_drain_union(
        &sealed.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &sealed_votes,
    );
    assert!(
        matches!(
            &result,
            Err(DrainSignerError::Node(NodeCoreError::PersistenceInvariant(
                "outgoing epoch is sealed; live work is forbidden"
            )))
        ),
        "unexpected sealed advance result: {result:?}"
    );
    let after: Vec<(runtime::portable::DurableRecordDescriptor, Vec<u8>)> =
        full_snapshot(&sealed.store);
    assert_eq!(
        before, after,
        "a sealed advance must write nothing beyond the Seal completion itself"
    );
}

#[test]
fn union_member_enumerator_refuses_an_entry_under_the_wrong_request_key() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let member: AvailabilityIdentity = identity(&bundle);
    let (signers, _) = four_validators();
    let signer: ValidatorId = signers[0].validator_id();
    let wrong_key: Vec<u8> = drain_signer_entry_key(
        protocol().chain_id(),
        protocol().epoch(),
        signer,
        &[REQUEST + 1; 32],
    )
    .unwrap();
    put_row(
        &replica.store,
        wrong_key,
        encode_availability_identity(&member).unwrap(),
    );
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let result: Result<Option<AvailabilityIdentity>, DrainSignerError> = next_union_member_after(
        &replica.store,
        &context(),
        domain(),
        &protocol(),
        &[signer],
        None,
        &mut reads,
    );
    assert!(matches!(
        result,
        Err(DrainSignerError::Invalid(
            "drain signer entry key disagrees with identity"
        ))
    ));
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
            id1.request_id,
        )
        .is_err()
    );
    // A caller expecting a different request id than the exact next staged
    // one is refused before any proof/possession re-verification, and
    // nothing is committed.
    let mut wrong_request_id: [u8; 32] = id1.request_id;
    wrong_request_id[0] ^= 1;
    let progress_key: Vec<u8> = drain_signer_progress_key(
        protocol().chain_id(),
        protocol().epoch(),
        signer.validator_id(),
    )
    .unwrap();
    let before_wrong_expectation: Vec<u8> = replica.row(&progress_key).unwrap();
    assert!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
            wrong_request_id,
        )
        .is_err()
    );
    assert_eq!(
        replica.row(&progress_key).unwrap(),
        before_wrong_expectation
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
            id1.request_id,
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
            id1.request_id,
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
            id2.request_id,
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
            id2.request_id,
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

    // A correct confirm arriving before import is not-ready, not a
    // permanently invalid proof. The HTTP E2E covers subsequent success.
    assert!(matches!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
            id1.request_id,
        ),
        Err(DrainSignerError::NotReady(
            "drain publication proof is not retained"
        ))
    ));

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
            id1.request_id,
        )
        .is_err()
    );

    let proof_key: Vec<u8> =
        drain_publication_key(protocol().chain_id(), protocol().epoch(), &id1.request_id).unwrap();
    delete_row(&replica.store, proof_key);
    assert!(matches!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
            id1.request_id,
        ),
        Err(DrainSignerError::Publication(error))
            if matches!(
                *error,
                PublicationRetentionError::InconsistentRetainedRecord("tombstoned drain publication")
            )
    ));
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
            [0xAB; 32],
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
                signer.validator_id(),
                id.request_id,
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
        &[],
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
        &[],
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
        &[],
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
        &[],
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

    // The CAS-read variant folds every read into a caller-owned set instead
    // of a fresh, standalone one -- exactly what DrainSet voting needs to
    // commit its own vote atomically together with this readiness check.
    let mut folded_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let verified_into: DrainUnionIdentity = verify_drain_ready_into(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        &selected,
        &mut folded_reads,
    )
    .unwrap();
    assert_eq!(verified_into, ready_identity);
    assert!(!folded_reads.is_empty());

    // A caller whose own read set already pins a stale revision for one of
    // these same keys is refused atomically, exactly like any other CAS
    // conflict in this module -- it never silently observes a newer,
    // inconsistent snapshot for the rest of its own commit.
    let (repeated_key, fresh_revision): (Vec<u8>, StateRevision) = folded_reads
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), *v))
        .unwrap();
    let mut stale_reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    stale_reads.insert(
        repeated_key,
        StateRevision::new(fresh_revision.get().wrapping_add(1)),
    );
    let stale_result = verify_drain_ready_into(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        &selected,
        &mut stale_reads,
    );
    assert!(
        stale_result
            .unwrap_err()
            .to_string()
            .contains("state changed"),
        "a pre-seeded stale revision for a key this check re-reads must fail as a state conflict"
    );

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

    let drain: DrainContext = fence_drain_context(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
    )
    .unwrap();
    let seed: DrainUnionAccumulator =
        selection_seed(&resolver(), &drain.fence, &protocol(), domain(), &selected).unwrap();
    let ready_key: Vec<u8> = drain_union_ready_key(
        &drain.fence.chain,
        drain.fence.epoch,
        &seed.identity().entries_digest,
    )
    .unwrap();
    delete_row(&replica.store, ready_key);
    assert!(matches!(
        verify_drain_ready(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            &selected,
        ),
        Err(DrainSignerError::Invalid("drain union ready is tombstoned"))
    ));
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
            &[],
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
            &[],
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
            &[],
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
            &[],
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
            id1.request_id,
        )
        .unwrap(),
        id1
    );
}

/// B1 regression: an empty signed frontier is already "terminal" the moment
/// it is seeded, so ingest must still verify the real registered signature
/// unconditionally before it can ever stage or complete anything -- not only
/// on the dry-run page-verification branch used for nonempty frontiers.
#[test]
fn ingest_rejects_a_forged_signature_on_an_empty_frontier_vote_and_stages_nothing() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (signers, _entries) = four_validators();
    let signer: &TestSigner = &signers[0];
    let mut forged_empty_vote: FrozenFrontierVote = cast_vote(signer, &[]);
    forged_empty_vote.signature[0] ^= 1;
    assert!(
        ingest_drain_signer_page(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
            forged_empty_vote,
            one_page(&[]),
        )
        .is_err()
    );
    let progress_key: Vec<u8> = drain_signer_progress_key(
        protocol().chain_id(),
        protocol().epoch(),
        signer.validator_id(),
    )
    .unwrap();
    assert!(replica.row(&progress_key).is_none());
}

/// B2 regression: two different, equally valid quorum selections over the
/// exact same completed signer set must progress at two independent keys,
/// each reaching its own `Ready` identity without one clobbering or wedging
/// the other's progress.
#[test]
fn two_valid_selections_over_the_same_signers_progress_independently() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let (signers, _entries) = four_validators();

    let vote0: FrozenFrontierVote = complete_signer(
        &replica.store,
        &signers[0],
        &[(id1.clone(), bundle1.clone())],
    );
    let vote1: FrozenFrontierVote = complete_signer(
        &replica.store,
        &signers[1],
        &[(id1.clone(), bundle1.clone())],
    );
    let vote2: FrozenFrontierVote = complete_signer(
        &replica.store,
        &signers[2],
        &[(id1.clone(), bundle1.clone())],
    );
    let vote3: FrozenFrontierVote =
        complete_signer(&replica.store, &signers[3], &[(id1.clone(), bundle1)]);

    let selection_a: Vec<FrozenFrontierVote> = sorted(vec![vote0.clone(), vote1.clone(), vote2]);
    let selection_b: Vec<FrozenFrontierVote> = sorted(vec![vote0, vote1, vote3]);

    let ready_a: DrainUnionIdentity = run_to_ready(&replica.store, &selection_a);
    let ready_b: DrainUnionIdentity = run_to_ready(&replica.store, &selection_b);
    assert_eq!(ready_a.member_count, 1);
    assert_eq!(ready_b.member_count, 1);
    assert_eq!(ready_a.signer_count, 3);
    assert_eq!(ready_b.signer_count, 3);
    // Different selected rosters must fold to different selection digests
    // even though they share the same single confirmed member.
    assert_ne!(ready_a.entries_digest, ready_b.entries_digest);

    // Each selection independently re-verifies from its own committed
    // marker, without disturbing the other's.
    assert_eq!(
        verify_drain_ready(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            &selection_a
        )
        .unwrap(),
        ready_a
    );
    assert_eq!(
        verify_drain_ready(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            &selection_b
        )
        .unwrap(),
        ready_b
    );
}

fn run_to_ready(
    store: &MemoryDurableStateStore,
    selection: &[FrozenFrontierVote],
) -> DrainUnionIdentity {
    loop {
        match advance_drain_union(
            store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            selection,
        )
        .unwrap()
        {
            DrainUnionStep::Ready(identity) => return *identity,
            DrainUnionStep::Advanced { .. } => {}
        }
    }
}

/// B3 regression: a same-epoch restore may carry the authenticated
/// `drain-publication/`+`drain-publication-artifact/` history while this
/// host's own `drain-possession/` marker is pristine (never written here).
/// Confirmation must independently re-verify the complete saved proof and
/// every artifact against the locally staged, page-authenticated identity,
/// then safely rebuild the marker atomically with this same confirmation.
#[test]
fn confirm_rebuilds_a_pristine_missing_marker_after_a_same_epoch_restore() {
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

    // Simulate the restore: the proof and artifacts exist, but the
    // possession marker was never written on this host.
    stage_proof_without_marker(&replica.store, &bundle1, &id1);
    let marker_key: Vec<u8> =
        drain_possession_key(protocol().chain_id(), protocol().epoch(), &id1.request_id).unwrap();
    assert!(replica.row(&marker_key).is_none());

    assert_eq!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
            id1.request_id,
        )
        .unwrap(),
        id1
    );
    assert_eq!(
        replica.row(&marker_key).unwrap(),
        encode_availability_identity(&id1).unwrap()
    );
}

/// B3 negative: a tombstoned marker (as opposed to a pristine one) must
/// still fail closed rather than being silently rebuilt, even though the
/// proof and artifacts independently re-verify.
#[test]
fn confirm_refuses_to_rebuild_a_tombstoned_marker() {
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
    import_into(&replica.store, &bundle1, &id1);
    let marker_key: Vec<u8> =
        drain_possession_key(protocol().chain_id(), protocol().epoch(), &id1.request_id).unwrap();
    delete_row(&replica.store, marker_key);
    assert!(
        confirm_drain_signer_entry(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            signer.validator_id(),
            id1.request_id,
        )
        .is_err()
    );
}

/// H1 regression: a union step must re-verify the winning member's complete
/// proof/artifacts/marker fresh from storage, not merely trust the signer-
/// entry row's own bytes -- even when *every* selected signer's entry row
/// agrees on a tampered identity (so no cross-signer conflict is raised).
#[test]
fn union_step_rechecks_possession_even_when_every_selected_entry_agrees_on_a_tampered_identity() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let (signers, _entries) = four_validators();

    let vote0: FrozenFrontierVote = complete_signer(
        &replica.store,
        &signers[0],
        &[(id1.clone(), bundle1.clone())],
    );
    let vote1: FrozenFrontierVote = complete_signer(
        &replica.store,
        &signers[1],
        &[(id1.clone(), bundle1.clone())],
    );
    let vote2: FrozenFrontierVote =
        complete_signer(&replica.store, &signers[2], &[(id1.clone(), bundle1)]);

    let mut tampered: AvailabilityIdentity = id1.clone();
    tampered.signed_intent_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    let tampered_bytes: Vec<u8> = encode_availability_identity(&tampered).unwrap();
    for signer in [&signers[0], &signers[1], &signers[2]] {
        let entry_key: Vec<u8> = drain_signer_entry_key(
            protocol().chain_id(),
            protocol().epoch(),
            signer.validator_id(),
            &id1.request_id,
        )
        .unwrap();
        put_row(&replica.store, entry_key, tampered_bytes.clone());
    }

    let selection: Vec<FrozenFrontierVote> = sorted(vec![vote0, vote1, vote2]);
    assert!(
        advance_drain_union(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &selection,
        )
        .is_err()
    );
    // Nothing was committed: no progress row exists for this selection.
    let seed = DrainUnionAccumulator::new(
        &resolver(),
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        domain(),
        CLOSURE_REQUEST_ID,
        CLOSURE_HEIGHT,
        &selected_pairs(&selection),
    )
    .unwrap();
    let progress_key: Vec<u8> = drain_union_progress_key(
        protocol().chain_id(),
        protocol().epoch(),
        &seed.identity().entries_digest,
    )
    .unwrap();
    assert!(replica.row(&progress_key).is_none());
}

#[test]
fn confirmed_signer_entry_without_its_proof_is_corruption_not_retryable_import_wait() {
    let source: RetentionReplica = logical_replica();
    close(&source.store);
    let (bundle, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let identity: AvailabilityIdentity = identity(&bundle);
    let (signers, _entries) = four_validators();
    let mut votes: Vec<FrozenFrontierVote> = Vec::new();
    for signer in signers.iter().take(3) {
        votes.push(complete_signer(
            &source.store,
            signer,
            &[(identity.clone(), bundle.clone())],
        ));
    }
    // Model an inconsistent partial restore that carried signed progress and
    // immutable entry rows but omitted the full publication and artifacts.
    let restored: RetentionReplica = logical_replica();
    close(&restored.store);
    for signer in signers.iter().take(3) {
        let progress_key: Vec<u8> = drain_signer_progress_key(
            protocol().chain_id(),
            protocol().epoch(),
            signer.validator_id(),
        )
        .unwrap();
        let entry_key: Vec<u8> = drain_signer_entry_key(
            protocol().chain_id(),
            protocol().epoch(),
            signer.validator_id(),
            &identity.request_id,
        )
        .unwrap();
        for key in [progress_key, entry_key] {
            restored.put_row(key.clone(), source.row(&key).unwrap());
        }
    }
    let selected: Vec<FrozenFrontierVote> = sorted(votes);
    assert!(matches!(
        advance_drain_union(
            &restored.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &selected,
        ),
        Err(DrainSignerError::Invalid(
            "confirmed signer entry lost its retained drain proof"
        ))
    ));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fixed_frontier_identity(entry_count: u64, digest_byte: u8) -> FrozenFrontierIdentity {
    FrozenFrontierIdentity {
        chain_id: ChainId::new("drain-union-vector-test").unwrap(),
        protocol_version: ProtocolVersion::new(4),
        epoch: Epoch::new(8),
        domain: AtomicityDomainId::new([9; 32]).unwrap(),
        closure_request_id: [7; 32],
        closure_height: 11,
        entry_count,
        entries_digest: Digest32::new(HashAlgorithmId::Sha2_256, [digest_byte; 32]),
    }
}

fn fixed_frontier_vote(validator_byte: u8, identity: FrozenFrontierIdentity) -> FrozenFrontierVote {
    FrozenFrontierVote {
        identity,
        validator: ValidatorId::new([validator_byte; 32]),
        signature_scheme: SignatureSchemeId::Ed25519,
        signature: vec![0x5a; 64],
    }
}

fn fixed_availability_identity(request_byte: u8) -> AvailabilityIdentity {
    AvailabilityIdentity {
        chain_id: ChainId::new("drain-union-vector-test").unwrap(),
        protocol_version: ProtocolVersion::new(4),
        epoch: Epoch::new(8),
        domain: AtomicityDomainId::new([9; 32]).unwrap(),
        request_id: [request_byte; 32],
        signed_intent_digest: Digest32::new(HashAlgorithmId::Sha2_256, [request_byte; 32]),
        execution_commitment: Digest32::new(HashAlgorithmId::Sha2_256, [request_byte + 1; 32]),
        semantic_artifacts_digest: Digest32::new(HashAlgorithmId::Sha2_256, [request_byte + 2; 32]),
    }
}

fn fixed_drain_union_identity() -> DrainUnionIdentity {
    DrainUnionIdentity {
        chain_id: ChainId::new("drain-union-vector-test").unwrap(),
        protocol_version: ProtocolVersion::new(4),
        epoch: Epoch::new(8),
        domain: AtomicityDomainId::new([9; 32]).unwrap(),
        closure_request_id: [7; 32],
        closure_height: 11,
        signer_count: 1,
        member_count: 0,
        entries_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xbb; 32]),
    }
}

/// Stable `0x645B/v1` [`SignerProgressRecord`] vector, pinned so an
/// unintended future field/framing change is caught by CI rather than only
/// by a live-store round trip.
#[test]
fn signer_progress_record_vector_is_stable() {
    let vote: FrozenFrontierVote = fixed_frontier_vote(1, fixed_frontier_identity(0, 0xaa));
    let record = SignerProgressRecord {
        vote: vote.clone(),
        confirmed_identity: fixed_frontier_identity(0, 0xaa),
        confirmed_last_request_id: None,
        staged_page: None,
        complete: false,
    };
    let encoded: Vec<u8> = encode_signer_progress(&record).unwrap();
    assert_eq!(decode_signer_progress(&encoded).unwrap(), record);
    assert_eq!(
        hex(&encoded),
        "534e52455b6401000500010069010000534e524537d0010004000100e5000000534e524536d001000800010017000000647261696e2d756e696f6e2d766563746f722d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b000000000000000700080000000000000000000000080038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa020020000000010101010101010101010101010101010101010101010101010101010101010103000200000001000400400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0200e5000000534e524536d001000800010017000000647261696e2d756e696f6e2d766563746f722d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b000000000000000700080000000000000000000000080038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0300000000000400000000000500020000000000"
    );

    let staged = SignerProgressRecord {
        vote,
        confirmed_identity: fixed_frontier_identity(0, 0xaa),
        confirmed_last_request_id: None,
        staged_page: Some(one_page(&[fixed_availability_identity(1)])),
        complete: false,
    };
    let staged_encoded: Vec<u8> = encode_signer_progress(&staged).unwrap();
    assert_eq!(decode_signer_progress(&staged_encoded).unwrap(), staged);
    assert_ne!(staged_encoded, encoded);
}

/// Stable `0x645C/v1`/`0x645D/v1` [`UnionProgressRecord`]/[`UnionReadyRecord`]
/// vectors.
#[test]
fn union_progress_and_ready_record_vectors_are_stable() {
    let vote: FrozenFrontierVote = fixed_frontier_vote(1, fixed_frontier_identity(1, 0xaa));
    let selection_digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0xcc; 32]);
    let progress = UnionProgressRecord {
        selection_digest,
        identity: fixed_drain_union_identity(),
        selected_votes: vec![vote.clone()],
        last_request_id: None,
    };
    let progress_encoded: Vec<u8> = encode_union_progress(&progress).unwrap();
    assert_eq!(decode_union_progress(&progress_encoded).unwrap(), progress);

    let ready = UnionReadyRecord {
        selection_digest,
        identity: fixed_drain_union_identity(),
        selected_votes: vec![vote],
    };
    let ready_encoded: Vec<u8> = encode_union_ready(&ready).unwrap();
    assert_eq!(decode_union_ready(&ready_encoded).unwrap(), ready);
    assert_ne!(ready_encoded, progress_encoded);

    assert_eq!(
        hex(&progress_encoded),
        "534e52455c64010005000100f3000000534e52453bd001000900010017000000647261696e2d756e696f6e2d766563746f722d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b0000000000000007000800000001000000000000000800080000000000000000000000090038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb020000000000030038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0400020000000100050069010000534e524537d0010004000100e5000000534e524536d001000800010017000000647261696e2d756e696f6e2d766563746f722d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b000000000000000700080000000100000000000000080038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa020020000000010101010101010101010101010101010101010101010101010101010101010103000200000001000400400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    );
    assert_eq!(
        hex(&ready_encoded),
        "534e52455d64010004000100f3000000534e52453bd001000900010017000000647261696e2d756e696f6e2d766563746f722d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b0000000000000007000800000001000000000000000800080000000000000000000000090038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb020038000000534e52450301010002000100020000000100020020000000cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0300020000000100040069010000534e524537d0010004000100e5000000534e524536d001000800010017000000647261696e2d756e696f6e2d766563746f722d74657374020004000000040000000300080000000800000000000000040020000000090909090909090909090909090909090909090909090909090909090909090905002000000007070707070707070707070707070707070707070707070707070707070707070600080000000b000000000000000700080000000100000000000000080038000000534e52450301010002000100020000000100020020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa020020000000010101010101010101010101010101010101010101010101010101010101010103000200000001000400400000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    );
}

/// DR-0158: pristine is not-ready, a partially staged page reports the
/// signer's own vote/running identity/cursor/staged page with `complete ==
/// false`, and full completion reports the terminal identity with `staged_page
/// == None` and `complete == true`. This never mutates or signs anything.
#[test]
fn read_signer_progress_reports_pristine_partial_and_complete_snapshots() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (signers, _entries) = four_validators();
    let signer: &TestSigner = &signers[0];

    // Pristine: nothing staged yet is not-ready, never a silently empty
    // snapshot that a caller could mistake for "zero entries confirmed".
    assert!(matches!(
        read_drain_signer_progress(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
        ),
        Err(DrainSignerError::NotReady(_))
    ));

    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let (bundle2, _) = transfer_bundle_bytes(REQUEST + 1, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let id2: AvailabilityIdentity = identity(&bundle2);
    let vote: FrozenFrontierVote = cast_vote(signer, &[id1.clone(), id2.clone()]);
    let page: FrozenFrontierPage = one_page(&[id1.clone(), id2.clone()]);
    ingest_drain_signer_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
        vote.clone(),
        page.clone(),
    )
    .unwrap();

    let staged: DrainSignerProgress = read_drain_signer_progress(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
    )
    .unwrap();
    assert_eq!(staged.signer, signer.validator_id());
    assert_eq!(staged.vote, vote);
    assert_eq!(staged.confirmed_last_request_id, None);
    assert_eq!(staged.staged_page, Some(page));
    assert!(!staged.complete);

    import_into(&replica.store, &bundle1, &id1);
    confirm_drain_signer_entry(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        signer.validator_id(),
        id1.request_id,
    )
    .unwrap();
    let partial: DrainSignerProgress = read_drain_signer_progress(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
    )
    .unwrap();
    assert_eq!(partial.confirmed_last_request_id, Some(id1.request_id));
    assert!(partial.staged_page.is_some());
    assert!(!partial.complete);

    import_into(&replica.store, &bundle2, &id2);
    confirm_drain_signer_entry(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        signer.validator_id(),
        id2.request_id,
    )
    .unwrap();
    let done: DrainSignerProgress = read_drain_signer_progress(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
    )
    .unwrap();
    assert_eq!(done.confirmed_last_request_id, Some(id2.request_id));
    assert_eq!(done.staged_page, None);
    assert!(done.complete);
    assert_eq!(done.confirmed_identity, vote.identity);
}

/// A caller pinned to a different epoch than the durably installed one gets
/// the same fenced `EpochMismatch` stop, wrapped by the shared publication
/// fence -- never a silently empty or foreign-epoch snapshot.
#[test]
fn read_signer_progress_rejects_wrong_epoch() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (signers, _entries) = four_validators();
    let signer: &TestSigner = &signers[0];
    let wrong_epoch: execution::publication::PublicationContext =
        execution::publication::PublicationContext::new(
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            Epoch::new(protocol().epoch().get() + 1),
        )
        .unwrap();
    assert!(matches!(
        read_drain_signer_progress(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &wrong_epoch,
            signer.validator_id(),
        ),
        Err(DrainSignerError::Publication(inner))
            if matches!(
                inner.as_ref(),
                PublicationRetentionError::Node(NodeCoreError::EpochMismatch { .. })
            )
    ));
}

/// A tombstoned progress row and a malformed one both fail closed rather
/// than being treated as pristine/not-ready.
#[test]
fn read_signer_progress_rejects_tombstoned_and_malformed_rows() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (signers, _entries) = four_validators();
    let signer: &TestSigner = &signers[0];
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
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
    delete_row(&replica.store, progress_key.clone());
    assert!(matches!(
        read_drain_signer_progress(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
        ),
        Err(DrainSignerError::Invalid("signer progress is tombstoned"))
    ));

    put_row(&replica.store, progress_key, vec![0xFF; 4]);
    assert!(matches!(
        read_drain_signer_progress(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
        ),
        Err(DrainSignerError::Node(_))
    ));
}

/// A progress row whose stored vote disagrees with the currently fenced
/// chain/protocol/epoch/domain/Freeze/signer context (for example, a foreign
/// or corrupted row surviving from a different deployment) fails closed
/// instead of being served as this signer's progress.
#[test]
fn read_signer_progress_rejects_context_foreign_row() {
    let replica: RetentionReplica = logical_replica();
    close(&replica.store);
    let (signers, _entries) = four_validators();
    let signer: &TestSigner = &signers[0];
    let (bundle1, _) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let id1: AvailabilityIdentity = identity(&bundle1);
    let vote: FrozenFrontierVote = cast_vote(signer, std::slice::from_ref(&id1));
    ingest_drain_signer_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
        vote.clone(),
        one_page(std::slice::from_ref(&id1)),
    )
    .unwrap();

    let progress_key: Vec<u8> = drain_signer_progress_key(
        protocol().chain_id(),
        protocol().epoch(),
        signer.validator_id(),
    )
    .unwrap();
    let mut foreign_vote: FrozenFrontierVote = vote.clone();
    foreign_vote.identity.domain = AtomicityDomainId::new([0x99; 32]).unwrap();
    let foreign_record = SignerProgressRecord {
        vote: foreign_vote,
        confirmed_identity: FrozenFrontierAccumulator::new(
            &resolver(),
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            protocol().epoch(),
            domain(),
            CLOSURE_REQUEST_ID,
            CLOSURE_HEIGHT,
        )
        .unwrap()
        .into_identity(),
        confirmed_last_request_id: None,
        staged_page: Some(one_page(std::slice::from_ref(&id1))),
        complete: false,
    };
    put_row(
        &replica.store,
        progress_key,
        encode_signer_progress(&foreign_record).unwrap(),
    );
    assert!(matches!(
        read_drain_signer_progress(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
        ),
        Err(DrainSignerError::Invalid(
            "signer progress context mismatch"
        ))
    ));

    let mut foreign_accumulator: FrozenFrontierIdentity = foreign_record.confirmed_identity;
    foreign_accumulator.domain = AtomicityDomainId::new([0x98; 32]).unwrap();
    let foreign_accumulator_record = SignerProgressRecord {
        vote,
        confirmed_identity: foreign_accumulator,
        confirmed_last_request_id: None,
        staged_page: Some(one_page(std::slice::from_ref(&id1))),
        complete: false,
    };
    put_row(
        &replica.store,
        drain_signer_progress_key(
            protocol().chain_id(),
            protocol().epoch(),
            signer.validator_id(),
        )
        .unwrap(),
        encode_signer_progress(&foreign_accumulator_record).unwrap(),
    );
    assert!(matches!(
        read_drain_signer_progress(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &protocol(),
            signer.validator_id(),
        ),
        Err(DrainSignerError::Invalid(
            "signer progress accumulator context mismatch"
        ))
    ));
}
