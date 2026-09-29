//! DR-0161 regressions: canonical round trips and negative decode cases for
//! both local rows, key stability, and a genuine two-member drain-completion
//! walk (a real 3-of-4 quorum, a real reconstructed union, and real committed
//! receipts) covering resumability, missing/mismatched receipts, tombstones
//! and a tampered terminal marker.
use super::*;
use crate::fast_path::FastPathEd25519Verifier;
use crate::fast_path::drain_publication::retain_drain_publication;
use crate::fast_path::tests::{
    RetentionReplica, TestSigner, four_validators, installed_validator_set, logical_replica,
    transfer_bundle_bytes,
};
use crate::ordered_economics::{
    AdmissionClosureRecord, DrainSetRecord, DrainUnionStep, admission_closure_key,
    advance_drain_union, confirm_drain_signer_entry, drain_set_record_key,
    encode_admission_closure_record, encode_drain_set_record, import_staged_drain_publication,
    ingest_drain_signer_page,
};
use crate::paid_execution::tests::{FIRST_PAID_NONCE, context, domain, protocol, resolver};
use canonical_encoding::CanonicalStruct;
use consensus::bundle::{PublicationBundle, encode_publication_bundle, verify_publication_bundle};
use consensus::{
    AvailabilityIdentity, ConsensusSigner, DrainUnionIdentity, FastPathCertifier,
    FrozenFrontierAccumulator, FrozenFrontierCertifier, FrozenFrontierPage, FrozenFrontierVote,
};
use protocol_types::{ChainId, Digest32, Epoch, HashAlgorithmId, ProtocolVersion};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicityDomainId,
    DurableCommitOutcome, DurableDomainStateStore, DurableInvocationTransaction,
    DurableObjectChanges, DurableRequestId, DurableRequestReceipt, StateMutation,
    StateMutationEntry, StateReadAssertion, StructuredDurableDomainStateStore, VersionedStateValue,
};

const CLOSURE_REQUEST_ID: [u8; 32] = [0x91; 32];
const CLOSURE_HEIGHT: u64 = 4;
const X_REQUEST: u8 = 0xC1;
const Z_REQUEST: u8 = 0xC3;

fn sample_union_identity() -> DrainUnionIdentity {
    DrainUnionIdentity {
        chain_id: ChainId::new("drain-completion-tests").unwrap(),
        protocol_version: ProtocolVersion::new(1),
        epoch: Epoch::new(3),
        domain: AtomicityDomainId::new([2; 32]).unwrap(),
        closure_request_id: [9; 32],
        closure_height: 7,
        signer_count: 3,
        member_count: 2,
        entries_digest: Digest32::new(HashAlgorithmId::Blake3_256, [3; 32]),
    }
}

#[test]
fn drain_completion_progress_round_trips_with_and_without_a_cursor() {
    let mut seed: DrainUnionIdentity = sample_union_identity();
    seed.member_count = 0;
    let base: DrainCompletionProgressRecord = DrainCompletionProgressRecord {
        drain_set_request_id: [4; 32],
        running_identity: seed,
        last_request_id: None,
    };
    let bytes: Vec<u8> = encode_completion_progress(&base).unwrap();
    assert_eq!(decode_completion_progress(&bytes).unwrap(), base);

    let mut running: DrainUnionIdentity = sample_union_identity();
    running.member_count = 1;
    let advanced: DrainCompletionProgressRecord = DrainCompletionProgressRecord {
        running_identity: running,
        last_request_id: Some([0xC1; 32]),
        ..base
    };
    let bytes: Vec<u8> = encode_completion_progress(&advanced).unwrap();
    assert_eq!(decode_completion_progress(&bytes).unwrap(), advanced);
}

#[test]
fn drain_completion_record_round_trips() {
    let record: DrainCompletionRecord = DrainCompletionRecord {
        drain_set_request_id: [4; 32],
        drain_union_identity: sample_union_identity(),
    };
    let bytes: Vec<u8> = encode_completion_record(&record).unwrap();
    assert_eq!(decode_completion_record(&bytes).unwrap(), record);
}

#[test]
fn drain_completion_progress_decode_rejects_wrong_frame_type() {
    let mut frame = CanonicalStruct::new(0x1234, ENCODING_VERSION);
    frame.field_bytes(1, vec![1, 2, 3]).unwrap();
    let bytes: Vec<u8> = frame.finish().unwrap();
    assert!(decode_completion_progress(&bytes).is_err());
}

#[test]
fn drain_completion_record_decode_rejects_truncation() {
    let record: DrainCompletionRecord = DrainCompletionRecord {
        drain_set_request_id: [4; 32],
        drain_union_identity: sample_union_identity(),
    };
    let mut bytes: Vec<u8> = encode_completion_record(&record).unwrap();
    bytes.truncate(bytes.len() - 1);
    assert!(decode_completion_record(&bytes).is_err());
}

#[test]
fn drain_completion_rows_reject_oversized_input_before_decoding() {
    let oversized: Vec<u8> = vec![0; MAX_DRAIN_COMPLETION_ROW_BYTES + 1];
    assert!(decode_completion_progress(&oversized).is_err());
    assert!(decode_completion_record(&oversized).is_err());
}

#[test]
fn drain_completion_keys_are_stable_and_chain_and_epoch_scoped() {
    let a: ChainId = ChainId::new("chain-a").unwrap();
    let b: ChainId = ChainId::new("chain-b").unwrap();
    assert_eq!(
        drain_completion_key(&a, Epoch::new(4)).unwrap(),
        drain_completion_key(&a, Epoch::new(4)).unwrap()
    );
    assert_ne!(
        drain_completion_key(&a, Epoch::new(4)).unwrap(),
        drain_completion_key(&b, Epoch::new(4)).unwrap()
    );
    assert_ne!(
        drain_completion_key(&a, Epoch::new(4)).unwrap(),
        drain_completion_key(&a, Epoch::new(5)).unwrap()
    );
    assert_ne!(
        drain_completion_key(&a, Epoch::new(4)).unwrap(),
        drain_completion_progress_key(&a, Epoch::new(4)).unwrap()
    );
}

fn close(replica: &RetentionReplica) {
    let record: AdmissionClosureRecord = AdmissionClosureRecord {
        closed_epoch: protocol().epoch(),
        request_id: CLOSURE_REQUEST_ID,
        closed_at_block_height: CLOSURE_HEIGHT,
    };
    let key: Vec<u8> = admission_closure_key(protocol().chain_id(), protocol().epoch()).unwrap();
    replica.put_row(key, encode_admission_closure_record(&record).unwrap());
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

/// Drives one signer's genuine two-member frontier over `entries` to
/// completion, importing each real bundle in ascending order along the way.
fn complete_signer(
    replica: &RetentionReplica,
    signer: &TestSigner,
    entries: &[AvailabilityIdentity],
    bundles: &[PublicationBundle],
) -> FrozenFrontierVote {
    let vote: FrozenFrontierVote = cast_vote(signer, entries);
    ingest_drain_signer_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &protocol(),
        signer.validator_id(),
        vote.clone(),
        one_page(entries),
    )
    .unwrap();
    for (entry, bundle) in entries.iter().zip(bundles.iter()) {
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
                entry.request_id,
            )
            .unwrap(),
            *entry
        );
    }
    vote
}

fn advance_to_ready(
    replica: &RetentionReplica,
    selected: &[FrozenFrontierVote],
) -> DrainUnionIdentity {
    loop {
        match advance_drain_union(
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
            DrainUnionStep::Ready(identity) => return *identity,
            DrainUnionStep::Advanced { .. } => {}
        }
    }
}

/// A fresh replica with a genuine locally committed two-member `DrainSet`
/// (`X` then `Z`, ascending by request id): a real 3-of-4 quorum of
/// validators each attesting a complete two-member frontier, the resulting
/// drain union reconstructed to readiness, and a coherent committed
/// [`DrainSetRecord`] installed directly (test-only, exactly like
/// `fast_path::drain_apply::tests`'s own fixture, exercising this module's
/// own independent re-verification rather than the consensus wiring
/// DR-0159's own tests already cover). No receipt exists for either member
/// yet.
fn drain_set_fixture() -> (
    RetentionReplica,
    AvailabilityIdentity,
    AvailabilityIdentity,
    DrainSetRecord,
) {
    let d: RetentionReplica = logical_replica();
    close(&d);

    let (x_bundle, _x_certificate) = transfer_bundle_bytes(X_REQUEST, FIRST_PAID_NONCE);
    let x_identity: AvailabilityIdentity = identity(&x_bundle);
    import_into(&d, &x_bundle, &x_identity);

    let (z_bundle, _z_certificate) = transfer_bundle_bytes(Z_REQUEST, FIRST_PAID_NONCE);
    let z_identity: AvailabilityIdentity = identity(&z_bundle);
    import_into(&d, &z_bundle, &z_identity);

    let (signers, _entries) = four_validators();
    let entries: Vec<AvailabilityIdentity> = vec![x_identity.clone(), z_identity.clone()];
    let bundles: Vec<PublicationBundle> = vec![x_bundle, z_bundle];
    let vote_a: FrozenFrontierVote = complete_signer(&d, &signers[0], &entries, &bundles);
    let vote_b: FrozenFrontierVote = complete_signer(&d, &signers[1], &entries, &bundles);
    let vote_c: FrozenFrontierVote = complete_signer(&d, &signers[2], &entries, &bundles);
    let selected: Vec<FrozenFrontierVote> = sorted(vec![vote_a, vote_b, vote_c]);
    let ready_identity: DrainUnionIdentity = advance_to_ready(&d, &selected);

    let record: DrainSetRecord = DrainSetRecord {
        closed_epoch: protocol().epoch(),
        request_id: [0xDD; 32],
        committed_at_block_height: CLOSURE_HEIGHT + 1,
        drain_union_identity: ready_identity,
        selected_votes: selected,
    };
    let key: Vec<u8> = drain_set_record_key(protocol().chain_id(), protocol().epoch()).unwrap();
    d.put_row(key, encode_drain_set_record(&record).unwrap());

    (d, x_identity, z_identity, record)
}

fn commit_receipt(replica: &RetentionReplica, request_id: [u8; 32], event_digest: Digest32) {
    let receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        DurableRequestId::new(request_id).unwrap(),
        event_digest,
        vec![0xAA],
    )
    .unwrap();
    let objects: DurableObjectChanges = DurableObjectChanges::new(Vec::new(), Vec::new()).unwrap();
    let invocation: DurableInvocationTransaction =
        DurableInvocationTransaction::new(domain(), None, objects, receipt, None).unwrap();
    assert_eq!(
        replica.store.commit_invocation(&context(), invocation),
        DurableCommitOutcome::Committed
    );
}

fn delete_row(replica: &RetentionReplica, key: Vec<u8>) {
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

#[test]
fn advance_drain_completion_stops_before_any_drain_set_is_committed() {
    let d: RetentionReplica = logical_replica();
    close(&d);
    let result = advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(result, Err(DrainCompletionError::NotReady(_))));
}

#[test]
fn advance_drain_completion_stops_when_the_first_members_receipt_is_missing() {
    let (d, _x, _z, _record) = drain_set_fixture();
    let result = advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(result, Err(DrainCompletionError::NotReady(_))));
}

#[test]
fn advance_drain_completion_rejects_a_receipt_with_a_mismatched_digest_without_recording_progress()
{
    let (d, x, _z, _record) = drain_set_fixture();
    let wrong: Digest32 = Digest32::new(x.signed_intent_digest.algorithm(), [0xEE; 32]);
    commit_receipt(&d, x.request_id, wrong);
    let result = advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(result, Err(DrainCompletionError::Invalid(_))));
    let progress_key: Vec<u8> =
        drain_completion_progress_key(protocol().chain_id(), protocol().epoch()).unwrap();
    assert!(d.row(&progress_key).is_none());
}

#[test]
fn advance_drain_completion_advances_each_member_then_completes_and_is_idempotent() {
    let (d, x, z, record) = drain_set_fixture();

    commit_receipt(&d, x.request_id, x.signed_intent_digest);
    let step =
        advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();
    assert_eq!(
        step,
        DrainCompletionStep::Advanced {
            request_id: x.request_id
        }
    );

    // Z has no receipt yet: still not ready, even though X already advanced.
    let result = advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(result, Err(DrainCompletionError::NotReady(_))));

    commit_receipt(&d, z.request_id, z.signed_intent_digest);
    let step =
        advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();
    assert_eq!(
        step,
        DrainCompletionStep::Advanced {
            request_id: z.request_id
        }
    );

    let step =
        advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();
    match step {
        DrainCompletionStep::Complete(identity) => {
            assert_eq!(*identity, record.drain_union_identity)
        }
        DrainCompletionStep::Advanced { .. } => panic!("expected completion"),
    }

    // Idempotent: the immutable marker is returned again without redoing work.
    let step =
        advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();
    match step {
        DrainCompletionStep::Complete(identity) => {
            assert_eq!(*identity, record.drain_union_identity)
        }
        DrainCompletionStep::Advanced { .. } => panic!("expected completion"),
    }

    let verified: DrainUnionIdentity =
        verify_drain_complete(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();
    assert_eq!(verified, record.drain_union_identity);
}

#[test]
fn verify_drain_complete_is_not_ready_before_completion() {
    let (d, _x, _z, _record) = drain_set_fixture();
    let result = verify_drain_complete(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(result, Err(DrainCompletionError::NotReady(_))));
}

#[test]
fn advance_drain_completion_rejects_a_tombstoned_progress_row() {
    let (d, x, _z, _record) = drain_set_fixture();
    commit_receipt(&d, x.request_id, x.signed_intent_digest);
    advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();

    let progress_key: Vec<u8> =
        drain_completion_progress_key(protocol().chain_id(), protocol().epoch()).unwrap();
    delete_row(&d, progress_key);

    let result = advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(result, Err(DrainCompletionError::Invalid(_))));
}

#[test]
fn advance_drain_completion_rejects_a_tombstoned_completion_row() {
    let (d, x, z, _record) = drain_set_fixture();
    commit_receipt(&d, x.request_id, x.signed_intent_digest);
    advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();
    commit_receipt(&d, z.request_id, z.signed_intent_digest);
    advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();
    advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();

    let completion_key: Vec<u8> =
        drain_completion_key(protocol().chain_id(), protocol().epoch()).unwrap();
    delete_row(&d, completion_key);

    let result = advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(result, Err(DrainCompletionError::Invalid(_))));
    let verify_result =
        verify_drain_complete(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(
        verify_result,
        Err(DrainCompletionError::Invalid(_))
    ));
}

#[test]
fn advance_drain_completion_rejects_a_completion_marker_disagreeing_with_the_drain_set() {
    let (d, x, z, record) = drain_set_fixture();
    commit_receipt(&d, x.request_id, x.signed_intent_digest);
    advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();
    commit_receipt(&d, z.request_id, z.signed_intent_digest);
    advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();
    advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol()).unwrap();

    let mut tampered_identity: DrainUnionIdentity = record.drain_union_identity.clone();
    tampered_identity.member_count += 1;
    let tampered: DrainCompletionRecord = DrainCompletionRecord {
        drain_set_request_id: record.request_id,
        drain_union_identity: tampered_identity,
    };
    let completion_key: Vec<u8> =
        drain_completion_key(protocol().chain_id(), protocol().epoch()).unwrap();
    d.put_row(completion_key, encode_completion_record(&tampered).unwrap());

    // A future Seal voter must not accept the marker without independently
    // checking it against the committed DrainSet and local ready marker.
    let verified = verify_drain_complete(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(verified, Err(DrainCompletionError::Invalid(_))));

    // `advance_drain_completion` always re-reads the committed record and
    // fails closed on the disagreement instead.
    let result = advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(result, Err(DrainCompletionError::Invalid(_))));
}

#[test]
fn terminal_scan_does_not_complete_with_a_skipped_member_cursor() {
    let (d, _x, z, record) = drain_set_fixture();
    let selected_pairs: Vec<(ValidatorId, consensus::FrozenFrontierIdentity)> = record
        .selected_votes
        .iter()
        .map(|vote| (vote.validator, vote.identity.clone()))
        .collect();
    let seed: DrainUnionAccumulator = DrainUnionAccumulator::new(
        &resolver(),
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        domain(),
        CLOSURE_REQUEST_ID,
        CLOSURE_HEIGHT,
        &selected_pairs,
    )
    .unwrap();
    let mut forged_running: DrainUnionIdentity = seed.identity().clone();
    forged_running.member_count = 1;
    let progress: DrainCompletionProgressRecord = DrainCompletionProgressRecord {
        drain_set_request_id: record.request_id,
        running_identity: forged_running,
        last_request_id: Some(z.request_id),
    };
    let progress_key: Vec<u8> =
        drain_completion_progress_key(protocol().chain_id(), protocol().epoch()).unwrap();
    d.put_row(progress_key, encode_completion_progress(&progress).unwrap());

    let result = advance_drain_completion(&d.store, &context(), domain(), &resolver(), &protocol());
    assert!(matches!(result, Err(DrainCompletionError::Invalid(_))));
    let completion_key: Vec<u8> =
        drain_completion_key(protocol().chain_id(), protocol().epoch()).unwrap();
    assert!(d.row(&completion_key).is_none());
}
