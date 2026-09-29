use super::*;
use crate::fast_path::tests::{
    RetentionReplica, installed_validator_set, logical_replica, transfer_bundle_bytes,
};
use crate::ordered_economics::{
    AdmissionClosureRecord, FrozenFrontierStep, advance_frozen_frontier,
    encode_admission_closure_record, read_frozen_frontier_page,
};
use crate::paid_execution::tests::{FIRST_PAID_NONCE, context, domain, protocol, resolver};
use consensus::bundle::encode_publication_bundle;
use consensus::{AvailabilityVote, FrozenFrontierPage, FrozenFrontierVote};
use std::num::NonZeroUsize;

const REQUEST: u8 = 0xE4;

fn close(replica: &RetentionReplica) {
    let record: AdmissionClosureRecord = AdmissionClosureRecord {
        closed_epoch: protocol().epoch(),
        request_id: [0x55; 32],
        closed_at_block_height: 3,
    };
    let key: Vec<u8> =
        crate::ordered_economics::admission_closure_key(protocol().chain_id(), protocol().epoch())
            .unwrap();
    replica.put_row(key, encode_admission_closure_record(&record).unwrap());
}

fn identity(bundle: &PublicationBundle) -> AvailabilityIdentity {
    verify_bundle(
        &resolver(),
        &[],
        &protocol(),
        domain(),
        &installed_validator_set(),
        bundle,
    )
    .unwrap()
}

fn import(
    replica: &RetentionReplica,
    bundle: &PublicationBundle,
    expected_identity: &AvailabilityIdentity,
) -> DrainResult<AvailabilityIdentity> {
    retain_drain_publication(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        expected_identity,
        &encode_publication_bundle(bundle).unwrap(),
    )
}

#[test]
fn post_freeze_import_keeps_full_proof_without_ack_or_application_and_replays_exactly() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let expected_identity: AvailabilityIdentity = identity(&bundle);
    let original_key: Vec<u8> = crate::fast_path::publication::fastpath_publication_key(
        protocol().chain_id(),
        protocol().epoch(),
        &[REQUEST; 32],
    )
    .unwrap();
    let ack_key: Vec<u8> = crate::fast_path::publication::fastpath_availability_ack_key(
        protocol().chain_id(),
        protocol().epoch(),
        &[REQUEST; 32],
    )
    .unwrap();
    let locks_before: Vec<Option<Vec<u8>>> = replica.lock_rows();
    let coin_before = replica.coin_head();
    close(&replica);
    assert_eq!(
        import(&replica, &bundle, &expected_identity).unwrap(),
        expected_identity
    );
    assert!(replica.row(&original_key).is_none());
    assert!(replica.row(&ack_key).is_none());
    assert_eq!(replica.lock_rows(), locks_before);
    assert_eq!(replica.coin_head(), coin_before);
    assert!(replica.request_receipt([REQUEST; 32]).is_none());
    let marker_key: Vec<u8> =
        drain_possession_key(protocol().chain_id(), protocol().epoch(), &[REQUEST; 32]).unwrap();
    assert_eq!(
        replica.row(&marker_key),
        Some(encode_availability_identity(&expected_identity).unwrap())
    );
    verify_drain_possession(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &expected_identity,
    )
    .unwrap();
    assert_eq!(
        import(&replica, &bundle, &expected_identity).unwrap(),
        expected_identity
    );
}

#[test]
fn import_requires_freeze_and_exact_frontier_identity_and_rechecks_saved_artifacts() {
    let replica: RetentionReplica = logical_replica();
    let (bundle, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let expected_identity: AvailabilityIdentity = identity(&bundle);
    assert!(import(&replica, &bundle, &expected_identity).is_err());
    close(&replica);
    let mut wrong: AvailabilityIdentity = expected_identity.clone();
    wrong.request_id[0] ^= 1;
    assert!(import(&replica, &bundle, &wrong).is_err());
    assert!(
        replica
            .row(
                &drain_possession_key(protocol().chain_id(), protocol().epoch(), &[REQUEST; 32])
                    .unwrap()
            )
            .is_none()
    );
    import(&replica, &bundle, &expected_identity).unwrap();
    let artifact: &ArtifactEntry = bundle.manifest.entries.first().unwrap();
    let key: Vec<u8> = drain_publication_artifact_key(
        protocol().chain_id(),
        protocol().epoch(),
        &[REQUEST; 32],
        artifact,
    )
    .unwrap();
    replica.put_row(key, vec![0xAA]);
    assert!(
        verify_drain_possession(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &expected_identity,
        )
        .is_err()
    );
    assert!(import(&replica, &bundle, &expected_identity).is_err());
}

#[test]
fn import_does_not_extend_the_already_signed_local_frontier() {
    let replica: RetentionReplica = logical_replica();
    let (first, _certificate) = transfer_bundle_bytes(REQUEST, FIRST_PAID_NONCE);
    let first_vote: AvailabilityVote = crate::fast_path::publication::retain_publication(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &encode_publication_bundle(&first).unwrap(),
        &replica.signer,
    )
    .unwrap();
    close(&replica);
    assert!(matches!(
        advance_frozen_frontier(
            &replica.store,
            &context(),
            domain(),
            &resolver(),
            &[],
            &protocol(),
            &replica.signer,
        )
        .unwrap(),
        FrozenFrontierStep::Advanced { .. }
    ));
    let final_vote: FrozenFrontierVote = match advance_frozen_frontier(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        &replica.signer,
    )
    .unwrap()
    {
        FrozenFrontierStep::Finalized(vote) => *vote,
        FrozenFrontierStep::Advanced { .. } => panic!("expected final frontier"),
    };
    let before: (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        replica.signer.validator_id(),
        None,
        NonZeroUsize::new(2).unwrap(),
    )
    .unwrap();
    assert_eq!(before.0, final_vote);
    assert_eq!(before.1.entries, vec![first_vote.identity]);
    let (second, _certificate) = transfer_bundle_bytes(REQUEST + 1, FIRST_PAID_NONCE);
    let second_identity: AvailabilityIdentity = identity(&second);
    import(&replica, &second, &second_identity).unwrap();
    let after: (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page(
        &replica.store,
        &context(),
        domain(),
        &resolver(),
        &[],
        &protocol(),
        replica.signer.validator_id(),
        None,
        NonZeroUsize::new(2).unwrap(),
    )
    .unwrap();
    assert_eq!(after, before);
}
