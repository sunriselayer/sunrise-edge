//! DR-0187 private acceptance-only closure (verify_live_seal_closure):
//! genuine real-consensus negative-path coverage.
//!
//! A genuine committed Seal candidate cannot be produced anywhere in this
//! repository today: the ordered-economics Seal dispatch arm explicitly
//! stops rather than completing one, because the mandatory outgoing
//! barrier/sealed record is a separate, runtime-owned deliverable not yet
//! integrated. Every test below therefore drives the exact same genuine,
//! already-proven-correct consensus history `preseal_cut.rs` itself
//! reconstructs (completed_source_with_generic_prefix, real Drain, real
//! multi-round empty finishing), then exercises verify_live_seal_closure
//! rejection paths against that real material. No certificate, quorum,
//! candidate or receipt is fabricated here, and no positive acceptance is
//! attempted or claimed.
use super::*;
use crate::business_reconstruction::cut::{BusinessCutError, verify_live_seal_closure};

fn seal_candidate(
    context: PublicationContext,
    request_id: [u8; 32],
    created_checkpoint: u64,
) -> OrderedCandidate {
    OrderedCandidate {
        context,
        request_id,
        kind: OrderedOperationKind::Seal,
        intent: vec![1, 2, 3, 4],
        created_checkpoint,
    }
}

#[test]
fn verify_live_seal_closure_rejects_the_genuine_empty_terminal_as_unaccepted() {
    let source = super::preseal_cut::completed_source_with_generic_prefix();
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history) = complete_history(network);
    let candidate: OrderedCandidate = seal_candidate(
        network.policy.context().clone(),
        [9; 32],
        identity.through_height,
    );
    let result = verify_live_seal_closure(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
        &candidate,
    );
    assert!(matches!(
        result,
        Err(BusinessCutError::Invalid(
            "cut seal acceptance child is not exactly the accepted seal candidate"
        ))
    ));
    assert_eq!(
        snapshot(network),
        before,
        "a refused seal acceptance leaves the source untouched"
    );
}

#[test]
fn verify_live_seal_closure_rejects_a_non_seal_candidate_kind() {
    let source = super::preseal_cut::completed_source_with_generic_prefix();
    let network: &Network = &source.fixture.network;
    let (identity, history) = complete_history(network);
    let mut candidate: OrderedCandidate = seal_candidate(
        network.policy.context().clone(),
        [9; 32],
        identity.through_height,
    );
    candidate.kind = OrderedOperationKind::DrainSet;
    let result = verify_live_seal_closure(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
        &candidate,
    );
    assert!(matches!(
        result,
        Err(BusinessCutError::Invalid(
            "seal acceptance candidate is not a Seal operation"
        ))
    ));
}

#[test]
fn verify_live_seal_closure_rejects_a_created_checkpoint_beyond_the_prior_applied_tip() {
    let source = super::preseal_cut::completed_source_with_generic_prefix();
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history) = complete_history(network);
    let candidate: OrderedCandidate = seal_candidate(
        network.policy.context().clone(),
        [9; 32],
        identity.through_height.checked_add(1).unwrap(),
    );
    let result = verify_live_seal_closure(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
        &candidate,
    );
    assert!(matches!(
        result,
        Err(BusinessCutError::Invalid(
            "seal claimed cut lies beyond the prior applied tip"
        ))
    ));
    assert_eq!(snapshot(network), before);
}

#[test]
fn verify_live_seal_closure_rejects_a_fixed_target_that_is_not_the_genuine_last_height() {
    let source = super::preseal_cut::completed_source_with_generic_prefix();
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history) = complete_history(network);
    let mut wrong_identity: OrderedHistoryIdentity = identity.clone();
    wrong_identity.through_height = wrong_identity.through_height.checked_sub(1).unwrap();
    let candidate: OrderedCandidate = seal_candidate(
        network.policy.context().clone(),
        [9; 32],
        wrong_identity.through_height,
    );
    let result = verify_live_seal_closure(
        reconstruction_plan(&source.fixture, &wrong_identity),
        &network.stores[0],
        &network.blobs,
        &history,
        &candidate,
    );
    assert!(
        result.is_err(),
        "a fixed target that is not the authenticated last height must never produce an accepted cut"
    );
    assert_eq!(snapshot(network), before);
}
