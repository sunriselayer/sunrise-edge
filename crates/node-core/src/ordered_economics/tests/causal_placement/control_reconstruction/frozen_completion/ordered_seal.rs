//! DR-0187 private acceptance-only closure (verify_live_seal_closure):
//! genuine real-consensus negative-path coverage.
//!
//! Every test below drives the same genuine consensus history `preseal_cut.rs`
//! reconstructs (completed_source_with_generic_prefix, real Drain, real
//! multi-round empty finishing), then exercises verify_live_seal_closure
//! rejection paths against that real material. The local Seal claims are
//! intentionally malformed; no accepted receipt or quorum is fabricated.
//! Positive acceptance is exercised through the four-store HTTP/CLI workflow.
use super::*;
use crate::business_reconstruction::cut::{BusinessCutError, verify_live_seal_closure};

fn terminal_child_digest(
    network: &Network,
    history: &[crate::ordered_economics::OrderedHistoryHeightMaterial],
) -> Digest32 {
    let material = history.last().unwrap();
    let bytes = &material
        .components
        .iter()
        .find(|(kind, _)| {
            *kind == crate::ordered_economics::OrderedHistoryComponentKind::CommitProof
        })
        .unwrap()
        .1;
    let proof: consensus::CommittedBlockProof =
        consensus::decode_committed_block_proof(bytes).unwrap();
    network
        .policy
        .engine()
        .proposal_digest(&proof.child)
        .unwrap()
}

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
        terminal_child_digest(network, &history),
        &[],
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
        terminal_child_digest(network, &history),
        &[],
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
        terminal_child_digest(network, &history),
        &[],
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
        terminal_child_digest(network, &history),
        &[],
    );
    assert!(
        result.is_err(),
        "a fixed target that is not the authenticated last height must never produce an accepted cut"
    );
    assert_eq!(snapshot(network), before);
}
