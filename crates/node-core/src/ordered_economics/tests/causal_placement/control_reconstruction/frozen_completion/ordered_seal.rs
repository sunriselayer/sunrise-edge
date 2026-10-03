//! Read-only full closure negatives over independently derived business cuts,
//! real successor readiness certificates and normal derived Seal request IDs.
//! Authenticated terminal-only shape controls live separately in cut::derive.
use super::seal_signing::{SealSigningFixture, candidate_for_cut, seal_signing_fixture};
use super::*;
use crate::business_reconstruction::cut::{
    BusinessCutError, BusinessCutIdentity, verify_live_seal_closure,
};

fn terminal_child_digest(network: &Network, history: &[OrderedHistoryHeightMaterial]) -> Digest32 {
    let material: &OrderedHistoryHeightMaterial = history.last().unwrap();
    let bytes: &Vec<u8> = &material
        .components
        .iter()
        .find(|(kind, _)| *kind == OrderedHistoryComponentKind::CommitProof)
        .unwrap()
        .1;
    let proof: consensus::CommittedBlockProof =
        consensus::decode_committed_block_proof(bytes).unwrap();
    ordered_history::verified_committed_block(&network.policy, &proof).unwrap();
    network
        .policy
        .engine()
        .proposal_digest(&proof.child)
        .unwrap()
}

fn next_members(fixture: &SealSigningFixture) -> Vec<crate::fast_path::FastPathValidatorEntry> {
    let network: &Network = &fixture.source.fixture.network;
    let certificate: consensus::readiness::ReadinessCertificate =
        seal::load_verified_seal_certificate(
            &seal_signing::env_with_seal(network),
            &fixture.candidate,
        )
        .unwrap();
    seal::seal_next_members(&certificate)
}

#[test]
fn verify_live_seal_closure_rejects_the_genuine_empty_terminal_as_unaccepted() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let source: &FrozenCompletionSource = &fixture.source;
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    network
        .policy
        .authenticate_candidate(&fixture.candidate)
        .unwrap();
    let result = verify_live_seal_closure(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
        &fixture.candidate,
        terminal_child_digest(network, &history),
        &next_members(&fixture),
    );
    let result: BusinessCutError = result
        .err()
        .expect("the closure must reject the empty child");
    assert!(
        matches!(
            result,
            BusinessCutError::Invalid(
                "cut seal acceptance child is not exactly the accepted seal candidate"
            )
        ),
        "unexpected closure result: {result:?}"
    );
    assert_eq!(snapshot(network), before);
}

#[test]
fn verify_live_seal_closure_rejects_a_non_seal_candidate_kind() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let source: &FrozenCompletionSource = &fixture.source;
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let mut candidate: OrderedCandidate = fixture.candidate.clone();
    candidate.kind = OrderedOperationKind::DrainSet;
    let result = verify_live_seal_closure(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
        &candidate,
        terminal_child_digest(network, &history),
        &next_members(&fixture),
    );
    let result: BusinessCutError = result
        .err()
        .expect("the closure must reject the operation kind");
    assert!(
        matches!(
            result,
            BusinessCutError::Invalid("seal acceptance candidate is not a Seal operation")
        ),
        "unexpected closure result: {result:?}"
    );
    assert_eq!(snapshot(network), before);
}

#[test]
fn verify_live_seal_closure_rejects_a_created_checkpoint_beyond_the_prior_applied_tip() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let source: &FrozenCompletionSource = &fixture.source;
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let mut cut_identity: BusinessCutIdentity = fixture.cut_identity.clone();
    cut_identity.ordered_history.through_height = identity.through_height.checked_add(1).unwrap();
    let candidate: OrderedCandidate = candidate_for_cut(
        network,
        &cut_identity,
        &fixture.subject,
        &fixture.next_set,
        cut_identity.ordered_history.through_height,
    );
    network.policy.authenticate_candidate(&candidate).unwrap();
    let result = verify_live_seal_closure(
        reconstruction_plan(&source.fixture, &identity),
        &network.stores[0],
        &network.blobs,
        &history,
        &candidate,
        terminal_child_digest(network, &history),
        &next_members(&fixture),
    );
    let result: BusinessCutError = result
        .err()
        .expect("the closure must reject the future cut");
    assert!(
        matches!(
            result,
            BusinessCutError::Invalid("seal claimed cut lies beyond the prior applied tip")
        ),
        "unexpected closure result: {result:?}"
    );
    assert_eq!(snapshot(network), before);
}

#[test]
fn verify_live_seal_closure_rejects_a_fixed_target_that_cannot_authenticate_source_controls() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let source: &FrozenCompletionSource = &fixture.source;
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let mut wrong_identity: OrderedHistoryIdentity = identity.clone();
    wrong_identity.through_height = wrong_identity.through_height.checked_sub(1).unwrap();
    let mut cut_identity: BusinessCutIdentity = fixture.cut_identity.clone();
    cut_identity.ordered_history = wrong_identity.clone();
    let candidate: OrderedCandidate = candidate_for_cut(
        network,
        &cut_identity,
        &fixture.subject,
        &fixture.next_set,
        wrong_identity.through_height,
    );
    network.policy.authenticate_candidate(&candidate).unwrap();
    let result = verify_live_seal_closure(
        reconstruction_plan(&source.fixture, &wrong_identity),
        &network.stores[0],
        &network.blobs,
        &history,
        &candidate,
        terminal_child_digest(network, &history),
        &next_members(&fixture),
    );
    let result: BusinessCutError = result
        .err()
        .expect("the closure must reject the wrong fixed target");
    assert!(
        matches!(
            result,
            BusinessCutError::Invalid("source control closure could not be authenticated")
        ),
        "unexpected closure result: {result:?}"
    );
    assert_eq!(snapshot(network), before);
}
