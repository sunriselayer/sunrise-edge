//! Genuine signed causal genesis, real owned execution, and actual ordered
//! Freeze/DrainSet history. No source Ready/progress/business rows seed the
//! private overlay; all local readiness is derived through ordinary handlers.
use super::business_reconstruction::{complete_history, reconstruction_plan, snapshot};
use super::*;
use crate::business_reconstruction::{
    BusinessReconstructionError, BusinessReconstructionOverlay, BusinessReconstructionPlan,
    BusinessReconstructionReport, DrainSetControlMaterial, DrainSetControlProofError,
    OwnedPublicationMaterial, SourceBusinessSnapshot, drain_control_material_from_source_snapshot,
    owned_material_from_source_snapshot,
};
use canonical_encoding::CanonicalStruct;
use consensus::{DrainUnionIdentity, FrozenFrontierPage, FrozenFrontierVote};
use std::num::NonZeroUsize;

const PAID_REQUEST: [u8; 32] = [0x6a; 32];
const FREEZE_REQUEST: [u8; 32] = [0xcb; 32];
const DRAIN_REQUEST: [u8; 32] = [0xcc; 32];

struct GenuineControlSource {
    fixture: CausalFixture,
    paid: CertifiedPaidMaterial,
    selected: Vec<(FrozenFrontierVote, FrozenFrontierPage)>,
    candidate: OrderedCandidate,
}

fn commit_freeze(network: &Network, request: [u8; 32]) {
    let candidate: OrderedCandidate = freeze_candidate(request);
    for view in 1..=3 {
        network.round(view, (view == 1).then_some(&candidate));
    }
}

fn derive_ready(
    network: &Network,
    replica: usize,
    selected: &[(FrozenFrontierVote, FrozenFrontierPage)],
    bundle: &[u8],
) -> DrainUnionIdentity {
    let votes: Vec<FrozenFrontierVote> = selected.iter().map(|(vote, _)| vote.clone()).collect();
    for (vote, page) in selected {
        ingest_drain_signer_page(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &fixture::protocol(),
            vote.validator,
            vote.clone(),
            page.clone(),
        )
        .unwrap();
        for entry in &page.entries {
            assert_eq!(
                import_staged_drain_publication(
                    &network.stores[replica],
                    &network.context,
                    network.domain(),
                    &network.resolver,
                    &network.history,
                    &fixture::protocol(),
                    vote.validator,
                    bundle,
                )
                .unwrap(),
                *entry
            );
            assert_eq!(
                confirm_drain_signer_entry(
                    &network.stores[replica],
                    &network.context,
                    network.domain(),
                    &network.resolver,
                    &network.history,
                    &fixture::protocol(),
                    vote.validator,
                    entry.request_id,
                )
                .unwrap(),
                *entry
            );
        }
    }
    for _ in 0..=1 {
        if let DrainUnionStep::Ready(identity) = advance_drain_union(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &votes,
        )
        .unwrap()
        {
            assert_eq!(identity.member_count, 1);
            return *identity;
        }
    }
    panic!("one genuine full member must derive readiness in two bounded steps");
}

fn genuine_control_source() -> GenuineControlSource {
    let fixture: CausalFixture = fresh_fixture();
    let signed: Vec<u8> = paid_transfer(
        &fixture,
        0,
        &fixture.manifest.objects[1].object,
        PAID_REQUEST,
        0,
    );
    let paid: CertifiedPaidMaterial = certify_and_apply_paid(&fixture, &signed, 11);
    let network: &Network = &fixture.network;
    commit_freeze(network, FREEZE_REQUEST);
    let mut selected: Vec<(FrozenFrontierVote, FrozenFrontierPage)> = Vec::new();
    for source in 0..3 {
        for _ in 0..=1 {
            if matches!(
                advance_frozen_frontier(
                    &network.stores[source],
                    &network.context,
                    network.domain(),
                    &network.resolver,
                    &network.history,
                    &fixture::protocol(),
                    &network.signers[source],
                )
                .unwrap(),
                FrozenFrontierStep::Finalized(_)
            ) {
                break;
            }
        }
        let pair: (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page(
            &network.stores[source],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            network.signers[source].id,
            None,
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
        assert!(pair.1.terminal);
        assert_eq!(pair.1.entries.len(), 1);
        assert_eq!(pair.1.entries[0].request_id, PAID_REQUEST);
        selected.push(pair);
    }
    selected.sort_by_key(|(vote, _)| vote.validator);
    let mut ready: Option<DrainUnionIdentity> = None;
    for replica in 0..REPLICAS {
        let actual: DrainUnionIdentity = derive_ready(network, replica, &selected, &paid.bundle);
        if let Some(previous) = &ready {
            assert_eq!(&actual, previous);
        } else {
            ready = Some(actual);
        }
    }
    let intent: DrainSetIntent = DrainSetIntent {
        context: fixture::protocol(),
        request_id: DRAIN_REQUEST,
        selected_votes: selected.iter().map(|(vote, _)| vote.clone()).collect(),
        drain_union_identity: ready.unwrap(),
    };
    let candidate: OrderedCandidate = OrderedCandidate {
        context: fixture::protocol(),
        request_id: DRAIN_REQUEST,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&intent).unwrap(),
        created_checkpoint: 12,
    };
    for view in 4..=6 {
        network.round(view, (view == 4).then_some(&candidate));
    }
    GenuineControlSource {
        fixture,
        paid,
        selected,
        candidate,
    }
}

#[test]
fn genuine_control_history_needs_complete_selected_proof_and_reconstructs_without_source_rows() {
    let source: GenuineControlSource = genuine_control_source();
    let network: &Network = &source.fixture.network;
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let before: SourceBusinessSnapshot = snapshot(network);
    let plan: BusinessReconstructionPlan<'_> = reconstruction_plan(&source.fixture, &identity);
    let owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&before, &plan).unwrap();
    let controls: Vec<DrainSetControlMaterial> =
        drain_control_material_from_source_snapshot(&before, &plan, &history).unwrap();
    assert_eq!(owned.len(), 1);
    assert_eq!(controls.len(), 1);
    assert_eq!(controls[0].signer_frontiers.len(), 3);

    let mut missing: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&source.fixture, &identity))
            .unwrap();
    assert!(matches!(
        missing.reconstruct(&owned, &history),
        Err(BusinessReconstructionError::ControlProof(
            DrainSetControlProofError::Incomplete(_)
        ))
    ));
    let mut missing_bundle: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&source.fixture, &identity))
            .unwrap();
    assert!(matches!(
        missing_bundle.reconstruct_with_control_material(&[], &history, &controls),
        Err(BusinessReconstructionError::ControlProof(
            DrainSetControlProofError::Incomplete(_)
        ))
    ));
    let mut corrupt: Vec<DrainSetControlMaterial> = controls.clone();
    corrupt[0].signer_frontiers[0].pages.clear();
    let mut missing_terminal: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&source.fixture, &identity))
            .unwrap();
    assert!(matches!(
        missing_terminal.reconstruct_with_control_material(&owned, &history, &corrupt),
        Err(BusinessReconstructionError::ControlProof(_))
    ));

    let mut overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(plan).unwrap();
    let report: BusinessReconstructionReport = overlay
        .reconstruct_with_control_material(&owned, &history, &controls)
        .unwrap();
    assert_eq!(report.ordered_height, identity.through_height);
    assert_eq!(report.owned_originals_replayed, 1);
    assert_eq!(report.semantic_snapshot_equal, None);
    overlay.compare_source(&before).unwrap();
    assert_eq!(
        snapshot(network),
        before,
        "every row/revision/token is source-read-only"
    );
}

#[test]
fn control_query_preserves_completed_and_earlier_refusals_and_actual_wrong_union() {
    let source: GenuineControlSource = genuine_control_source();
    let completed: &Network = &source.fixture.network;
    let mut fresh: OrderedCandidate = source.candidate.clone();
    let mut intent: DrainSetIntent = decode_drain_set_intent(&fresh.intent).unwrap();
    intent.request_id = [0xcd; 32];
    fresh.request_id = intent.request_id;
    fresh.intent = encode_drain_set_intent(&intent).unwrap();
    // Deliberate local-control corruption only, never proof/authority seeding:
    // exact completion and AlreadyDrained must not depend on retained local
    // signer progress being available after the accepted operation finished.
    let progress_key: Vec<u8> = drain_signer_progress_key(
        fixture::protocol().chain_id(),
        fixture::protocol().epoch(),
        source.selected[0].0.validator,
    )
    .unwrap();
    assert!(completed.value(0, &progress_key).is_some());
    completed.put(0, progress_key, StateMutation::Delete);
    let before: SourceBusinessSnapshot = snapshot(completed);
    assert!(
        !engine::reconstruction_drain_readiness_needed(
            &completed.stores[0],
            &completed.context,
            &completed.env(),
            &source.candidate,
            7,
        )
        .unwrap()
    );
    assert!(
        !engine::reconstruction_drain_readiness_needed(
            &completed.stores[0],
            &completed.context,
            &completed.env(),
            &fresh,
            7,
        )
        .unwrap()
    );
    assert!(matches!(
        preflight::preflight(
            &completed.stores[0],
            &completed.context,
            &completed.env(),
            &fresh,
            7,
        ),
        Err(OrderedEconomicsError::Refused(
            OrderedRefusal::AlreadyDrained
        ))
    ));
    assert_eq!(snapshot(completed), before);

    let no_freeze: CausalFixture = fresh_fixture();
    let network: &Network = &no_freeze.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    assert!(
        !engine::reconstruction_drain_readiness_needed(
            &network.stores[0],
            &network.context,
            &network.env(),
            &fresh,
            4,
        )
        .unwrap()
    );
    assert!(matches!(
        preflight::preflight(
            &network.stores[0],
            &network.context,
            &network.env(),
            &fresh,
            4,
        ),
        Err(OrderedEconomicsError::Refused(OrderedRefusal::NoFreeze))
    ));
    assert_eq!(snapshot(network), before);

    let foreign: CausalFixture = fresh_fixture();
    let network: &Network = &foreign.network;
    commit_freeze(network, [0xce; 32]);
    let before: SourceBusinessSnapshot = snapshot(network);
    assert!(
        !engine::reconstruction_drain_readiness_needed(
            &network.stores[0],
            &network.context,
            &network.env(),
            &fresh,
            4,
        )
        .unwrap()
    );
    assert!(matches!(
        preflight::preflight(
            &network.stores[0],
            &network.context,
            &network.env(),
            &fresh,
            4,
        ),
        Err(OrderedEconomicsError::Refused(
            OrderedRefusal::ForeignDrainSet
        ))
    ));
    assert_eq!(snapshot(network), before);

    let needs_proof: CausalFixture = fresh_fixture();
    let network: &Network = &needs_proof.network;
    commit_freeze(network, FREEZE_REQUEST);
    let mut wrong: OrderedCandidate = fresh.clone();
    let mut wrong_intent: DrainSetIntent = decode_drain_set_intent(&wrong.intent).unwrap();
    wrong_intent.drain_union_identity.member_count += 1;
    wrong.intent = encode_drain_set_intent(&wrong_intent).unwrap();
    assert!(network.policy.authenticate_candidate(&wrong).is_ok());
    let before: SourceBusinessSnapshot = snapshot(network);
    assert!(
        engine::reconstruction_drain_readiness_needed(
            &network.stores[0],
            &network.context,
            &network.env(),
            &wrong,
            4,
        )
        .unwrap()
    );
    assert_eq!(snapshot(network), before);
    let actual: DrainUnionIdentity =
        derive_ready(network, 0, &source.selected, &source.paid.bundle);
    assert_eq!(actual.member_count, 1);
    let before: SourceBusinessSnapshot = snapshot(network);
    assert!(
        !engine::reconstruction_drain_readiness_needed(
            &network.stores[0],
            &network.context,
            &network.env(),
            &wrong,
            4,
        )
        .unwrap()
    );
    assert!(matches!(
        preflight::preflight(
            &network.stores[0],
            &network.context,
            &network.env(),
            &wrong,
            4,
        ),
        Err(OrderedEconomicsError::Refused(
            OrderedRefusal::ForeignDrainSet
        ))
    ));
    assert!(
        preflight::preflight(
            &network.stores[0],
            &network.context,
            &network.env(),
            &fresh,
            4,
        )
        .is_ok()
    );
    assert_eq!(snapshot(network), before);
}

#[test]
fn forged_refused_control_companions_do_not_hide_independently_required_readiness() {
    let source: GenuineControlSource = genuine_control_source();
    let network: &Network = &source.fixture.network;
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let before: SourceBusinessSnapshot = snapshot(network);
    let plan: BusinessReconstructionPlan<'_> = reconstruction_plan(&source.fixture, &identity);
    let owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&before, &plan).unwrap();
    let genuine_controls: Vec<DrainSetControlMaterial> =
        drain_control_material_from_source_snapshot(&before, &plan, &history).unwrap();
    let mut forged: Vec<OrderedHistoryHeightMaterial> = history.clone();
    let mut changed: usize = 0;
    for material in &mut forged {
        let Some((_, candidate_bytes)) = material
            .components
            .iter()
            .find(|(kind, _)| *kind == OrderedHistoryComponentKind::Candidate)
        else {
            continue;
        };
        let candidate: OrderedCandidate = decode_ordered_candidate(candidate_bytes).unwrap();
        if candidate.request_id != DRAIN_REQUEST {
            continue;
        }
        let candidate_digest: Digest32 = network
            .resolver
            .hash_for_purpose(
                candidate.context.epoch(),
                HashPurpose::NodeEvent,
                &encode_ordered_candidate(&candidate).unwrap(),
            )
            .unwrap();
        let original_receipt: crate::NodeDedupRecord = crate::NodeDedupRecord::decode(
            &material
                .components
                .iter()
                .find(|(kind, _)| *kind == OrderedHistoryComponentKind::OriginalReceipt)
                .unwrap()
                .1,
        )
        .unwrap();
        assert_eq!(
            original_receipt.responses()[0].status(),
            crate::NodeResponseStatus::Accepted
        );
        let response: crate::NodeResponse = crate::NodeResponse::new(
            original_receipt.request_id(),
            crate::NodeResponseStatus::Rejected,
            Some(encode_ordered_refusal_payload(OrderedRefusal::ForeignDrainSet).unwrap()),
        )
        .unwrap();
        let forged_receipt: Vec<u8> = crate::NodeDedupRecord::new(
            original_receipt.request_id(),
            candidate_digest,
            vec![response.clone()],
        )
        .unwrap()
        .encode()
        .unwrap();
        let retained: &[u8] = &material
            .components
            .iter()
            .find(|(kind, _)| *kind == OrderedHistoryComponentKind::RetainedOutcome)
            .unwrap()
            .1;
        let wrapper = decode_canonical_frame(retained).unwrap();
        wrapper.require_type(0x644f).unwrap();
        let mut outcome: OrderedOutcome =
            decode_ordered_outcome(wrapper.required_field(1).unwrap()).unwrap();
        outcome.output = crate::NodeOutput::new(vec![response], Vec::new()).unwrap();
        let mut frame: CanonicalStruct = CanonicalStruct::new(0x644f, 1);
        frame
            .field_bytes(1, encode_ordered_outcome(&outcome).unwrap())
            .unwrap();
        replace_history_component(
            &network.policy,
            material,
            OrderedHistoryComponentKind::OriginalReceipt,
            forged_receipt,
        );
        replace_history_component(
            &network.policy,
            material,
            OrderedHistoryComponentKind::RetainedOutcome,
            frame.finish().unwrap(),
        );
        changed += 1;
    }
    assert_eq!(changed, 1);
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), identity.clone()).unwrap();
    for material in &forged {
        verifier.verify_next_height(material).unwrap();
    }
    assert_eq!(verifier.finish().unwrap().identity(), &identity);
    let controls: Vec<DrainSetControlMaterial> =
        drain_control_material_from_source_snapshot(&before, &plan, &forged).unwrap();
    assert_eq!(
        controls, genuine_controls,
        "source Refused never decides proof omission"
    );
    let mut withheld: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&source.fixture, &identity))
            .unwrap();
    assert!(matches!(
        withheld.reconstruct(&owned, &forged),
        Err(BusinessReconstructionError::ControlProof(
            DrainSetControlProofError::Incomplete(_)
        ))
    ));
    let mut supplied: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(plan).unwrap();
    assert!(matches!(
        supplied.reconstruct_with_control_material(&owned, &forged, &controls),
        Err(BusinessReconstructionError::OrderedHistory {
            height: 4,
            source,
        }) if matches!(*source, OrderedEconomicsError::Prerequisite(_))
    ));
    assert_eq!(snapshot(network), before);
}
