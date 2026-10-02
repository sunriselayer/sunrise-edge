//! Actual post-Freeze paid completion with no aggregate AV ever constructed.
//! Selected signer streams and committed control history, not source effects,
//! establish the reconstruction overlay's only frozen execution authority.
use super::*;
use crate::NodeDedupRecord;
use crate::fast_path::records::{FastPathSettlementRecord, decode_fastpath_settlement_record};
use crate::local_instance_state::{fastpath_certificate_key, fastpath_settlement_key};
use consensus::{
    CommittedBlockProof, ConsensusProposal, FastCertificate, FastPathCertifier, FastVote,
};
use execution::paid_execution::{
    PaidContractEngine, PaidExecutionError, PaidExecutionOutcome, PaidExecutionRequest,
};
use runtime::portable::{DurablePortableSnapshotRepository, PortableSnapshotError};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

#[path = "frozen_completion/preseal_cut.rs"]
mod preseal_cut;

#[path = "frozen_completion/preseal_cut_contracts.rs"]
mod preseal_cut_contracts;

#[path = "frozen_completion/inactive_business_import.rs"]
mod inactive_business_import;

#[path = "frozen_completion/inactive_business_import_faults.rs"]
mod inactive_business_import_faults;

#[path = "frozen_completion/conditional_readiness.rs"]
mod conditional_readiness;

struct ObservedPaidEngine<'a> {
    inner: &'a dyn PaidContractEngine,
    calls: Cell<usize>,
}

impl PaidContractEngine for ObservedPaidEngine<'_> {
    fn execute_paid(
        &self,
        request: PaidExecutionRequest<'_>,
    ) -> Result<PaidExecutionOutcome, PaidExecutionError> {
        self.calls.set(self.calls.get().checked_add(1).unwrap());
        self.inner.execute_paid(request)
    }
}

#[derive(Clone, Copy)]
enum DrainScenario {
    Accepted,
    WrongUnion,
    Nonmember,
}

struct FrozenCompletionSource {
    fixture: CausalFixture,
    paid: CertifiedPaidMaterial,
    freeze_identity: OrderedHistoryIdentity,
    freeze_history: Vec<OrderedHistoryHeightMaterial>,
}

fn certify_without_aggregate_av(
    fixture: &CausalFixture,
    signed: &[u8],
    checkpoint: u64,
    retention_replicas: &[usize],
) -> CertifiedPaidMaterial {
    let network: &Network = &fixture.network;
    let votes: Vec<FastVote> = (0..REPLICAS)
        .map(|replica: usize| {
            crate::fast_path::prepare(
                &network.stores[replica],
                &network.blobs,
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &fixture::protocol(),
                &network.leg_policy,
                &fixture.manifest.fee_policy,
                &network.engine,
                &network.signers[replica],
                signed,
                checkpoint,
            )
            .unwrap()
        })
        .collect();
    let certifier: FastPathCertifier = FastPathCertifier::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        fixture::protocol().epoch(),
        validator_set(&network.signers),
    )
    .unwrap();
    let certificate: FastCertificate = certifier
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes[..3],
            &crate::fast_path::FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let bundle: PublicationBundle = crate::fast_path::publication::assemble_publication_bundle(
        &network.stores[0],
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        signed,
        &certificate_bytes,
    )
    .unwrap();
    let retained_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
    for replica in retention_replicas {
        // Individual ACKs prove actual retention. No AvailabilityCertifier or
        // aggregation is called anywhere in this fixture.
        let _ack: consensus::AvailabilityVote = crate::fast_path::publication::retain_publication(
            &network.stores[*replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &retained_bytes,
            &network.signers[*replica],
        )
        .unwrap();
    }
    let (_, result): (Digest32, PaidExecutionResult) =
        crate::fast_path::publication::decode_certified_execution_witness(&bundle.witness).unwrap();
    assert_eq!(result.status, PaidExecutionStatus::Success);
    // A different independently executed full quorum can carry exactly the
    // same producer into drain import. Source normal retention uses 0/1/2;
    // its actual drain application uses 1/2/3, not forged completion bytes.
    let imported_certificate: FastCertificate = certifier
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes[1..],
            &crate::fast_path::FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    assert_ne!(imported_certificate, bundle.certificate);
    let mut imported_bundle: PublicationBundle = bundle;
    imported_bundle.certificate = imported_certificate;
    CertifiedPaidMaterial {
        bundle: consensus::bundle::encode_publication_bundle(&imported_bundle).unwrap(),
        certificate: consensus::encode_fast_certificate(&imported_bundle.certificate).unwrap(),
        availability_certificate: Vec::new(),
        result,
    }
}

fn frozen_completion_source(scenario: DrainScenario) -> FrozenCompletionSource {
    frozen_completion_source_with_prefix(scenario, false)
}

fn frozen_completion_source_with_prefix(
    scenario: DrainScenario,
    generic_prefix: bool,
) -> FrozenCompletionSource {
    let fixture: CausalFixture = fresh_fixture();
    let prefix: Vec<CertifiedPaidMaterial> = if generic_prefix {
        preseal_cut_contracts::generic_import_prefix(&fixture)
    } else {
        Vec::new()
    };
    let coin: Object = if generic_prefix {
        current_object(&fixture.network, 0, fixture.manifest.objects[1].object.id)
    } else {
        fixture.manifest.objects[1].object.clone()
    };
    let signed: Vec<u8> = paid_transfer(
        &fixture,
        0,
        &coin,
        PAID_REQUEST,
        u64::try_from(prefix.len()).unwrap(),
    );
    let retention_replicas: &[usize] = if matches!(scenario, DrainScenario::Nonmember) {
        &[0]
    } else {
        &[0, 1, 2, 3]
    };
    let paid: CertifiedPaidMaterial =
        certify_without_aggregate_av(&fixture, &signed, 11, retention_replicas);
    let retained_signed: Vec<u8> =
        paid_transfer(&fixture, 1, &fixture.claimant_coin, UNAPPLIED_REQUEST, 0);
    let retained: CertifiedPaidMaterial =
        certify_without_aggregate_av(&fixture, &retained_signed, 12, &[0, 1, 2, 3]);
    let network: &Network = &fixture.network;
    assert!(receipt(network, 0, PAID_REQUEST).is_none());
    assert!(receipt(network, 0, UNAPPLIED_REQUEST).is_none());
    commit_freeze(network, FREEZE_REQUEST);
    let (freeze_identity, freeze_history): (
        OrderedHistoryIdentity,
        Vec<OrderedHistoryHeightMaterial>,
    ) = complete_history(network);
    let sources: &[usize] = if matches!(scenario, DrainScenario::Nonmember) {
        &[1, 2, 3]
    } else {
        &[0, 1, 2]
    };
    let count: usize = if matches!(scenario, DrainScenario::Nonmember) {
        1
    } else {
        2 + prefix.len()
    };
    let mut selected: Vec<(FrozenFrontierVote, FrozenFrontierPage)> = Vec::new();
    for replica in sources {
        let mut finalized: bool = false;
        for _ in 0..=count {
            if matches!(
                advance_frozen_frontier(
                    &network.stores[*replica],
                    &network.context,
                    network.domain(),
                    &network.resolver,
                    &network.history,
                    &fixture::protocol(),
                    &network.signers[*replica],
                )
                .unwrap(),
                FrozenFrontierStep::Finalized(_)
            ) {
                finalized = true;
                break;
            }
        }
        assert!(finalized);
        let pair: (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page(
            &network.stores[*replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            network.signers[*replica].id,
            None,
            NonZeroUsize::new(count + 1).unwrap(),
        )
        .unwrap();
        assert!(pair.1.terminal);
        assert_eq!(pair.1.entries.len(), count);
        assert_eq!(pair.1.entries.last().unwrap().request_id, UNAPPLIED_REQUEST);
        selected.push(pair);
    }
    selected.sort_by_key(|(vote, _)| vote.validator);
    let mut bundles: Vec<&[u8]> = prefix
        .iter()
        .map(|material| material.bundle.as_slice())
        .collect();
    bundles.extend([paid.bundle.as_slice(), retained.bundle.as_slice()]);
    let mut ready: Option<DrainUnionIdentity> = None;
    for replica in 0..REPLICAS {
        let actual: DrainUnionIdentity = derive_ready(network, replica, &selected, &bundles);
        if let Some(previous) = &ready {
            assert_eq!(&actual, previous);
        } else {
            ready = Some(actual);
        }
    }
    let mut claimed: DrainUnionIdentity = ready.unwrap();
    if matches!(scenario, DrainScenario::WrongUnion) {
        claimed.member_count = claimed.member_count.checked_add(1).unwrap();
    }
    let candidate: OrderedCandidate = OrderedCandidate {
        context: fixture::protocol(),
        request_id: DRAIN_REQUEST,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&DrainSetIntent {
            context: fixture::protocol(),
            request_id: DRAIN_REQUEST,
            selected_votes: selected.iter().map(|(vote, _)| vote.clone()).collect(),
            drain_union_identity: claimed,
        })
        .unwrap(),
        created_checkpoint: 12,
    };
    let refused_claim: bool = matches!(scenario, DrainScenario::WrongUnion);
    if refused_claim {
        let leader: usize = network.leader_index(4);
        assert!(matches!(
            propose(
                &network.stores[leader],
                &network.context,
                &network.env(),
                Some(&candidate),
                &network.signers[leader],
            ),
            Err(OrderedEconomicsError::Refused(
                OrderedRefusal::ForeignDrainSet
            ))
        ));
    }
    for view in 4..=6 {
        // A wrong union is refused by the real proposal owner; never bypass
        // its preflight to fabricate a committed candidate or receipt.
        network.round(view, (view == 4 && !refused_claim).then_some(&candidate));
    }
    if matches!(scenario, DrainScenario::Accepted) {
        for replica in 0..REPLICAS {
            let output: NodeOutput = crate::fast_path::drain_apply::apply_drain_member(
                &network.stores[replica],
                &network.blobs,
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &fixture::protocol(),
                &network.leg_policy,
                &fixture.manifest.fee_policy,
                &network.engine,
                PAID_REQUEST,
                11,
            )
            .unwrap();
            assert_eq!(
                execution::paid_execution::decode_paid_execution_result(
                    output.responses()[0].payload().unwrap()
                )
                .unwrap(),
                paid.result
            );
            assert!(receipt(network, replica, UNAPPLIED_REQUEST).is_none());
            let availability_key: Vec<u8> =
                crate::fast_path::records::fastpath_availability_certificate_key(
                    &fixture::chain(),
                    &PAID_REQUEST,
                )
                .unwrap();
            let availability = network.stores[replica]
                .get_versioned_durable(&network.context, network.domain(), &availability_key)
                .unwrap();
            assert_eq!(availability.revision(), StateRevision::INITIAL);
            assert!(availability.value().is_none());
        }
    }
    FrozenCompletionSource {
        fixture,
        paid,
        freeze_identity,
        freeze_history,
    }
}

fn observed_plan<'a>(
    source: &'a FrozenCompletionSource,
    identity: &'a OrderedHistoryIdentity,
    engine: &'a ObservedPaidEngine<'a>,
) -> BusinessReconstructionPlan<'a> {
    let mut plan: BusinessReconstructionPlan<'a> = reconstruction_plan(&source.fixture, identity);
    plan.paid_engine = engine;
    plan
}

#[test]
fn completed_frozen_member_without_av_reconstructs_exact_business_and_preserves_unapplied() {
    let source: FrozenCompletionSource = frozen_completion_source(DrainScenario::Accepted);
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let plan: BusinessReconstructionPlan<'_> = reconstruction_plan(&source.fixture, &identity);
    let mut owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&before, &plan).unwrap();
    let controls: Vec<DrainSetControlMaterial> =
        drain_control_material_from_source_snapshot(&before, &plan, &history).unwrap();
    assert_eq!(owned.len(), 2);
    assert!(
        owned
            .iter()
            .all(|item| item.availability_certificate.is_none())
    );
    assert_eq!(
        owned
            .iter()
            .filter(|item| item.source_application_present)
            .count(),
        1
    );
    assert!(
        owned
            .iter()
            .find(|item| item.bundle.request_id == PAID_REQUEST)
            .unwrap()
            .source_application_present
    );
    assert!(
        !owned
            .iter()
            .find(|item| item.bundle.request_id == UNAPPLIED_REQUEST)
            .unwrap()
            .source_application_present
    );
    let applied_certificate: FastCertificate = consensus::decode_fast_certificate(
        &crate::fast_path::records::decode_fastpath_certificate_record(
            &network
                .value(
                    0,
                    &fastpath_certificate_key(&fixture::chain(), &PAID_REQUEST).unwrap(),
                )
                .unwrap(),
        )
        .unwrap()
        .certificate,
    )
    .unwrap();
    assert_ne!(
        applied_certificate,
        owned
            .iter()
            .find(|item| { item.bundle.request_id == PAID_REQUEST })
            .unwrap()
            .bundle
            .certificate
    );
    assert_eq!(
        applied_certificate.execution_effects_hash,
        owned
            .iter()
            .find(|item| { item.bundle.request_id == PAID_REQUEST })
            .unwrap()
            .bundle
            .certificate
            .execution_effects_hash
    );
    let receipt_before: NodeDedupRecord = NodeDedupRecord::decode(
        before
            .records
            .iter()
            .find(|row| {
                row.descriptor.key()
                    == &DurableRecordKey::Receipt(
                        runtime::DurableRequestId::new(PAID_REQUEST).unwrap(),
                    )
            })
            .unwrap()
            .value
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        execution::paid_execution::decode_paid_execution_result(
            receipt_before.responses()[0].payload().unwrap()
        )
        .unwrap(),
        source.paid.result
    );
    let settlement: FastPathSettlementRecord = decode_fastpath_settlement_record(
        &network
            .value(
                0,
                &fastpath_settlement_key(&fixture::chain(), &PAID_REQUEST).unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(settlement.request_id, PAID_REQUEST);
    assert_eq!(
        settlement.total_amount,
        Some(source.paid.result.charged.as_ref().unwrap().actual.get())
    );
    assert_eq!(settlement.shares.len(), REPLICAS);
    assert_eq!(
        settlement
            .shares
            .iter()
            .map(|share| share.amount)
            .sum::<u64>(),
        settlement.total_amount.unwrap()
    );
    assert_eq!(
        query_sender_next_nonce(
            &network.stores[0],
            &network.context,
            network.domain(),
            fixture::chain(),
            fixture::protocol().protocol_version(),
            fixture::protocol().epoch(),
            *network.signers[0].id.as_bytes(),
        )
        .unwrap(),
        1
    );
    assert_eq!(nonce(network, 0), 0);
    owned.reverse();
    let observed: ObservedPaidEngine<'_> = ObservedPaidEngine {
        inner: &network.engine,
        calls: Cell::new(0),
    };
    let mut overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(observed_plan(&source, &identity, &observed)).unwrap();
    let report: BusinessReconstructionReport = overlay
        .reconstruct_with_control_material(&owned, &history, &controls)
        .unwrap();
    assert_eq!(report.owned_originals_replayed, 1);
    assert_eq!(
        observed.calls.get(),
        1,
        "retained-but-unapplied member must not execute"
    );
    // Full semantic projection compares exact receipts, charged effects,
    // logical provenance, object heads/versions and sender nonces. The absent
    // AV carrier must remain absent rather than be invented for equality.
    overlay.compare_source(&before).unwrap();
    assert_eq!(
        observed.calls.get(),
        1,
        "comparison never executes source output"
    );
    let replay: NodeOutput = crate::fast_path::drain_apply::apply_drain_member(
        &network.stores[0],
        &network.blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        &network.leg_policy,
        &source.fixture.manifest.fee_policy,
        &network.engine,
        PAID_REQUEST,
        99,
    )
    .unwrap();
    assert_eq!(replay.responses(), receipt_before.responses());
    assert_eq!(
        snapshot(network),
        before,
        "source replay and audit preserve every source byte"
    );
}

#[test]
fn completed_frozen_member_refuses_missing_controls_and_uncommitted_drain_without_execution() {
    let source: FrozenCompletionSource = frozen_completion_source(DrainScenario::Accepted);
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let owned: Vec<OwnedPublicationMaterial> = owned_material_from_source_snapshot(
        &before,
        &reconstruction_plan(&source.fixture, &identity),
    )
    .unwrap();
    for (pin, prefix, expects_control_error) in [
        (&identity, history.as_slice(), true),
        (
            &source.freeze_identity,
            source.freeze_history.as_slice(),
            false,
        ),
    ] {
        let observed: ObservedPaidEngine<'_> = ObservedPaidEngine {
            inner: &network.engine,
            calls: Cell::new(0),
        };
        let mut overlay: BusinessReconstructionOverlay<'_> =
            BusinessReconstructionOverlay::new(observed_plan(&source, pin, &observed)).unwrap();
        let error: BusinessReconstructionError = overlay.reconstruct(&owned, prefix).unwrap_err();
        if expects_control_error {
            assert!(matches!(
                error,
                BusinessReconstructionError::ControlProof(DrainSetControlProofError::Incomplete(_))
            ));
        } else {
            assert!(matches!(error, BusinessReconstructionError::Execution(_)));
        }
        assert_eq!(
            observed.calls.get(),
            0,
            "no normal pre-Freeze execution of no-AV completion"
        );
    }
    assert_eq!(snapshot(network), before);
}

#[test]
fn completed_frozen_member_refuses_owner_rejected_drain_and_committed_nonmembership() {
    for scenario in [DrainScenario::WrongUnion, DrainScenario::Nonmember] {
        let source: FrozenCompletionSource = frozen_completion_source(scenario);
        let network: &Network = &source.fixture.network;
        let before: SourceBusinessSnapshot = snapshot(network);
        let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
            complete_history(network);
        let plan: BusinessReconstructionPlan<'_> = reconstruction_plan(&source.fixture, &identity);
        let mut owned: Vec<OwnedPublicationMaterial> =
            owned_material_from_source_snapshot(&before, &plan).unwrap();
        assert!(owned.iter().all(|item| !item.source_application_present));
        // A supplied comparison-target hint cannot turn a retained full
        // certificate into a member of an absent/refused or different union.
        owned
            .iter_mut()
            .find(|item| item.bundle.request_id == PAID_REQUEST)
            .unwrap()
            .source_application_present = true;
        let controls: Vec<DrainSetControlMaterial> =
            drain_control_material_from_source_snapshot(&before, &plan, &history).unwrap();
        let observed: ObservedPaidEngine<'_> = ObservedPaidEngine {
            inner: &network.engine,
            calls: Cell::new(0),
        };
        let mut overlay: BusinessReconstructionOverlay<'_> =
            BusinessReconstructionOverlay::new(observed_plan(&source, &identity, &observed))
                .unwrap();
        assert!(matches!(
            overlay.reconstruct_with_control_material(&owned, &history, &controls),
            Err(BusinessReconstructionError::Execution(_))
        ));
        assert_eq!(observed.calls.get(), 0);
        assert_eq!(snapshot(network), before);
    }
}

#[test]
fn frozen_completion_requires_all_companions_full_certificate_and_exact_control_proof() {
    let source: FrozenCompletionSource = frozen_completion_source(DrainScenario::Accepted);
    let network: &Network = &source.fixture.network;
    let before: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let plan: BusinessReconstructionPlan<'_> = reconstruction_plan(&source.fixture, &identity);
    let owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&before, &plan).unwrap();
    let controls: Vec<DrainSetControlMaterial> =
        drain_control_material_from_source_snapshot(&before, &plan, &history).unwrap();
    for key in [
        DurableRecordKey::State(
            fastpath_certificate_key(&fixture::chain(), &PAID_REQUEST).unwrap(),
        ),
        DurableRecordKey::State(
            crate::local_instance_state::fastpath_commitment_witness_key(
                &fixture::chain(),
                &PAID_REQUEST,
            )
            .unwrap(),
        ),
        DurableRecordKey::State(fastpath_settlement_key(&fixture::chain(), &PAID_REQUEST).unwrap()),
        DurableRecordKey::Receipt(runtime::DurableRequestId::new(PAID_REQUEST).unwrap()),
    ] {
        let mut partial: SourceBusinessSnapshot = before.clone();
        partial.records.retain(|row| row.descriptor.key() != &key);
        assert!(matches!(
            owned_material_from_source_snapshot(&partial, &plan),
            Err(BusinessReconstructionError::Invalid(_))
        ));
    }
    let frozen_key: Vec<u8> = crate::fast_path::drain_publication::drain_publication_key(
        &fixture::chain(),
        fixture::protocol().epoch(),
        &PAID_REQUEST,
    )
    .unwrap();
    let mut absent_carrier: SourceBusinessSnapshot = before.clone();
    absent_carrier
        .records
        .retain(|row| row.descriptor.key() != &DurableRecordKey::State(frozen_key.clone()));
    for artifact in &owned
        .iter()
        .find(|item| item.bundle.request_id == PAID_REQUEST)
        .unwrap()
        .bundle
        .manifest
        .entries
    {
        let key: Vec<u8> = crate::fast_path::drain_publication::drain_publication_artifact_key(
            &fixture::chain(),
            fixture::protocol().epoch(),
            &PAID_REQUEST,
            artifact,
        )
        .unwrap();
        absent_carrier
            .records
            .retain(|row| row.descriptor.key() != &DurableRecordKey::State(key.clone()));
    }
    assert!(matches!(
        owned_material_from_source_snapshot(&absent_carrier, &plan),
        Err(BusinessReconstructionError::Invalid(_))
    ));
    let mut tombstoned_carrier: SourceBusinessSnapshot = before.clone();
    let row: &mut SourceSnapshotRecord = tombstoned_carrier
        .records
        .iter_mut()
        .find(|row| row.descriptor.key() == &DurableRecordKey::State(frozen_key.clone()))
        .unwrap();
    let DurableRecordMetadata::State { revision, .. } = row.descriptor.metadata() else {
        panic!("retained carrier is a state row");
    };
    row.descriptor = DurableRecordDescriptor::new(
        DurableRecordKey::State(frozen_key),
        DurableRecordMetadata::State {
            revision: *revision,
            value_length: None,
        },
    )
    .unwrap();
    row.value = None;
    assert!(matches!(
        owned_material_from_source_snapshot(&tombstoned_carrier, &plan),
        Err(BusinessReconstructionError::Invalid(_))
    ));
    let application_key: Vec<u8> =
        fastpath_certificate_key(&fixture::chain(), &PAID_REQUEST).unwrap();
    let mut partial_source: SourceBusinessSnapshot = before.clone();
    let mut application: crate::fast_path::records::FastPathCertificateRecord =
        crate::fast_path::records::decode_fastpath_certificate_record(
            &network.value(0, &application_key).unwrap(),
        )
        .unwrap();
    let mut certificate: FastCertificate =
        consensus::decode_fast_certificate(&application.certificate).unwrap();
    certificate.votes.truncate(1);
    application.certificate = consensus::encode_fast_certificate(&certificate).unwrap();
    replace_snapshot_state(
        &mut partial_source,
        application_key,
        crate::fast_path::records::encode_fastpath_certificate_record(&application).unwrap(),
    );
    assert!(matches!(
        owned_material_from_source_snapshot(&partial_source, &plan),
        Err(BusinessReconstructionError::Invalid(_))
    ));
    let mut partial_certificate: Vec<OwnedPublicationMaterial> = owned.clone();
    partial_certificate
        .iter_mut()
        .find(|item| item.bundle.request_id == PAID_REQUEST)
        .unwrap()
        .bundle
        .certificate
        .votes
        .truncate(1);
    let mut wrong_control: Vec<DrainSetControlMaterial> = controls.clone();
    wrong_control[0].signer_frontiers[0].pages[0].entries[0].request_id = [0x6c; 32];
    for (material, proof) in [
        (partial_certificate.as_slice(), controls.as_slice()),
        (owned.as_slice(), wrong_control.as_slice()),
        (owned.as_slice(), &[]),
    ] {
        let observed: ObservedPaidEngine<'_> = ObservedPaidEngine {
            inner: &network.engine,
            calls: Cell::new(0),
        };
        let mut overlay: BusinessReconstructionOverlay<'_> =
            BusinessReconstructionOverlay::new(observed_plan(&source, &identity, &observed))
                .unwrap();
        assert!(
            overlay
                .reconstruct_with_control_material(material, &history, proof)
                .is_err()
        );
        assert_eq!(observed.calls.get(), 0);
    }
    assert_eq!(snapshot(network), before);
}

fn derive_sqlite_control(
    source: &FrozenCompletionSource,
    store: &SqliteDurableStore,
    control: &DrainSetControlMaterial,
    owned: &[OwnedPublicationMaterial],
) {
    let network: &Network = &source.fixture.network;
    let mut members: BTreeSet<[u8; 32]> = BTreeSet::new();
    for (vote, frontier) in control.selected_votes.iter().zip(&control.signer_frontiers) {
        for page in &frontier.pages {
            ingest_drain_signer_page(
                store,
                &network.context,
                network.domain(),
                &network.resolver,
                &fixture::protocol(),
                frontier.signer,
                vote.clone(),
                page.clone(),
            )
            .unwrap();
            for entry in &page.entries {
                let material: &OwnedPublicationMaterial = owned
                    .iter()
                    .find(|item| item.bundle.request_id == entry.request_id)
                    .unwrap();
                let bundle: Vec<u8> =
                    consensus::bundle::encode_publication_bundle(&material.bundle).unwrap();
                assert_eq!(
                    import_staged_drain_publication(
                        store,
                        &network.context,
                        network.domain(),
                        &network.resolver,
                        &network.history,
                        &fixture::protocol(),
                        frontier.signer,
                        &bundle,
                    )
                    .unwrap(),
                    *entry
                );
                assert_eq!(
                    confirm_drain_signer_entry(
                        store,
                        &network.context,
                        network.domain(),
                        &network.resolver,
                        &network.history,
                        &fixture::protocol(),
                        frontier.signer,
                        entry.request_id,
                    )
                    .unwrap(),
                    *entry
                );
                members.insert(entry.request_id);
            }
        }
    }
    let mut ready: bool = false;
    for _ in 0..=members.len() {
        if let DrainUnionStep::Ready(identity) = advance_drain_union(
            store,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &control.selected_votes,
        )
        .unwrap()
        {
            assert_eq!(identity.member_count, u64::try_from(members.len()).unwrap());
            ready = true;
            break;
        }
    }
    assert!(ready);
}

#[test]
fn frozen_completion_sqlite_source_survives_reopen_fences_stale_writer_and_reconstructs() {
    use super::super::business_reconstruction::captured_source;
    let source: FrozenCompletionSource = frozen_completion_source(DrainScenario::Accepted);
    let network: &Network = &source.fixture.network;
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let memory_snapshot: SourceBusinessSnapshot = snapshot(network);
    let plan: BusinessReconstructionPlan<'_> = reconstruction_plan(&source.fixture, &identity);
    let owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&memory_snapshot, &plan).unwrap();
    let controls: Vec<DrainSetControlMaterial> =
        drain_control_material_from_source_snapshot(&memory_snapshot, &plan, &history).unwrap();
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory: std::path::PathBuf = std::env::temp_dir().join(format!(
        "frozen-completion-source-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let state_path: std::path::PathBuf = directory.join("state.sqlite");
    let blob_path: std::path::PathBuf = directory.join("blobs.sqlite");
    let namespace: SqliteNamespace =
        SqliteNamespace::new(fixture::chain(), network.signers[0].id, network.domain());
    let first: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let second: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
    let store: SqliteDurableStore =
        SqliteDurableStore::open(&state_path, namespace.clone(), first).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open(&blob_path).unwrap();
    // This real file-backed source is independently installed and executed.
    // No source row, object, nonce, ready flag, result or receipt is copied.
    genesis::install_genesis(
        &store,
        &network.context,
        network.domain(),
        &network.resolver,
        &source.fixture.manifest,
        10,
    )
    .unwrap();
    let environment: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: &network.policy,
        resolver: &network.resolver,
        history: &network.history,
        leg_policy: &network.leg_policy,
        engine: &network.engine,
        blobs: &blobs,
    };
    install_ordered_genesis(&store, &network.context, &environment, TRUSTED_NOW_MILLIS).unwrap();
    for material in &owned {
        let checkpoint: u64 = if material.bundle.request_id == PAID_REQUEST {
            11
        } else {
            12
        };
        let vote: FastVote = crate::fast_path::prepare(
            &store,
            &blobs,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &network.leg_policy,
            &source.fixture.manifest.fee_policy,
            &network.engine,
            &network.signers[0],
            &material.bundle.signed_intent,
            checkpoint,
        )
        .unwrap();
        assert_eq!(
            vote.execution_effects_hash,
            material.bundle.certificate.execution_effects_hash
        );
        let certificate: Vec<u8> =
            consensus::encode_fast_certificate(&material.bundle.certificate).unwrap();
        let assembled: PublicationBundle =
            crate::fast_path::publication::assemble_publication_bundle(
                &store,
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &fixture::protocol(),
                &material.bundle.signed_intent,
                &certificate,
            )
            .unwrap();
        assert_eq!(assembled, material.bundle);
        let _ack: consensus::AvailabilityVote = crate::fast_path::publication::retain_publication(
            &store,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &consensus::bundle::encode_publication_bundle(&assembled).unwrap(),
            &network.signers[0],
        )
        .unwrap();
    }
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), identity.clone()).unwrap();
    let mut proposals: BTreeMap<u64, ConsensusProposal> = BTreeMap::new();
    let mut certificates: BTreeMap<u64, QuorumCertificate> = BTreeMap::new();
    let mut candidates: BTreeMap<Digest32, OrderedCandidate> = BTreeMap::new();
    for material in &history {
        verifier.verify_next_height(material).unwrap();
        let proof: CommittedBlockProof = consensus::decode_committed_block_proof(
            &material
                .components
                .iter()
                .find(|(kind, _)| *kind == OrderedHistoryComponentKind::CommitProof)
                .unwrap()
                .1,
        )
        .unwrap();
        for proposal in [proof.committed, proof.child, proof.grandchild] {
            if let Some(previous) =
                certificates.insert(proposal.justify.view, proposal.justify.clone())
            {
                assert_eq!(previous, proposal.justify);
            }
            if let Some(previous) = proposals.insert(proposal.height, proposal.clone()) {
                assert_eq!(previous, proposal);
            }
        }
        let certificate: QuorumCertificate = proof.grandchild_certificate;
        if let Some(previous) = certificates.insert(certificate.view, certificate.clone()) {
            assert_eq!(previous, certificate);
        }
        if let Some((_, bytes)) = material
            .components
            .iter()
            .find(|(kind, _)| *kind == OrderedHistoryComponentKind::Candidate)
        {
            let candidate: OrderedCandidate = decode_ordered_candidate(bytes).unwrap();
            let digest: Digest32 = network.policy.candidate_digest(&candidate).unwrap();
            if let Some(previous) = candidates.insert(digest, candidate.clone()) {
                assert_eq!(previous, candidate);
            }
        }
    }
    assert_eq!(verifier.finish().unwrap().identity(), &identity);
    let mut control_prepared: bool = false;
    for proposal in proposals.into_values() {
        let candidate: Option<OrderedCandidate> = proposal
            .transactions
            .first()
            .map(|digest| candidates.get(digest).unwrap().clone());
        if !control_prepared
            && candidate
                .as_ref()
                .is_some_and(|candidate| candidate.kind == OrderedOperationKind::DrainSet)
        {
            derive_sqlite_control(&source, &store, &controls[0], &owned);
            control_prepared = true;
        }
        // Only authenticated proposal/QC transport bytes are replayed into
        // this real source. Ordinary runtime-neutral owning handlers derive
        // and atomically retain its actual business outcomes and receipts.
        let observed: OrderedEventOutput = observe_proposal(
            &store,
            &network.context,
            &environment,
            &OrderedProposal {
                proposal: proposal.clone(),
                candidate,
            },
        )
        .unwrap();
        assert!(
            !observed
                .messages
                .iter()
                .any(|message| { matches!(message, ConsensusMessage::Vote(_)) })
        );
        let certificate: &QuorumCertificate = certificates.get(&proposal.view).unwrap();
        let _output: OrderedEventOutput =
            process_certificate(&store, &network.context, &environment, certificate).unwrap();
    }
    assert!(control_prepared);
    assert_eq!(
        query_ordered_history_summary(&store, &network.context, &environment)
            .unwrap()
            .identity,
        identity
    );
    let output: NodeOutput = crate::fast_path::drain_apply::apply_drain_member(
        &store,
        &blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        &network.leg_policy,
        &source.fixture.manifest.fee_policy,
        &network.engine,
        PAID_REQUEST,
        11,
    )
    .unwrap();
    let before: SourceBusinessSnapshot =
        captured_source(&store, &blobs, &network.context, network.domain());
    drop(store);
    drop(blobs);
    let reopened: SqliteDurableStore =
        SqliteDurableStore::open(&state_path, namespace.clone(), first).unwrap();
    let reopened_blobs: SqliteBlobStore = SqliteBlobStore::open(&blob_path).unwrap();
    assert_eq!(
        captured_source(
            &reopened,
            &reopened_blobs,
            &network.context,
            network.domain()
        ),
        before
    );
    let replay: NodeOutput = crate::fast_path::drain_apply::apply_drain_member(
        &reopened,
        &reopened_blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &fixture::protocol(),
        &network.leg_policy,
        &source.fixture.manifest.fee_policy,
        &network.engine,
        PAID_REQUEST,
        99,
    )
    .unwrap();
    assert_eq!(replay, output);
    assert_eq!(
        captured_source(
            &reopened,
            &reopened_blobs,
            &network.context,
            network.domain()
        ),
        before
    );
    assert_eq!(
        reopened.advance_writer_fence(first, second).unwrap(),
        second
    );
    assert_eq!(
        reopened.begin_portable_snapshot(&network.context, network.domain()),
        Err(PortableSnapshotError::Read(
            runtime::DurableReadError::WriterFenced {
                active_generation: second,
            }
        ))
    );
    let observed: ObservedPaidEngine<'_> = ObservedPaidEngine {
        inner: &network.engine,
        calls: Cell::new(0),
    };
    assert!(
        crate::fast_path::drain_apply::apply_drain_member(
            &reopened,
            &reopened_blobs,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &network.leg_policy,
            &source.fixture.manifest.fee_policy,
            &observed,
            PAID_REQUEST,
            99,
        )
        .is_err()
    );
    assert_eq!(
        observed.calls.get(),
        0,
        "fenced receipt replay must not execute"
    );
    let current: DurableOperationContext = fixture::context(2);
    let fenced_snapshot: SourceBusinessSnapshot =
        captured_source(&reopened, &reopened_blobs, &current, network.domain());
    assert_eq!(fenced_snapshot.records, before.records);
    assert_eq!(fenced_snapshot.referenced_blobs, before.referenced_blobs);
    let mut current_plan: BusinessReconstructionPlan<'_> =
        observed_plan(&source, &identity, &observed);
    current_plan.operation_context = current;
    let current_owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&fenced_snapshot, &current_plan).unwrap();
    let current_controls: Vec<DrainSetControlMaterial> =
        drain_control_material_from_source_snapshot(&fenced_snapshot, &current_plan, &history)
            .unwrap();
    let mut overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(current_plan).unwrap();
    assert_eq!(
        overlay
            .reconstruct_with_control_material(&current_owned, &history, &current_controls)
            .unwrap()
            .owned_originals_replayed,
        1
    );
    overlay.compare_source(&fenced_snapshot).unwrap();
    assert_eq!(observed.calls.get(), 1);
    assert_eq!(
        captured_source(&reopened, &reopened_blobs, &current, network.domain()),
        fenced_snapshot
    );
    drop(reopened);
    drop(reopened_blobs);
    std::fs::remove_dir_all(directory).unwrap();
}
