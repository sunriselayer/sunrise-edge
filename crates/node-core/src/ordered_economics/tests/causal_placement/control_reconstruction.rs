//! Genuine signed causal genesis, real owned execution, and actual ordered
//! Freeze/DrainSet history. No source Ready/progress/business rows seed the
//! private overlay; all local readiness is derived through ordinary handlers.
use super::business_reconstruction::{complete_history, reconstruction_plan, snapshot};
use super::*;
use crate::business_reconstruction::{
    BusinessReconstructionError, BusinessReconstructionOverlay, BusinessReconstructionPlan,
    BusinessReconstructionReport, DrainSetControlMaterial, DrainSetControlProofError,
    OwnedPublicationMaterial, SourceBusinessSnapshot, SourceSnapshotRecord,
    drain_control_material_from_source_snapshot, owned_material_from_source_snapshot,
};
use crate::ordered_economics::frontier;
use canonical_encoding::CanonicalStruct;
use consensus::{
    DrainUnionIdentity, FrozenFrontierAccumulator, FrozenFrontierCertifier, FrozenFrontierPage,
    FrozenFrontierVote,
};
use runtime::portable::{DurableRecordDescriptor, DurableRecordKey, DurableRecordMetadata};
use std::num::NonZeroUsize;

const PAID_REQUEST: [u8; 32] = [0x6a; 32];
const UNAPPLIED_REQUEST: [u8; 32] = [0x6b; 32];
const FREEZE_REQUEST: [u8; 32] = [0xcb; 32];
const DRAIN_REQUEST: [u8; 32] = [0xcc; 32];

#[path = "control_reconstruction/frozen_completion.rs"]
mod frozen_completion;

struct GenuineControlSource {
    fixture: CausalFixture,
    paid: CertifiedPaidMaterial,
    unapplied: Option<CertifiedPaidMaterial>,
    selected: Vec<(FrozenFrontierVote, FrozenFrontierPage)>,
    candidate: OrderedCandidate,
}

fn commit_freeze(network: &Network, request: [u8; 32]) {
    let candidate: OrderedCandidate = freeze_candidate(request);
    for view in 1..=3 {
        network.round(view, (view == 1).then_some(&candidate));
    }
}

pub(super) fn derive_ready(
    network: &Network,
    replica: usize,
    selected: &[(FrozenFrontierVote, FrozenFrontierPage)],
    bundles: &[&[u8]],
) -> DrainUnionIdentity {
    let votes: Vec<FrozenFrontierVote> = selected.iter().map(|(vote, _)| vote.clone()).collect();
    let member_count: usize = selected[0].1.entries.len();
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
            let bundle: &[u8] = bundles
                .iter()
                .copied()
                .find(|bytes| {
                    consensus::bundle::decode_publication_bundle(bytes)
                        .unwrap()
                        .request_id
                        == entry.request_id
                })
                .unwrap();
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
    for _ in 0..=member_count {
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
            assert_eq!(identity.member_count, member_count as u64);
            return *identity;
        }
    }
    panic!("genuine full members must derive readiness in bounded member steps");
}

pub(super) fn registration_generic_prefix(fixture: &CausalFixture) -> Vec<CertifiedPaidMaterial> {
    frozen_completion::registration_generic_prefix(fixture)
}

pub(super) fn registration_transfer_cut(
    cut: &crate::business_reconstruction::cut::VerifiedBusinessCut,
    resolver: &HashSuiteResolver,
) -> crate::business_reconstruction::cut::SavedBusinessCut {
    frozen_completion::registration_transfer_cut(cut, resolver)
}

fn genuine_control_source(retain_unapplied: bool) -> GenuineControlSource {
    let fixture: CausalFixture = fresh_fixture();
    let signed: Vec<u8> = paid_transfer(
        &fixture,
        0,
        &fixture.manifest.objects[1].object,
        PAID_REQUEST,
        0,
    );
    let paid: CertifiedPaidMaterial = certify_and_apply_paid(&fixture, &signed, 11);
    // This first paid target is not a prerequisite of any earlier ordered
    // business candidate: the first ordered operation below is actual Freeze.
    // Its successful application must be replayed before ordinary admission
    // closes, without using its source outcome as authority.
    let unapplied: Option<CertifiedPaidMaterial> = retain_unapplied.then(|| {
        let signed: Vec<u8> =
            paid_transfer(&fixture, 1, &fixture.claimant_coin, UNAPPLIED_REQUEST, 0);
        certify_paid_with_subsets(
            &fixture,
            &signed,
            12,
            &[0, 1, 2],
            &[1, 2, 3],
            &[0, 1, 2],
            false,
        )
    });
    let member_count: usize = 1 + usize::from(unapplied.is_some());
    let network: &Network = &fixture.network;
    commit_freeze(network, FREEZE_REQUEST);
    let mut selected: Vec<(FrozenFrontierVote, FrozenFrontierPage)> = Vec::new();
    for source in 0..3 {
        for _ in 0..=member_count {
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
            NonZeroUsize::new(member_count + 1).unwrap(),
        )
        .unwrap();
        assert!(pair.1.terminal);
        assert_eq!(pair.1.entries.len(), member_count);
        assert_eq!(pair.1.entries[0].request_id, PAID_REQUEST);
        if unapplied.is_some() {
            assert_eq!(pair.1.entries[1].request_id, UNAPPLIED_REQUEST);
        }
        selected.push(pair);
    }
    selected.sort_by_key(|(vote, _)| vote.validator);
    let mut bundles: Vec<&[u8]> = vec![paid.bundle.as_slice()];
    if let Some(material) = &unapplied {
        bundles.push(material.bundle.as_slice());
    }
    let mut ready: Option<DrainUnionIdentity> = None;
    for replica in 0..REPLICAS {
        let actual: DrainUnionIdentity = derive_ready(network, replica, &selected, &bundles);
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
        unapplied,
        selected,
        candidate,
    }
}

fn assert_ordinary_owned_recovery_stays_closed(source: &GenuineControlSource) {
    let network: &Network = &source.fixture.network;
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    // This store is created only from the exact pinned signed genesis and
    // actual independently verified committed Freeze history, never copied
    // source Ready/progress, objects, nonce rows or application receipts.
    genesis::install_genesis(
        &store,
        &network.context,
        network.domain(),
        &network.resolver,
        &source.fixture.manifest,
        0,
    )
    .unwrap();
    install_ordered_genesis(&store, &network.context, &network.env(), TRUSTED_NOW_MILLIS).unwrap();
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), identity).unwrap();
    for material in history.iter().take(3) {
        let _derived: Option<OrderedOutcome> = engine::reconstruct_ordered_history_height(
            &store,
            &network.context,
            &network.env(),
            &mut verifier,
            material,
        )
        .unwrap();
    }
    assert_eq!(verifier.height(), 3);
    let bundle: PublicationBundle =
        consensus::bundle::decode_publication_bundle(&source.paid.bundle).unwrap();
    let error: crate::fast_path::FastPathError =
        crate::fast_path::apply_with_recovery_after_publication(
            &store,
            &network.blobs,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &network.leg_policy,
            &source.fixture.manifest.fee_policy,
            &network.engine,
            &bundle.signed_intent,
            &source.paid.certificate,
            11,
            &source.paid.availability_certificate,
        )
        .expect_err("a certified recovery is not permission to bypass committed Freeze");
    assert!(matches!(
        error,
        crate::fast_path::FastPathError::Node(NodeCoreError::PersistenceInvariant(
            "admission closed by a committed ordered-economics epoch freeze"
        ))
    ));
    eprintln!("typed ordinary recovery cause: {error:?}");
}

#[test]
fn genuine_control_history_needs_complete_selected_proof_and_reconstructs_without_source_rows() {
    let source: GenuineControlSource = genuine_control_source(true);
    let network: &Network = &source.fixture.network;
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let before: SourceBusinessSnapshot = snapshot(network);
    let plan: BusinessReconstructionPlan<'_> = reconstruction_plan(&source.fixture, &identity);
    let mut owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&before, &plan).unwrap();
    let controls: Vec<DrainSetControlMaterial> =
        drain_control_material_from_source_snapshot(&before, &plan, &history).unwrap();
    assert_eq!(owned.len(), 2);
    assert!(source.unapplied.is_some());
    assert_eq!(
        owned
            .iter()
            .filter(|material| material.source_application_present)
            .count(),
        1
    );
    assert!(receipt(network, 0, UNAPPLIED_REQUEST).is_none());
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
    let one_member: Vec<OwnedPublicationMaterial> = owned
        .iter()
        .filter(|material| material.bundle.request_id != UNAPPLIED_REQUEST)
        .cloned()
        .collect();
    assert_eq!(one_member.len(), 1);
    let mut missing_member: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&source.fixture, &identity))
            .unwrap();
    assert!(matches!(
        missing_member.reconstruct_with_control_material(&one_member, &history, &controls),
        Err(BusinessReconstructionError::ControlProof(
            DrainSetControlProofError::Incomplete(_)
        ))
    ));
    let mut corrupt_member: Vec<OwnedPublicationMaterial> = owned.clone();
    corrupt_member[1].bundle.contents[0][0] ^= 1;
    let mut bad_member: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&source.fixture, &identity))
            .unwrap();
    assert!(matches!(
        bad_member.reconstruct_with_control_material(&corrupt_member, &history, &controls),
        Err(BusinessReconstructionError::Invalid(_))
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

    // The public input sequence is not the sorted verified catalog's index
    // space. Exact full identity lookup must work independently of this order.
    owned.reverse();
    assert_eq!(owned[0].bundle.request_id, UNAPPLIED_REQUEST);
    assert_eq!(owned[1].bundle.request_id, PAID_REQUEST);
    let mut overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(plan).unwrap();
    let report: BusinessReconstructionReport = overlay
        .reconstruct_with_control_material(&owned, &history, &controls)
        .unwrap();
    assert_eq!(report.ordered_height, identity.through_height);
    assert_eq!(report.owned_originals_replayed, 1);
    assert!(receipt(network, 0, UNAPPLIED_REQUEST).is_none());
    assert_eq!(report.semantic_snapshot_equal, None);
    overlay.compare_source(&before).unwrap();
    assert_eq!(
        snapshot(network),
        before,
        "every row/revision/token is source-read-only"
    );
    assert_canonical_source_fact_corruptions_refuse_without_writes(&source, &before, &overlay);
}

#[derive(Clone, Copy, Debug)]
enum SourceFactMutation {
    Nonce,
    Bond,
    Receipt,
    HeadOwner,
    SelectedFrontier,
    UnknownReservedRow,
    UnknownReservedTombstone,
}

fn replace_snapshot_state(snapshot: &mut SourceBusinessSnapshot, key: Vec<u8>, value: Vec<u8>) {
    let row: &mut SourceSnapshotRecord = snapshot
        .records
        .iter_mut()
        .find(|row| row.descriptor.key() == &DurableRecordKey::State(key.clone()))
        .unwrap();
    let original: SourceSnapshotRecord = row.clone();
    assert_ne!(original.value.as_deref(), Some(value.as_slice()));
    let DurableRecordMetadata::State { revision, .. } = row.descriptor.metadata() else {
        panic!("a state key has state metadata");
    };
    row.descriptor = DurableRecordDescriptor::new(
        DurableRecordKey::State(key),
        DurableRecordMetadata::State {
            revision: *revision,
            value_length: Some(value.len()),
        },
    )
    .unwrap();
    row.value = Some(value);
    assert_ne!(*row, original);
}

fn altered_source_fact(
    source: &GenuineControlSource,
    before: &SourceBusinessSnapshot,
    mutation: SourceFactMutation,
) -> SourceBusinessSnapshot {
    let network: &Network = &source.fixture.network;
    let mut altered: SourceBusinessSnapshot = before.clone();
    match mutation {
        SourceFactMutation::Nonce => {
            let key: Vec<u8> = runtime::PersistenceLayout::new(
                fixture::chain(),
                fixture::protocol().protocol_version(),
            )
            .sender_nonce_key(
                *network.signers[0].id.as_bytes(),
                fixture::protocol().epoch(),
            );
            let bytes: &[u8] = before
                .records
                .iter()
                .find(|row| row.descriptor.key() == &DurableRecordKey::State(key.clone()))
                .unwrap()
                .value
                .as_deref()
                .unwrap();
            let frame = decode_canonical_frame(bytes).unwrap();
            frame.require_type(0xE006).unwrap();
            frame.require_version(1).unwrap();
            frame.require_only_fields(&[1, 2, 3]).unwrap();
            let mut changed: CanonicalStruct = CanonicalStruct::new(0xE006, 1);
            changed
                .field_bytes(1, frame.required_field(1).unwrap().to_vec())
                .unwrap();
            changed
                .field_u64(2, frame.required_u64(2).unwrap())
                .unwrap();
            changed
                .field_u64(3, frame.required_u64(3).unwrap().checked_add(1).unwrap())
                .unwrap();
            let value: Vec<u8> = changed.finish().unwrap();
            assert_eq!(
                decode_canonical_frame(&value)
                    .unwrap()
                    .required_u64(3)
                    .unwrap(),
                2
            );
            replace_snapshot_state(&mut altered, key, value);
        }
        SourceFactMutation::Bond => {
            let key: Vec<u8> =
                fastpath_bond_record_key(&fixture::chain(), &network.signers[0].id).unwrap();
            let bytes: &[u8] = before
                .records
                .iter()
                .find(|row| row.descriptor.key() == &DurableRecordKey::State(key.clone()))
                .unwrap()
                .value
                .as_deref()
                .unwrap();
            let mut bond: FastPathBondRecord = decode_fastpath_bond_record(bytes).unwrap();
            bond.generation = bond.generation.checked_add(1).unwrap();
            let value: Vec<u8> = encode_fastpath_bond_record(&bond).unwrap();
            assert_eq!(decode_fastpath_bond_record(&value).unwrap(), bond);
            replace_snapshot_state(&mut altered, key, value);
        }
        SourceFactMutation::Receipt => {
            let row: &mut SourceSnapshotRecord = altered
                .records
                .iter_mut()
                .find(|row| matches!(row.descriptor.key(), DurableRecordKey::Receipt(id) if id.as_bytes() == &PAID_REQUEST))
                .unwrap();
            let original_row: SourceSnapshotRecord = row.clone();
            let original: crate::NodeDedupRecord =
                crate::NodeDedupRecord::decode(row.value.as_deref().unwrap()).unwrap();
            assert_eq!(original.responses().len(), 1);
            assert_eq!(
                original.responses()[0].status(),
                crate::NodeResponseStatus::Accepted
            );
            let response: crate::NodeResponse = crate::NodeResponse::new(
                original.request_id(),
                crate::NodeResponseStatus::Rejected,
                original.responses()[0].payload().map(<[u8]>::to_vec),
            )
            .unwrap();
            let changed: crate::NodeDedupRecord = crate::NodeDedupRecord::new(
                original.request_id(),
                original.event_digest(),
                vec![response],
            )
            .unwrap();
            let value: Vec<u8> = changed.encode().unwrap();
            assert_eq!(crate::NodeDedupRecord::decode(&value).unwrap(), changed);
            assert_ne!(original_row.value.as_deref(), Some(value.as_slice()));
            row.descriptor = DurableRecordDescriptor::new(
                row.descriptor.key().clone(),
                DurableRecordMetadata::Receipt {
                    event_digest: original.event_digest(),
                    length: NonZeroUsize::new(value.len()).unwrap(),
                },
            )
            .unwrap();
            row.value = Some(value);
            assert_ne!(*row, original_row);
        }
        SourceFactMutation::HeadOwner => {
            let row: &mut SourceSnapshotRecord = altered
                .records
                .iter_mut()
                .find(|row| {
                    row.descriptor.key()
                        == &DurableRecordKey::ObjectHead(
                            source.fixture.manifest.objects[1].object.id,
                        )
                })
                .unwrap();
            let original_row: SourceSnapshotRecord = row.clone();
            let DurableRecordMetadata::ObjectHead(mut head) = row.descriptor.metadata().clone()
            else {
                panic!("an object head has typed metadata");
            };
            let DurableObjectHead::Current {
                owner_projection, ..
            } = &mut head
            else {
                panic!("the paid transfer retains a current source head");
            };
            let other_owner: Owner =
                Owner::Address(Address::new(*network.signers[1].id.as_bytes()));
            let changed: runtime::DurableObjectOwnerProjection =
                runtime::DurableObjectOwnerProjection::from_owner(other_owner.clone()).unwrap();
            assert_ne!(*owner_projection, changed);
            assert_eq!(
                objects::decode_owner(changed.bytes().unwrap()).unwrap(),
                other_owner
            );
            *owner_projection = changed;
            row.descriptor = DurableRecordDescriptor::new(
                row.descriptor.key().clone(),
                DurableRecordMetadata::ObjectHead(head),
            )
            .unwrap();
            assert_ne!(row.descriptor, original_row.descriptor);
        }
        SourceFactMutation::SelectedFrontier => {
            // Unsigned drain-signer-entry rows are local progress, not semantic
            // facts. Corrupt the selected signed descriptor's digest instead.
            let key: Vec<u8> =
                frontier::key(&fixture::chain(), fixture::protocol().epoch(), b"frontier/")
                    .unwrap();
            let bytes: &[u8] = before
                .records
                .iter()
                .find(|row| row.descriptor.key() == &DurableRecordKey::State(key.clone()))
                .unwrap()
                .value
                .as_deref()
                .unwrap();
            let original: frontier::FinalFrontier = frontier::decode_final(bytes).unwrap();
            let selected: &(FrozenFrontierVote, FrozenFrontierPage) = source
                .selected
                .iter()
                .find(|(vote, _)| vote.validator == original.vote.validator)
                .unwrap();
            assert_eq!(original.vote, selected.0);
            let mut entries: Vec<consensus::AvailabilityIdentity> = selected.1.entries.clone();
            let other_digest: Digest32 = entries
                .iter()
                .find(|entry| entry.request_id == UNAPPLIED_REQUEST)
                .unwrap()
                .semantic_artifacts_digest;
            let entry: &mut consensus::AvailabilityIdentity = entries
                .iter_mut()
                .find(|entry| entry.request_id == PAID_REQUEST)
                .unwrap();
            assert_ne!(entry.semantic_artifacts_digest, other_digest);
            entry.semantic_artifacts_digest = other_digest;
            assert_ne!(entries, selected.1.entries);
            // Rehash a complete, bounded alternative stream with the production
            // accumulator. The digest is genuine; the retained signature still
            // authenticates only the original stream, never this changed one.
            let mut accumulator: FrozenFrontierAccumulator = FrozenFrontierAccumulator::new(
                &network.resolver,
                original.identity.chain_id.clone(),
                original.identity.protocol_version,
                original.identity.epoch,
                original.identity.domain,
                original.identity.closure_request_id,
                original.identity.closure_height,
            )
            .unwrap();
            for entry in &entries {
                accumulator.push(&network.resolver, entry).unwrap();
            }
            let mut changed: frontier::FinalFrontier = original.clone();
            changed.identity = accumulator.into_identity();
            changed.vote.identity = changed.identity.clone();
            assert_eq!(changed.identity.entry_count, original.identity.entry_count);
            assert_ne!(
                changed.identity.entries_digest,
                original.identity.entries_digest
            );
            let frame: canonical_encoding::CanonicalFrame<'_> =
                decode_canonical_frame(bytes).unwrap();
            let mut encoded: CanonicalStruct =
                CanonicalStruct::new(frame.type_id(), frame.version());
            encoded
                .field_bytes(
                    1,
                    consensus::encode_frozen_frontier_identity(&changed.identity).unwrap(),
                )
                .unwrap();
            encoded
                .field_bytes(
                    2,
                    consensus::encode_frozen_frontier_vote(&changed.vote).unwrap(),
                )
                .unwrap();
            let value: Vec<u8> = encoded.finish().unwrap();
            assert_ne!(bytes, value.as_slice());
            assert_eq!(frontier::decode_final(&value).unwrap(), changed);
            let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
                original.identity.chain_id.clone(),
                original.identity.protocol_version,
                original.identity.epoch,
                network.policy.engine().validator_set().clone(),
            )
            .unwrap();
            certifier
                .verify_vote(&original.vote, &policy::Ed25519ConsensusVerifier)
                .unwrap();
            assert!(matches!(
                certifier.verify_vote(&changed.vote, &policy::Ed25519ConsensusVerifier),
                Err(consensus::FrontierError::Consensus(consensus::ConsensusError::InvalidSignature(validator)))
                    if validator == original.vote.validator
            ));
            replace_snapshot_state(&mut altered, key, value);
        }
        SourceFactMutation::UnknownReservedRow | SourceFactMutation::UnknownReservedTombstone => {
            let value: Vec<u8> =
                encode_ordered_refusal_payload(OrderedRefusal::IneligibleState).unwrap();
            decode_canonical_frame(&value).unwrap();
            let value: Option<Vec<u8>> = match mutation {
                SourceFactMutation::UnknownReservedRow => Some(value),
                SourceFactMutation::UnknownReservedTombstone => None,
                _ => unreachable!(),
            };
            let key: DurableRecordKey = DurableRecordKey::State(
                b"se/instances/v1/fastpath/unrecognized-business-v999".to_vec(),
            );
            assert!(
                !before
                    .records
                    .iter()
                    .any(|row| row.descriptor.key() == &key)
            );
            altered.records.push(SourceSnapshotRecord {
                descriptor: DurableRecordDescriptor::new(
                    key,
                    DurableRecordMetadata::State {
                        revision: runtime::StateRevision::new(1),
                        value_length: value.as_ref().map(Vec::len),
                    },
                )
                .unwrap(),
                value,
            });
        }
    }
    assert_ne!(altered.records, before.records);
    assert_eq!(altered.token, before.token);
    assert_eq!(altered.referenced_blobs, before.referenced_blobs);
    assert_ne!(altered, *before);
    // Descriptor lengths, original receipt identity/digest and body closure all
    // remain valid. Refusal must come from business/proof checks, not decoding.
    altered.validate().unwrap();
    altered
}

fn assert_canonical_source_fact_corruptions_refuse_without_writes(
    source: &GenuineControlSource,
    before: &SourceBusinessSnapshot,
    overlay: &BusinessReconstructionOverlay<'_>,
) {
    let network: &Network = &source.fixture.network;
    overlay.compare_source(before).unwrap();
    for mutation in [
        SourceFactMutation::Nonce,
        SourceFactMutation::Bond,
        SourceFactMutation::Receipt,
        SourceFactMutation::HeadOwner,
        SourceFactMutation::SelectedFrontier,
        SourceFactMutation::UnknownReservedRow,
        SourceFactMutation::UnknownReservedTombstone,
    ] {
        let altered: SourceBusinessSnapshot = altered_source_fact(source, before, mutation);
        let comparison: Result<(), BusinessReconstructionError> = overlay.compare_source(&altered);
        assert!(
            matches!(&comparison, Err(BusinessReconstructionError::Invalid(_))),
            "canonical {mutation:?} must not inherit semantic equality"
        );
        if matches!(mutation, SourceFactMutation::SelectedFrontier) {
            assert!(matches!(
                comparison,
                Err(BusinessReconstructionError::Invalid(
                    "source local ordered key/schema/proof differs"
                ))
            ));
        }
        overlay.compare_source(before).unwrap();
        assert_eq!(
            snapshot(network),
            *before,
            "{mutation:?} comparison never writes its genuine source"
        );
    }
}

#[test]
fn control_query_preserves_completed_and_earlier_refusals_and_actual_wrong_union() {
    let source: GenuineControlSource = genuine_control_source(false);
    assert_ordinary_owned_recovery_stays_closed(&source);
    let completed: &Network = &source.fixture.network;
    let original_freeze: OrderedCandidate = freeze_candidate(FREEZE_REQUEST);
    assert!(
        !engine::reconstruction_freeze_barrier_needed(
            &completed.stores[0],
            &completed.context,
            &completed.env(),
            &original_freeze,
            0,
        )
        .unwrap(),
        "exact completed Freeze precedes a now-premature height"
    );
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
        !engine::reconstruction_freeze_barrier_needed(
            &network.stores[0],
            &network.context,
            &network.env(),
            &original_freeze,
            0,
        )
        .unwrap(),
        "a genuine but premature Freeze does not flush Owned targets"
    );
    assert!(matches!(
        preflight::preflight(
            &network.stores[0],
            &network.context,
            &network.env(),
            &original_freeze,
            0,
        ),
        Err(OrderedEconomicsError::Refused(
            OrderedRefusal::PrematureFreeze
        ))
    ));
    assert!(
        engine::reconstruction_freeze_barrier_needed(
            &network.stores[0],
            &network.context,
            &network.env(),
            &original_freeze,
            1,
        )
        .unwrap(),
        "the owning warrant at the actual eligible height requests the barrier"
    );
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
        !engine::reconstruction_freeze_barrier_needed(
            &network.stores[0],
            &network.context,
            &network.env(),
            &original_freeze,
            4,
        )
        .unwrap(),
        "a fresh AlreadyFrozen refusal does not move later Owned targets"
    );
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
    let actual: DrainUnionIdentity = derive_ready(
        network,
        0,
        &source.selected,
        &[source.paid.bundle.as_slice()],
    );
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
    let source: GenuineControlSource = genuine_control_source(false);
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
