//! Genuine signed-v4 execution through the complete private audit, not a
//! fixture which copies source business rows into reconstruction memory.

use super::*;
use crate::business_reconstruction::{
    BusinessReconstructionError, BusinessReconstructionOverlay, BusinessReconstructionPlan,
    BusinessReconstructionReport, OwnedPublicationMaterial, SourceBusinessSnapshot,
    SourceSnapshotRecord, owned_material_from_source_snapshot, referenced_blob_bounds,
};
use crate::logical_generation::{
    LogicalObservation, LogicalProvenanceRecord, LogicalSubject, decode_logical_provenance_record,
    encode_logical_provenance_record,
};
use consensus::bundle::{ArtifactEntry, ArtifactKind};
use runtime::portable::{
    DurableCollection, DurablePortableSnapshotRepository, DurableRecordChunkOutcome,
    DurableRecordChunkRequest, DurableRecordDescriptor, DurableRecordKey, DurableRecordPage,
    DurableRecordScan, PortableBlobChunkOutcome, PortableBlobChunkRequest, PortableBlobDescriptor,
    PortableBlobRepository, PortableSnapshotToken,
};
use std::{collections::BTreeMap, num::NonZeroUsize};

const ESCROW: [u8; 32] = [0x6e; 32];
const NONCE_PRODUCER: [u8; 32] = [0x6f; 32];
const CLAIM: [u8; 32] = [0xda; 32];

pub(super) fn reconstruction_plan<'a>(
    fixture: &'a CausalFixture,
    identity: &'a OrderedHistoryIdentity,
) -> BusinessReconstructionPlan<'a> {
    let network: &Network = &fixture.network;
    BusinessReconstructionPlan {
        admission_profile: network.policy.admission_profile().unwrap(),
        genesis: &fixture.manifest,
        pinned_genesis_digest: network.policy.genesis_digest(),
        operation_context: network.context,
        domain: network.domain(),
        resolver: &network.resolver,
        resolver_history: &network.history,
        ordered_policy: &network.policy,
        ordered_history_identity: identity,
        ordered_leg_policy: &network.leg_policy,
        ordered_engine: &network.engine,
        paid_base_policy: &network.leg_policy,
        paid_engine: &network.engine,
    }
}

fn captured_value<S: DurablePortableSnapshotRepository>(
    store: &S,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
    token: &PortableSnapshotToken,
    descriptor: &DurableRecordDescriptor,
) -> Option<Vec<u8>> {
    let length: usize = descriptor.payload_length()?;
    let mut bytes: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let count: usize = 1024.min(length.checked_sub(offset).unwrap());
        let request: DurableRecordChunkRequest = DurableRecordChunkRequest::new(
            descriptor.clone(),
            offset,
            NonZeroUsize::new(count.max(1)).unwrap(),
        )
        .unwrap();
        let DurableRecordChunkOutcome::Chunk(chunk) = store
            .read_portable_chunk_at(operation, domain, token, &request)
            .unwrap()
        else {
            panic!("source changed while capturing one consistent snapshot");
        };
        assert_eq!(chunk.request(), &request);
        assert_eq!(chunk.bytes().len(), count);
        bytes.extend_from_slice(chunk.bytes());
        offset = offset.checked_add(count).unwrap();
        if chunk.is_last() {
            break;
        }
    }
    assert_eq!(bytes.len(), length);
    Some(bytes)
}

fn captured_blob<B: PortableBlobRepository>(
    source: &B,
    digest: Digest32,
    maximum: usize,
) -> Vec<u8> {
    let descriptor: PortableBlobDescriptor = source
        .read_portable_blob_descriptor(&digest)
        .unwrap()
        .unwrap();
    assert_eq!(descriptor.digest(), digest);
    assert!(descriptor.length() <= maximum);
    let mut bytes: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    loop {
        let count: usize = 1024.min(descriptor.length().checked_sub(offset).unwrap());
        let request: PortableBlobChunkRequest = PortableBlobChunkRequest::new(
            descriptor,
            offset,
            NonZeroUsize::new(count.max(1)).unwrap(),
        )
        .unwrap();
        let PortableBlobChunkOutcome::Chunk(chunk) =
            source.read_portable_blob_chunk(&request).unwrap()
        else {
            panic!("genuine source referenced blob is missing or changed");
        };
        assert_eq!(chunk.request(), &request);
        assert_eq!(chunk.bytes().len(), count);
        bytes.extend_from_slice(chunk.bytes());
        offset = offset.checked_add(count).unwrap();
        if chunk.is_last() {
            break;
        }
    }
    bytes
}

// No allowlist or hand-selected source business rows: scan all four complete
// collections, including local tombstones and original/synthetic receipts.
fn captured_source<S: DurablePortableSnapshotRepository, B: PortableBlobRepository>(
    store: &S,
    blobs: &B,
    operation: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> SourceBusinessSnapshot {
    let token: PortableSnapshotToken = store.begin_portable_snapshot(operation, domain).unwrap();
    store
        .check_portable_outbox_empty_at(operation, domain, &token)
        .unwrap();
    let mut records: Vec<SourceSnapshotRecord> = Vec::new();
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        let mut after: Option<DurableRecordKey> = None;
        loop {
            let scan: DurableRecordScan =
                DurableRecordScan::new(collection, after.clone(), NonZeroUsize::new(7).unwrap())
                    .unwrap();
            let page: DurableRecordPage = store
                .scan_portable_keys_at(operation, domain, &token, &scan)
                .unwrap();
            for key in page.keys() {
                let descriptor: DurableRecordDescriptor = store
                    .read_portable_descriptor_at(operation, domain, &token, key)
                    .unwrap()
                    .unwrap();
                assert_eq!(descriptor.key(), key);
                let value: Option<Vec<u8>> =
                    captured_value(store, operation, domain, &token, &descriptor);
                records.push(SourceSnapshotRecord { descriptor, value });
            }
            let Some(next) = page.continuation() else {
                break;
            };
            assert!(after.as_ref().is_none_or(|previous| next > previous));
            after = Some(next.clone());
        }
    }
    let mut snapshot: SourceBusinessSnapshot = SourceBusinessSnapshot {
        token,
        records,
        referenced_blobs: BTreeMap::new(),
    };
    for (digest, maximum) in referenced_blob_bounds(&snapshot).unwrap() {
        snapshot
            .referenced_blobs
            .insert(digest, captured_blob(blobs, digest, maximum));
    }
    store
        .check_portable_outbox_empty_at(operation, domain, &snapshot.token)
        .unwrap();
    snapshot.validate().unwrap();
    snapshot
}

pub(super) fn snapshot(network: &Network) -> SourceBusinessSnapshot {
    captured_source(
        &network.stores[0],
        &network.blobs,
        &network.context,
        network.domain(),
    )
}

fn changed_marker_provenance(
    source: &SourceBusinessSnapshot,
    marker_key: &[u8],
    update: impl FnOnce(&mut LogicalProvenanceRecord),
) -> SourceBusinessSnapshot {
    let mut altered: SourceBusinessSnapshot = source.clone();
    let row: &mut SourceSnapshotRecord = altered
        .records
        .iter_mut()
        .find(|row| {
            matches!(row.descriptor.key(), DurableRecordKey::State(key)
                if key.starts_with(crate::logical_generation::LOGICAL_STATE_PREFIX))
                && row.value.as_deref().is_some_and(|bytes| {
                    decode_logical_provenance_record(bytes).is_ok_and(|record| {
                        record.subject == LogicalSubject::StateKey(marker_key.to_vec())
                    })
                })
        })
        .expect("genesis marker provenance row");
    let mut provenance: LogicalProvenanceRecord =
        decode_logical_provenance_record(row.value.as_deref().expect("marker provenance value"))
            .expect("canonical marker provenance");
    update(&mut provenance);
    row.value = Some(encode_logical_provenance_record(&provenance).unwrap());
    altered
}

pub(super) fn complete_history(
    network: &Network,
) -> (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) {
    let identity: OrderedHistoryIdentity =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .identity;
    let mut history: Vec<OrderedHistoryHeightMaterial> = Vec::new();
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), identity.clone()).unwrap();
    for height in 1..=identity.through_height {
        let descriptor: OrderedHistoryHeightDescriptor = read_ordered_history_height_descriptor(
            &network.stores[0],
            &network.context,
            &network.env(),
            &identity,
            height,
        )
        .unwrap();
        let digest: Digest32 =
            ordered_history_descriptor_digest(&network.policy, &descriptor).unwrap();
        let mut components: Vec<(OrderedHistoryComponentKind, Vec<u8>)> = Vec::new();
        for reference in &descriptor.components {
            let mut bytes: Vec<u8> = Vec::new();
            let mut offset: u64 = 0;
            while offset < reference.length {
                let limit: u32 =
                    u32::try_from(1024.min(reference.length.checked_sub(offset).unwrap())).unwrap();
                let chunk: Vec<u8> = read_ordered_history_component_chunk(
                    &network.stores[0],
                    &network.context,
                    &network.env(),
                    &identity,
                    height,
                    digest,
                    reference.kind,
                    offset,
                    limit,
                )
                .unwrap();
                assert_eq!(chunk.len(), usize::try_from(limit).unwrap());
                offset = offset.checked_add(u64::from(limit)).unwrap();
                bytes.extend(chunk);
            }
            assert_eq!(u64::try_from(bytes.len()).unwrap(), reference.length);
            components.push((reference.kind, bytes));
        }
        let material: OrderedHistoryHeightMaterial = OrderedHistoryHeightMaterial {
            descriptor,
            components,
        };
        verifier.verify_next_height(&material).unwrap();
        history.push(material);
    }
    assert_eq!(verifier.finish().unwrap().identity(), &identity);
    (identity, history)
}

fn claim_source(
    vary_quorums: bool,
    pending_recommit: bool,
) -> (CausalFixture, [CertifiedPaidMaterial; 2], OrderedCandidate) {
    let fixture: CausalFixture = fresh_fixture();
    let escrow_intent: Vec<u8> =
        paid_transfer(&fixture, 0, &fixture.manifest.objects[1].object, ESCROW, 0);
    let nonce_intent: Vec<u8> =
        paid_transfer(&fixture, 1, &fixture.claimant_coin, NONCE_PRODUCER, 0);
    let materials: [CertifiedPaidMaterial; 2] = if vary_quorums {
        [
            certify_paid_with_subsets(
                &fixture,
                &escrow_intent,
                11,
                &[0, 1, 2],
                &[1, 2, 3],
                &[0, 1, 2],
                true,
            ),
            certify_paid_with_subsets(
                &fixture,
                &nonce_intent,
                12,
                &[1, 2, 3],
                &[0, 1, 2],
                &[1, 2, 3],
                true,
            ),
        ]
    } else {
        [
            certify_and_apply_paid(&fixture, &escrow_intent, 11),
            certify_and_apply_paid(&fixture, &nonce_intent, 12),
        ]
    };
    let (candidate, expected): (OrderedCandidate, FastPathSettlementRecord) =
        positive_claim(&fixture, ESCROW, CLAIM);
    for view in 1..=3 {
        fixture
            .network
            .round(view, (view == 1).then_some(&candidate));
    }
    if pending_recommit {
        // The ordinary ordered proposer correctly refuses a completed
        // request. Mirror the established delayed-observer path instead:
        // generate a real signed consensus proposal/QC for the same
        // candidate after h1, observe it at every replica, then apply its QC
        // and assert the original receipt is retained byte-for-byte.
        use consensus::{ConsensusEngine, ConsensusEvent};

        let original: DurableRequestReceipt = receipt(&fixture.network, 0, CLAIM).unwrap();
        let leader: usize = fixture.network.leader_index(4);
        let state: consensus::ConsensusState = consensus::decode_consensus_state(
            &fixture
                .network
                .value(
                    leader,
                    &crate::ordered_economics::engine::ordered_state_key_for_tests(
                        &fixture::chain(),
                    ),
                )
                .unwrap(),
        )
        .unwrap();
        let digest: Digest32 = fixture.network.policy.candidate_digest(&candidate).unwrap();
        let proposal: consensus::ConsensusProposal = fixture
            .network
            .policy
            .engine()
            .propose(&state, vec![digest], &fixture.network.signers[leader])
            .unwrap();
        let ordered: OrderedProposal = OrderedProposal {
            proposal: proposal.clone(),
            candidate: Some(candidate.clone()),
        };
        for store in &fixture.network.stores {
            observe_proposal(
                store,
                &fixture.network.context,
                &fixture.network.env(),
                &ordered,
            )
            .unwrap();
        }
        let genesis: consensus::ConsensusState = fixture
            .network
            .policy
            .engine()
            .genesis_state(TRUSTED_NOW_MILLIS);
        let votes: Vec<ConsensusVote> = fixture
            .network
            .signers
            .iter()
            .map(|signer| {
                fixture
                    .network
                    .policy
                    .engine()
                    .on_event(
                        &genesis,
                        ConsensusEvent::Proposal(proposal.clone()),
                        signer,
                        &super::super::super::policy::Ed25519ConsensusVerifier,
                    )
                    .unwrap()
                    .outbound_messages
                    .into_iter()
                    .find_map(|message| match message {
                        ConsensusMessage::Vote(vote) => Some(vote),
                        _ => None,
                    })
                    .unwrap()
            })
            .collect();
        let certificate: QuorumCertificate = fixture
            .network
            .policy
            .engine()
            .certificate_from_votes(
                &proposal,
                &votes,
                &super::super::super::policy::Ed25519ConsensusVerifier,
            )
            .unwrap()
            .unwrap();
        for store in &fixture.network.stores {
            process_certificate(
                store,
                &fixture.network.context,
                &fixture.network.env(),
                &certificate,
            )
            .unwrap();
        }
        assert_eq!(receipt(&fixture.network, 0, CLAIM), Some(original));
        for view in 5..=6 {
            fixture.network.round(view, None);
        }
    }
    for replica in 0..REPLICAS {
        assert_eq!(nonce(&fixture.network, replica), 2);
        assert_eq!(settlement(&fixture.network, replica, ESCROW), expected);
        assert!(receipt(&fixture.network, replica, CLAIM).is_some());
    }
    (fixture, materials, candidate)
}

fn availability_subset(network: &Network, request: [u8; 32], signers: &[usize]) -> Vec<u8> {
    let key: Vec<u8> =
        crate::fast_path::publication::fastpath_availability_ack_key(&fixture::chain(), &request)
            .unwrap();
    let votes: Vec<consensus::AvailabilityVote> = signers
        .iter()
        .map(|replica: &usize| {
            let retained: crate::fast_path::publication::FastPathAvailabilityAckRecord =
                crate::fast_path::publication::decode_fastpath_availability_ack_record(
                    &network.value(*replica, &key).unwrap(),
                )
                .unwrap();
            consensus::decode_availability_vote(&retained.vote).unwrap()
        })
        .collect();
    let certifier: consensus::AvailabilityCertifier = consensus::AvailabilityCertifier::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        fixture::protocol().epoch(),
        validator_set(&network.signers),
    )
    .unwrap();
    let certificate: consensus::AvailabilityCertificate = certifier
        .try_form_certificate(
            &votes[0].identity,
            &votes,
            &crate::fast_path::FastPathEd25519Verifier,
        )
        .unwrap()
        .unwrap();
    consensus::encode_availability_certificate(&certificate).unwrap()
}

#[test]
fn reconstructs_two_genuine_owned_producers_and_positive_claim_with_closed_source_comparison() {
    let (fixture, materials, _candidate): (
        CausalFixture,
        [CertifiedPaidMaterial; 2],
        OrderedCandidate,
    ) = claim_source(false, true);
    let network: &Network = &fixture.network;
    let original: DurableRequestReceipt = receipt(network, 0, CLAIM).unwrap();
    let after_first: FastPathSettlementRecord = settlement(network, 0, ESCROW);
    assert_eq!(receipt(network, 0, CLAIM).unwrap(), original);
    assert_eq!(settlement(network, 0, ESCROW), after_first);
    assert_eq!(nonce(network, 0), 2);
    let source: SourceBusinessSnapshot = snapshot(network);
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        assert!(
            source
                .records
                .iter()
                .any(|row| row.descriptor.key().collection() == collection)
        );
    }
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    let owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&source, &reconstruction_plan(&fixture, &identity))
            .unwrap();
    assert_eq!(owned.len(), 2);
    assert!(
        owned
            .iter()
            .all(|material| material.source_application_present)
    );
    let mut overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&fixture, &identity)).unwrap();
    assert!(matches!(
        overlay.compare_source(&source),
        Err(BusinessReconstructionError::Incomplete(_))
    ));
    let report: BusinessReconstructionReport = overlay.reconstruct(&owned, &history).unwrap();
    assert_eq!(report.owned_originals_replayed, 2);
    assert_eq!(report.ordered_originals_replayed, 1);
    assert_eq!(report.ordered_height, 4);
    assert_eq!(report.empty_ordered_heights, 2);
    assert!(
        history
            .get(3)
            .unwrap()
            .components
            .iter()
            .any(|(kind, _)| *kind == OrderedHistoryComponentKind::ReplayOriginProof)
    );
    overlay.compare_source(&source).unwrap();

    // Both are real, necessary producers: another sender created the escrow,
    // and this claimant's independent paid operation committed nonce zero.
    for missing in [ESCROW, NONCE_PRODUCER] {
        let incomplete: Vec<OwnedPublicationMaterial> = owned
            .iter()
            .filter(|material| material.bundle.request_id != missing)
            .cloned()
            .collect();
        let mut missing_overlay: BusinessReconstructionOverlay<'_> =
            BusinessReconstructionOverlay::new(reconstruction_plan(&fixture, &identity)).unwrap();
        assert!(missing_overlay.reconstruct(&incomplete, &history).is_err());
        assert!(missing_overlay.compare_source(&source).is_err());
    }
    let mut incomplete_history: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&fixture, &identity)).unwrap();
    assert!(incomplete_history.reconstruct(&owned, &[]).is_err());
    assert!(incomplete_history.compare_source(&source).is_err());

    // The fixture stores its small objects inline. Their genuine retained
    // ObjectBody artifacts still exercise the authenticated body closure;
    // this does not pretend to test a fabricated BlobReference object row.
    let bundle: PublicationBundle =
        consensus::bundle::decode_publication_bundle(&materials[0].bundle).unwrap();
    let entry: &ArtifactEntry = bundle
        .manifest
        .entries
        .iter()
        .find(|entry| entry.kind == ArtifactKind::ObjectBody)
        .unwrap();
    let artifact: DurableRecordKey = DurableRecordKey::State(
        crate::fast_path::publication::fastpath_publication_artifact_key(
            &fixture::chain(),
            &ESCROW,
            entry.kind,
            &entry.content_digest.bytes(),
        )
        .unwrap(),
    );
    let mut missing_body: SourceBusinessSnapshot = source.clone();
    missing_body
        .records
        .retain(|row| row.descriptor.key() != &artifact);
    assert_eq!(
        missing_body.records.len().checked_add(1).unwrap(),
        source.records.len()
    );
    assert!(
        owned_material_from_source_snapshot(
            &missing_body,
            &reconstruction_plan(&fixture, &identity)
        )
        .is_err()
    );
    assert!(overlay.compare_source(&missing_body).is_err());
    let mut corrupt_body: SourceBusinessSnapshot = source.clone();
    let body: &mut Vec<u8> = corrupt_body
        .records
        .iter_mut()
        .find(|row| row.descriptor.key() == &artifact)
        .unwrap()
        .value
        .as_mut()
        .unwrap();
    body[0] ^= 1;
    corrupt_body.validate().unwrap();
    assert!(
        owned_material_from_source_snapshot(
            &corrupt_body,
            &reconstruction_plan(&fixture, &identity)
        )
        .is_err()
    );
    assert!(overlay.compare_source(&corrupt_body).is_err());
    assert_eq!(
        snapshot(network),
        source,
        "the audit never writes its source"
    );
}

#[test]
fn equivalent_real_quorums_and_normal_drain_aliases_compare_equal_after_independent_replay() {
    let (fixture, materials, _): (CausalFixture, [CertifiedPaidMaterial; 2], OrderedCandidate) =
        claim_source(true, false);
    let network: &Network = &fixture.network;
    let freeze: OrderedCandidate = freeze_candidate([0xdb; 32]);
    for view in 4..=6 {
        network.round(view, (view == 4).then_some(&freeze));
    }
    let normal_source: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    assert_eq!(identity.through_height, 4);
    let mut owned: Vec<OwnedPublicationMaterial> = owned_material_from_source_snapshot(
        &normal_source,
        &reconstruction_plan(&fixture, &identity),
    )
    .unwrap();
    assert_eq!(owned.len(), 2);
    for (index, request) in [ESCROW, NONCE_PRODUCER].into_iter().enumerate() {
        let material: &mut OwnedPublicationMaterial = owned
            .iter_mut()
            .find(|material| material.bundle.request_id == request)
            .unwrap();
        assert_ne!(
            consensus::encode_fast_certificate(&material.bundle.certificate).unwrap(),
            materials[index].certificate,
            "genuine source application and publication use different quorums"
        );
        if index == 0 {
            // Also vary the replay catalog's full certificate against the
            // source's retained publication, not merely a local carrier row.
            // The other producer keeps the opposite application-carrier
            // variation, so both normalization boundaries are exercised.
            material.bundle.certificate =
                consensus::decode_fast_certificate(&materials[index].certificate).unwrap();
        }
        let alternate: Vec<u8> = availability_subset(
            network,
            request,
            if index == 0 { &[1, 2, 3] } else { &[0, 1, 2] },
        );
        assert_ne!(
            material.availability_certificate.as_ref().unwrap(),
            &alternate
        );
        let alternate_identity: consensus::AvailabilityIdentity =
            consensus::decode_availability_certificate(&alternate)
                .unwrap()
                .identity;
        assert_eq!(
            alternate_identity,
            consensus::decode_availability_certificate(
                material.availability_certificate.as_ref().unwrap()
            )
            .unwrap()
            .identity
        );
        material.availability_certificate = Some(alternate);
    }
    let mut overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&fixture, &identity)).unwrap();
    let report: BusinessReconstructionReport = overlay.reconstruct(&owned, &history).unwrap();
    assert_eq!(report.owned_originals_replayed, 2);
    assert_eq!(report.ordered_originals_replayed, 2);
    assert_eq!(report.empty_ordered_heights, 2);
    overlay.compare_source(&normal_source).unwrap();

    // Actual post-Freeze retention, not a copied alias row. Each alias has
    // the other real execution quorum for the same verified subject.
    for (index, request) in [ESCROW, NONCE_PRODUCER].into_iter().enumerate() {
        let mut alias: PublicationBundle =
            consensus::bundle::decode_publication_bundle(&materials[index].bundle).unwrap();
        alias.certificate =
            consensus::decode_fast_certificate(&materials[index].certificate).unwrap();
        let expected: consensus::AvailabilityIdentity =
            consensus::decode_availability_certificate(&materials[index].availability_certificate)
                .unwrap()
                .identity;
        assert_eq!(alias.request_id, request);
        crate::fast_path::drain_publication::retain_drain_publication(
            &network.stores[0],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &expected,
            &consensus::bundle::encode_publication_bundle(&alias).unwrap(),
        )
        .unwrap();
    }
    let alias_source: SourceBusinessSnapshot = snapshot(network);
    assert!(alias_source.records.len() > normal_source.records.len());
    let extracted: Vec<OwnedPublicationMaterial> = owned_material_from_source_snapshot(
        &alias_source,
        &reconstruction_plan(&fixture, &identity),
    )
    .unwrap();
    assert_eq!(
        extracted.len(),
        2,
        "aliases do not create another operation"
    );
    overlay.compare_source(&alias_source).unwrap();
    for request in [ESCROW, NONCE_PRODUCER, CLAIM] {
        let key: DurableRecordKey =
            DurableRecordKey::Receipt(DurableRequestId::new(request).unwrap());
        assert_eq!(
            normal_source
                .records
                .iter()
                .find(|row| row.descriptor.key() == &key),
            alias_source
                .records
                .iter()
                .find(|row| row.descriptor.key() == &key),
            "retention changes no original receipt"
        );
    }
    assert_eq!(snapshot(network), alias_source);
}

#[test]
fn signed_v4_genesis_install_checkpoint_does_not_change_first_bond_transition() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;

    // This genuine signed-v4 source fixture installs at checkpoint 10. The
    // independently reconstructed private store installs the same signed
    // genesis at checkpoint 0. Installation coordinates are local markers;
    // the business genesis bond generation must be deterministic across both.
    assert_eq!(network.bond.committed_at_checkpoint, 0);
    let request: [u8; 32] = [0xec; 32];
    let (candidate, expected): (OrderedCandidate, FastPathBondRecord) =
        replacement(&fixture, request);
    for view in 1..=3 {
        network.round(view, (view == 1).then_some(&candidate));
    }
    assert_eq!(network.committed_bond(0), expected);

    let source: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    assert_eq!(identity.through_height, 1);
    let owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&source, &reconstruction_plan(&fixture, &identity))
            .unwrap();
    let mut overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&fixture, &identity)).unwrap();
    let report: BusinessReconstructionReport = overlay.reconstruct(&owned, &history).unwrap();
    assert_eq!(report.ordered_originals_replayed, 1);
    overlay.compare_source(&source).unwrap();
    assert_eq!(snapshot(network), source);
}

#[test]
fn genuine_unapplied_publication_compares_but_orphan_availability_ack_refuses() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let request: [u8; 32] = [0x70; 32];
    let signed: Vec<u8> =
        paid_transfer(&fixture, 0, &fixture.manifest.objects[1].object, request, 0);
    let retained: CertifiedPaidMaterial = certify_paid_with_subsets(
        &fixture,
        &signed,
        11,
        &[0, 1, 2],
        &[1, 2, 3],
        &[0, 1, 2],
        false,
    );
    assert!(receipt(network, 0, request).is_none());
    let source: SourceBusinessSnapshot = snapshot(network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(network);
    assert_eq!(identity.through_height, 0);
    assert!(history.is_empty());
    let owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&source, &reconstruction_plan(&fixture, &identity))
            .unwrap();
    assert_eq!(owned.len(), 1);
    assert!(!owned[0].source_application_present);
    let mut overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&fixture, &identity)).unwrap();
    assert_eq!(
        overlay
            .reconstruct(&owned, &history)
            .unwrap()
            .owned_originals_replayed,
        0
    );
    overlay.compare_source(&source).unwrap();

    let bundle: PublicationBundle =
        consensus::bundle::decode_publication_bundle(&retained.bundle).unwrap();
    let mut removed: Vec<DurableRecordKey> = vec![DurableRecordKey::State(
        crate::fast_path::publication::fastpath_publication_key(&fixture::chain(), &request)
            .unwrap(),
    )];
    for entry in &bundle.manifest.entries {
        removed.push(DurableRecordKey::State(
            crate::fast_path::publication::fastpath_publication_artifact_key(
                &fixture::chain(),
                &request,
                entry.kind,
                &entry.content_digest.bytes(),
            )
            .unwrap(),
        ));
    }
    let mut orphan: SourceBusinessSnapshot = source.clone();
    orphan
        .records
        .retain(|row| !removed.contains(row.descriptor.key()));
    let ack_key: DurableRecordKey = DurableRecordKey::State(
        crate::fast_path::publication::fastpath_availability_ack_key(&fixture::chain(), &request)
            .unwrap(),
    );
    assert_eq!(
        orphan
            .records
            .iter()
            .find(|row| row.descriptor.key() == &ack_key),
        source
            .records
            .iter()
            .find(|row| row.descriptor.key() == &ack_key)
    );
    assert!(
        orphan
            .records
            .iter()
            .any(|row| row.descriptor.key() == &ack_key)
    );
    orphan.validate().unwrap();
    let orphan_owned: Vec<OwnedPublicationMaterial> =
        owned_material_from_source_snapshot(&orphan, &reconstruction_plan(&fixture, &identity))
            .unwrap();
    assert!(orphan_owned.is_empty());
    let mut orphan_overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&fixture, &identity)).unwrap();
    orphan_overlay.reconstruct(&orphan_owned, &history).unwrap();
    assert!(matches!(
        orphan_overlay.compare_source(&orphan),
        Err(BusinessReconstructionError::Invalid(
            "local availability key/identity differs"
        ))
    ));
    assert_eq!(snapshot(network), source);
}

#[test]
fn genesis_marker_provenance_projection_rejects_noninitial_or_unbound_rows() {
    let fixture: CausalFixture = fresh_fixture();
    let source: SourceBusinessSnapshot = snapshot(&fixture.network);
    let (identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        complete_history(&fixture.network);
    let marker_key: Vec<u8> =
        crate::genesis::genesis_marker_key(fixture.manifest.context()).unwrap();
    let mut overlay: BusinessReconstructionOverlay<'_> =
        BusinessReconstructionOverlay::new(reconstruction_plan(&fixture, &identity)).unwrap();
    overlay.reconstruct(&[], &history).unwrap();
    overlay.compare_source(&source).unwrap();

    let incorrect_observation: SourceBusinessSnapshot =
        changed_marker_provenance(&source, &marker_key, |record| match record.observation {
            LogicalObservation::StatePresent { content_digest } => {
                let mut digest: [u8; 32] = content_digest.bytes();
                digest[0] ^= 1;
                record.observation = LogicalObservation::StatePresent {
                    content_digest: Digest32::new(content_digest.algorithm(), digest),
                };
            }
            _ => panic!("genesis marker provenance must bind a present state"),
        });
    assert!(overlay.compare_source(&incorrect_observation).is_err());

    let incorrect_generation: SourceBusinessSnapshot =
        changed_marker_provenance(&source, &marker_key, |record| {
            record.generation = protocol_types::ExecutionGeneration::new(1);
        });
    assert!(overlay.compare_source(&incorrect_generation).is_err());

    let incorrect_epoch: SourceBusinessSnapshot =
        changed_marker_provenance(&source, &marker_key, |record| {
            record.observed_epoch =
                protocol_types::Epoch::new(record.observed_epoch.get().saturating_add(1));
        });
    assert!(overlay.compare_source(&incorrect_epoch).is_err());

    let mut missing: SourceBusinessSnapshot = source.clone();
    missing.records.retain(|row| {
        !row.value.as_deref().is_some_and(|bytes| {
            decode_logical_provenance_record(bytes)
                .is_ok_and(|record| record.subject == LogicalSubject::StateKey(marker_key.clone()))
        })
    });
    assert!(overlay.compare_source(&missing).is_err());

    let mut tombstoned: SourceBusinessSnapshot = source.clone();
    let row: &mut SourceSnapshotRecord = tombstoned
        .records
        .iter_mut()
        .find(|row| {
            row.value.as_deref().is_some_and(|bytes| {
                decode_logical_provenance_record(bytes).is_ok_and(|record| {
                    record.subject == LogicalSubject::StateKey(marker_key.clone())
                })
            })
        })
        .expect("genesis marker provenance row");
    row.value = None;
    assert!(overlay.compare_source(&tombstoned).is_err());
}
