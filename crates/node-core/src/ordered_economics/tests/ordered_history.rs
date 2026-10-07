use super::*;
use crate::ordered_economics::ordered_history::*;
use consensus::{CommittedBlockProof, decode_committed_block_proof};

#[test]
fn identity_has_an_independently_assembled_stable_vector() {
    let anchor: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]);
    let identity: OrderedHistoryIdentity = OrderedHistoryIdentity {
        context: PublicationContext::new(
            ChainId::new("h").unwrap(),
            protocol_types::ProtocolVersion::new(1),
            Epoch::new(2),
        )
        .unwrap(),
        domain: AtomicityDomainId::new([0x11; 32]).unwrap(),
        genesis_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
        anchor,
        through_height: 0,
        through_view: 0,
        through_digest: anchor,
    };
    // Literal assembled from the canonical field table independently of this encoder.
    let expected: &str = "534e5245906401000700010029000000534e5245016301000300010001000000680200040000000100000003000800000002000000000000000200200000001111111111111111111111111111111111111111111111111111111111111111030038000000534e524503010100020001000200000001000200200000002222222222222222222222222222222222222222222222222222222222222222040038000000534e52450301010002000100020000000100020020000000333333333333333333333333333333333333333333333333333333333333333305000800000000000000000000000600080000000000000000000000070038000000534e524503010100020001000200000001000200200000003333333333333333333333333333333333333333333333333333333333333333";
    let encoded: Vec<u8> = encode_ordered_history_identity(&identity).unwrap();
    assert_eq!(encoded.len(), 309);
    assert_eq!(
        encoded
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        expected
    );
    assert_eq!(decode_ordered_history_identity(&encoded).unwrap(), identity);
    let summary: OrderedHistorySummary = OrderedHistorySummary { identity };
    let encoded: Vec<u8> = encode_ordered_history_summary(&summary).unwrap();
    assert_eq!(&encoded[..10], &[83, 78, 82, 69, 147, 100, 1, 0, 1, 0]);
    assert_eq!(decode_ordered_history_summary(&encoded).unwrap(), summary);
}

fn completed_logical_network() -> (Network, OrderedCandidate) {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let recipient: Address = address_of(0x67);
    let next: FastPathBondRecord = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let candidate: OrderedCandidate =
        unbond_candidate(&network, &network.bond, &next, [0xc1; 32], recipient, 11);
    network.round(1, Some(&candidate));
    for view in 2..=8 {
        network.round(view, None);
    }
    (network, candidate)
}

fn material(
    network: &Network,
    identity: &OrderedHistoryIdentity,
    height: u64,
) -> OrderedHistoryHeightMaterial {
    let descriptor: OrderedHistoryHeightDescriptor = read_ordered_history_height_descriptor(
        &network.stores[0],
        &network.context,
        &network.env(),
        identity,
        height,
    )
    .unwrap();
    let descriptor_digest: Digest32 =
        ordered_history_descriptor_digest(&network.policy, &descriptor).unwrap();
    let mut components: Vec<(OrderedHistoryComponentKind, Vec<u8>)> = Vec::new();
    for reference in &descriptor.components {
        let mut bytes: Vec<u8> = Vec::new();
        while (bytes.len() as u64) < reference.length {
            bytes.extend(
                read_ordered_history_component_chunk(
                    &network.stores[0],
                    &network.context,
                    &network.env(),
                    identity,
                    height,
                    descriptor_digest,
                    reference.kind,
                    bytes.len() as u64,
                    MAX_ORDERED_HISTORY_CHUNK_BYTES as u32,
                )
                .unwrap(),
            );
        }
        components.push((reference.kind, bytes));
    }
    OrderedHistoryHeightMaterial {
        descriptor,
        components,
    }
}

fn refresh_descriptor(
    policy: &OrderedEconomicsPolicy,
    material: &mut OrderedHistoryHeightMaterial,
) {
    material.descriptor.components = material
        .components
        .iter()
        .map(|(kind, bytes)| OrderedHistoryComponentRef {
            kind: *kind,
            length: bytes.len() as u64,
            digest: ordered_history_component_digest(policy, bytes).unwrap(),
        })
        .collect();
}

#[test]
fn real_pruned_history_exports_from_genesis_and_is_read_only_on_exact_resume() {
    let (network, candidate): (Network, OrderedCandidate) = completed_logical_network();
    let before = network.snapshot(0, &[candidate.request_id], 8);
    let summary: OrderedHistorySummary =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap();
    assert_eq!(summary.identity.through_height, 6);
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), summary.identity.clone()).unwrap();
    assert!(verifier.finish().is_err());
    for height in 1..=6 {
        let data: OrderedHistoryHeightMaterial = material(&network, &summary.identity, height);
        let bytes: Vec<u8> = encode_ordered_history_height_descriptor(&data.descriptor).unwrap();
        assert_eq!(
            decode_ordered_history_height_descriptor(&bytes).unwrap(),
            data.descriptor
        );
        verifier.verify_next_height(&data).unwrap();
    }
    let verified: VerifiedOrderedHistory = verifier.finish().unwrap();
    assert_eq!(verified.identity(), &summary.identity);
    assert!(verified.target_is_empty_three_chain()); // Not drain/cut authority.
    assert_eq!(network.snapshot(0, &[candidate.request_id], 8), before);
    let first: OrderedHistoryHeightMaterial = material(&network, &summary.identity, 1);
    let mut restarted: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), summary.identity.clone()).unwrap();
    restarted.verify_next_height(&first).unwrap();
    assert_eq!(restarted.height(), 1);
    assert!(restarted.verify_next_height(&first).is_err());
    assert_eq!(restarted.height(), 1);
}

#[test]
fn gaps_foreign_context_changed_components_and_bad_signatures_never_advance() {
    let (network, _): (Network, OrderedCandidate) = completed_logical_network();
    let identity: OrderedHistoryIdentity =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .identity;
    let first: OrderedHistoryHeightMaterial = material(&network, &identity, 1);
    let second: OrderedHistoryHeightMaterial = material(&network, &identity, 2);
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), identity.clone()).unwrap();
    assert!(verifier.verify_next_height(&second).is_err());
    let mut changed: OrderedHistoryHeightMaterial = first.clone();
    changed.components[0].1[0] ^= 1;
    assert!(verifier.verify_next_height(&changed).is_err());
    let mut proof: CommittedBlockProof =
        decode_committed_block_proof(&first.components[0].1).unwrap();
    proof.committed.signature[0] ^= 1;
    changed.components[0].1 = consensus::encode_committed_block_proof(&proof).unwrap();
    refresh_descriptor(&network.policy, &mut changed);
    assert!(verifier.verify_next_height(&changed).is_err());
    proof = decode_committed_block_proof(&first.components[0].1).unwrap();
    proof.grandchild_certificate.votes.truncate(2);
    changed.components[0].1 = consensus::encode_committed_block_proof(&proof).unwrap();
    refresh_descriptor(&network.policy, &mut changed);
    assert!(verifier.verify_next_height(&changed).is_err());
    changed = first.clone();
    changed.descriptor.identity.domain = AtomicityDomainId::new([0xf1; 32]).unwrap();
    assert!(verifier.verify_next_height(&changed).is_err());
    changed = first.clone();
    changed.components.swap(1, 2);
    assert!(verifier.verify_next_height(&changed).is_err());
    changed = first.clone();
    changed.components.pop();
    assert!(verifier.verify_next_height(&changed).is_err());
    assert_eq!(verifier.height(), 0);
    verifier.verify_next_height(&first).unwrap();
}

#[test]
fn full_companions_require_exact_response_event_and_original_height_links() {
    let (network, _): (Network, OrderedCandidate) = completed_logical_network();
    let identity: OrderedHistoryIdentity =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .identity;
    let first: OrderedHistoryHeightMaterial = material(&network, &identity, 1);
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), identity).unwrap();
    let mut changed: OrderedHistoryHeightMaterial = first.clone();
    let receipt: NodeDedupRecord = NodeDedupRecord::decode(&changed.components[4].1).unwrap();
    changed.components[4].1 = NodeDedupRecord::new(
        receipt.request_id(),
        fixture::resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::NodeEvent, b"foreign")
            .unwrap(),
        receipt.responses().to_vec(),
    )
    .unwrap()
    .encode()
    .unwrap();
    refresh_descriptor(&network.policy, &mut changed);
    assert!(verifier.verify_next_height(&changed).is_err());
    changed = first.clone();
    let mut outcome: OrderedOutcome =
        engine::decode_retained_outcome(&changed.components[3].1).unwrap();
    outcome.block_height = 0;
    changed.components[3].1 = engine::encode_retained_outcome_for_tests(&outcome);
    refresh_descriptor(&network.policy, &mut changed);
    assert!(verifier.verify_next_height(&changed).is_err());
    assert_eq!(verifier.height(), 0);
}

#[test]
fn descriptor_chunk_bounds_and_changed_descriptor_are_explicit() {
    let (network, _): (Network, OrderedCandidate) = completed_logical_network();
    let identity: OrderedHistoryIdentity =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .identity;
    let descriptor: OrderedHistoryHeightDescriptor = read_ordered_history_height_descriptor(
        &network.stores[0],
        &network.context,
        &network.env(),
        &identity,
        1,
    )
    .unwrap();
    let digest: Digest32 = ordered_history_descriptor_digest(&network.policy, &descriptor).unwrap();
    for (offset, limit) in [
        (0, 0),
        (0, MAX_ORDERED_HISTORY_CHUNK_BYTES as u32 + 1),
        (u64::MAX, 1),
        (descriptor.components[0].length, 1),
    ] {
        assert!(
            read_ordered_history_component_chunk(
                &network.stores[0],
                &network.context,
                &network.env(),
                &identity,
                1,
                digest,
                OrderedHistoryComponentKind::CommitProof,
                offset,
                limit
            )
            .is_err()
        );
    }
    assert!(
        read_ordered_history_component_chunk(
            &network.stores[0],
            &network.context,
            &network.env(),
            &identity,
            1,
            identity.anchor,
            OrderedHistoryComponentKind::CommitProof,
            0,
            1
        )
        .is_err()
    );
    assert_eq!(
        read_ordered_history_component_chunk(
            &network.stores[0],
            &network.context,
            &network.env(),
            &identity,
            1,
            digest,
            OrderedHistoryComponentKind::CommitProof,
            0,
            13
        )
        .unwrap()
        .len(),
        13
    );
    let mut bad: OrderedHistoryHeightDescriptor = descriptor.clone();
    bad.components[0].length = 0;
    assert!(encode_ordered_history_height_descriptor(&bad).is_err());
    assert!(
        decode_ordered_history_height_descriptor(&vec![
            0;
            MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES + 1
        ])
        .is_err()
    );
    assert!(OrderedHistoryComponentKind::from_wire(7).is_err());
}

#[test]
fn genesis_only_target_is_order_proof_not_empty_terminal_and_physical_export_refuses() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let summary: OrderedHistorySummary =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap();
    let verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), summary.identity).unwrap();
    assert!(!verifier.finish().unwrap().target_is_empty_three_chain());
    let historical: Network = setup();
    historical.install_ordered();
    historical.round(1, None);
    historical.round(2, None);
    historical.round(3, None);
    assert!(
        query_ordered_history_summary(
            &historical.stores[0],
            &historical.context,
            &historical.env()
        )
        .is_err()
    );
}

#[test]
fn missing_older_archive_refuses_export_but_does_not_change_ordering_admission() {
    let (network, _): (Network, OrderedCandidate) = completed_logical_network();
    let identity: OrderedHistoryIdentity =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .identity;
    let key: Vec<u8> =
        engine::ordered_committed_proof_key(&fixture::chain(), Epoch::new(0), 1).unwrap();
    network.put(0, key, StateMutation::Delete);
    assert!(
        read_ordered_history_height_descriptor(
            &network.stores[0],
            &network.context,
            &network.env(),
            &identity,
            1
        )
        .is_err()
    );
    let tip_key: Vec<u8> =
        engine::ordered_committed_proof_key(&fixture::chain(), Epoch::new(0), 6).unwrap();
    network.put(0, tip_key, StateMutation::Delete);
    network.round(9, None);
    assert_eq!(
        query_status(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .committed_height,
        7
    );
    let next: OrderedHistoryIdentity =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .identity;
    assert!(
        read_ordered_history_height_descriptor(
            &network.stores[0],
            &network.context,
            &network.env(),
            &next,
            6
        )
        .is_err()
    );
}

#[test]
fn conflicting_archive_stops_consensus_application_and_business_atomically() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let recipient: Address = address_of(0x68);
    let next: FastPathBondRecord = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let candidate: OrderedCandidate =
        unbond_candidate(&network, &network.bond, &next, [0xc2; 32], recipient, 11);
    network.round(1, Some(&candidate));
    network.round(2, None);
    let (certificate, _): (QuorumCertificate, OrderedProposal) = network.certify(3, None);
    let key: Vec<u8> =
        engine::ordered_committed_proof_key(&fixture::chain(), Epoch::new(0), 1).unwrap();
    network.put(0, key.clone(), StateMutation::Put(vec![1]));
    let before = network.snapshot(0, &[candidate.request_id], 3);
    assert!(
        process_certificate(
            &network.stores[0],
            &network.context,
            &network.env(),
            &certificate
        )
        .is_err()
    );
    assert_eq!(network.snapshot(0, &[candidate.request_id], 3), before);
    assert_eq!(network.committed_bond(0), network.bond);
    assert!(
        network.stores[0]
            .get_request_receipt(
                &network.context,
                network.domain(),
                DurableRequestId::new(candidate.request_id).unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(network.value(0, &key), Some(vec![1]));
}

#[test]
fn original_deterministic_refusal_receipt_is_retained_and_linked() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let recipient: Address = address_of(0x69);
    let next: FastPathBondRecord = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let first: OrderedCandidate =
        unbond_candidate(&network, &network.bond, &next, [0xc3; 32], recipient, 11);
    let stale: OrderedCandidate =
        unbond_candidate(&network, &network.bond, &next, [0xc4; 32], recipient, 11);
    network.round(1, Some(&first));
    network.round(2, None);
    network.round(3, None);
    network.round(4, Some(&stale));
    network.round(5, None);
    let (output, _, _): (Vec<OrderedEventOutput>, QuorumCertificate, OrderedProposal) =
        network.round(6, None);
    assert_eq!(
        refusal_of(&output[0].committed[0]),
        OrderedRefusal::StaleGeneration
    );
    let identity: OrderedHistoryIdentity =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .identity;
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), identity.clone()).unwrap();
    for height in 1..=4 {
        verifier
            .verify_next_height(&material(&network, &identity, height))
            .unwrap();
    }
    verifier.finish().unwrap();
}

#[test]
fn accepted_fee_claim_receipt_event_is_derived_through_the_claim_handler() {
    // History links an accepted completion's original receipt through the
    // committing handler's own receipt digest. The real ordered fee-claim
    // handler keys it by the signed claim envelope, never the candidate.
    let network: Network = setup();
    network.install_ordered();
    let settlement: FastPathSettlementRecord = seed_charged_settlement(&network, [0xca; 32]);
    let next: FastPathSettlementRecord =
        predicted_claim_row(&settlement, network.bond.validator_id);
    let candidate: OrderedCandidate =
        zero_share_claim_candidate(&network, &settlement, &next, [0xcb; 32]);
    network.round(1, Some(&candidate));
    network.round(2, None);
    network.round(3, None);
    let candidate_digest: Digest32 = network.policy.candidate_digest(&candidate).unwrap();
    let expected: Digest32 = network
        .policy
        .accepted_receipt_digest(&candidate, candidate_digest)
        .unwrap();
    assert_ne!(expected, candidate_digest);
    let request_id: DurableRequestId = DurableRequestId::new(candidate.request_id).unwrap();
    for store in &network.stores {
        let receipt: DurableRequestReceipt = store
            .get_request_receipt(&network.context, network.domain(), request_id)
            .unwrap()
            .unwrap();
        let record: NodeDedupRecord = NodeDedupRecord::decode(receipt.canonical_bytes()).unwrap();
        let status: NodeResponseStatus = record.responses()[0].status();
        assert_eq!(status, NodeResponseStatus::Accepted);
        assert_eq!(record.event_digest(), expected);
        assert_eq!(receipt.event_digest(), expected);
    }
}

#[test]
fn mutually_consistent_large_companions_are_not_certified_execution_truth() {
    let (network, _): (Network, OrderedCandidate) = completed_logical_network();
    let identity: OrderedHistoryIdentity =
        query_ordered_history_summary(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .identity;
    let mut first: OrderedHistoryHeightMaterial = material(&network, &identity, 1);
    let original: NodeDedupRecord = NodeDedupRecord::decode(&first.components[4].1).unwrap();
    // A malicious source can forge BOTH opaque output and receipt companions.
    // This intentionally proves only their exact ordering linkage, never effects.
    let mut opaque: CanonicalStruct = CanonicalStruct::new(0x0105, 1);
    opaque
        .field_bytes(1, vec![0x45; 2 * MAX_ORDERED_HISTORY_CHUNK_BYTES + 17])
        .unwrap();
    let response: NodeResponse = NodeResponse::new(
        original.request_id(),
        NodeResponseStatus::Accepted,
        Some(opaque.finish().unwrap()),
    )
    .unwrap();
    let receipt: NodeDedupRecord = NodeDedupRecord::new(
        original.request_id(),
        original.event_digest(),
        vec![response.clone()],
    )
    .unwrap();
    let mut outcome: OrderedOutcome =
        engine::decode_retained_outcome(&first.components[3].1).unwrap();
    outcome.output = NodeOutput::new(vec![response], Vec::new()).unwrap();
    first.components[3].1 = engine::encode_retained_outcome_for_tests(&outcome);
    first.components[4].1 = receipt.encode().unwrap();
    refresh_descriptor(&network.policy, &mut first);
    assert!(first.descriptor.components[3].length > 2 * MAX_ORDERED_HISTORY_CHUNK_BYTES as u64);
    assert!(
        encode_ordered_history_height_descriptor(&first.descriptor)
            .unwrap()
            .len()
            < MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES
    );
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(network.policy.clone(), identity.clone()).unwrap();
    verifier.verify_next_height(&first).unwrap();
    for height in 2..=identity.through_height {
        verifier
            .verify_next_height(&material(&network, &identity, height))
            .unwrap();
    }
    assert_eq!(verifier.finish().unwrap().identity(), &identity);
    // There is no public verified-execution/cut/import permit in this result.
}

fn delayed_observer_with_one_economic_batch(replay: bool) {
    use consensus::{ConsensusEngine, ConsensusEvent};
    let source: Network = setup_with_freeze_height(1);
    source.install_ordered();
    let recipient: Address = address_of(0x70);
    let next: FastPathBondRecord = predicted_unbond(&source.bond, 11, *recipient.as_bytes());
    let candidate: OrderedCandidate =
        unbond_candidate(&source, &source.bond, &next, [0xc5; 32], recipient, 11);
    let mut proposals: Vec<OrderedProposal> = Vec::new();
    let mut terminal: Option<QuorumCertificate> = None;
    for view in 1..=8 {
        if replay && view == 4 {
            let leader: usize = source.leader_index(view);
            let state: consensus::ConsensusState = consensus::decode_consensus_state(
                &source
                    .value(
                        leader,
                        &engine::ordered_state_key_for_tests(&fixture::chain()),
                    )
                    .unwrap(),
            )
            .unwrap();
            let digest: Digest32 = source.policy.candidate_digest(&candidate).unwrap();
            let proposal: consensus::ConsensusProposal = source
                .policy
                .engine()
                .propose(&state, vec![digest], &source.signers[leader])
                .unwrap();
            let ordered: OrderedProposal = OrderedProposal {
                proposal: proposal.clone(),
                candidate: Some(candidate.clone()),
            };
            for store in &source.stores {
                observe_proposal(store, &source.context, &source.env(), &ordered).unwrap();
            }
            let genesis: consensus::ConsensusState =
                source.policy.engine().genesis_state(TRUSTED_NOW_MILLIS);
            let votes: Vec<ConsensusVote> = source
                .signers
                .iter()
                .map(|signer| {
                    source
                        .policy
                        .engine()
                        .on_event(
                            &genesis,
                            ConsensusEvent::Proposal(proposal.clone()),
                            signer,
                            &consensus::Ed25519ConsensusVerifier::new(
                                consensus::UnsupportedSignatureSchemeResponse::InvalidSignature,
                            ),
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
            let certificate: QuorumCertificate = source
                .policy
                .engine()
                .certificate_from_votes(
                    &proposal,
                    &votes,
                    &consensus::Ed25519ConsensusVerifier::new(
                        consensus::UnsupportedSignatureSchemeResponse::InvalidSignature,
                    ),
                )
                .unwrap()
                .unwrap();
            for store in &source.stores {
                process_certificate(store, &source.context, &source.env(), &certificate).unwrap();
            }
            proposals.push(ordered);
        } else {
            let included: Option<&OrderedCandidate> =
                if (replay && view == 1) || (!replay && view == 4) {
                    Some(&candidate)
                } else {
                    None
                };
            let (_, certificate, proposal): (
                Vec<OrderedEventOutput>,
                QuorumCertificate,
                OrderedProposal,
            ) = source.round(view, included);
            terminal = Some(certificate);
            proposals.push(proposal);
        }
    }
    let destination: Network = setup_with_freeze_height(1);
    destination.install_ordered();
    // Learn future bodies while direct parent h5 is missing. Filling h5
    // commits only empty prefix heights; QC8 later batches h4,h5,h6.
    for index in [0usize, 1, 2, 3, 5, 6, 7, 4] {
        let output: OrderedEventOutput = observe_proposal(
            &destination.stores[0],
            &destination.context,
            &destination.env(),
            &proposals[index],
        )
        .unwrap();
        assert!(
            !output
                .messages
                .iter()
                .any(|message| matches!(message, ConsensusMessage::Vote(_)))
        );
    }
    assert_eq!(
        query_status(
            &destination.stores[0],
            &destination.context,
            &destination.env()
        )
        .unwrap()
        .committed_height,
        3
    );
    let before_receipt: Option<DurableRequestReceipt> = destination.stores[0]
        .get_request_receipt(
            &destination.context,
            destination.domain(),
            DurableRequestId::new(candidate.request_id).unwrap(),
        )
        .unwrap();
    let before_bond_revision: StateRevision = destination.revision(0, &destination.bond_key());
    let certificate: QuorumCertificate = terminal.unwrap();
    let output: OrderedEventOutput = process_certificate(
        &destination.stores[0],
        &destination.context,
        &destination.env(),
        &certificate,
    )
    .unwrap();
    assert_eq!(output.committed.len(), 1);
    assert_eq!(output.committed[0].block_height, if replay { 1 } else { 4 });
    assert_eq!(destination.committed_bond(0), next);
    if replay {
        assert_eq!(
            destination.revision(0, &destination.bond_key()),
            before_bond_revision
        );
        assert_eq!(
            destination.stores[0]
                .get_request_receipt(
                    &destination.context,
                    destination.domain(),
                    DurableRequestId::new(candidate.request_id).unwrap()
                )
                .unwrap(),
            before_receipt
        );
    }
    let (applied, _, _): (u64, Vec<u8>, StateRevision) = engine::load_applied_height(
        &destination.stores[0],
        &destination.context,
        &destination.env(),
    )
    .unwrap();
    assert_eq!(applied, 6);
    let identity: OrderedHistoryIdentity = query_ordered_history_summary(
        &destination.stores[0],
        &destination.context,
        &destination.env(),
    )
    .unwrap()
    .identity;
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(destination.policy.clone(), identity.clone()).unwrap();
    for height in 1..=6 {
        let data: OrderedHistoryHeightMaterial = material(&destination, &identity, height);
        if replay && height == 4 {
            assert_eq!(
                data.components.last().unwrap().0,
                OrderedHistoryComponentKind::ReplayOriginProof
            );
            let mut missing: OrderedHistoryHeightMaterial = data.clone();
            missing.components.pop();
            missing.descriptor.components.pop();
            assert!(verifier.verify_next_height(&missing).is_err());

            // A real recommit proof cannot turn the already observed h1
            // application into a new h4 origin by changing unsigned metadata.
            let mut moved: OrderedHistoryHeightMaterial = data.clone();
            let mut outcome: OrderedOutcome =
                engine::decode_retained_outcome(&moved.components[3].1).unwrap();
            outcome.block_height = height;
            outcome.block_digest = moved.descriptor.block_digest;
            moved.components[3].1 = engine::encode_retained_outcome_for_tests(&outcome);
            moved.components.pop();
            refresh_descriptor(&destination.policy, &mut moved);
            assert!(verifier.verify_next_height(&moved).is_err());
            assert_eq!(verifier.height(), 3);

            // Even keeping the authentic origin proof, two mutually matching
            // changed companions must not overwrite the h1 fingerprints.
            let mut changed: OrderedHistoryHeightMaterial = data.clone();
            let original: NodeDedupRecord =
                NodeDedupRecord::decode(&changed.components[4].1).unwrap();
            let mut payload: CanonicalStruct = CanonicalStruct::new(0x0105, 1);
            payload.field_u64(1, 999).unwrap();
            let response: NodeResponse = NodeResponse::new(
                original.request_id(),
                NodeResponseStatus::Accepted,
                Some(payload.finish().unwrap()),
            )
            .unwrap();
            let receipt: NodeDedupRecord = NodeDedupRecord::new(
                original.request_id(),
                original.event_digest(),
                vec![response.clone()],
            )
            .unwrap();
            let mut outcome: OrderedOutcome =
                engine::decode_retained_outcome(&changed.components[3].1).unwrap();
            outcome.output = NodeOutput::new(vec![response], Vec::new()).unwrap();
            changed.components[3].1 = engine::encode_retained_outcome_for_tests(&outcome);
            changed.components[4].1 = receipt.encode().unwrap();
            refresh_descriptor(&destination.policy, &mut changed);
            assert!(verifier.verify_next_height(&changed).is_err());
            assert_eq!(verifier.height(), 3);
        }
        verifier.verify_next_height(&data).unwrap();
    }
    verifier.finish().unwrap();
    let before = destination.snapshot(0, &[candidate.request_id], 8);
    let proof_key: Vec<u8> =
        engine::ordered_committed_proof_key(&fixture::chain(), Epoch::new(0), 6).unwrap();
    let proof_revision: StateRevision = destination.revision(0, &proof_key);
    process_certificate(
        &destination.stores[0],
        &destination.context,
        &destination.env(),
        &certificate,
    )
    .unwrap();
    assert_eq!(destination.snapshot(0, &[candidate.request_id], 8), before);
    assert_eq!(destination.revision(0, &proof_key), proof_revision);
}

#[test]
fn signerless_delayed_economic_batch_archives_all_empty_followers_atomically() {
    delayed_observer_with_one_economic_batch(false);
}

#[test]
fn signerless_delayed_replay_batch_keeps_original_result_receipt_and_effects() {
    delayed_observer_with_one_economic_batch(true);
}

#[test]
fn ambiguous_commit_withholds_archive_and_reconciliation_publishes_once() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let recipient: Address = address_of(0x71);
    let next: FastPathBondRecord = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let candidate: OrderedCandidate =
        unbond_candidate(&network, &network.bond, &next, [0xc6; 32], recipient, 11);
    network.round(1, Some(&candidate));
    network.round(2, None);
    let (certificate, _): (QuorumCertificate, OrderedProposal) = network.certify(3, None);
    let key: Vec<u8> =
        engine::ordered_committed_proof_key(&fixture::chain(), Epoch::new(0), 1).unwrap();
    let flaky: FlakyStore<'_> = FlakyStore {
        inner: &network.stores[0],
        fail_next_invocation: std::cell::Cell::new(true),
    };
    let before = network.snapshot(0, &[candidate.request_id], 3);
    assert!(process_certificate(&flaky, &network.context, &network.env(), &certificate).is_err());
    assert_eq!(network.snapshot(0, &[candidate.request_id], 3), before);
    assert!(network.value(0, &key).is_none());
    process_certificate(&flaky, &network.context, &network.env(), &certificate).unwrap();
    let proof: Vec<u8> = network.value(0, &key).unwrap();
    let revision: StateRevision = network.revision(0, &key);
    process_certificate(&flaky, &network.context, &network.env(), &certificate).unwrap();
    assert_eq!(network.value(0, &key), Some(proof));
    assert_eq!(network.revision(0, &key), revision);
    assert_eq!(network.committed_bond(0), next);
}
