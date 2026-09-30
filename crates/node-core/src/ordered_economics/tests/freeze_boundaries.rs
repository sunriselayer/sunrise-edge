use super::*;

#[test]
fn historical_signed_votes_replay_exactly_after_a_real_freeze_without_mutation() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let (certificate, proposal): (QuorumCertificate, OrderedProposal) = network.certify(1, None);
    for replica in 0..REPLICAS {
        process_certificate(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &certificate,
        )
        .unwrap();
    }
    let freeze: OrderedCandidate = freeze_candidate([0xA1; 32]);
    network.round(2, None);
    network.round(3, None);
    network.round(4, Some(&freeze));
    network.round(5, None);
    network.round(6, None);
    let vote_key: Vec<u8> = engine::ordered_vote_record_key_for_tests(&fixture::chain(), 1);
    for replica in 0..REPLICAS {
        let bytes: Vec<u8> = network.value(replica, &vote_key).unwrap();
        let (_, retained) = identity::decode_local_vote_record(&bytes).unwrap();
        let revision: StateRevision = network.revision(replica, &vote_key);
        let output: OrderedEventOutput = process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &proposal,
            &network.signers[replica],
        )
        .unwrap();
        assert_eq!(output.messages, vec![ConsensusMessage::Vote(retained)]);
        assert!(output.committed.is_empty());
        assert_eq!(network.value(replica, &vote_key), Some(bytes));
        assert_eq!(network.revision(replica, &vote_key), revision);
    }
}

struct ProposalRace<'a> {
    race: RaceStore<'a>,
}
impl DurableDomainStateStore for ProposalRace<'_> {
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.race.get_versioned_durable(context, domain, key)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        if !self.race.raced.replace(true) {
            self.race.land_foreign_write();
        }
        self.race.inner.commit_durable(context, transaction)
    }
}
impl StructuredDurableDomainStateStore for ProposalRace<'_> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.race.get_object_head(context, domain, id)
    }
    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        id: ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.race.get_object_version(context, domain, id, version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.race.get_request_receipt(context, domain, id)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.race.inner.commit_invocation(context, transaction)
    }
}

#[test]
fn a_racing_freeze_rejects_fresh_proposal_before_its_signing_identity_is_exposed() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let leader: usize = network.leader_index(1);
    let recipient: Address = address_of(0xB1);
    let next: FastPathBondRecord = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let business: OrderedCandidate =
        unbond_candidate(&network, &network.bond, &next, [0xB2; 32], recipient, 11);
    let closure: AdmissionClosureRecord = AdmissionClosureRecord {
        closed_epoch: fixture::protocol().epoch(),
        request_id: [0xB3; 32],
        closed_at_block_height: 1,
    };
    let race: ProposalRace<'_> = ProposalRace {
        race: RaceStore {
            inner: &network.stores[leader],
            context: network.context,
            domain: network.domain(),
            race_key: engine::admission_closure_key_for_tests(
                &fixture::chain(),
                fixture::protocol().epoch(),
            ),
            race_value: encode_admission_closure_record(&closure).unwrap(),
            raced: std::cell::Cell::new(false),
        },
    };
    assert!(
        propose(
            &race,
            &network.context,
            &network.env(),
            Some(&business),
            &network.signers[leader]
        )
        .is_err()
    );
    assert!(race.race.raced.get());
    assert!(
        network
            .value(
                leader,
                &engine::ordered_leader_record_key_for_tests(&fixture::chain(), 1)
            )
            .is_none()
    );
    assert!(
        network
            .value(
                leader,
                &engine::ordered_request_header_key_for_tests(
                    &fixture::chain(),
                    &business.request_id
                )
            )
            .is_none()
    );
}

#[test]
fn justification_committing_freeze_never_exposes_a_vote_for_its_own_business_payload() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let chain: ChainId = fixture::chain();
    let target: usize = network.non_leader(&[4]);
    let leader: usize = network.leader_index(4);
    let freeze: OrderedCandidate = freeze_candidate([0x79; 32]);

    // All four independently vote for the real Freeze chain. The target
    // receives QCs at heights 1 and 2 but not the height-3 QC that commits
    // Freeze; the other replicas receive all three. This is a normal delayed
    // certificate delivery, not a forged closure row.
    for view in 1..=3 {
        let candidate: Option<&OrderedCandidate> = (view == 1).then_some(&freeze);
        let (certificate, _proposal): (QuorumCertificate, OrderedProposal) =
            network.certify(view, candidate);
        for replica in 0..REPLICAS {
            if view == 3 && replica == target {
                continue;
            }
            process_certificate(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &certificate,
            )
            .unwrap();
        }
    }
    let closure_key: Vec<u8> =
        engine::admission_closure_key_for_tests(&chain, fixture::protocol().epoch());
    assert!(network.value(target, &closure_key).is_none());
    assert!(network.value(leader, &closure_key).is_some());

    // A faulty leader bypasses node-core's honest post-Freeze proposal gate
    // and signs a business-bearing height-4 proposal directly through the
    // authenticated consensus engine. Its justify QC is exactly the missing
    // height-3 QC. The lagging target must process that QC and persist Freeze
    // without signing the proposal's own business payload.
    let recipient: Address = address_of(0x7a);
    let next: FastPathBondRecord = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id: [u8; 32] = [0x7b; 32];
    let business: OrderedCandidate =
        unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);
    let state_key: Vec<u8> = engine::ordered_state_key_for_tests(&chain);
    let leader_state: consensus::ConsensusState =
        decode_consensus_state(&network.value(leader, &state_key).unwrap()).unwrap();
    let candidate_digest: Digest32 =
        engine::ordered_candidate_digest_for_tests(&network.resolver, &business);
    let signed: consensus::ConsensusProposal = network
        .policy
        .engine()
        .propose(
            &leader_state,
            vec![candidate_digest],
            &network.signers[leader],
        )
        .unwrap();
    assert_eq!(signed.height, 4);
    let carrying: OrderedProposal = OrderedProposal {
        proposal: signed,
        candidate: Some(business),
    };
    let freeze_digest: Digest32 =
        engine::ordered_candidate_digest_for_tests(&network.resolver, &freeze);
    let freeze_key: Vec<u8> = engine::ordered_candidate_record_key(&chain, freeze_digest).unwrap();
    let original_freeze_bytes: Vec<u8> = network.value(target, &freeze_key).unwrap();
    network.put(
        target,
        freeze_key.clone(),
        StateMutation::Put(encode_ordered_candidate(carrying.candidate.as_ref().unwrap()).unwrap()),
    );
    assert!(
        process_proposal(
            &network.stores[target],
            &network.context,
            &network.env(),
            &carrying,
            &network.signers[target],
        )
        .is_err()
    );
    assert!(network.value(target, &closure_key).is_none());
    assert!(
        network
            .value(
                target,
                &engine::ordered_vote_record_key_for_tests(&chain, 4)
            )
            .is_none()
    );
    network.put(
        target,
        freeze_key,
        StateMutation::Put(original_freeze_bytes),
    );
    let observed: OrderedEventOutput = process_proposal(
        &network.stores[target],
        &network.context,
        &network.env(),
        &carrying,
        &network.signers[target],
    )
    .unwrap();
    assert!(
        observed
            .messages
            .iter()
            .all(|message| !matches!(message, ConsensusMessage::Vote(_)))
    );
    assert_eq!(observed.committed.len(), 1);
    assert_eq!(observed.committed[0].request_id, freeze.request_id);
    assert!(network.value(target, &closure_key).is_some());
    assert!(
        network
            .value(
                target,
                &engine::ordered_vote_record_key_for_tests(&chain, 4)
            )
            .is_none()
    );
    assert!(
        network
            .value(
                target,
                &engine::ordered_outcome_key_for_tests(&chain, &request_id)
            )
            .is_none()
    );
}
