//! DR-0168 shared-engine acceptance over independent in-memory replicas.
use super::*;
use consensus::decode_consensus_state;

struct DrainRaceStore<'a> {
    inner: &'a MemoryDurableStateStore,
    context: DurableOperationContext,
    domain: AtomicityDomainId,
    race_key: Vec<u8>,
    race_value: Vec<u8>,
    race_on_durable: bool,
    raced: std::cell::Cell<bool>,
}

impl DrainRaceStore<'_> {
    fn land_foreign_write(&self) {
        let revision = self
            .inner
            .get_versioned_durable(&self.context, self.domain, &self.race_key)
            .unwrap()
            .revision();
        let transaction = AtomicStateTransaction::new(
            self.domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(self.race_key.clone(), revision).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(
                    self.race_key.clone(),
                    StateMutation::Put(self.race_value.clone()),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            self.inner.commit_durable(&self.context, transaction),
            DurableCommitOutcome::Committed
        );
    }
}

impl DurableDomainStateStore for DrainRaceStore<'_> {
    fn get_outgoing_barrier(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, runtime::DurableReadError> {
        self.inner.get_outgoing_barrier(context, domain)
    }

    fn get_namespace_lifecycle(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, runtime::DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }

    fn get_successor_serving(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::SuccessorServingSlot, runtime::DurableReadError> {
        self.inner.get_successor_serving(context, domain)
    }
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        self.inner.get_versioned_durable(context, domain, key)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        if self.race_on_durable && !self.raced.replace(true) {
            self.land_foreign_write();
        }
        self.inner.commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for DrainRaceStore<'_> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.inner.get_object_head(context, domain, object_id)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object_id: ObjectId,
        object_version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, object_version)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request_id: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request_id)
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        if !self.race_on_durable && !self.raced.replace(true) {
            self.land_foreign_write();
        }
        self.inner.commit_invocation(context, transaction)
    }
}

fn genesis_transfer_paid_intent_bytes(
    resolver: &HashSuiteResolver,
    fee_policy: &execution::paid_execution::PaidFeePolicy,
    instance_record: &execution::local_execution::InstanceRecord,
    coin: &Object,
    request_id: [u8; 32],
    nonce: u64,
    recipient: [u8; 32],
) -> Vec<u8> {
    let target: execution::call::InstanceTarget =
        execution::local_execution::instance_target(resolver, instance_record).unwrap();
    let source_ref: ObjectRef = ObjectRef {
        id: coin.id,
        version: coin.version,
        digest: resolver
            .hash_for_purpose(
                fixture::protocol().epoch(),
                HashPurpose::Object,
                &objects::encode_object(coin).unwrap(),
            )
            .unwrap(),
    };
    let application: execution::call::CallIntent = execution::call::CallIntent {
        context: fixture::protocol(),
        request_id,
        sender: fixture::sender(),
        nonce,
        code: instance_record.code.clone(),
        instance: target,
        entrypoint: "transfer".into(),
        type_arguments: fee_policy.type_arguments.clone(),
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: source_ref.clone(),
                mode: objects::AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&recipient).unwrap(),
        gas_limit: 100_000,
    };
    let intent: execution::paid_execution::PaidIntent = execution::paid_execution::PaidIntent {
        context: fixture::protocol(),
        request_id,
        sender: fixture::sender(),
        nonce,
        fee_policy_digest: execution::paid_execution::paid_fee_policy_digest(resolver, fee_policy)
            .unwrap(),
        consent: execution::paid_execution::FeeSourceConsent {
            source: source_ref,
            access: execution::paid_execution::ReservationAccessKind::Write,
            max_fee: fees::Amount::new(1_000_000),
            refund_recipient: recipient,
        },
        application: execution::paid_execution::PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> =
        execution::paid_execution::paid_intent_signing_frame(&fixture::protocol(), &intent)
            .unwrap();
    execution::paid_execution::encode_signed_paid_intent(
        &execution::paid_execution::SignedPaidIntent {
            signature: fixture::key().sign(&frame).into(),
            intent,
        },
    )
    .unwrap()
}

fn reconstruct_drain_union_ready(
    network: &Network,
    replica: usize,
    selected: &[(consensus::FrozenFrontierVote, consensus::FrozenFrontierPage)],
    votes: &[consensus::FrozenFrontierVote],
    bundle_bytes: &[u8],
    expected: &PublicationContext,
    member_request_id: [u8; 32],
) -> consensus::DrainUnionIdentity {
    for (vote, page) in selected {
        ingest_drain_signer_page(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            expected,
            vote.validator,
            vote.clone(),
            page.clone(),
        )
        .unwrap();
        import_staged_drain_publication(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            expected,
            vote.validator,
            bundle_bytes,
        )
        .unwrap();
        confirm_drain_signer_entry(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            expected,
            vote.validator,
            member_request_id,
        )
        .unwrap();
    }
    loop {
        match advance_drain_union(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            expected,
            votes,
        )
        .unwrap()
        {
            DrainUnionStep::Ready(identity) => return *identity,
            DrainUnionStep::Advanced { .. } => continue,
        }
    }
}

#[test]
fn ordered_drain_set_requires_local_readiness_then_commits_once_on_four_replicas() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let freeze: OrderedCandidate = freeze_candidate([0xA1; 32]);
    network.round(1, Some(&freeze));
    network.round(2, None);
    network.round(3, None);

    let expected: PublicationContext = fixture::protocol();
    let mut selected: Vec<(consensus::FrozenFrontierVote, consensus::FrozenFrontierPage)> =
        Vec::new();
    for source in 0..3 {
        let step: FrozenFrontierStep = advance_frozen_frontier(
            &network.stores[source],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &network.signers[source],
        )
        .unwrap();
        assert!(matches!(step, FrozenFrontierStep::Finalized(_)));
        let pair: (consensus::FrozenFrontierVote, consensus::FrozenFrontierPage) =
            read_frozen_frontier_page(
                &network.stores[source],
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &expected,
                network.signers[source].validator_id(),
                None,
                std::num::NonZeroUsize::new(1).unwrap(),
            )
            .unwrap();
        assert!(pair.1.terminal && pair.1.entries.is_empty());
        selected.push(pair);
    }
    selected.sort_by_key(|pair| pair.0.validator);
    let votes: Vec<consensus::FrozenFrontierVote> =
        selected.iter().map(|pair| pair.0.clone()).collect();

    // Leave one non-leader without its selection-scoped union marker. The
    // leader can propose, but the lagging replica must neither vote nor
    // produce a deterministic global refusal from its local storage lag.
    let leader: usize = network.leader_index(4);
    let lagging: usize = (0..REPLICAS).find(|&replica| replica != leader).unwrap();
    let mut ready: Option<consensus::DrainUnionIdentity> = None;
    for replica in (0..REPLICAS).filter(|&replica| replica != lagging) {
        for (vote, page) in &selected {
            ingest_drain_signer_page(
                &network.stores[replica],
                &network.context,
                network.domain(),
                &network.resolver,
                &expected,
                vote.validator,
                vote.clone(),
                page.clone(),
            )
            .unwrap();
        }
        let identity: consensus::DrainUnionIdentity = match advance_drain_union(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &votes,
        )
        .unwrap()
        {
            DrainUnionStep::Ready(identity) => *identity,
            DrainUnionStep::Advanced { .. } => panic!("empty frontier union must finish"),
        };
        if let Some(previous) = &ready {
            assert_eq!(&identity, previous);
        } else {
            ready = Some(identity);
        }
    }
    let identity: consensus::DrainUnionIdentity = ready.unwrap();
    let intent: DrainSetIntent = DrainSetIntent {
        context: expected.clone(),
        request_id: [0xA2; 32],
        selected_votes: votes.clone(),
        drain_union_identity: identity.clone(),
    };
    let candidate: OrderedCandidate = OrderedCandidate {
        context: expected.clone(),
        request_id: intent.request_id,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&intent).unwrap(),
        created_checkpoint: 12,
    };
    assert!(authenticate_candidate(&network.env(), &candidate).is_ok());
    // A valid signed selection cannot be ordered before this replica has
    // committed Freeze. This is a deterministic no-effect refusal, not a
    // synthetic locally-ready marker or a way to close admission early.
    let before_freeze: Network = setup_with_freeze_height(1);
    before_freeze.install_ordered();
    assert!(matches!(
        preflight::preflight(
            &before_freeze.stores[0],
            &before_freeze.context,
            &before_freeze.env(),
            &candidate,
            4,
        ),
        Err(OrderedEconomicsError::Refused(OrderedRefusal::NoFreeze))
    ));
    let absent_drain_key: Vec<u8> =
        drain_set::drain_set_record_key(expected.chain_id(), expected.epoch()).unwrap();
    assert!(before_freeze.value(0, &absent_drain_key).is_none());
    assert_eq!(
        before_freeze.revision(0, &absent_drain_key),
        StateRevision::INITIAL
    );
    // A refused pre-Freeze DrainSet does not install the accepted record and
    // therefore cannot close honest candidate voting for the real Freeze.
    let freeze_after_refusal: OrderedCandidate = freeze_candidate([0xA3; 32]);
    let leader1: usize = before_freeze.leader_index(1);
    assert!(
        propose(
            &before_freeze.stores[leader1],
            &before_freeze.context,
            &before_freeze.env(),
            Some(&freeze_after_refusal),
            &before_freeze.signers[leader1],
        )
        .is_ok()
    );
    let different_freeze: Network = setup_with_freeze_height(1);
    different_freeze.install_ordered();
    let other_freeze: OrderedCandidate = freeze_candidate([0xA4; 32]);
    different_freeze.round(1, Some(&other_freeze));
    different_freeze.round(2, None);
    different_freeze.round(3, None);
    let other_leader: usize = different_freeze.leader_index(4);
    assert!(matches!(
        propose(
            &different_freeze.stores[other_leader],
            &different_freeze.context,
            &different_freeze.env(),
            Some(&candidate),
            &different_freeze.signers[other_leader],
        ),
        Err(OrderedEconomicsError::Refused(
            OrderedRefusal::ForeignDrainSet
        ))
    ));
    assert!(
        different_freeze
            .value(other_leader, &absent_drain_key)
            .is_none()
    );
    let mut forged_intent: DrainSetIntent = intent.clone();
    forged_intent.selected_votes[0].signature[0] ^= 1;
    let mut forged: OrderedCandidate = candidate.clone();
    forged.intent = encode_drain_set_intent(&forged_intent).unwrap();
    assert!(matches!(
        authenticate_candidate(&network.env(), &forged),
        Err(OrderedEconomicsError::Unauthenticated(_))
    ));
    let mut weak_intent: DrainSetIntent = intent.clone();
    weak_intent.selected_votes.pop();
    weak_intent.drain_union_identity.signer_count = 2;
    let mut underpowered: OrderedCandidate = candidate.clone();
    underpowered.intent = encode_drain_set_intent(&weak_intent).unwrap();
    assert!(matches!(
        authenticate_candidate(&network.env(), &underpowered),
        Err(OrderedEconomicsError::Unauthenticated(_))
    ));
    let mut mixed_intent: DrainSetIntent = intent.clone();
    mixed_intent.selected_votes[0].identity.closure_request_id = [0xAB; 32];
    assert!(encode_drain_set_intent(&mixed_intent).is_err());
    let mut foreign_intent: DrainSetIntent = intent.clone();
    foreign_intent.drain_union_identity.entries_digest =
        Digest32::new(HashAlgorithmId::Blake3_256, [0xFA; 32]);
    let mut foreign: OrderedCandidate = candidate.clone();
    foreign.intent = encode_drain_set_intent(&foreign_intent).unwrap();
    assert!(matches!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&foreign),
            &network.signers[leader],
        ),
        Err(OrderedEconomicsError::Refused(
            OrderedRefusal::ForeignDrainSet
        ))
    ));
    let ready_key: Vec<u8> = drain_union_ready_key(
        expected.chain_id(),
        expected.epoch(),
        &identity.entries_digest,
    )
    .unwrap();
    let race: DrainRaceStore<'_> = DrainRaceStore {
        inner: &network.stores[leader],
        context: network.context,
        domain: network.domain(),
        race_key: ready_key.clone(),
        race_value: network.value(leader, &ready_key).unwrap(),
        race_on_durable: true,
        raced: std::cell::Cell::new(false),
    };
    assert!(
        propose(
            &race,
            &network.context,
            &network.env(),
            Some(&candidate),
            &network.signers[leader],
        )
        .is_err()
    );
    assert!(race.raced.get());
    let leader_key: Vec<u8> = engine::ordered_leader_record_key_for_tests(expected.chain_id(), 4);
    assert!(network.value(leader, &leader_key).is_none());

    let ambiguous: crate::fast_path::tests::AmbiguousCommitStore<'_> =
        crate::fast_path::tests::AmbiguousCommitStore {
            inner: &network.stores[leader],
            state: std::cell::Cell::new(true),
            invocation: std::cell::Cell::new(false),
            land_before_outcome: false,
        };
    assert!(matches!(
        propose(
            &ambiguous,
            &network.context,
            &network.env(),
            Some(&candidate),
            &network.signers[leader]
        ),
        Err(OrderedEconomicsError::Node(
            NodeCoreError::DurableCommitIndeterminate(_)
        ))
    ));
    assert!(network.value(leader, &leader_key).is_none());

    let proposal: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader],
    )
    .unwrap();
    assert!(matches!(
        process_proposal(
            &network.stores[lagging],
            &network.context,
            &network.env(),
            &proposal,
            &network.signers[lagging],
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    let vote_key: Vec<u8> = engine::ordered_vote_record_key_for_tests(&fixture::chain(), 4);
    assert!(network.value(lagging, &vote_key).is_none());

    for (vote, page) in &selected {
        ingest_drain_signer_page(
            &network.stores[lagging],
            &network.context,
            network.domain(),
            &network.resolver,
            &expected,
            vote.validator,
            vote.clone(),
            page.clone(),
        )
        .unwrap();
    }
    let recovered: DrainUnionStep = advance_drain_union(
        &network.stores[lagging],
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &expected,
        &votes,
    )
    .unwrap();
    assert_eq!(recovered, DrainUnionStep::Ready(Box::new(identity.clone())));

    let vote_race: DrainRaceStore<'_> = DrainRaceStore {
        inner: &network.stores[lagging],
        context: network.context,
        domain: network.domain(),
        race_key: ready_key.clone(),
        race_value: network.value(lagging, &ready_key).unwrap(),
        race_on_durable: true,
        raced: std::cell::Cell::new(false),
    };
    assert!(
        process_proposal(
            &vote_race,
            &network.context,
            &network.env(),
            &proposal,
            &network.signers[lagging],
        )
        .is_err()
    );
    assert!(vote_race.raced.get());
    assert!(network.value(lagging, &vote_key).is_none());

    // The exact authenticated, terminal selected signer row is also part
    // of the vote CAS, not just the final readiness marker. Even an
    // identical-byte revision change must withhold the signature.
    let signer_progress_key: Vec<u8> =
        drain_signer_progress_key(expected.chain_id(), expected.epoch(), votes[0].validator)
            .unwrap();
    let signer_race: DrainRaceStore<'_> = DrainRaceStore {
        inner: &network.stores[lagging],
        context: network.context,
        domain: network.domain(),
        race_value: network.value(lagging, &signer_progress_key).unwrap(),
        race_key: signer_progress_key,
        race_on_durable: true,
        raced: std::cell::Cell::new(false),
    };
    assert!(
        process_proposal(
            &signer_race,
            &network.context,
            &network.env(),
            &proposal,
            &network.signers[lagging],
        )
        .is_err()
    );
    assert!(signer_race.raced.get());
    assert!(network.value(lagging, &vote_key).is_none());

    network.round(4, Some(&candidate));
    network.round(5, None);
    let (outputs, certificate, _) = network.round(6, None);
    let key: Vec<u8> =
        drain_set::drain_set_record_key(expected.chain_id(), expected.epoch()).unwrap();
    let mut original_bytes: Option<Vec<u8>> = None;
    for (replica, output) in outputs.iter().enumerate() {
        assert_eq!(output.committed.len(), 1, "replica {replica}");
        assert_eq!(output.committed[0].request_id, candidate.request_id);
        assert_eq!(
            output.committed[0].output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let bytes: Vec<u8> = network.value(replica, &key).unwrap();
        let record: DrainSetRecord = decode_drain_set_record(&bytes).unwrap();
        assert_eq!(record.request_id, candidate.request_id);
        assert_eq!(record.closed_epoch, expected.epoch());
        assert_eq!(record.committed_at_block_height, 4);
        assert_eq!(record.drain_union_identity, identity);
        assert_eq!(record.selected_votes, votes);
        if let Some(previous) = &original_bytes {
            assert_eq!(&bytes, previous);
        } else {
            original_bytes = Some(bytes);
        }
        let revision: StateRevision = network.revision(replica, &key);
        let replay: OrderedEventOutput = process_certificate(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &certificate,
        )
        .unwrap();
        assert!(replay.committed.is_empty());
        assert_eq!(network.revision(replica, &key), revision);
        assert_eq!(network.value(replica, &key), original_bytes);
    }

    let mut second_intent: DrainSetIntent = intent;
    second_intent.request_id = [0xA3; 32];
    let second: OrderedCandidate = OrderedCandidate {
        context: expected.clone(),
        request_id: second_intent.request_id,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&second_intent).unwrap(),
        created_checkpoint: 13,
    };
    // Post-DrainSet closure: once this epoch's one-per-epoch `DrainSetRecord`
    // is installed, an honest replica never again proposes or votes for a
    // fresh `DrainSet` -- it is refused on sight, exactly like every other
    // fresh candidate kind, instead of being placed, voted on and only
    // refused once committed.
    for replica in 0..REPLICAS {
        assert!(matches!(
            propose(
                &network.stores[replica],
                &network.context,
                &network.env(),
                Some(&second),
                &network.signers[replica],
            ),
            Err(OrderedEconomicsError::Refused(
                OrderedRefusal::AlreadyDrained
            ))
        ));
        assert!(
            network
                .value(
                    replica,
                    &engine::ordered_request_header_key_for_tests(
                        expected.chain_id(),
                        &second.request_id
                    )
                )
                .is_none()
        );
        assert_eq!(network.value(replica, &key), original_bytes);
    }
}

#[test]
fn candidate_signatures_cas_fence_a_racing_drain_set_record() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let expected: PublicationContext = fixture::protocol();
    let candidate: OrderedCandidate = freeze_candidate([0xE4; 32]);
    let drain_key: Vec<u8> = drain_set_record_key(expected.chain_id(), expected.epoch()).unwrap();
    let leader: usize = network.leader_index(1);
    let leader_race: DrainRaceStore<'_> = DrainRaceStore {
        inner: &network.stores[leader],
        context: network.context,
        domain: network.domain(),
        race_key: drain_key.clone(),
        race_value: vec![0xA5],
        race_on_durable: true,
        raced: std::cell::Cell::new(false),
    };
    assert!(
        propose(
            &leader_race,
            &network.context,
            &network.env(),
            Some(&candidate),
            &network.signers[leader],
        )
        .is_err()
    );
    assert!(leader_race.raced.get());
    assert!(
        network
            .value(
                leader,
                &engine::ordered_leader_record_key_for_tests(expected.chain_id(), 1)
            )
            .is_none()
    );
    assert!(
        network
            .value(
                leader,
                &engine::ordered_request_header_key_for_tests(
                    expected.chain_id(),
                    &candidate.request_id
                )
            )
            .is_none()
    );

    // The same absence assertion is part of a vote commit, not only leader
    // proposal creation. Sign a valid proposal directly with the leader key;
    // the separate voter must lose its CAS when the row appears at commit.
    let state_key: Vec<u8> = engine::ordered_state_key_for_tests(expected.chain_id());
    let leader_state: consensus::ConsensusState =
        decode_consensus_state(&network.value(leader, &state_key).unwrap()).unwrap();
    let candidate_digest: Digest32 =
        engine::ordered_candidate_digest_for_tests(&network.resolver, &candidate);
    let signed: consensus::ConsensusProposal = network
        .policy
        .engine()
        .propose(
            &leader_state,
            vec![candidate_digest],
            &network.signers[leader],
        )
        .unwrap();
    let proposal: OrderedProposal = OrderedProposal {
        proposal: signed,
        candidate: Some(candidate.clone()),
    };
    let voter: usize = (0..REPLICAS).find(|&replica| replica != leader).unwrap();
    let voter_race: DrainRaceStore<'_> = DrainRaceStore {
        inner: &network.stores[voter],
        context: network.context,
        domain: network.domain(),
        race_key: drain_key,
        race_value: vec![0xA5],
        race_on_durable: true,
        raced: std::cell::Cell::new(false),
    };
    assert!(
        process_proposal(
            &voter_race,
            &network.context,
            &network.env(),
            &proposal,
            &network.signers[voter],
        )
        .is_err()
    );
    assert!(voter_race.raced.get());
    assert!(
        network
            .value(
                voter,
                &engine::ordered_vote_record_key_for_tests(expected.chain_id(), 1)
            )
            .is_none()
    );
}

#[test]
fn justification_committing_drain_set_never_exposes_a_vote_for_its_own_freeze_payload() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let chain: ChainId = fixture::chain();
    let expected: PublicationContext = fixture::protocol();
    let freeze: OrderedCandidate = freeze_candidate([0xE5; 32]);
    network.round(1, Some(&freeze));
    network.round(2, None);
    network.round(3, None);

    // An empty-frontier `DrainSet`, ready on every replica up front: this
    // test is about vote timing, not readiness catch-up.
    let mut selected: Vec<(consensus::FrozenFrontierVote, consensus::FrozenFrontierPage)> =
        Vec::new();
    for source in 0..3 {
        let step: FrozenFrontierStep = advance_frozen_frontier(
            &network.stores[source],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &network.signers[source],
        )
        .unwrap();
        assert!(matches!(step, FrozenFrontierStep::Finalized(_)));
        let pair: (consensus::FrozenFrontierVote, consensus::FrozenFrontierPage) =
            read_frozen_frontier_page(
                &network.stores[source],
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &expected,
                network.signers[source].validator_id(),
                None,
                std::num::NonZeroUsize::new(1).unwrap(),
            )
            .unwrap();
        selected.push(pair);
    }
    selected.sort_by_key(|pair| pair.0.validator);
    let votes: Vec<consensus::FrozenFrontierVote> =
        selected.iter().map(|pair| pair.0.clone()).collect();
    let mut ready: Option<consensus::DrainUnionIdentity> = None;
    for replica in 0..REPLICAS {
        for (vote, page) in &selected {
            ingest_drain_signer_page(
                &network.stores[replica],
                &network.context,
                network.domain(),
                &network.resolver,
                &expected,
                vote.validator,
                vote.clone(),
                page.clone(),
            )
            .unwrap();
        }
        let identity: consensus::DrainUnionIdentity = match advance_drain_union(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &votes,
        )
        .unwrap()
        {
            DrainUnionStep::Ready(identity) => *identity,
            DrainUnionStep::Advanced { .. } => panic!("empty frontier union must finish"),
        };
        if let Some(previous) = &ready {
            assert_eq!(&identity, previous);
        } else {
            ready = Some(identity);
        }
    }
    let identity: consensus::DrainUnionIdentity = ready.unwrap();
    let intent: DrainSetIntent = DrainSetIntent {
        context: expected.clone(),
        request_id: [0xE6; 32],
        selected_votes: votes.clone(),
        drain_union_identity: identity.clone(),
    };
    let drain_candidate: OrderedCandidate = OrderedCandidate {
        context: expected.clone(),
        request_id: intent.request_id,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&intent).unwrap(),
        created_checkpoint: 12,
    };

    // All four independently vote for the real DrainSet chain. The target
    // receives QCs at heights 4 and 5 but not the height-6 QC that commits
    // DrainSet; the other replicas receive all three. This is a normal
    // delayed certificate delivery, not a forged closure row.
    let target: usize = network.non_leader(&[7]);
    let leader: usize = network.leader_index(7);
    for view in 4..=6 {
        let candidate: Option<&OrderedCandidate> = (view == 4).then_some(&drain_candidate);
        let (certificate, _proposal): (QuorumCertificate, OrderedProposal) =
            network.certify(view, candidate);
        for replica in 0..REPLICAS {
            if view == 6 && replica == target {
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
    let record_key: Vec<u8> = drain_set_record_key(&chain, expected.epoch()).unwrap();
    assert!(network.value(target, &record_key).is_none());
    assert!(network.value(leader, &record_key).is_some());

    // A second `Freeze` -- a kind the pre-generalization preview exempted
    // entirely -- is this racing proposal's own payload. A faulty leader
    // signs it directly through the authenticated consensus engine; its
    // justify QC is exactly the missing height-6 QC.
    let second_freeze: OrderedCandidate = freeze_candidate([0xE7; 32]);
    let state_key: Vec<u8> = engine::ordered_state_key_for_tests(&chain);
    let leader_state: consensus::ConsensusState =
        decode_consensus_state(&network.value(leader, &state_key).unwrap()).unwrap();
    let candidate_digest: Digest32 =
        engine::ordered_candidate_digest_for_tests(&network.resolver, &second_freeze);
    let signed: consensus::ConsensusProposal = network
        .policy
        .engine()
        .propose(
            &leader_state,
            vec![candidate_digest],
            &network.signers[leader],
        )
        .unwrap();
    assert_eq!(signed.height, 7);
    let carrying: OrderedProposal = OrderedProposal {
        proposal: signed,
        candidate: Some(second_freeze.clone()),
    };

    // The target must not expose a vote for this racing proposal's own
    // `Freeze` payload in the same event that first observes DrainSet's
    // commit -- the exact generalization under test.
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
    assert_eq!(observed.committed[0].request_id, drain_candidate.request_id);
    assert_eq!(
        observed.committed[0].output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    assert!(network.value(target, &record_key).is_some());
    assert!(
        network
            .value(
                target,
                &engine::ordered_vote_record_key_for_tests(&chain, 7)
            )
            .is_none()
    );
    assert!(
        network
            .value(
                target,
                &engine::ordered_outcome_key_for_tests(&chain, &second_freeze.request_id)
            )
            .is_none()
    );
}

#[test]
fn nonempty_drain_set_from_real_ordered_consensus_lets_a_nonpreparing_replica_apply_the_certified_member()
 {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let expected: PublicationContext = fixture::protocol();

    let (base_manifest, _origin, instance_record, _def_id, _coin_id) = fixture::build_fixture();
    let fee_policy: execution::paid_execution::PaidFeePolicy = base_manifest.fee_policy.clone();
    let coin_object: Object = base_manifest.objects[1].object.clone();
    let recipient: [u8; 32] = *address_of(0x70).as_bytes();
    let nonce: u64 = query_sender_next_nonce(
        &network.stores[0],
        &network.context,
        network.domain(),
        fixture::chain(),
        fixture::protocol().protocol_version(),
        fixture::protocol().epoch(),
        fixture::sender(),
    )
    .unwrap();

    // X: a genuine 3-of-4 quorum prepares and certifies a real transfer
    // against the genesis coin, before Freeze, each on its own independent
    // replica -- never a shared or ad hoc store.
    let x_request_id: [u8; 32] = [0xC1; 32];
    let x_bytes: Vec<u8> = genesis_transfer_paid_intent_bytes(
        &network.resolver,
        &fee_policy,
        &instance_record,
        &coin_object,
        x_request_id,
        nonce,
        recipient,
    );
    let quorum: [usize; 3] = [0, 1, 2];
    let d: usize = 3;
    let mut x_votes: Vec<consensus::FastVote> = Vec::new();
    for &idx in &quorum {
        let vote: consensus::FastVote = crate::fast_path::prepare(
            &network.stores[idx],
            &network.blobs,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &network.leg_policy,
            &fee_policy,
            &crate::paid_execution::tests::CountingEngine::new(),
            &network.signers[idx],
            &x_bytes,
            11,
        )
        .unwrap();
        x_votes.push(vote);
    }
    let fastpath_certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        fixture::protocol().epoch(),
        validator_set(&network.signers),
    )
    .unwrap();
    let certificate: consensus::FastCertificate = fastpath_certifier
        .try_form_certificate(
            x_votes[0].tx_hash,
            x_votes[0].execution_effects_hash,
            x_votes[0].locked_objects_digest,
            &x_votes,
            &crate::fast_path::FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("three real independent votes reach fast-path quorum");
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let bundle: consensus::bundle::PublicationBundle =
        crate::fast_path::publication::assemble_publication_bundle(
            &network.stores[quorum[0]],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &x_bytes,
            &certificate_bytes,
        )
        .unwrap();
    let bundle_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
    let x_identity: consensus::AvailabilityIdentity = consensus::bundle::verify_publication_bundle(
        &bundle,
        &fastpath_certifier,
        &crate::fast_path::FastPathEd25519Verifier,
        &network.resolver,
        &network.history,
    )
    .unwrap()
    .identity;
    assert_eq!(x_identity.request_id, x_request_id);

    // Each of the three quorum replicas independently, durably retains X's
    // publication before Freeze -- this is what later makes its own local
    // frontier genuinely nonempty. D never does this for X.
    for &idx in &quorum {
        crate::fast_path::publication::retain_publication(
            &network.stores[idx],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &bundle_bytes,
            &network.signers[idx],
        )
        .unwrap();
    }

    // Y: D's own genuine conflicting local partial prepare over the exact
    // same coin and sender/epoch nonce X's own certified inputs require. D
    // never prepares X or retains its proof before Freeze.
    let y_request_id: [u8; 32] = [0xC2; 32];
    let y_bytes: Vec<u8> = genesis_transfer_paid_intent_bytes(
        &network.resolver,
        &fee_policy,
        &instance_record,
        &coin_object,
        y_request_id,
        nonce,
        recipient,
    );
    crate::fast_path::prepare(
        &network.stores[d],
        &network.blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &expected,
        &network.leg_policy,
        &fee_policy,
        &crate::paid_execution::tests::CountingEngine::new(),
        &network.signers[d],
        &y_bytes,
        11,
    )
    .unwrap();

    let object_lock_key: Vec<u8> =
        local_instance_state::fastpath_lock_key(expected.chain_id(), coin_object.id).unwrap();
    let nonce_lock_key: Vec<u8> = local_instance_state::fastpath_nonce_lock_key(
        expected.chain_id(),
        &fixture::sender(),
        expected.epoch(),
    )
    .unwrap();
    let y_locks_before_freeze: (Option<Vec<u8>>, Option<Vec<u8>>) = (
        network.value(d, &object_lock_key),
        network.value(d, &nonce_lock_key),
    );
    assert!(y_locks_before_freeze.0.is_some());
    assert!(y_locks_before_freeze.1.is_some());

    // Real ordered Freeze, committed identically on all four replicas.
    let freeze: OrderedCandidate = freeze_candidate([0xB1; 32]);
    network.round(1, Some(&freeze));
    network.round(2, None);
    network.round(3, None);

    // The three quorum replicas each independently advance their own real
    // post-Freeze frontier -- genuinely nonempty, naming exactly X.
    let mut selected: Vec<(consensus::FrozenFrontierVote, consensus::FrozenFrontierPage)> =
        Vec::new();
    for &source in &quorum {
        let vote: consensus::FrozenFrontierVote = loop {
            match advance_frozen_frontier(
                &network.stores[source],
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &expected,
                &network.signers[source],
            )
            .unwrap()
            {
                FrozenFrontierStep::Finalized(vote) => break *vote,
                FrozenFrontierStep::Advanced { .. } => continue,
            }
        };
        assert_eq!(vote.identity.entry_count, 1);
        let (served_vote, page): (consensus::FrozenFrontierVote, consensus::FrozenFrontierPage) =
            read_frozen_frontier_page(
                &network.stores[source],
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &expected,
                network.signers[source].validator_id(),
                None,
                std::num::NonZeroUsize::new(2).unwrap(),
            )
            .unwrap();
        assert_eq!(served_vote, vote);
        assert!(page.terminal);
        assert_eq!(page.entries, vec![x_identity.clone()]);
        selected.push((vote, page));
    }
    selected.sort_by_key(|pair| pair.0.validator);
    let votes: Vec<consensus::FrozenFrontierVote> =
        selected.iter().map(|pair| pair.0.clone()).collect();

    // Every replica -- including D, which never prepared X or retained its
    // proof before Freeze but now imports it through the drain path --
    // independently reconstructs the identical real union readiness.
    let mut ready_identity: Option<consensus::DrainUnionIdentity> = None;
    for replica in 0..REPLICAS {
        let identity: consensus::DrainUnionIdentity = reconstruct_drain_union_ready(
            &network,
            replica,
            &selected,
            &votes,
            &bundle_bytes,
            &expected,
            x_identity.request_id,
        );
        if let Some(previous) = &ready_identity {
            assert_eq!(&identity, previous, "replica {replica}");
        } else {
            ready_identity = Some(identity);
        }
    }
    let identity: consensus::DrainUnionIdentity = ready_identity.unwrap();

    // A real, ordered DrainSetIntent naming this exact selection and union
    // identity, committed identically on all four replicas by the same
    // chained HotStuff engine the empty-frontier DrainSet test already
    // uses -- never a directly inserted record.
    let intent: DrainSetIntent = DrainSetIntent {
        context: expected.clone(),
        request_id: [0xB2; 32],
        selected_votes: votes.clone(),
        drain_union_identity: identity.clone(),
    };
    let candidate: OrderedCandidate = OrderedCandidate {
        context: expected.clone(),
        request_id: intent.request_id,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&intent).unwrap(),
        created_checkpoint: 14,
    };
    network.round(4, Some(&candidate));
    network.round(5, None);
    let (outputs, _certificate, _) = network.round(6, None);
    let record_key: Vec<u8> = drain_set_record_key(expected.chain_id(), expected.epoch()).unwrap();
    let mut committed_bytes: Option<Vec<u8>> = None;
    for (replica, output) in outputs.iter().enumerate() {
        assert_eq!(output.committed.len(), 1, "replica {replica}");
        assert_eq!(
            output.committed[0].output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let bytes: Vec<u8> = network.value(replica, &record_key).unwrap();
        let record: DrainSetRecord = decode_drain_set_record(&bytes).unwrap();
        assert_eq!(record.drain_union_identity, identity);
        assert_eq!(record.selected_votes, votes);
        if let Some(previous) = &committed_bytes {
            assert_eq!(&bytes, previous, "replica {replica}");
        } else {
            committed_bytes = Some(bytes);
        }
    }

    let selected_pairs: Vec<(ValidatorId, consensus::FrozenFrontierIdentity)> = votes
        .iter()
        .map(|vote| (vote.validator, vote.identity.clone()))
        .collect();
    let seed: consensus::DrainUnionAccumulator = consensus::DrainUnionAccumulator::new(
        &network.resolver,
        fixture::chain(),
        expected.protocol_version(),
        expected.epoch(),
        network.domain(),
        votes[0].identity.closure_request_id,
        votes[0].identity.closure_height,
        &selected_pairs,
    )
    .unwrap();
    let selection_digest: Digest32 = seed.identity().entries_digest;
    assert_ne!(selection_digest, identity.entries_digest);
    let ready_key: Vec<u8> =
        drain_union_ready_key(expected.chain_id(), expected.epoch(), &selection_digest).unwrap();
    let original_ready: Vec<u8> = network.value(d, &ready_key).unwrap();

    // Missing/foreign member refusal: neither Y's own real but never-drained
    // request nor a wholly unrelated request id may be applied, and neither
    // attempt moves Y's own still-held locks or writes a receipt.
    for foreign_request_id in [y_request_id, [0xFE; 32]] {
        let result = crate::fast_path::drain_apply::apply_drain_member(
            &network.stores[d],
            &network.blobs,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &network.leg_policy,
            &fee_policy,
            &crate::paid_execution::tests::CountingEngine::new(),
            foreign_request_id,
            15,
        );
        assert!(result.is_err(), "request {foreign_request_id:?}");
        assert_eq!(network.value(d, &object_lock_key), y_locks_before_freeze.0);
        assert_eq!(network.value(d, &nonce_lock_key), y_locks_before_freeze.1);
    }

    // The positive path: D applies X's certified effects from its retained
    // full certificate -- with no aggregated availability certificate ever
    // formed -- atomically resolving Y's conflicting locks, and touches no
    // unrelated lock.
    let unrelated_key: Vec<u8> =
        local_instance_state::fastpath_lock_key(expected.chain_id(), ObjectId::new([0xEE; 32]))
            .unwrap();
    network.put(d, unrelated_key.clone(), StateMutation::Put(vec![0xA5]));

    // The same exact locator must fail closed before its first application
    // when the real, selection-keyed local ready marker is corrupt. Restore
    // the original test fixture bytes only after checking no effect escaped.
    network.put(d, ready_key.clone(), StateMutation::Put(vec![0xFF]));
    assert_eq!(network.value(d, &ready_key), Some(vec![0xFF]));
    assert!(
        crate::fast_path::drain_apply::apply_drain_member(
            &network.stores[d],
            &network.blobs,
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &network.leg_policy,
            &fee_policy,
            &crate::paid_execution::tests::CountingEngine::new(),
            x_identity.request_id,
            15,
        )
        .is_err()
    );
    assert_eq!(network.value(d, &object_lock_key), y_locks_before_freeze.0);
    assert_eq!(network.value(d, &nonce_lock_key), y_locks_before_freeze.1);
    assert!(
        network.stores[d]
            .get_request_receipt(
                &network.context,
                network.domain(),
                runtime::DurableRequestId::new(x_identity.request_id).unwrap(),
            )
            .unwrap()
            .is_none()
    );
    network.put(d, ready_key.clone(), StateMutation::Put(original_ready));
    let apply_engine: crate::paid_execution::tests::CountingEngine =
        crate::paid_execution::tests::CountingEngine::new();
    let output: NodeOutput = crate::fast_path::drain_apply::apply_drain_member(
        &network.stores[d],
        &network.blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &expected,
        &network.leg_policy,
        &fee_policy,
        &apply_engine,
        x_identity.request_id,
        15,
    )
    .unwrap();
    let executions_after_apply: u32 = apply_engine.calls.get();
    assert_eq!(executions_after_apply, 1);
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);
    assert!(network.value(d, &object_lock_key).is_none());
    assert!(network.value(d, &nonce_lock_key).is_none());
    assert_eq!(network.value(d, &unrelated_key), Some(vec![0xA5]));

    let certificate_row_key: Vec<u8> =
        local_instance_state::fastpath_certificate_key(expected.chain_id(), &x_identity.request_id)
            .unwrap();
    assert!(network.value(d, &certificate_row_key).is_some());
    let settlement_row_key: Vec<u8> =
        local_instance_state::fastpath_settlement_key(expected.chain_id(), &x_identity.request_id)
            .unwrap();
    assert!(network.value(d, &settlement_row_key).is_some());

    let audit_key: Vec<u8> = crate::fast_path::drain_apply::drain_lock_resolution_key(
        expected.chain_id(),
        expected.epoch(),
        &x_identity.request_id,
        &object_lock_key,
    )
    .unwrap();
    let audit_bytes: Vec<u8> = network
        .value(d, &audit_key)
        .expect("lock resolution audit row");
    let audit_record: crate::fast_path::drain_apply::FastPathDrainLockResolutionRecord =
        crate::fast_path::drain_apply::decode_drain_lock_resolution_record(&audit_bytes).unwrap();
    assert_eq!(audit_record.resolving_request_id, x_identity.request_id);
    assert_eq!(audit_record.displaced_request_id, y_request_id);
    assert_eq!(audit_record.resolved_key, object_lock_key);

    let head_after_apply: runtime::DurableObjectHead = network.stores[d]
        .get_object_head(&network.context, network.domain(), coin_object.id)
        .unwrap();
    let receipt_after_apply: runtime::DurableRequestReceipt = network.stores[d]
        .get_request_receipt(
            &network.context,
            network.domain(),
            runtime::DurableRequestId::new(x_identity.request_id).unwrap(),
        )
        .unwrap()
        .unwrap();
    let next_nonce_after_apply: u64 = query_sender_next_nonce(
        &network.stores[d],
        &network.context,
        network.domain(),
        fixture::chain(),
        fixture::protocol().protocol_version(),
        fixture::protocol().epoch(),
        fixture::sender(),
    )
    .unwrap();
    let settlement_after_apply: Option<Vec<u8>> = network.value(d, &settlement_row_key);

    // Exact replay, even with a corrupted local ready marker: receipt-first,
    // no re-execution, no re-resolution or mutation of the completed bytes.
    assert!(network.value(d, &ready_key).is_some());
    network.put(d, ready_key.clone(), StateMutation::Put(vec![0xFF]));
    let replay: NodeOutput = crate::fast_path::drain_apply::apply_drain_member(
        &network.stores[d],
        &network.blobs,
        &network.context,
        network.domain(),
        &network.resolver,
        &network.history,
        &expected,
        &network.leg_policy,
        &fee_policy,
        &apply_engine,
        x_identity.request_id,
        15,
    )
    .unwrap();
    assert_eq!(apply_engine.calls.get(), executions_after_apply);
    assert_eq!(network.value(d, &ready_key), Some(vec![0xFF]));
    assert_eq!(replay.responses(), output.responses());
    assert_eq!(
        network.stores[d]
            .get_object_head(&network.context, network.domain(), coin_object.id)
            .unwrap(),
        head_after_apply
    );
    assert_eq!(
        network.stores[d]
            .get_request_receipt(
                &network.context,
                network.domain(),
                runtime::DurableRequestId::new(x_identity.request_id).unwrap(),
            )
            .unwrap()
            .unwrap(),
        receipt_after_apply
    );
    assert_eq!(
        query_sender_next_nonce(
            &network.stores[d],
            &network.context,
            network.domain(),
            fixture::chain(),
            fixture::protocol().protocol_version(),
            fixture::protocol().epoch(),
            fixture::sender(),
        )
        .unwrap(),
        next_nonce_after_apply
    );
    assert_eq!(
        network.value(d, &settlement_row_key),
        settlement_after_apply
    );
    assert_eq!(network.value(d, &audit_key), Some(audit_bytes));
    assert!(network.value(d, &object_lock_key).is_none());
    assert!(network.value(d, &nonce_lock_key).is_none());
    assert_eq!(network.value(d, &unrelated_key), Some(vec![0xA5]));
}
