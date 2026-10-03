//! DR-0187 real acceptance/post-Seal coverage: drives the genuine
//! `seal_signing` candidate through real propose/vote/certify rounds to an
//! actual committed Seal, then exercises the Sealed barrier against further
//! real signing attempts (`process_tick`, a further leader `propose`) and
//! the unsupported-capability Stop at the exact commit site.
use super::seal_faults::{
    CertificateFault, PHANTOM_KEY, PHANTOM_VALUE, SealBlobFault, SealFaultStore, SealRace,
};
use super::seal_signing::{SealSigningFixture, env_with_seal, seal_signing_fixture};
use super::*;
use consensus::{
    ConsensusEngine, ConsensusEvent, ConsensusMessage, ConsensusState, QuorumCertificate,
};
use runtime::portable::{DurableRecordKey, PortableBlobRepository};
use runtime::{
    DurableCommitRejection, DurableDomainStateStore, OutgoingBarrier, SealBarrier,
    StructuredDurableDomainStateStore, TransitionHistoryState,
};

fn certify_with_env(
    network: &Network,
    env: &OrderedEconomicsEnvironment<'_>,
    view: u64,
    candidate: Option<&OrderedCandidate>,
) -> (QuorumCertificate, OrderedProposal) {
    let voters: Vec<usize> = (0..REPLICAS).collect();
    certify_on_with_env(network, env, view, candidate, &voters)
}

fn certify_on_with_env(
    network: &Network,
    env: &OrderedEconomicsEnvironment<'_>,
    view: u64,
    candidate: Option<&OrderedCandidate>,
    voters: &[usize],
) -> (QuorumCertificate, OrderedProposal) {
    let leader: usize = network.leader_index(view);
    let ordered_proposal: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        env,
        candidate,
        &network.signers[leader],
    )
    .unwrap();
    assert_eq!(ordered_proposal.proposal.view, view);
    let mut votes: Vec<consensus::ConsensusVote> = Vec::new();
    for &replica in voters {
        let output = process_proposal(
            &network.stores[replica],
            &network.context,
            env,
            &ordered_proposal,
            &network.signers[replica],
        )
        .unwrap();
        let vote = output
            .messages
            .iter()
            .find_map(|message| match message {
                ConsensusMessage::Vote(vote) => Some(vote.clone()),
                _ => None,
            })
            .expect("every honest replica votes on a safe proposal");
        votes.push(vote);
    }
    let certificate: QuorumCertificate = network
        .policy
        .engine()
        .certificate_from_votes(
            &ordered_proposal.proposal,
            &votes,
            &crate::ordered_economics::policy::Ed25519ConsensusVerifier,
        )
        .unwrap()
        .expect("independent weighted votes reach quorum");
    (certificate, ordered_proposal)
}

fn round_with_env(
    network: &Network,
    env: &OrderedEconomicsEnvironment<'_>,
    view: u64,
    candidate: Option<&OrderedCandidate>,
) -> QuorumCertificate {
    let (certificate, _ordered_proposal) = certify_with_env(network, env, view, candidate);
    for replica in 0..REPLICAS {
        process_certificate(
            &network.stores[replica],
            &network.context,
            env,
            &certificate,
        )
        .unwrap();
    }
    certificate
}

/// Drives the genuine `seal_signing_fixture` candidate through a real
/// propose/vote/certify round at its own height, then two further genuine
/// empty rounds -- the exact DR-0187 justified-prefix lag -- so the real
/// 3-chain commits the Seal block on every replica.
pub(super) fn accept_genuine_seal(
    fixture: &SealSigningFixture,
    env: &OrderedEconomicsEnvironment<'_>,
) -> Vec<OrderedProposal> {
    accept_seal_candidate(
        &fixture.source.fixture.network,
        env,
        fixture.view,
        &fixture.candidate,
    )
}

/// The same genuine three-round acceptance for any honest Seal candidate
/// proposed at the economic `view` of the outgoing source committee.
pub(super) fn accept_seal_candidate(
    network: &Network,
    env: &OrderedEconomicsEnvironment<'_>,
    view: u64,
    seal: &OrderedCandidate,
) -> Vec<OrderedProposal> {
    let mut proposals: Vec<OrderedProposal> = Vec::new();
    for offset in 0..3 {
        let candidate: Option<&OrderedCandidate> = (offset == 0).then_some(seal);
        let (certificate, proposal): (QuorumCertificate, OrderedProposal) = certify_with_env(
            network,
            env,
            view.checked_add(offset).unwrap(),
            candidate,
        );
        for replica in 0..REPLICAS {
            process_certificate(
                &network.stores[replica],
                &network.context,
                env,
                &certificate,
            )
            .unwrap();
        }
        proposals.push(proposal);
    }
    proposals
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompleteSealState {
    source: SourceBusinessSnapshot,
    barrier: OutgoingBarrier,
    status: OrderedStatus,
}

fn complete_state(network: &Network, replica: usize) -> CompleteSealState {
    CompleteSealState {
        source: crate::test_support::capture::captured_source(
            &network.stores[replica],
            &network.blobs,
            &network.context,
            network.domain(),
        ),
        barrier: network.stores[replica]
            .get_outgoing_barrier(&network.context, network.domain())
            .unwrap(),
        status: query_status(&network.stores[replica], &network.context, &network.env()).unwrap(),
    }
}

fn expected_seal_barrier(
    network: &Network,
    candidate: &OrderedCandidate,
    height: u64,
    block_digest: Digest32,
) -> OutgoingBarrier {
    let intent: SealIntent = seal::decode_seal_intent(&candidate.intent).unwrap();
    let subject: Digest32 = intent
        .readiness_subject
        .identity(&network.resolver)
        .unwrap();
    let target: Digest32 = seal::seal_target_digest(
        &network.resolver,
        &candidate.context,
        subject,
        intent.predecessor_tag,
        intent.predecessor_digest,
    )
    .unwrap();
    OutgoingBarrier::Sealed(SealBarrier {
        outgoing_epoch: candidate.context.epoch(),
        request: candidate.request_id,
        height,
        block_digest,
        target_digest: target,
        transition_history: TransitionHistoryState::Virgin,
    })
}

fn assert_accepted_seal(
    network: &Network,
    replica: usize,
    candidate: &OrderedCandidate,
    height: u64,
    block_digest: Digest32,
) {
    let outcome: OrderedOutcome = query_ordered_outcome(
        &network.stores[replica],
        &network.context,
        &network.env(),
        &candidate.request_id,
    )
    .unwrap()
    .expect("the original Seal outcome was atomically retained");
    assert_eq!(
        outcome.candidate_digest,
        network.policy.candidate_digest(candidate).unwrap()
    );
    assert_eq!(outcome.request_id, candidate.request_id);
    assert_eq!(outcome.block_height, height);
    assert_eq!(outcome.block_digest, block_digest);
    assert!(outcome.output.outbound_messages().is_empty());
    assert_eq!(outcome.output.responses().len(), 1);
    let response: &NodeResponse = &outcome.output.responses()[0];
    assert_eq!(response.request_id().as_bytes(), &candidate.request_id);
    assert_eq!(response.status(), NodeResponseStatus::Accepted);
    let seal_outcome: seal::SealOutcome =
        seal::decode_seal_outcome(response.payload().unwrap()).unwrap();
    let expected: OutgoingBarrier = expected_seal_barrier(network, candidate, height, block_digest);
    let sealed: &SealBarrier = expected.sealed().unwrap();
    assert_eq!(
        seal_outcome,
        seal::SealOutcome {
            target: sealed.target_digest,
            request: candidate.request_id,
            seal_block_height: height,
            seal_block_digest: block_digest,
        }
    );
    assert_eq!(
        network.stores[replica]
            .get_outgoing_barrier(&network.context, network.domain())
            .unwrap(),
        expected
    );
    let retained_receipt: DurableRequestReceipt =
        receipt(network, replica, candidate.request_id).unwrap();
    let dedup: NodeDedupRecord =
        NodeDedupRecord::decode(retained_receipt.canonical_bytes()).unwrap();
    assert_eq!(dedup.request_id().as_bytes(), &candidate.request_id);
    assert_eq!(dedup.event_digest(), retained_receipt.event_digest());
    assert_eq!(dedup.responses(), outcome.output.responses());
    assert_eq!(
        engine::load_applied_height(&network.stores[replica], &network.context, &network.env())
            .unwrap()
            .0,
        height
    );
}

fn expected_completed_state(
    network: &Network,
    candidate: &OrderedCandidate,
    proof: &CommittedBlockProof,
    certificate: &QuorumCertificate,
    source: SourceBusinessSnapshot,
) -> CompleteSealState {
    let block_digest: Digest32 = network
        .policy
        .engine()
        .proposal_digest(&proof.committed)
        .unwrap();
    CompleteSealState {
        source,
        barrier: expected_seal_barrier(network, candidate, proof.committed.height, block_digest),
        status: OrderedStatus {
            current_view: certificate.view.checked_add(1).unwrap(),
            high_qc: certificate.clone(),
            committed_height: proof.committed.height,
        },
    }
}

fn state_for(network: &Network, replica: usize) -> ConsensusState {
    let key: Vec<u8> = engine::ordered_state_key_for_tests(&fixture::chain());
    let state: ConsensusState =
        consensus::decode_consensus_state(&network.value(replica, &key).unwrap()).unwrap();
    network
        .policy
        .engine()
        .validate_state(&state, &policy::Ed25519ConsensusVerifier)
        .unwrap();
    state
}

/// The owning consensus engine derives this proof from the real retained
/// state and the incoming genuine QC. No private verified-proof constructor
/// or header-only fixture stands in for normal commit proof authentication.
fn proof_for_certificate(
    network: &Network,
    replica: usize,
    certificate: &QuorumCertificate,
    candidate: &OrderedCandidate,
) -> CommittedBlockProof {
    let output: consensus::ConsensusOutput = network
        .policy
        .engine()
        .on_observer_event(
            &state_for(network, replica),
            ConsensusEvent::Certificate(certificate.clone()),
            &policy::Ed25519ConsensusVerifier,
        )
        .unwrap();
    let digest: Digest32 = network.policy.candidate_digest(candidate).unwrap();
    let proof: CommittedBlockProof = output
        .committed_proofs
        .into_iter()
        .find(|proof| proof.committed.transactions.as_slice() == [digest])
        .expect("the genuine QC commits the original Seal block");
    let block: consensus::CommittedBlock =
        ordered_history::verified_committed_block(&network.policy, &proof).unwrap();
    assert_eq!(block.transactions.as_slice(), &[digest]);
    proof
}

fn ready_seal_completion(
    fixture: &SealSigningFixture,
) -> (QuorumCertificate, CommittedBlockProof, OrderedProposal) {
    ready_seal_completion_with_retained_leader(fixture, false)
}

fn ready_seal_completion_with_retained_leader(
    fixture: &SealSigningFixture,
    leave_leader_unvoted: bool,
) -> (QuorumCertificate, CommittedBlockProof, OrderedProposal) {
    let network: &Network = &fixture.source.fixture.network;
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    round_with_env(network, &env, fixture.view, Some(&fixture.candidate));
    round_with_env(network, &env, fixture.view.checked_add(1).unwrap(), None);
    let view: u64 = fixture.view.checked_add(2).unwrap();
    let leader: usize = network.leader_index(view);
    let voters: Vec<usize> = (0..REPLICAS)
        .filter(|replica: &usize| !leave_leader_unvoted || *replica != leader)
        .collect();
    let (certificate, proposal): (QuorumCertificate, OrderedProposal) =
        certify_on_with_env(network, &env, view, None, &voters);
    if leave_leader_unvoted {
        assert_eq!(
            certificate.votes.len(),
            3,
            "the other three actual validators form quorum"
        );
        // Ordinary signerless observation records this exact already retained
        // leader proposal without voting or manufacturing a local identity.
        let observed: OrderedEventOutput =
            observe_proposal(&network.stores[leader], &network.context, &env, &proposal).unwrap();
        assert!(observed.messages.is_empty());
        assert!(observed.committed.is_empty());
        let state: ConsensusState = state_for(network, leader);
        assert_eq!(state.current_view, view);
        assert!(state.last_voted_view < view);
    }
    let proof: CommittedBlockProof =
        proof_for_certificate(network, 0, &certificate, &fixture.candidate);
    assert_eq!(proof.committed.height, 10);
    for replica in 0..REPLICAS {
        assert_eq!(
            query_status(&network.stores[replica], &network.context, &env)
                .unwrap()
                .committed_height,
            9
        );
        assert_eq!(
            engine::load_applied_height(&network.stores[replica], &network.context, &env)
                .unwrap()
                .0,
            9
        );
        assert!(!barrier_sealed(network, replica));
    }
    (certificate, proof, proposal)
}

fn assert_seal_absent(network: &Network, replica: usize, candidate: &OrderedCandidate) {
    assert!(!barrier_sealed(network, replica));
    assert!(receipt(network, replica, candidate.request_id).is_none());
    assert!(
        query_ordered_outcome(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &candidate.request_id
        )
        .unwrap()
        .is_none()
    );
}

fn assert_sealed_error<T: std::fmt::Debug>(result: Result<T, OrderedEconomicsError>) {
    assert!(
        matches!(
            result,
            Err(OrderedEconomicsError::Node(
                NodeCoreError::PersistenceInvariant(
                    "outgoing epoch is sealed; live work is forbidden"
                )
            ))
        ),
        "unexpected sealed guard result: {result:?}"
    );
}

fn env_with_certificate_blob<'a>(
    network: &'a Network,
    blobs: &'a dyn PortableBlobRepository,
) -> OrderedEconomicsEnvironment<'a> {
    OrderedEconomicsEnvironment {
        seal: Some(OrderedSealComposition {
            genesis_root: &network.root,
            paid_base_policy: &network.leg_policy,
            paid_engine: &network.engine,
            blobs,
        }),
        ..env_with_seal(network)
    }
}

fn barrier_sealed(network: &Network, replica: usize) -> bool {
    network.stores[replica]
        .get_outgoing_barrier(&network.context, network.domain())
        .unwrap()
        .is_sealed()
}

#[test]
fn seal_acceptance_commits_on_the_justified_prefix_and_seals_every_replica() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    assert!(!barrier_sealed(network, 0));
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    let proposals: Vec<OrderedProposal> = accept_genuine_seal(&fixture, &env);
    let original: &consensus::ConsensusProposal = &proposals[0].proposal;
    let block_digest: Digest32 = network.policy.engine().proposal_digest(original).unwrap();
    for replica in 0..REPLICAS {
        assert_accepted_seal(
            network,
            replica,
            &fixture.candidate,
            original.height,
            block_digest,
        );
    }
}

#[test]
fn seal_acceptance_requires_the_live_composition_and_store_capability_without_any_commit() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    round_with_env(network, &env, fixture.view, Some(&fixture.candidate));
    round_with_env(network, &env, fixture.view.checked_add(1).unwrap(), None);
    let (certificate, _) =
        certify_with_env(network, &env, fixture.view.checked_add(2).unwrap(), None);
    for replica in [0usize, 1, 2] {
        process_certificate(
            &network.stores[replica],
            &network.context,
            &env,
            &certificate,
        )
        .unwrap();
    }
    let before: CompleteSealState = complete_state(network, 3);
    let unsupported: SealFaultStore<'_> =
        SealFaultStore::new(network, 3, fixture.candidate.request_id, false, None);
    let result = process_certificate(&unsupported, &network.context, &env, &certificate);
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Prerequisite(
            "ordered Seal completion requires the live composition and same-store capability"
        ))
    ));
    assert!(
        unsupported.getter_calls.get() > 0,
        "the actual same-store getter returns None"
    );
    assert_eq!(unsupported.retention_calls.get(), 0);
    assert_eq!(unsupported.completion_calls.get(), 0);
    assert_eq!(complete_state(network, 3), before);
    assert_seal_absent(network, 3, &fixture.candidate);
    for replica in [0usize, 1, 2] {
        assert!(barrier_sealed(network, replica));
    }
}

#[test]
fn process_tick_after_seal_exposes_no_further_signature() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    accept_genuine_seal(&fixture, &env);
    let before: CompleteSealState = complete_state(network, 0);
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[0],
        calls: Cell::new(0),
    };
    // This is a genuinely due pacemaker tick: the owner would advance its
    // view/deadline, not emit a separate NewView message. The exact Sealed
    // error and full unchanged state witness the guard; the counting signer
    // separately checks that no own signature is requested.
    let deadline: u64 = state_for(network, 0).view_deadline_unix_millis;
    let result = process_tick(
        &network.stores[0],
        &network.context,
        &env,
        deadline,
        &signer,
    );
    assert_sealed_error(result);
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(complete_state(network, 0), before);
}

#[test]
fn propose_after_seal_exposes_no_further_leader_signature() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    accept_genuine_seal(&fixture, &env);
    let next_view: u64 = seal_signing::agreed_status(network).current_view;
    let leader: usize = network.leader_index(next_view);
    let before: CompleteSealState = complete_state(network, leader);
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[leader],
        calls: Cell::new(0),
    };
    let result = propose(
        &network.stores[leader],
        &network.context,
        &env,
        None,
        &signer,
    );
    assert_sealed_error(result);
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(complete_state(network, leader), before);
}

/// The retained EMPTY12 identity is genuinely replayable before QC12 is
/// applied. A concurrent, genuine completion after an Unsealed observation
/// must not let that earlier read authorize exposure of the cached signature.
/// This is not the original Seal's legal AlreadyCompleted reconciliation.
fn assert_retained_empty_cache_guard(vote: bool) {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    let (certificate, proof, empty): (QuorumCertificate, CommittedBlockProof, OrderedProposal) =
        ready_seal_completion_with_retained_leader(&fixture, !vote);
    assert!(empty.candidate.is_none());
    assert!(empty.proposal.transactions.is_empty());
    let leader: usize = network.leader_index(empty.proposal.view);
    let replica: usize = if vote {
        (leader + 1) % REPLICAS
    } else {
        leader
    };
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[replica],
        calls: Cell::new(0),
    };
    let before: CompleteSealState = complete_state(network, replica);
    let key: Vec<u8> = if vote {
        identity::ordered_vote_record_key(&fixture::chain(), empty.proposal.view).unwrap()
    } else {
        identity::ordered_leader_record_key(&fixture::chain(), empty.proposal.view).unwrap()
    };
    let retained_bytes: Vec<u8> = network.value(replica, &key).unwrap();
    if vote {
        let (_, retained): (identity::LocalVoteRecord, consensus::ConsensusVote) =
            identity::decode_local_vote_record(&retained_bytes).unwrap();
        network
            .policy
            .engine()
            .verify_vote(&retained, &policy::Ed25519ConsensusVerifier)
            .unwrap();
        let replay: OrderedEventOutput = process_proposal(
            &network.stores[replica],
            &network.context,
            &env,
            &empty,
            &signer,
        )
        .unwrap();
        assert_eq!(replay.messages, vec![ConsensusMessage::Vote(retained)]);
        assert!(replay.committed.is_empty());
    } else {
        let (_, retained): (identity::LeaderProposalRecord, consensus::ConsensusProposal) =
            identity::decode_leader_proposal_record(&retained_bytes).unwrap();
        assert_eq!(retained, empty.proposal);
        let replay: OrderedProposal = propose(
            &network.stores[replica],
            &network.context,
            &env,
            None,
            &signer,
        )
        .unwrap();
        assert_eq!(replay, empty);
    }
    assert_eq!(
        signer.calls.get(),
        0,
        "the positive replay uses the actual retained signature"
    );
    assert_eq!(complete_state(network, replica), before);

    let mut store: SealFaultStore<'_> =
        SealFaultStore::new(network, replica, fixture.candidate.request_id, true, None);
    // Leader: the first live barrier is after loading the real state and its
    // no-op justified prefix, immediately before preview/cache reconciliation.
    // Vote: the second live barrier is after the no-op prefix and immediately
    // before its existing immutable vote identity is reconciled.
    let stale_read: usize = if vote { 2 } else { 1 };
    store.complete_seal_after_barrier_observation(stale_read, &env, &certificate);
    if vote {
        assert_sealed_error(process_proposal(
            &store,
            &network.context,
            &env,
            &empty,
            &signer,
        ));
    } else {
        assert_sealed_error(propose(&store, &network.context, &env, None, &signer));
    }
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(
        store.barrier_completion_calls.get(),
        1,
        "the real original QC completes Seal in this exact store"
    );
    assert_eq!(
        store.barrier_calls.get(),
        stale_read.checked_add(1).unwrap(),
        "the final cache-exposure guard observes Sealed"
    );
    assert_eq!(store.retention_calls.get(), 0);
    assert_eq!(
        store.completion_calls.get(),
        0,
        "the concurrent completion used the same owning inner store"
    );
    let completed_source: SourceBusinessSnapshot = store
        .after_barrier_completion
        .borrow()
        .as_ref()
        .unwrap()
        .clone();
    let expected: CompleteSealState = expected_completed_state(
        network,
        &fixture.candidate,
        &proof,
        &certificate,
        completed_source,
    );
    assert_eq!(
        complete_state(network, replica),
        expected,
        "the stale caller changes no row, revision, blob, barrier or token after genuine completion"
    );
    assert_eq!(network.value(replica, &key).unwrap(), retained_bytes);
    let block_digest: Digest32 = network
        .policy
        .engine()
        .proposal_digest(&proof.committed)
        .unwrap();
    assert_accepted_seal(
        network,
        replica,
        &fixture.candidate,
        proof.committed.height,
        block_digest,
    );
    // An ordinary static replay after completion also stops at the live
    // barrier; retaining bytes is not permission to expose an own signature.
    if vote {
        assert_sealed_error(process_proposal(
            &network.stores[replica],
            &network.context,
            &env,
            &empty,
            &signer,
        ));
    } else {
        assert_sealed_error(propose(
            &network.stores[replica],
            &network.context,
            &env,
            None,
            &signer,
        ));
    }
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(complete_state(network, replica), expected);
}

#[test]
fn retained_empty_leader_replay_rechecks_the_barrier_after_genuine_seal_completion() {
    assert_retained_empty_cache_guard(false);
}

#[test]
fn retained_empty_vote_replay_rechecks_the_barrier_after_genuine_seal_completion() {
    assert_retained_empty_cache_guard(true);
}

/// A peer-formed EMPTY13 carrier produced by the real consensus owner after
/// consuming QC12. Honest core signing would already be sealed at this point;
/// this does not claim it can emit that peer carrier. It only authenticates a
/// normal adversarial input, without persisting a fabricated repaired state.
fn peer_empty_after_certificate(
    network: &Network,
    certificate: &QuorumCertificate,
) -> OrderedProposal {
    let view: u64 = certificate.view.checked_add(1).unwrap();
    let leader: usize = network.leader_index(view);
    let progressed: consensus::ConsensusOutput = network
        .policy
        .engine()
        .on_observer_event(
            &state_for(network, leader),
            ConsensusEvent::Certificate(certificate.clone()),
            &policy::Ed25519ConsensusVerifier,
        )
        .unwrap();
    assert_eq!(progressed.state.current_view, view);
    let proposal: consensus::ConsensusProposal = network
        .policy
        .engine()
        .propose(
            &progressed.state,
            Vec::<Digest32>::new(),
            &network.signers[leader],
        )
        .unwrap();
    assert_eq!(proposal.justify, *certificate);
    network
        .policy
        .engine()
        .verify_proposal(&proposal, &policy::Ed25519ConsensusVerifier)
        .unwrap();
    OrderedProposal {
        proposal,
        candidate: None,
    }
}

fn assert_business_rows_unchanged(before: &SourceBusinessSnapshot, after: &SourceBusinessSnapshot) {
    // These are additional business-effect assertions, not a normalized
    // snapshot comparison: the full post-completion image is compared above.
    // Every original non-order state, original receipt, object head/version
    // and referenced blob is checked at its actual revision with exact bytes.
    for record in &before.records {
        if let DurableRecordKey::State(key) = record.descriptor.key()
            && key.starts_with(engine::ORDERED_ECONOMICS_STATE_PREFIX)
        {
            continue;
        }
        let actual: &crate::business_reconstruction::SourceSnapshotRecord = after
            .records
            .iter()
            .find(|actual| actual.descriptor.key() == record.descriptor.key())
            .unwrap();
        assert_eq!(actual, record);
    }
    assert_eq!(after.referenced_blobs, before.referenced_blobs);
    for record in &after.records {
        if matches!(
            record.descriptor.key(),
            DurableRecordKey::ObjectHead(_) | DurableRecordKey::ObjectVersion(_, _)
        ) {
            assert!(
                before.records.contains(record),
                "Seal creates no object or fee effects"
            );
        }
    }
}

#[test]
fn justified_prefix_completes_genuine_seal_before_any_fresh_empty_vote_and_peer_qc_relay_remains_read_only()
 {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    let (certificate, proof, retained_empty): (
        QuorumCertificate,
        CommittedBlockProof,
        OrderedProposal,
    ) = ready_seal_completion(&fixture);
    let incoming: OrderedProposal = peer_empty_after_certificate(network, &certificate);
    assert_eq!(
        incoming.proposal.height,
        proof.committed.height.checked_add(3).unwrap()
    );
    let replica: usize = (network.leader_index(incoming.proposal.view) + 1) % REPLICAS;
    let before: CompleteSealState = complete_state(network, replica);
    let previous_vote_key: Vec<u8> =
        identity::ordered_vote_record_key(&fixture::chain(), retained_empty.proposal.view).unwrap();
    let previous_vote: Vec<u8> = network.value(replica, &previous_vote_key).unwrap();
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[replica],
        calls: Cell::new(0),
    };
    let store: SealFaultStore<'_> =
        SealFaultStore::new(network, replica, fixture.candidate.request_id, true, None);
    assert_sealed_error(process_proposal(
        &store,
        &network.context,
        &env,
        &incoming,
        &signer,
    ));
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(store.completion_calls.get(), 1);
    assert_eq!(store.retention_calls.get(), 0);
    let completed_source: SourceBusinessSnapshot = store
        .after_seal_completion
        .borrow()
        .as_ref()
        .unwrap()
        .clone();
    let expected: CompleteSealState = expected_completed_state(
        network,
        &fixture.candidate,
        &proof,
        &certificate,
        completed_source,
    );
    let after: CompleteSealState = complete_state(network, replica);
    assert_eq!(
        after, expected,
        "prefix completion is the only durable progress of this stopped live caller"
    );
    assert_business_rows_unchanged(&before.source, &after.source);
    assert_eq!(
        network.value(replica, &previous_vote_key).unwrap(),
        previous_vote
    );
    for key in [
        identity::ordered_vote_record_key(&fixture::chain(), incoming.proposal.view).unwrap(),
        identity::ordered_leader_record_key(&fixture::chain(), incoming.proposal.view).unwrap(),
    ] {
        assert!(
            network.value(replica, &key).is_none(),
            "no new own signing identity was retained"
        );
    }
    let block_digest: Digest32 = network
        .policy
        .engine()
        .proposal_digest(&proof.committed)
        .unwrap();
    assert_accepted_seal(
        network,
        replica,
        &fixture.candidate,
        proof.committed.height,
        block_digest,
    );
    assert_sealed_error(process_proposal(
        &network.stores[replica],
        &network.context,
        &env,
        &incoming,
        &signer,
    ));
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(complete_state(network, replica), expected);

    let relayed: OrderedEventOutput = process_certificate(
        &network.stores[replica],
        &network.context,
        &env,
        &certificate,
    )
    .unwrap();
    assert!(
        !relayed.messages.iter().any(|message| matches!(
            message,
            ConsensusMessage::Vote(_) | ConsensusMessage::Proposal(_)
        )),
        "peer-formed certificate relay grants no own-signature exposure"
    );
    assert!(relayed.committed.is_empty());
    assert_eq!(complete_state(network, replica), expected);

    let original: OrderedProposal = OrderedProposal {
        proposal: proof.committed.clone(),
        candidate: Some(fixture.candidate.clone()),
    };
    let outcome: OrderedOutcome = query_ordered_outcome(
        &network.stores[replica],
        &network.context,
        &env,
        &fixture.candidate.request_id,
    )
    .unwrap()
    .unwrap();
    match process_proposal(
        &network.stores[replica],
        &network.context,
        &env,
        &original,
        &signer,
    ) {
        Err(OrderedEconomicsError::AlreadyCompleted(retained)) => assert_eq!(*retained, outcome),
        other => panic!("unexpected original Seal replay: {other:?}"),
    }
    let observed: OrderedEventOutput =
        observe_proposal(&network.stores[replica], &network.context, &env, &original).unwrap();
    assert_eq!(observed, OrderedEventOutput::default());
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(complete_state(network, replica), expected);
}

#[test]
fn seal_acceptance_without_live_composition_stops_without_a_refusal_or_prefix_advance() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let (certificate, _, _): (QuorumCertificate, CommittedBlockProof, OrderedProposal) =
        ready_seal_completion(&fixture);
    let before: CompleteSealState = complete_state(network, 0);
    let result = process_certificate(
        &network.stores[0],
        &network.context,
        &network.env(),
        &certificate,
    );
    assert!(
        matches!(
            result,
            Err(OrderedEconomicsError::Prerequisite(
                "ordered Seal completion requires the live composition and same-store capability"
            ))
        ),
        "unexpected composition Stop: {result:?}"
    );
    assert_eq!(complete_state(network, 0), before);
    assert_seal_absent(network, 0, &fixture.candidate);
}

fn assert_certificate_completion_stop(fault: CertificateFault, expected: &'static str) {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let (certificate, proof, _): (QuorumCertificate, CommittedBlockProof, OrderedProposal) =
        ready_seal_completion(&fixture);
    let staged: runtime::portable::PortableBlobDescriptor = network
        .blobs
        .read_portable_blob_descriptor(&fixture.certificate_digest)
        .unwrap()
        .unwrap();
    assert_eq!(
        staged.length(),
        usize::try_from(fixture.certificate_length).unwrap()
    );
    let faulty: SealBlobFault<'_> =
        SealBlobFault::new(&network.blobs, fixture.certificate_digest, fault);
    let env: OrderedEconomicsEnvironment<'_> = env_with_certificate_blob(network, &faulty);
    let before: CompleteSealState = complete_state(network, 0);
    // Exercise execute_seal_candidate itself with the verified genuine Seal
    // proof, rather than counting only its earlier warrant/preflight check.
    engine::seal_acceptance_dispatch_tests::assert_execute_seal_stops(
        network.stores[0].outgoing_seal_repository().unwrap(),
        &network.context,
        &env,
        &fixture.candidate,
        &proof,
        expected,
    );
    assert_eq!(faulty.descriptor_calls.get(), 1);
    assert_eq!(complete_state(network, 0), before);
    let result = process_certificate(&network.stores[0], &network.context, &env, &certificate);
    match result {
        Err(OrderedEconomicsError::Prerequisite(actual)) => assert_eq!(actual, expected),
        other => panic!("unexpected certificate completion result: {other:?}"),
    }
    assert_eq!(
        faulty.descriptor_calls.get(),
        2,
        "both direct dispatch and real completion read the faulty certificate"
    );
    assert_eq!(
        faulty.chunk_calls.get(),
        if fault == CertificateFault::WrongDigest {
            2
        } else {
            0
        }
    );
    assert_eq!(complete_state(network, 0), before);
    assert_seal_absent(network, 0, &fixture.candidate);
    // Restoring only the actual immutable blob owner makes this same normal
    // QC successfully complete, establishing all other proof preconditions.
    process_certificate(
        &network.stores[0],
        &network.context,
        &env_with_seal(network),
        &certificate,
    )
    .unwrap();
    assert!(barrier_sealed(network, 0));
}

#[test]
fn seal_acceptance_dispatch_and_completion_stop_when_the_staged_certificate_is_absent() {
    assert_certificate_completion_stop(CertificateFault::Absent, "seal certificate blob is absent");
}

#[test]
fn seal_acceptance_dispatch_and_completion_stop_when_the_staged_certificate_length_differs() {
    assert_certificate_completion_stop(
        CertificateFault::WrongLength,
        "seal certificate length disagrees with the staged blob",
    );
}

#[test]
fn seal_acceptance_dispatch_and_completion_stop_when_the_staged_certificate_digest_differs() {
    assert_certificate_completion_stop(
        CertificateFault::WrongDigest,
        "seal certificate blob digest mismatch",
    );
}

#[test]
fn seal_acceptance_dispatch_requires_the_actual_applied_prior_tip_and_declared_recovery_repairs_the_lag()
 {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    round_with_env(network, &env, fixture.view, Some(&fixture.candidate));
    let next: u64 = fixture.view.checked_add(1).unwrap();
    let last: u64 = fixture.view.checked_add(2).unwrap();
    let lagging: usize = network.non_leader(&[next, last]);
    let voters: Vec<usize> = (0..REPLICAS)
        .filter(|replica| *replica != lagging)
        .collect();
    let (prior_certificate, prior_proposal): (QuorumCertificate, OrderedProposal) =
        certify_on_with_env(network, &env, next, None, &voters);
    for &replica in &voters {
        process_certificate(
            &network.stores[replica],
            &network.context,
            &env,
            &prior_certificate,
        )
        .unwrap();
    }
    let (certificate, proposal): (QuorumCertificate, OrderedProposal) =
        certify_on_with_env(network, &env, last, None, &voters);
    let proof: CommittedBlockProof =
        proof_for_certificate(network, voters[0], &certificate, &fixture.candidate);
    let before: CompleteSealState = complete_state(network, lagging);
    assert_eq!(before.status.committed_height, 8);
    assert_eq!(
        engine::load_applied_height(&network.stores[lagging], &network.context, &env)
            .unwrap()
            .0,
        8
    );
    engine::seal_acceptance_dispatch_tests::assert_execute_seal_stops(
        network.stores[lagging].outgoing_seal_repository().unwrap(),
        &network.context,
        &env,
        &fixture.candidate,
        &proof,
        "ordered Seal acceptance requires the actual applied and committed prior tip h-1; declared recovery required",
    );
    assert_eq!(complete_state(network, lagging), before);
    assert_seal_absent(network, lagging, &fixture.candidate);
    // Ordinary signerless recovery really advances 8 -> 9 before allowing
    // this same genuine h=10 proof; no heights or views are patched.
    observe_proposal(
        &network.stores[lagging],
        &network.context,
        &env,
        &prior_proposal,
    )
    .unwrap();
    process_certificate(
        &network.stores[lagging],
        &network.context,
        &env,
        &prior_certificate,
    )
    .unwrap();
    assert_eq!(
        engine::load_applied_height(&network.stores[lagging], &network.context, &env)
            .unwrap()
            .0,
        9
    );
    observe_proposal(&network.stores[lagging], &network.context, &env, &proposal).unwrap();
    process_certificate(
        &network.stores[lagging],
        &network.context,
        &env,
        &certificate,
    )
    .unwrap();
    assert!(barrier_sealed(network, lagging));
}

/// A cryptographically genuine adversarial carrier formed by the consensus
/// owner. It deliberately bypasses honest signing admission so the semantic
/// acceptance comparison itself is exercised, with no fabricated private
/// proof or saved outcome. Ordinary signerless observation stores its bytes.
pub(super) fn certify_adversarial_candidate(
    network: &Network,
    candidate: &OrderedCandidate,
    view: u64,
) -> QuorumCertificate {
    network.policy.authenticate_candidate(candidate).unwrap();
    let leader: usize = network.leader_index(view);
    let digest: Digest32 = network.policy.candidate_digest(candidate).unwrap();
    let proposal: consensus::ConsensusProposal = network
        .policy
        .engine()
        .propose(
            &state_for(network, leader),
            vec![digest],
            &network.signers[leader],
        )
        .unwrap();
    assert_eq!(proposal.view, view);
    assert_eq!(proposal.height % 3, 1);
    let mut votes: Vec<consensus::ConsensusVote> = Vec::new();
    for replica in 0..REPLICAS {
        let output: consensus::ConsensusOutput = network
            .policy
            .engine()
            .on_event(
                &state_for(network, replica),
                ConsensusEvent::Proposal(proposal.clone()),
                &network.signers[replica],
                &policy::Ed25519ConsensusVerifier,
            )
            .unwrap();
        let vote: consensus::ConsensusVote = output
            .outbound_messages
            .into_iter()
            .find_map(|message| match message {
                ConsensusMessage::Vote(vote) => Some(vote),
                _ => None,
            })
            .unwrap();
        votes.push(vote);
    }
    let certificate: QuorumCertificate = network
        .policy
        .engine()
        .certificate_from_votes(&proposal, &votes, &policy::Ed25519ConsensusVerifier)
        .unwrap()
        .unwrap();
    let carrier: OrderedProposal = OrderedProposal {
        proposal,
        candidate: Some(candidate.clone()),
    };
    for replica in 0..REPLICAS {
        let observed: OrderedEventOutput = observe_proposal(
            &network.stores[replica],
            &network.context,
            &env_with_seal(network),
            &carrier,
        )
        .unwrap();
        assert!(
            !observed
                .messages
                .iter()
                .any(|message| matches!(message, ConsensusMessage::Vote(_)))
        );
        process_certificate(
            &network.stores[replica],
            &network.context,
            &env_with_seal(network),
            &certificate,
        )
        .unwrap();
    }
    certificate
}

#[test]
fn seal_acceptance_dispatch_and_actual_completion_independently_reject_the_entire_cut_mismatch() {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let mut cut: crate::business_reconstruction::cut::BusinessCutIdentity =
        fixture.cut_identity.clone();
    cut.generation_floor = protocol_types::ExecutionGeneration::new(u64::MAX);
    let candidate: OrderedCandidate = seal_signing::candidate_for_cut(
        network,
        &cut,
        &fixture.subject,
        &fixture.next_set,
        cut.ordered_history.through_height,
    );
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    seal::load_verified_seal_certificate(&env, &candidate).unwrap();
    certify_adversarial_candidate(network, &candidate, fixture.view);
    round_with_env(network, &env, fixture.view.checked_add(1).unwrap(), None);
    let (certificate, _): (QuorumCertificate, OrderedProposal) =
        certify_with_env(network, &env, fixture.view.checked_add(2).unwrap(), None);
    let proof: CommittedBlockProof = proof_for_certificate(network, 0, &certificate, &candidate);
    let before: CompleteSealState = complete_state(network, 0);
    engine::seal_acceptance_dispatch_tests::assert_execute_seal_stops(
        network.stores[0].outgoing_seal_repository().unwrap(),
        &network.context,
        &env,
        &candidate,
        &proof,
        "ordered Seal acceptance verified business cut differs from the candidates own intent",
    );
    assert_eq!(complete_state(network, 0), before);
    let result = process_certificate(&network.stores[0], &network.context, &env, &certificate);
    assert!(
        matches!(
            result,
            Err(OrderedEconomicsError::Prerequisite(
                "ordered Seal acceptance verified business cut differs from the candidates own intent"
            ))
        ),
        "unexpected acceptance cut result: {result:?}"
    );
    assert_eq!(complete_state(network, 0), before);
    assert_seal_absent(network, 0, &candidate);
}

fn assert_race_failure(result: Result<OrderedEventOutput, OrderedEconomicsError>) {
    assert!(
        matches!(
            result,
            Err(OrderedEconomicsError::Node(
                NodeCoreError::DurableCommitRejected(DurableCommitRejection::InvalidPersistedState)
            ))
        ),
        "unexpected raced completion result: {result:?}"
    );
}

fn assert_expected_race_state(
    network: &Network,
    replica: usize,
    candidate: &OrderedCandidate,
    store: &SealFaultStore<'_>,
    before: &CompleteSealState,
    before_row: &runtime::VersionedStateValue,
    inventory: bool,
) {
    assert_eq!(store.race_calls.get(), 1);
    let source: SourceBusinessSnapshot = store.after_race.borrow().as_ref().unwrap().clone();
    assert_eq!(
        source.token.mutation_sequence(),
        before
            .source
            .token
            .mutation_sequence()
            .checked_add(1)
            .unwrap()
    );
    let expected: CompleteSealState = CompleteSealState {
        source,
        barrier: before.barrier,
        status: before.status.clone(),
    };
    // This expected image was captured immediately after the one specified
    // legitimate ordinary CAS, before the challenged Seal commit was sent.
    // No rows, revisions, metadata or token are normalized for comparison.
    assert_eq!(complete_state(network, replica), expected);
    let key: Vec<u8> = if inventory {
        PHANTOM_KEY.to_vec()
    } else {
        engine::ordered_vote_record_key_for_tests(&fixture::chain(), 2)
    };
    let after_row: runtime::VersionedStateValue = network.stores[replica]
        .get_versioned_durable(&network.context, network.domain(), &key)
        .unwrap();
    assert_eq!(
        after_row.revision(),
        before_row.revision().checked_next().unwrap()
    );
    if inventory {
        assert!(before_row.value().is_none());
        assert_eq!(after_row.value(), Some(PHANTOM_VALUE));
        assert_eq!(
            expected.source.records.len(),
            before.source.records.len().checked_add(1).unwrap()
        );
    } else {
        assert_eq!(after_row.value(), before_row.value());
        assert_eq!(expected.source.records.len(), before.source.records.len());
    }
    assert_seal_absent(network, replica, candidate);
}

fn assert_retention_race(race: SealRace, vote: bool) {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let env: OrderedEconomicsEnvironment<'_> = env_with_seal(network);
    let leader: usize = network.leader_index(fixture.view);
    let replica: usize = if vote {
        (leader + 1) % REPLICAS
    } else {
        leader
    };
    let proposal: Option<OrderedProposal> = if vote {
        Some(
            propose(
                &network.stores[leader],
                &network.context,
                &env,
                Some(&fixture.candidate),
                &network.signers[leader],
            )
            .unwrap(),
        )
    } else {
        None
    };
    let before: CompleteSealState = complete_state(network, replica);
    let inventory: bool = race == SealRace::RetentionInventory;
    let key: Vec<u8> = if inventory {
        PHANTOM_KEY.to_vec()
    } else {
        engine::ordered_vote_record_key_for_tests(&fixture::chain(), 2)
    };
    let before_row: runtime::VersionedStateValue = network.stores[replica]
        .get_versioned_durable(&network.context, network.domain(), &key)
        .unwrap();
    let store: SealFaultStore<'_> = SealFaultStore::new(
        network,
        replica,
        fixture.candidate.request_id,
        true,
        Some(race),
    );
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[replica],
        calls: Cell::new(0),
    };
    if let Some(proposal) = proposal.as_ref() {
        assert_race_failure(process_proposal(
            &store,
            &network.context,
            &env,
            proposal,
            &signer,
        ));
    } else {
        let result = propose(
            &store,
            &network.context,
            &env,
            Some(&fixture.candidate),
            &signer,
        );
        assert!(
            matches!(
                result,
                Err(OrderedEconomicsError::Node(
                    NodeCoreError::DurableCommitRejected(
                        DurableCommitRejection::InvalidPersistedState
                    )
                ))
            ),
            "unexpected raced leader result: {result:?}"
        );
    }
    assert_eq!(
        signer.calls.get(),
        1,
        "the signature is prepared but a failed CAS never exposes it"
    );
    assert_eq!(store.retention_calls.get(), 1);
    assert_eq!(store.completion_calls.get(), 0);
    assert_expected_race_state(
        network,
        replica,
        &fixture.candidate,
        &store,
        &before,
        &before_row,
        inventory,
    );
}

fn assert_completion_race(race: SealRace) {
    let fixture: SealSigningFixture = seal_signing_fixture();
    let network: &Network = &fixture.source.fixture.network;
    let (certificate, _, _): (QuorumCertificate, CommittedBlockProof, OrderedProposal) =
        ready_seal_completion(&fixture);
    let before: CompleteSealState = complete_state(network, 0);
    let inventory: bool = race == SealRace::CompletionInventory;
    let key: Vec<u8> = if inventory {
        PHANTOM_KEY.to_vec()
    } else {
        engine::ordered_vote_record_key_for_tests(&fixture::chain(), 2)
    };
    let before_row: runtime::VersionedStateValue = network.stores[0]
        .get_versioned_durable(&network.context, network.domain(), &key)
        .unwrap();
    let store: SealFaultStore<'_> =
        SealFaultStore::new(network, 0, fixture.candidate.request_id, true, Some(race));
    assert_race_failure(process_certificate(
        &store,
        &network.context,
        &env_with_seal(network),
        &certificate,
    ));
    assert_eq!(store.retention_calls.get(), 0);
    assert_eq!(
        store.completion_calls.get(),
        1,
        "the actual original invocation consumes this final-token race"
    );
    assert_expected_race_state(
        network,
        0,
        &fixture.candidate,
        &store,
        &before,
        &before_row,
        inventory,
    );
}

#[test]
fn seal_leader_retention_consumes_a_changed_token_without_exposing_the_signature() {
    assert_retention_race(SealRace::RetentionSequence, false);
}
#[test]
fn seal_leader_retention_consumes_a_phantom_inventory_without_exposing_the_signature() {
    assert_retention_race(SealRace::RetentionInventory, false);
}
#[test]
fn seal_vote_retention_consumes_a_changed_token_without_exposing_the_signature() {
    assert_retention_race(SealRace::RetentionSequence, true);
}
#[test]
fn seal_vote_retention_consumes_a_phantom_inventory_without_exposing_the_signature() {
    assert_retention_race(SealRace::RetentionInventory, true);
}
#[test]
fn original_seal_completion_consumes_a_changed_token_without_any_seal_effect() {
    assert_completion_race(SealRace::CompletionSequence);
}
#[test]
fn original_seal_completion_consumes_a_phantom_inventory_without_any_seal_effect() {
    assert_completion_race(SealRace::CompletionInventory);
}
