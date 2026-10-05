//! Counted engine composition on one genuinely activated successor world.
//! Lost replies hide real protected commits; the race is a real live write.
use super::super::sqlite_handoff_faults::{HandoffFaultPlan, SqliteHandoffFaults};
use super::*;
use crate::business_reconstruction::SourceBusinessSnapshot;
use crate::serving_authority::LiveWarrant;
use consensus::{ConsensusMessage, ConsensusProposal, ConsensusVote, QuorumCertificate};
use runtime::{DurableCommitRejection, IndeterminateCommitReason, OutgoingBarrier};
use std::cell::Cell;

struct CountedSigner<'a> {
    member: &'a TestSigner,
    signatures: Cell<usize>,
}

impl consensus::ConsensusSigner for CountedSigner<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.member.id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        self.signatures
            .set(self.signatures.get().checked_add(1).unwrap());
        consensus::ConsensusSigner::sign_framed(self.member, frame)
    }
}

fn env_for(world: &SuccessorWorld, index: usize) -> OrderedEconomicsEnvironment<'_> {
    let network: &Network = world.network();
    let blobs: &SqliteBlobStore = &world.targets[index].1;
    OrderedEconomicsEnvironment {
        policy: &world.policy,
        history: &network.history,
        leg_policy: &world.next_base,
        engine: &network.engine,
        blobs,
        seal: Some(OrderedSealComposition {
            genesis_root: &network.root,
            paid_base_policy: &world.next_base,
            paid_engine: &network.engine,
            blobs,
        }),
    }
}

fn capture(world: &SuccessorWorld, index: usize) -> SourceBusinessSnapshot {
    crate::test_support::capture::captured_source(
        &world.targets[index].0,
        &world.targets[index].1,
        &world.operation,
        world.network().domain(),
    )
}

fn signature_counts(signers: &[CountedSigner<'_>]) -> Vec<usize> {
    signers
        .iter()
        .map(|signer: &CountedSigner<'_>| signer.signatures.get())
        .collect()
}

fn certify_proposal(
    world: &SuccessorWorld,
    proposal: &OrderedProposal,
    signers: &[CountedSigner<'_>],
) -> QuorumCertificate {
    let mut votes: Vec<ConsensusVote> = Vec::new();
    for (index, signer) in signers.iter().enumerate() {
        let output: OrderedEventOutput = process_proposal_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &env_for(world, index),
            proposal,
            signer,
        )
        .unwrap();
        let vote: ConsensusVote = output
            .messages
            .into_iter()
            .find_map(|message: ConsensusMessage| match message {
                ConsensusMessage::Vote(vote) => Some(vote),
                _ => None,
            })
            .expect("each actual successor member votes on the safe carrier");
        votes.push(vote);
    }
    world
        .policy
        .engine()
        .certificate_from_votes(
            &proposal.proposal,
            &votes,
            &crate::ordered_economics::policy::Ed25519ConsensusVerifier,
        )
        .unwrap()
        .expect("actual independent successor votes reach weighted quorum")
}

fn certify_empty(world: &SuccessorWorld, signers: &[CountedSigner<'_>]) -> QuorumCertificate {
    let view: u64 =
        query_status_successor(&world.warrant(0), &world.targets[0].0, &env_for(world, 0))
            .unwrap()
            .current_view;
    let leader_id: ValidatorId = world.policy.engine().validator_set().leader(view).unwrap();
    let leader: usize = world
        .members
        .iter()
        .position(|member: &TestSigner| member.id == leader_id)
        .unwrap();
    let proposal: OrderedProposal = propose_successor(
        &world.warrant(leader),
        &world.targets[leader].0,
        &env_for(world, leader),
        None,
        &signers[leader],
    )
    .unwrap();
    certify_proposal(world, &proposal, signers)
}

fn apply_certificate(world: &SuccessorWorld, certificate: &QuorumCertificate) {
    for index in 0..world.targets.len() {
        process_certificate_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &env_for(world, index),
            certificate,
        )
        .unwrap();
    }
}

fn assert_successor_ports_only(faults: &SqliteHandoffFaults<'_>) {
    assert_eq!(faults.outgoing_getter_calls.get(), 0);
    assert_eq!(faults.ordinary_durable_calls.get(), 0);
    assert_eq!(faults.ordinary_invocation_calls.get(), 0);
    assert_eq!(faults.successor_activation_calls.get(), 0);
    assert!(faults.pending_faults().is_empty());
}

fn seal_receipt(world: &SuccessorWorld, index: usize, request: [u8; 32]) -> DurableRequestReceipt {
    world.targets[index]
        .0
        .get_request_receipt(
            &world.operation,
            world.network().domain(),
            DurableRequestId::new(request).unwrap(),
        )
        .unwrap()
        .expect("the actual Seal invocation retained its original receipt")
}

#[test]
fn genuine_successor_seal_engine_reconciles_retention_and_completion_reply_loss_and_live_race() {
    let world: SuccessorWorld = successor_chain::recurring_world();
    let prepared: successor_chain::PreparedSuccessorSeal =
        successor_chain::prepare_current_successor_seal(&world);
    let network: &Network = world.network();
    assert_eq!(world.targets.len(), 4);
    let seal: &OrderedCandidate = &prepared.seal;
    let certificate_body: Vec<u8> = network.blobs.get_blob(&prepared.digest).unwrap().unwrap();
    // The shared source fixture originally writes its artifact closure into
    // the real memory blob owner. Transfer those exact bytes to every host's
    // actual SQLite owner before any fault invocation or physical capture.
    for (store, blobs) in &world.targets {
        let source: SourceBusinessSnapshot = crate::test_support::capture::captured_source(
            store,
            &network.blobs,
            &world.operation,
            network.domain(),
        );
        for (digest, body) in &source.referenced_blobs {
            blobs.put_blob(*digest, body.clone()).unwrap();
        }
        blobs
            .put_blob(prepared.digest, certificate_body.clone())
            .unwrap();
    }
    let signers: Vec<CountedSigner<'_>> = world
        .members
        .iter()
        .map(|member: &TestSigner| CountedSigner {
            member,
            signatures: Cell::new(0),
        })
        .collect();
    let view: u64 =
        query_status_successor(&world.warrant(0), &world.targets[0].0, &env_for(&world, 0))
            .unwrap()
            .current_view;
    let leader_id: ValidatorId = world.policy.engine().validator_set().leader(view).unwrap();
    let leader: usize = world
        .members
        .iter()
        .position(|member: &TestSigner| member.id == leader_id)
        .unwrap();
    let retention: SqliteHandoffFaults<'_> = SqliteHandoffFaults::new(
        &world.targets[leader].0,
        HandoffFaultPlan::SuccessorRetentionReplyLoss,
    );
    let retained_warrant: LiveWarrant<'_> = world.warrant_on(&retention, leader);
    assert!(matches!(
        propose_successor(
            &retained_warrant,
            &retention,
            &env_for(&world, leader),
            Some(seal),
            &signers[leader],
        ),
        Err(OrderedEconomicsError::Node(
            NodeCoreError::DurableCommitIndeterminate(IndeterminateCommitReason::ConnectionLost)
        ))
    ));
    assert_eq!(signers[leader].signatures.get(), 1);
    assert_eq!(retention.successor_retention_calls.get(), 1);
    assert_eq!(retention.successor_completion_calls.get(), 0);
    assert_successor_ports_only(&retention);
    let leader_key: Vec<u8> = crate::ordered_economics::identity::scoped_leader_record_key(
        world.policy.key_scope(),
        world.policy.context().chain_id(),
        view,
    )
    .unwrap();
    let retained_bytes: Vec<u8> = world.value(leader, &leader_key).1.unwrap();
    let (record, retained): (
        crate::ordered_economics::identity::LeaderProposalRecord,
        ConsensusProposal,
    ) = crate::ordered_economics::identity::decode_leader_proposal_record(&retained_bytes).unwrap();
    let after_retention: SourceBusinessSnapshot = capture(&world, leader);
    let proposal: OrderedProposal = propose_successor(
        &world.warrant(leader),
        &world.targets[leader].0,
        &env_for(&world, leader),
        Some(seal),
        &signers[leader],
    )
    .unwrap();
    assert_eq!(proposal.proposal, retained);
    assert_eq!(
        consensus::encode_proposal(&proposal.proposal).unwrap(),
        record.proposal
    );
    let expected_proposal: OrderedProposal = OrderedProposal {
        proposal: retained,
        candidate: Some(seal.clone()),
    };
    assert_eq!(
        crate::ordered_economics::engine::encode_ordered_proposal(&proposal).unwrap(),
        crate::ordered_economics::engine::encode_ordered_proposal(&expected_proposal).unwrap(),
    );
    assert_eq!(
        signers[leader].signatures.get(),
        1,
        "retention reconciliation never signs again"
    );
    assert_eq!(world.value(leader, &leader_key).1.unwrap(), retained_bytes);
    assert_eq!(capture(&world, leader), after_retention);
    let first: QuorumCertificate = certify_proposal(&world, &proposal, &signers);
    apply_certificate(&world, &first);
    let second: QuorumCertificate = certify_empty(&world, &signers);
    apply_certificate(&world, &second);
    let completing: QuorumCertificate = certify_empty(&world, &signers);
    let before_completion_signatures: Vec<usize> = signature_counts(&signers);
    for index in [0usize, 1usize] {
        let completed: OrderedEventOutput = process_certificate_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &env_for(&world, index),
            &completing,
        )
        .unwrap();
        assert_eq!(completed.committed.len(), 1);
        assert_eq!(completed.committed[0].request_id, seal.request_id);
        assert_eq!(
            completed.committed[0].output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
    }
    let clean_barrier: OutgoingBarrier = world.targets[0]
        .0
        .get_outgoing_barrier(&world.operation, network.domain())
        .unwrap();
    assert!(clean_barrier.is_sealed());
    let clean_receipt: DurableRequestReceipt = seal_receipt(&world, 0, seal.request_id);
    let applied_key: Vec<u8> = crate::ordered_economics::engine::scoped_applied_height_key(
        world.policy.key_scope(),
        world.policy.context().chain_id(),
    )
    .unwrap();
    let before_race: SourceBusinessSnapshot = capture(&world, 2);
    let raced: SqliteHandoffFaults<'_> = SqliteHandoffFaults::completion_live_race(
        &world.targets[2].0,
        &world.targets[2].1,
        applied_key,
    );
    let race_warrant: LiveWarrant<'_> = world.warrant_on(&raced, 2);
    assert!(matches!(
        process_certificate_successor(&race_warrant, &raced, &env_for(&world, 2), &completing),
        Err(OrderedEconomicsError::Node(
            NodeCoreError::DurableCommitRejected(DurableCommitRejection::InvalidPersistedState)
        ))
    ));
    assert_eq!(raced.live_race_calls.get(), 1);
    assert_eq!(raced.successor_retention_calls.get(), 0);
    assert_eq!(raced.successor_completion_calls.get(), 1);
    assert_successor_ports_only(&raced);
    let after_race: SourceBusinessSnapshot = raced.after_race.borrow().as_ref().unwrap().clone();
    assert!(after_race.token.mutation_sequence() > before_race.token.mutation_sequence());
    assert_eq!(
        capture(&world, 2),
        after_race,
        "the rejected completion adds no write after the live race"
    );
    assert_eq!(
        world.targets[2]
            .0
            .get_outgoing_barrier(&world.operation, network.domain())
            .unwrap(),
        OutgoingBarrier::Unsealed
    );
    assert!(
        world.targets[2]
            .0
            .get_request_receipt(
                &world.operation,
                network.domain(),
                DurableRequestId::new(seal.request_id).unwrap(),
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(signature_counts(&signers), before_completion_signatures);
    let retried: OrderedEventOutput = process_certificate_successor(
        &world.warrant(2),
        &world.targets[2].0,
        &env_for(&world, 2),
        &completing,
    )
    .unwrap();
    assert_eq!(retried.committed.len(), 1);
    assert_eq!(retried.committed[0].request_id, seal.request_id);
    assert_eq!(
        world.targets[2]
            .0
            .get_outgoing_barrier(&world.operation, network.domain())
            .unwrap(),
        clean_barrier
    );
    assert_eq!(seal_receipt(&world, 2, seal.request_id), clean_receipt);
    let completion: SqliteHandoffFaults<'_> = SqliteHandoffFaults::new(
        &world.targets[3].0,
        HandoffFaultPlan::SuccessorCompletionReplyLoss,
    );
    let completion_warrant: LiveWarrant<'_> = world.warrant_on(&completion, 3);
    assert!(matches!(
        process_certificate_successor(
            &completion_warrant,
            &completion,
            &env_for(&world, 3),
            &completing
        ),
        Err(OrderedEconomicsError::Node(
            NodeCoreError::DurableCommitIndeterminate(IndeterminateCommitReason::ConnectionLost)
        ))
    ));
    assert_eq!(completion.successor_retention_calls.get(), 0);
    assert_eq!(completion.successor_completion_calls.get(), 1);
    assert_successor_ports_only(&completion);
    assert_eq!(
        world.targets[3]
            .0
            .get_outgoing_barrier(&world.operation, network.domain())
            .unwrap(),
        clean_barrier
    );
    assert_eq!(seal_receipt(&world, 3, seal.request_id), clean_receipt);
    assert_eq!(signature_counts(&signers), before_completion_signatures);
    let sealed: SourceBusinessSnapshot = capture(&world, 3);
    assert!(
        world.resolve(3).is_err(),
        "normal live resolution refuses the genuinely sealed namespace"
    );
    assert!(
        propose_successor(
            &completion_warrant,
            &completion,
            &env_for(&world, 3),
            None,
            &signers[3],
        )
        .is_err()
    );
    assert_eq!(signature_counts(&signers), before_completion_signatures);
    assert_eq!(capture(&world, 3), sealed);
    assert_eq!(completion.successor_completion_calls.get(), 1);
    assert_successor_ports_only(&completion);
}
