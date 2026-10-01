use super::*;
use crate::test_support::{TestCrypto, proposal_votes, setup};
use crate::{CommittedBlock, ConsensusEngine, ConsensusEvent, ConsensusMessage, ConsensusState};
use sha2::Digest as _;

/// Drives `up_to_byte` real propose/vote/certify rounds across all four
/// validators (mirroring `test_support::certify`, but also collecting every
/// `(CommittedBlock, CommittedBlockProof)` pair validator 0's own
/// `on_event` output produces along the way).
fn drive_heights(
    engine: &ChainedHotStuff,
    cryptos: &[TestCrypto],
    states: &mut [ConsensusState],
    up_to_byte: u8,
) -> Vec<(CommittedBlock, CommittedBlockProof)> {
    let mut captured = Vec::new();
    for byte in 1..=up_to_byte {
        let (_, votes) = proposal_votes(engine, states, cryptos, byte);
        let mut aggregator = states[0].clone();
        let mut certificate = None;
        for vote in votes.iter().take(3).rev() {
            let output = engine
                .on_event(
                    &aggregator,
                    ConsensusEvent::Vote(vote.clone()),
                    &cryptos[0],
                    &cryptos[0],
                )
                .unwrap();
            aggregator = output.state;
            certificate = output
                .outbound_messages
                .into_iter()
                .find_map(|message| match message {
                    ConsensusMessage::Certificate(qc) => Some(qc),
                    _ => None,
                })
                .or(certificate);
        }
        let certificate = certificate.expect("three of four votes must certify");
        for (index, crypto) in cryptos.iter().enumerate() {
            let output = engine
                .on_event(
                    &states[index],
                    ConsensusEvent::Certificate(certificate.clone()),
                    crypto,
                    crypto,
                )
                .unwrap();
            states[index] = output.state;
            if index == 0 {
                captured.extend(
                    output
                        .committed_blocks
                        .into_iter()
                        .zip(output.committed_proofs),
                );
            }
        }
    }
    captured
}

#[test]
fn three_chain_proof_verifies_the_exact_committed_block() {
    let (engine, cryptos) = setup();
    let mut states = vec![engine.genesis_state(0); 4];
    let committed = drive_heights(&engine, &cryptos, &mut states, 3);
    let (expected, proof) = committed
        .into_iter()
        .find(|(block, _)| block.height == 1)
        .expect("height 1 must commit after a three-chain");

    assert_eq!(proof.committed.height, 1);
    assert_eq!(proof.child.height, 2);
    assert_eq!(proof.grandchild.height, 3);
    assert_eq!(proof.grandchild_certificate.height, 3);
    engine
        .verify_committed_block_proof(&expected, &proof, &cryptos[0])
        .unwrap();
}

#[test]
fn committed_block_proof_survives_state_pruning() {
    let (engine, cryptos) = setup();
    let mut states = vec![engine.genesis_state(0); 4];
    // Six rounds commits heights 1-4, well past `RETAIN_COMMITTED_HEIGHTS`
    // (2), so height 1's own proposal/certificate are pruned from live
    // state by the time this returns.
    let committed = drive_heights(&engine, &cryptos, &mut states, 6);
    let (expected, proof) = committed
        .into_iter()
        .find(|(block, _)| block.height == 1)
        .expect("height 1 must commit");

    assert!(
        states[0].known_proposal(&expected.digest).is_none(),
        "height 1's proposal must already be pruned from live state"
    );
    // The proof is self-contained and carries every proposal/certificate it
    // needs inline, so it verifies independently of any validator's live,
    // pruned state.
    engine
        .verify_committed_block_proof(&expected, &proof, &cryptos[0])
        .unwrap();
}

#[test]
fn committed_block_proof_round_trips_through_canonical_codec() {
    let (engine, cryptos) = setup();
    let mut states = vec![engine.genesis_state(0); 4];
    let committed = drive_heights(&engine, &cryptos, &mut states, 3);
    let (expected, proof) = committed
        .into_iter()
        .find(|(block, _)| block.height == 1)
        .unwrap();

    let bytes = encode_committed_block_proof(&proof).unwrap();
    let hash: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    assert_eq!(bytes.len(), 3_808);
    assert_eq!(
        hash,
        [
            113, 59, 87, 192, 29, 64, 31, 37, 68, 38, 223, 234, 125, 143, 121, 75, 69, 201, 14, 64,
            196, 230, 250, 1, 225, 194, 115, 89, 100, 78, 182, 181,
        ]
    );
    let decoded = decode_committed_block_proof(&bytes).unwrap();
    assert_eq!(decoded, proof);
    assert_eq!(encode_committed_block_proof(&decoded).unwrap(), bytes);
    engine
        .verify_committed_block_proof(&expected, &decoded, &cryptos[0])
        .unwrap();
}

#[test]
fn truncated_proof_bytes_are_rejected_before_parsing() {
    let (engine, cryptos) = setup();
    let mut states = vec![engine.genesis_state(0); 4];
    let committed = drive_heights(&engine, &cryptos, &mut states, 3);
    let (_, proof) = committed
        .into_iter()
        .find(|(block, _)| block.height == 1)
        .unwrap();

    let bytes = encode_committed_block_proof(&proof).unwrap();
    let truncated = &bytes[..bytes.len() - 1];
    assert!(decode_committed_block_proof(truncated).is_err());
}

#[test]
fn tampered_committed_signature_is_rejected() {
    let (engine, cryptos) = setup();
    let mut states = vec![engine.genesis_state(0); 4];
    let committed = drive_heights(&engine, &cryptos, &mut states, 3);
    let (expected, mut proof) = committed
        .into_iter()
        .find(|(block, _)| block.height == 1)
        .unwrap();

    let last = proof.committed.signature.len() - 1;
    proof.committed.signature[last] ^= 0xFF;
    let error = engine
        .verify_committed_block_proof(&expected, &proof, &cryptos[0])
        .unwrap_err();
    assert!(matches!(error, ConsensusError::InvalidSignature(_)));
}

#[test]
fn splicing_an_unrelated_but_individually_valid_grandchild_is_rejected() {
    let (engine, cryptos) = setup();
    let mut states = vec![engine.genesis_state(0); 4];
    // Six rounds produces two independent, individually valid three-chain
    // commits: height 1 (grandchild = height 3) and height 4
    // (grandchild = height 6).
    let committed = drive_heights(&engine, &cryptos, &mut states, 6);
    let (expected_one, proof_one) = committed
        .iter()
        .find(|(block, _)| block.height == 1)
        .cloned()
        .expect("height 1 must commit");
    let (_, proof_four) = committed
        .into_iter()
        .find(|(block, _)| block.height == 4)
        .expect("height 4 must commit");

    // `proof_four.grandchild`/`grandchild_certificate` are a real proposal
    // and a real, independently verifiable quorum certificate -- just for
    // an unrelated block, not for `proof_one.child`'s successor. A verifier
    // that trusted `grandchild_certificate`'s own validity alone, without
    // checking it actually certifies `grandchild`, and that `grandchild`
    // actually extends `child`, would wrongly accept this.
    let mut spliced = proof_one.clone();
    spliced.grandchild = proof_four.grandchild;
    spliced.grandchild_certificate = proof_four.grandchild_certificate;

    engine
        .verify_certificate(&spliced.grandchild_certificate, &cryptos[0])
        .expect("the spliced certificate is individually well-formed");
    let error = engine
        .verify_committed_block_proof(&expected_one, &spliced, &cryptos[0])
        .unwrap_err();
    assert!(matches!(
        error,
        ConsensusError::CommittedBlockProofChainMismatch(_)
    ));
}

#[test]
fn observer_event_produces_the_same_committed_proof_as_on_event() {
    let (engine, cryptos) = setup();
    let mut states = vec![engine.genesis_state(0); 4];
    let committed = drive_heights(&engine, &cryptos, &mut states, 3);
    let (expected, proof) = committed
        .into_iter()
        .find(|(block, _)| block.height == 1)
        .unwrap();

    // Replay the exact same authenticated history (already-signed
    // proposals and the final certificate) through the untrusted-observer
    // path from a fresh genesis state, with no local voting or signing.
    let observer_state = engine.genesis_state(0);
    let output = engine
        .on_observer_event(
            &observer_state,
            ConsensusEvent::Proposal(proof.committed.clone()),
            &cryptos[0],
        )
        .unwrap();
    let output = engine
        .on_observer_event(
            &output.state,
            ConsensusEvent::Proposal(proof.child.clone()),
            &cryptos[0],
        )
        .unwrap();
    let output = engine
        .on_observer_event(
            &output.state,
            ConsensusEvent::Proposal(proof.grandchild.clone()),
            &cryptos[0],
        )
        .unwrap();
    let output = engine
        .on_observer_event(
            &output.state,
            ConsensusEvent::Certificate(proof.grandchild_certificate.clone()),
            &cryptos[0],
        )
        .unwrap();

    let (observed_block, observed_proof) = output
        .committed_blocks
        .into_iter()
        .zip(output.committed_proofs)
        .find(|(block, _)| block.height == 1)
        .expect("the observer path must also commit height 1 with a proof");
    assert_eq!(observed_block, expected);
    assert_eq!(observed_proof, proof);
    engine
        .verify_committed_block_proof(&expected, &observed_proof, &cryptos[0])
        .unwrap();
}

#[test]
fn one_delayed_certificate_builds_distinct_proofs_for_every_batched_height() {
    let (engine, cryptos) = setup();
    let mut source_states: Vec<ConsensusState> = vec![engine.genesis_state(0); 4];
    let source: Vec<(CommittedBlock, CommittedBlockProof)> =
        drive_heights(&engine, &cryptos, &mut source_states, 6);
    let mut delayed: ConsensusState = engine.genesis_state(0);
    for (_, proof) in &source {
        for proposal in [&proof.committed, &proof.child, &proof.grandchild] {
            let digest = engine.proposal_digest(proposal).unwrap();
            delayed.known_proposals.insert(digest, proposal.clone());
        }
    }
    // The source proposals and votes are all real signed network material,
    // but this observer has learned their bodies before the terminal QC. It
    // can therefore discover several committed heights in one transition.
    let terminal: QuorumCertificate = source
        .iter()
        .find(|(block, _)| block.height == 4)
        .unwrap()
        .1
        .grandchild_certificate
        .clone();
    let output = engine
        .on_observer_event(&delayed, ConsensusEvent::Certificate(terminal), &cryptos[0])
        .unwrap();
    assert_eq!(output.committed_blocks.len(), 4);
    assert_eq!(output.committed_proofs.len(), 4);
    for (index, (block, proof)) in output
        .committed_blocks
        .iter()
        .zip(output.committed_proofs.iter())
        .enumerate()
    {
        assert_eq!(block.height, index as u64 + 1);
        assert_eq!(proof.committed.height, block.height);
        assert_eq!(proof.grandchild.height, block.height + 2);
        assert_eq!(proof.grandchild_certificate.height, block.height + 2);
        engine
            .verify_committed_block_proof(block, proof, &cryptos[0])
            .unwrap();
    }
}
