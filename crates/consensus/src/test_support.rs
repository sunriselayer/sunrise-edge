//! Shared, `cfg(test)`-only fixtures used by both `lib.rs`'s and
//! `durable`'s test modules. Not part of any public API.

use crate::{
    ChainedHotStuff, CommittedBlock, ConsensusEngine, ConsensusEvent, ConsensusMessage,
    ConsensusParameters, ConsensusProposal, ConsensusSigner, ConsensusState, ConsensusVerifier,
    ConsensusVote, QuorumCertificate,
};
use hashing::HashSuiteResolver;
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
    SignatureSchemeId, ValidatorId,
};
use sha2::{Digest as _, Sha256};
use validator_set::{ValidatorInfo, ValidatorSet};

#[derive(Clone)]
pub(crate) struct TestCrypto {
    pub(crate) validator: ValidatorId,
}

impl TestCrypto {
    fn signature(validator: ValidatorId, framed: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(validator.as_bytes());
        hasher.update(framed);
        hasher.finalize().to_vec()
    }
}

impl ConsensusSigner for TestCrypto {
    fn validator_id(&self) -> ValidatorId {
        self.validator
    }

    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }

    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        Ok(Self::signature(self.validator, framed))
    }
}

impl ConsensusVerifier for TestCrypto {
    fn verify_framed(
        &self,
        validator: ValidatorId,
        _scheme: SignatureSchemeId,
        public_key: &[u8],
        framed: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        Ok(public_key == validator.as_bytes() && signature == Self::signature(validator, framed))
    }
}

pub(crate) fn validator(byte: u8) -> ValidatorInfo {
    ValidatorInfo {
        id: ValidatorId::new([byte; 32]),
        voting_power: 1,
        signature_scheme: SignatureSchemeId::Ed25519,
        public_key: vec![byte; 32],
    }
}

pub(crate) fn setup() -> (ChainedHotStuff, Vec<TestCrypto>) {
    let chain = ChainId::new("sunrise-consensus-test").unwrap();
    let version = ProtocolVersion::new(1);
    let epoch = Epoch::new(8);
    let validators = (1..=4).map(validator).collect::<Vec<_>>();
    let set = ValidatorSet::new(epoch, validators).unwrap();
    let resolver = HashSuiteResolver::new(
        chain.clone(),
        version,
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let engine = ChainedHotStuff::new(
        chain,
        version,
        epoch,
        set,
        ConsensusParameters::genesis(),
        resolver,
        Digest32::new(HashAlgorithmId::Sha2_256, [0; 32]),
    )
    .unwrap();
    let cryptos = (1..=4)
        .map(|byte| TestCrypto {
            validator: ValidatorId::new([byte; 32]),
        })
        .collect();
    (engine, cryptos)
}

pub(crate) fn proposal_votes(
    engine: &ChainedHotStuff,
    states: &mut [ConsensusState],
    cryptos: &[TestCrypto],
    transaction_byte: u8,
) -> (ConsensusProposal, Vec<ConsensusVote>) {
    let view = states[0].current_view;
    let leader = engine.validator_set().leader(view).unwrap();
    let leader_index = cryptos
        .iter()
        .position(|crypto| crypto.validator == leader)
        .unwrap();
    let proposal = engine
        .propose(
            &states[leader_index],
            vec![Digest32::new(
                HashAlgorithmId::Sha2_256,
                [transaction_byte; 32],
            )],
            &cryptos[leader_index],
        )
        .unwrap();
    let mut votes = Vec::new();
    for (index, crypto) in cryptos.iter().enumerate() {
        let output = engine
            .on_event(
                &states[index],
                ConsensusEvent::Proposal(proposal.clone()),
                crypto,
                crypto,
            )
            .unwrap();
        states[index] = output.state;
        let ConsensusMessage::Vote(vote) = output.outbound_messages[0].clone() else {
            panic!("proposal must emit a vote")
        };
        votes.push(vote);
    }
    (proposal, votes)
}

pub(crate) fn certify(
    engine: &ChainedHotStuff,
    states: &mut [ConsensusState],
    cryptos: &[TestCrypto],
    votes: &[ConsensusVote],
) -> (QuorumCertificate, Vec<CommittedBlock>) {
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
            .find_map(|message| {
                if let ConsensusMessage::Certificate(qc) = message {
                    Some(qc)
                } else {
                    None
                }
            })
            .or(certificate);
    }
    let certificate = certificate.expect("three of four votes must certify");
    let mut committed = Vec::new();
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
        committed.extend(output.committed_blocks);
    }
    (certificate, committed)
}
