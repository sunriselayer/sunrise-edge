//! Authenticated terminal-only shape controls. These call the actual private
//! terminal with genuine proposals/votes/QCs and pure-authenticated canonical
//! Seal bytes, but do not establish a complete business cut or readiness
//! warrant. Full closure coverage is separate. A scheduled Seal child is mod1,
//! so its consecutive prior/grandchild are mod0/mod2 and necessarily EMPTY.
//! Scheduled nonempty prior/grandchild controls therefore cannot also supply a
//! scheduled accepted Seal child; these are owning terminal-guard controls,
//! never otherwise-valid whole-closure negatives.
use super::*;
use crate::genesis::tests as fixture;
use crate::ordered_economics::{
    SEAL_PREDECESSOR_TAG_GENESIS, SealIntent, encode_seal_intent, seal_request_id,
    seal_target_digest,
};
use consensus::readiness::{ReadinessSubject, readiness_schedule_digest};
use consensus::{
    ConsensusEngine, ConsensusEvent, ConsensusMessage, ConsensusOutput, ConsensusSigner,
    ConsensusState,
};
use ed25519_zebra::SigningKey;
use protocol_types::{Epoch, HashAlgorithmId, SignatureSchemeId, ValidatorId};

struct Signer(SigningKey);

impl ConsensusSigner for Signer {
    fn validator_id(&self) -> ValidatorId {
        ValidatorId::new(fixture::sender())
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.0.sign(frame).into();
        Ok(signature.to_vec())
    }
}

fn policy() -> OrderedEconomicsPolicy {
    let (mut manifest, _, _, _, _) = fixture::build_fixture();
    manifest.commitment_profile = crate::logical_generation::CommitmentProfile::CausalAdmission;
    manifest.minimum_freeze_block_height = 1;
    fixture::resign_manifest(&mut manifest);
    let resolver: HashSuiteResolver = fixture::resolver();
    let digest: Digest32 =
        crate::genesis::genesis_manifest_commitment(&resolver, &manifest).unwrap();
    let root: crate::genesis::VerifiedGenesisRoot =
        crate::genesis::VerifiedGenesisRoot::verify_bytes(
            &resolver,
            &crate::genesis::encode_genesis_manifest(&manifest).unwrap(),
            digest.bytes(),
            manifest.context(),
        )
        .unwrap();
    OrderedEconomicsPolicy::from_genesis_root(&root, fixture::domain()).unwrap()
}

fn canonical_root(collection: BusinessCutCollection, seed: u8) -> BusinessCutCollectionRoot {
    BusinessCutCollectionRoot {
        collection,
        count: 0,
        root: Digest32::new(HashAlgorithmId::Blake3_256, [seed; 32]),
    }
}

/// Canonical-only untrusted identity: codecs and pure policy authentication
/// are real, but the fixed roots/anchor/certificate digest are not a derived
/// business cut or a staged readiness warrant. The private shape guard reads
/// neither of those capabilities. No production or test-proof export exists.
fn canonical_only_seal_candidate(policy: &OrderedEconomicsPolicy) -> OrderedCandidate {
    let resolver: &HashSuiteResolver = policy.resolver();
    let cut: BusinessCutIdentity = BusinessCutIdentity {
        context: policy.context().clone(),
        domain: policy.domain(),
        genesis_digest: policy.genesis_digest(),
        validator_set_digest: policy.engine().validator_set().digest(resolver).unwrap(),
        ordered_history: OrderedHistoryIdentity {
            context: policy.context().clone(),
            domain: policy.domain(),
            genesis_digest: policy.genesis_digest(),
            anchor: policy.anchor(),
            through_height: 7,
            through_view: 7,
            through_digest: Digest32::new(HashAlgorithmId::Blake3_256, [4; 32]),
        },
        drain_request_id: [0x85; 32],
        drain_block_height: 5,
        drain_candidate_digest: Digest32::new(HashAlgorithmId::Blake3_256, [6; 32]),
        drain_union: consensus::DrainUnionIdentity {
            chain_id: policy.context().chain_id().clone(),
            protocol_version: policy.context().protocol_version(),
            epoch: policy.context().epoch(),
            domain: policy.domain(),
            closure_request_id: [7; 32],
            closure_height: 3,
            signer_count: 1,
            member_count: 1,
            entries_digest: Digest32::new(HashAlgorithmId::Blake3_256, [8; 32]),
        },
        generation_floor: ExecutionGeneration::new(1),
        business: [
            canonical_root(BusinessCutCollection::State, 9),
            canonical_root(BusinessCutCollection::Receipts, 10),
            canonical_root(BusinessCutCollection::ObjectHeads, 11),
            canonical_root(BusinessCutCollection::ObjectVersions, 12),
        ],
        artifacts: canonical_root(BusinessCutCollection::Artifacts, 13),
    };
    let subject: ReadinessSubject = ReadinessSubject {
        chain_id: policy.context().chain_id().clone(),
        protocol_version: policy.context().protocol_version(),
        epoch: policy.context().epoch(),
        genesis_digest: policy.genesis_digest(),
        domain: policy.domain(),
        outgoing_set_digest: policy.engine().validator_set().digest(resolver).unwrap(),
        cut_digest: business_cut_identity_digest(resolver, &cut).unwrap(),
        next_epoch: Epoch::new(policy.context().epoch().get().checked_add(1).unwrap()),
        next_set_digest: policy.engine().validator_set().digest(resolver).unwrap(),
        schedule_digest: readiness_schedule_digest(resolver, policy.context().epoch()).unwrap(),
    };
    let target: Digest32 = seal_target_digest(
        resolver,
        policy.context(),
        subject.identity(resolver).unwrap(),
        SEAL_PREDECESSOR_TAG_GENESIS,
        policy.genesis_digest(),
    )
    .unwrap();
    let certificate_digest: Digest32 = Digest32::new(HashAlgorithmId::Blake3_256, [30; 32]);
    let request_id: [u8; 32] =
        seal_request_id(resolver, policy.context(), target, certificate_digest).unwrap();
    let intent: SealIntent = SealIntent {
        readiness_subject: subject,
        cut_identity_bytes: encode_business_cut_identity(&cut).unwrap(),
        predecessor_tag: SEAL_PREDECESSOR_TAG_GENESIS,
        predecessor_digest: policy.genesis_digest(),
        certificate_digest,
        certificate_length: 64,
    };
    let candidate: OrderedCandidate = OrderedCandidate {
        context: policy.context().clone(),
        request_id,
        kind: OrderedOperationKind::Seal,
        intent: encode_seal_intent(&intent).unwrap(),
        created_checkpoint: cut.ordered_history.through_height,
    };
    policy.authenticate_candidate(&candidate).unwrap();
    candidate
}

fn terminal_material(
    policy: &OrderedEconomicsPolicy,
    nonempty_height: u64,
    terminal_height: u64,
) -> OrderedHistoryHeightMaterial {
    let signer: Signer = Signer(fixture::key());
    let mut state: ConsensusState = policy.engine().genesis_state(0);
    let mut selected: Option<consensus::CommittedBlockProof> = None;
    for height in 1..=terminal_height.checked_add(2).unwrap() {
        let transactions: Vec<Digest32> = if height == nonempty_height {
            assert_eq!(
                height % 3,
                1,
                "nonempty controls obey the real scheduling profile"
            );
            vec![
                policy
                    .resolver()
                    .hash_for_purpose(
                        policy.context().epoch(),
                        protocol_types::HashPurpose::NodeEvent,
                        b"authenticated-terminal-control",
                    )
                    .unwrap(),
            ]
        } else {
            Vec::new()
        };
        let proposal: consensus::ConsensusProposal = policy
            .engine()
            .propose(&state, transactions, &signer)
            .unwrap();
        assert_eq!(proposal.height, height);
        let voted: ConsensusOutput = policy
            .engine()
            .on_event(
                &state,
                ConsensusEvent::Proposal(proposal),
                &signer,
                &ReconstructionEd25519Verifier,
            )
            .unwrap();
        let vote: consensus::ConsensusVote = voted
            .outbound_messages
            .iter()
            .find_map(|message| match message {
                ConsensusMessage::Vote(vote) => Some(vote.clone()),
                _ => None,
            })
            .unwrap();
        let certified: ConsensusOutput = policy
            .engine()
            .on_event(
                &voted.state,
                ConsensusEvent::Vote(vote),
                &signer,
                &ReconstructionEd25519Verifier,
            )
            .unwrap();
        policy
            .engine()
            .validate_state(&certified.state, &ReconstructionEd25519Verifier)
            .unwrap();
        for proof in &certified.committed_proofs {
            if proof.committed.height == terminal_height {
                selected = Some(proof.clone());
            }
        }
        state = certified.state;
    }
    let proof: consensus::CommittedBlockProof = selected.unwrap();
    let block: consensus::CommittedBlock = verified_committed_block(policy, &proof).unwrap();
    let bytes: Vec<u8> = consensus::encode_committed_block_proof(&proof).unwrap();
    let identity: OrderedHistoryIdentity = OrderedHistoryIdentity {
        context: policy.context().clone(),
        domain: policy.domain(),
        genesis_digest: policy.genesis_digest(),
        anchor: policy.anchor(),
        through_height: block.height,
        through_view: block.view,
        through_digest: block.digest,
    };
    OrderedHistoryHeightMaterial {
        descriptor: crate::ordered_economics::OrderedHistoryHeightDescriptor {
            identity,
            height: block.height,
            view: block.view,
            block_digest: block.digest,
            components: vec![crate::ordered_economics::OrderedHistoryComponentRef {
                kind: OrderedHistoryComponentKind::CommitProof,
                length: u64::try_from(bytes.len()).unwrap(),
                digest:
                    crate::ordered_economics::ordered_history::ordered_history_component_digest(
                        policy, &bytes,
                    )
                    .unwrap(),
            }],
        },
        components: vec![(OrderedHistoryComponentKind::CommitProof, bytes)],
    }
}

fn assert_nonempty_terminal(nonempty_height: u64, terminal_height: u64) {
    let policy: OrderedEconomicsPolicy = policy();
    let material: OrderedHistoryHeightMaterial =
        terminal_material(&policy, nonempty_height, terminal_height);
    let candidate: OrderedCandidate = canonical_only_seal_candidate(&policy);
    let digest: Digest32 = policy.candidate_digest(&candidate).unwrap();
    let proof: consensus::CommittedBlockProof =
        consensus::decode_committed_block_proof(&material.components[0].1).unwrap();
    let block_digest: Digest32 = policy.engine().proposal_digest(&proof.child).unwrap();
    let result = seal_terminal(
        std::slice::from_ref(&material),
        &material.descriptor.identity,
        &policy,
        &candidate,
        digest,
        block_digest,
    );
    assert!(
        matches!(
            result,
            Err(BusinessCutError::Invalid(
                "cut seal acceptance three-chain is not prior/empty/empty"
            ))
        ),
        "unexpected terminal result: {result:?}"
    );
}

#[test]
fn authenticated_terminal_rejects_a_nonempty_grandchild() {
    assert_nonempty_terminal(10, 8);
}

#[test]
fn authenticated_terminal_rejects_a_nonempty_prior_committed_block() {
    assert_nonempty_terminal(7, 7);
}

#[test]
fn authenticated_terminal_rejects_a_fixed_target_that_is_not_the_last_height() {
    let policy: OrderedEconomicsPolicy = policy();
    let material: OrderedHistoryHeightMaterial = terminal_material(&policy, 0, 9);
    let mut wrong: OrderedHistoryIdentity = material.descriptor.identity.clone();
    wrong.through_height = wrong.through_height.checked_sub(1).unwrap();
    let candidate: OrderedCandidate = canonical_only_seal_candidate(&policy);
    let digest: Digest32 = policy.candidate_digest(&candidate).unwrap();
    let result = seal_terminal(
        std::slice::from_ref(&material),
        &wrong,
        &policy,
        &candidate,
        digest,
        material.descriptor.block_digest,
    );
    assert!(
        matches!(
            result,
            Err(BusinessCutError::Invalid(
                "cut terminal proof is not the fixed target"
            ))
        ),
        "unexpected terminal result: {result:?}"
    );
}
