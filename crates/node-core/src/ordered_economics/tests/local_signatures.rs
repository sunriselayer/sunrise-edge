//! DR-0215 checks at the actual ordered owners, not custody qualification.
//! All keys are deterministic test keys in the genuine installed committee.
use super::*;
use consensus::{
    ConsensusEngine, ConsensusEvent, ConsensusOutput, ConsensusProposal, ConsensusState,
};
use runtime::outbox_guard::{StructuredOutboxExclusionGuard, StructuredOutboxInventory};
use runtime::{DurableStateKeyScanner, StateKeyScan};
use std::cell::{Cell, RefCell};

const DIAGNOSTIC_MARKER: &str = "ordered-test-provider-diagnostic-must-not-escape";

#[derive(Clone, Copy, Debug)]
enum SigningResult {
    Valid,
    WrongKey,
    WrongFrame,
    Bytes(usize),
    Error,
}

/// Metadata can drift independently of signing; ConsensusSigner promises no
/// stable getter. `initial_reads` counts only validator getter calls, not keys.
struct ScriptedSigner<'a> {
    initial: ValidatorId,
    initial_reads: usize,
    signing: &'a TestSigner,
    scheme: SignatureSchemeId,
    initial_scheme_reads: usize,
    result: SigningResult,
    reads: Cell<usize>,
    scheme_reads: Cell<usize>,
    frames: RefCell<Vec<Vec<u8>>>,
}

impl<'a> ScriptedSigner<'a> {
    fn stable(signing: &'a TestSigner, result: SigningResult) -> Self {
        Self {
            initial: signing.id,
            initial_reads: usize::MAX,
            signing,
            scheme: SignatureSchemeId::Ed25519,
            initial_scheme_reads: 0,
            result,
            reads: Cell::new(0),
            scheme_reads: Cell::new(0),
            frames: RefCell::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.frames.borrow().len()
    }
}

impl ConsensusSigner for ScriptedSigner<'_> {
    fn validator_id(&self) -> ValidatorId {
        let read: usize = self.reads.get();
        self.reads.set(read.checked_add(1).unwrap());
        if read < self.initial_reads {
            self.initial
        } else {
            self.signing.id
        }
    }

    fn signature_scheme(&self) -> SignatureSchemeId {
        let read: usize = self.scheme_reads.get();
        self.scheme_reads.set(read.checked_add(1).unwrap());
        if read < self.initial_scheme_reads {
            SignatureSchemeId::Ed25519
        } else {
            self.scheme
        }
    }

    fn sign_framed(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        self.frames.borrow_mut().push(frame.to_vec());
        match self.result {
            SigningResult::Valid => self.signing.sign_framed(frame),
            SigningResult::WrongKey => {
                let wrong: SigningKey = SigningKey::from([0x5a; 32]);
                let signature: [u8; 64] = wrong.sign(frame).into();
                Ok(signature.to_vec())
            }
            SigningResult::WrongFrame => {
                let mut different: Vec<u8> = frame.to_vec();
                different[0] ^= 1;
                self.signing.sign_framed(&different)
            }
            SigningResult::Bytes(length) => Ok(vec![0; length]),
            SigningResult::Error => Err(DIAGNOSTIC_MARKER.to_owned()),
        }
    }
}

fn verifier() -> consensus::Ed25519ConsensusVerifier {
    consensus::Ed25519ConsensusVerifier::new(
        consensus::UnsupportedSignatureSchemeResponse::InvalidSignature,
    )
}

fn state(network: &Network, replica: usize) -> ConsensusState {
    consensus::decode_consensus_state(
        &network
            .value(
                replica,
                &engine::ordered_state_key_for_tests(&fixture::chain()),
            )
            .unwrap(),
    )
    .unwrap()
}

fn vote(output: &OrderedEventOutput) -> ConsensusVote {
    output
        .messages
        .iter()
        .find_map(|message| match message {
            ConsensusMessage::Vote(vote) => Some(vote.clone()),
            _ => None,
        })
        .expect("genuine successful voting output")
}

fn engine_vote(output: &ConsensusOutput) -> ConsensusVote {
    output
        .outbound_messages
        .iter()
        .find_map(|message| match message {
            ConsensusMessage::Vote(vote) => Some(vote.clone()),
            _ => None,
        })
        .expect("independent real engine vote")
}

fn assert_opaque(error: &OrderedEconomicsError) {
    assert!(matches!(error, OrderedEconomicsError::Prerequisite(_)));
    assert!(!error.to_string().contains(DIAGNOSTIC_MARKER));
    assert!(!format!("{error:?}").contains(DIAGNOSTIC_MARKER));
    assert!(std::error::Error::source(error).is_none());
}

/// Genuine genesis/profile installation, sharing the parent's committee and
/// business fixture builders. No patched policy, state or privileged asset.
fn causal_network() -> Network {
    let signers: Vec<TestSigner> = signers();
    let mut manifest: GenesisManifest = four_validator_manifest(&signers);
    manifest.commitment_profile = crate::logical_generation::CommitmentProfile::CausalAdmission;
    manifest.minimum_freeze_block_height = 1;
    fixture::resign_manifest(&mut manifest);
    let context: DurableOperationContext = fixture::context(1);
    let mut stores: Vec<MemoryDurableStateStore> = Vec::with_capacity(REPLICAS);
    for _ in 0..REPLICAS {
        let store: MemoryDurableStateStore = MemoryDurableStateStore::new_bound(
            fixture::domain(),
            WriterFenceGeneration::new(1).unwrap(),
        );
        genesis::install_genesis(
            &store,
            &context,
            fixture::domain(),
            &fixture::resolver(),
            &manifest,
            10,
        )
        .unwrap();
        stores.push(store);
    }
    let bond_key: Vec<u8> = fastpath_bond_record_key(&fixture::chain(), &signers[0].id).unwrap();
    let bond: FastPathBondRecord = decode_fastpath_bond_record(
        stores[0]
            .get_versioned_durable(&context, fixture::domain(), &bond_key)
            .unwrap()
            .value()
            .unwrap(),
    )
    .unwrap();
    let digest: Digest32 =
        genesis::genesis_manifest_commitment(&fixture::resolver(), &manifest).unwrap();
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &fixture::resolver(),
        &encode_genesis_manifest(&manifest).unwrap(),
        digest.bytes(),
        manifest.context(),
    )
    .unwrap();
    let policy: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&root, fixture::domain()).unwrap();
    let network: Network = Network {
        stores,
        context,
        root,
        policy,
        leg_policy: LocalExecutionPolicy::generic_object_results(fixture::protocol()),
        engine: LocalWasmExecutionEngine::new(),
        blobs: MemoryBlobStore::default(),
        resolver: fixture::resolver(),
        history: Vec::new(),
        signers,
        bond,
    };
    network.install_ordered();
    network
}

fn installed_network(causal: bool) -> Network {
    if causal {
        causal_network()
    } else {
        let network: Network = setup();
        network.install_ordered();
        network
    }
}

fn unbond(network: &Network, request: [u8; 32], checkpoint: u64) -> OrderedCandidate {
    let recipient: Address = address_of(0x58);
    let next: FastPathBondRecord =
        predicted_unbond(&network.bond, checkpoint, *recipient.as_bytes());
    unbond_candidate(
        network,
        &network.bond,
        &next,
        request,
        recipient,
        checkpoint,
    )
}

type Rows = Vec<(Vec<u8>, StateRevision, Option<Vec<u8>>)>;

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    rows: Rows,
    receipts: Vec<([u8; 32], Option<DurableRequestReceipt>)>,
    outbox: StructuredOutboxInventory,
    legacy_outbox_present: bool,
}

/// The complete relevant before/after observations, not a handler-result
/// oracle. Includes candidate/reservation/outcome, typed original/admission
/// receipts, nonce/lock rows and both outbox representations.
fn observe(
    network: &Network,
    replica: usize,
    candidates: &[&OrderedCandidate],
    views: u64,
) -> Observation {
    let chain: ChainId = fixture::chain();
    let layout: PersistenceLayout =
        PersistenceLayout::new(chain.clone(), fixture::protocol().protocol_version());
    let requests: Vec<[u8; 32]> = candidates
        .iter()
        .map(|candidate| candidate.request_id)
        .collect();
    let mut rows: Rows = network.snapshot(replica, &requests, views);
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut receipt_ids: Vec<[u8; 32]> = requests.clone();
    for height in 1..=views {
        keys.push(
            engine::ordered_committed_proof_key(&chain, fixture::protocol().epoch(), height)
                .unwrap(),
        );
    }
    for candidate in candidates {
        let digest: Digest32 = network.policy.candidate_digest(candidate).unwrap();
        keys.push(engine::ordered_candidate_record_key_for_tests(
            &chain, digest,
        ));
        keys.push(engine::ordered_outcome_key_for_tests(
            &chain,
            &candidate.request_id,
        ));
        keys.push(layout.request_dedup_key(candidate.request_id));
        keys.push(layout.outbox_batch_key(candidate.request_id));
        keys.push(layout.outbox_delivery_key(candidate.request_id));
        for view in 1..=views {
            for stage in [
                reservation::OrderedAdmissionStage::LeaderProposal,
                reservation::OrderedAdmissionStage::Vote,
            ] {
                receipt_ids.push(
                    reservation::ordered_admission_request_id(
                        &network.resolver,
                        fixture::protocol().epoch(),
                        &candidate.request_id,
                        digest,
                        stage,
                        view,
                    )
                    .unwrap(),
                );
            }
        }
    }
    for signer in &network.signers {
        keys.push(
            fastpath_nonce_lock_key(&chain, signer.id.as_bytes(), fixture::protocol().epoch())
                .unwrap(),
        );
        keys.push(layout.sender_nonce_key(*signer.id.as_bytes(), fixture::protocol().epoch()));
    }
    let coin: ObjectId = fixture::build_fixture().4;
    keys.push(local_instance_state::fastpath_lock_key(&chain, coin).unwrap());
    for key in keys {
        rows.push((
            key.clone(),
            network.revision(replica, &key),
            network.value(replica, &key),
        ));
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    rows.dedup_by(|left, right| left.0 == right.0);
    let receipts: Vec<([u8; 32], Option<DurableRequestReceipt>)> = receipt_ids
        .into_iter()
        .map(|request| {
            let receipt: Option<DurableRequestReceipt> = network.stores[replica]
                .get_request_receipt(
                    &network.context,
                    network.domain(),
                    DurableRequestId::new(request).unwrap(),
                )
                .unwrap();
            (request, receipt)
        })
        .collect();
    Observation {
        rows,
        receipts,
        outbox: network.stores[replica]
            .inspect_outbox_exclusion(&network.context, network.domain())
            .unwrap(),
        legacy_outbox_present: !network.stores[replica]
            .scan_durable_keys(
                &network.context,
                network.domain(),
                &StateKeyScan::new(layout.outbox_prefix(), None, std::num::NonZeroUsize::MIN)
                    .unwrap(),
            )
            .unwrap()
            .keys()
            .is_empty(),
    }
}

fn retain_vote(network: &Network, replica: usize, vote: &ConsensusVote) {
    let record: identity::LocalVoteRecord = identity::LocalVoteRecord {
        view: vote.view,
        proposal_digest: vote.proposal_digest,
        vote: consensus::encode_vote(vote).unwrap(),
    };
    network.put(
        replica,
        engine::ordered_vote_record_key_for_tests(&fixture::chain(), vote.view),
        StateMutation::Put(identity::encode_local_vote_record(&record).unwrap()),
    );
}

#[test]
fn fresh_votes_refuse_invalid_results_before_any_fresh_completion() {
    for causal in [false, true] {
        for result in [
            SigningResult::WrongKey,
            SigningResult::WrongFrame,
            SigningResult::Bytes(64),
            SigningResult::Bytes(63),
            SigningResult::Bytes(65),
            SigningResult::Bytes(0),
            SigningResult::Bytes(4097),
            SigningResult::Error,
        ] {
            let network: Network = installed_network(causal);
            let candidate: OrderedCandidate = if causal {
                unbond(&network, [0xb1; 32], 11)
            } else {
                withdraw_candidate(&network, [0xb1; 32], 0)
            };
            let leader: usize = network.leader_index(1);
            let replica: usize = (leader + 1) % REPLICAS;
            let proposal: OrderedProposal = propose(
                &network.stores[leader],
                &network.context,
                &network.env(),
                Some(&candidate),
                &network.signers[leader],
            )
            .unwrap();
            let before: Observation = observe(&network, replica, &[&candidate], 1);
            let initial: ConsensusState = state(&network, replica);
            // The independent engine still accepts nonempty <=4096 returned
            // bytes structurally. 63/65 are not an old exact-length refusal.
            let control: ScriptedSigner<'_> =
                ScriptedSigner::stable(&network.signers[replica], result);
            let structural: Result<ConsensusOutput, consensus::ConsensusError> =
                network.policy.engine().on_event(
                    &initial,
                    ConsensusEvent::Proposal(proposal.proposal.clone()),
                    &control,
                    &verifier(),
                );
            if matches!(
                result,
                SigningResult::Bytes(0) | SigningResult::Bytes(4097) | SigningResult::Error
            ) {
                assert!(structural.is_err());
            } else {
                let actual: ConsensusVote = engine_vote(&structural.unwrap());
                assert!(
                    network
                        .policy
                        .engine()
                        .verify_vote(&actual, &verifier())
                        .is_err()
                );
            }
            let signer: ScriptedSigner<'_> =
                ScriptedSigner::stable(&network.signers[replica], result);
            let error: OrderedEconomicsError = process_proposal(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &proposal,
                &signer,
            )
            .unwrap_err();
            assert_opaque(&error);
            assert_eq!(signer.calls(), 1, "{result:?}");
            assert_eq!(
                observe(&network, replica, &[&candidate], 1),
                before,
                "{result:?}"
            );
            assert_eq!(state(&network, replica), initial);
        }
    }
}

#[test]
fn noncausal_fresh_leaders_refuse_invalid_results_without_retention() {
    for result in [
        SigningResult::WrongKey,
        SigningResult::WrongFrame,
        SigningResult::Bytes(64),
        SigningResult::Bytes(63),
        SigningResult::Bytes(65),
        SigningResult::Bytes(0),
        SigningResult::Bytes(4097),
        SigningResult::Error,
    ] {
        let network: Network = setup();
        network.install_ordered();
        let candidate: OrderedCandidate = withdraw_candidate(&network, [0xb2; 32], 0);
        let leader: usize = network.leader_index(1);
        let before: Observation = observe(&network, leader, &[&candidate], 1);
        let control: ScriptedSigner<'_> = ScriptedSigner::stable(&network.signers[leader], result);
        let structural: Result<ConsensusProposal, consensus::ConsensusError> =
            network.policy.engine().propose(
                &state(&network, leader),
                vec![network.policy.candidate_digest(&candidate).unwrap()],
                &control,
            );
        if matches!(
            result,
            SigningResult::Bytes(0) | SigningResult::Bytes(4097) | SigningResult::Error
        ) {
            assert!(structural.is_err());
        } else {
            assert!(
                network
                    .policy
                    .engine()
                    .verify_proposal(&structural.unwrap(), &verifier())
                    .is_err()
            );
        }
        let signer: ScriptedSigner<'_> = ScriptedSigner::stable(&network.signers[leader], result);
        let error: OrderedEconomicsError = propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&candidate),
            &signer,
        )
        .unwrap_err();
        assert_opaque(&error);
        assert_eq!(signer.calls(), 1, "{result:?}");
        assert_eq!(
            observe(&network, leader, &[&candidate], 1),
            before,
            "{result:?}"
        );
    }
}

#[test]
fn valid_encoding_retention_replay_and_conflict_keep_existing_order() {
    let network: Network = setup();
    network.install_ordered();
    let candidate: OrderedCandidate = unbond(&network, [0xb3; 32], 11);
    let other: OrderedCandidate = unbond(&network, [0xb4; 32], 12);
    let leader: usize = network.leader_index(1);
    let signer: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[leader], SigningResult::Valid);
    let control: ConsensusProposal = network
        .policy
        .engine()
        .propose(
            &state(&network, leader),
            vec![network.policy.candidate_digest(&candidate).unwrap()],
            &network.signers[leader],
        )
        .unwrap();
    let proposal: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        Some(&candidate),
        &signer,
    )
    .unwrap();
    assert_eq!(
        consensus::encode_proposal(&proposal.proposal).unwrap(),
        consensus::encode_proposal(&control).unwrap()
    );
    assert_eq!(signer.calls(), 1);
    let retained: Observation = observe(&network, leader, &[&candidate, &other], 1);
    assert_eq!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&candidate),
            &signer
        )
        .unwrap(),
        proposal
    );
    assert_eq!(
        signer.calls(),
        2,
        "historical exact replay signs before reconciliation"
    );
    assert_eq!(
        observe(&network, leader, &[&candidate, &other], 1),
        retained
    );
    assert!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&other),
            &signer
        )
        .is_err()
    );
    assert_eq!(
        signer.calls(),
        3,
        "historical leader conflict also follows signing"
    );
    assert_eq!(
        observe(&network, leader, &[&candidate, &other], 1),
        retained
    );

    let replica: usize = (leader + 1) % REPLICAS;
    let initial: ConsensusState = state(&network, replica);
    let control_output: ConsensusOutput = network
        .policy
        .engine()
        .on_event(
            &initial,
            ConsensusEvent::Proposal(proposal.proposal.clone()),
            &network.signers[replica],
            &verifier(),
        )
        .unwrap();
    let voter: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[replica], SigningResult::Valid);
    let output: OrderedEventOutput = process_proposal(
        &network.stores[replica],
        &network.context,
        &network.env(),
        &proposal,
        &voter,
    )
    .unwrap();
    assert_eq!(
        consensus::encode_vote(&vote(&output)).unwrap(),
        consensus::encode_vote(&engine_vote(&control_output)).unwrap()
    );
    assert_eq!(state(&network, replica), control_output.state);
    let retained_vote: Observation = observe(&network, replica, &[&candidate, &other], 1);
    assert_eq!(
        process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &proposal,
            &voter
        )
        .unwrap(),
        output
    );
    assert_eq!(voter.calls(), 1, "retained voter replay adds no signature");
    assert_eq!(
        observe(&network, replica, &[&candidate, &other], 1),
        retained_vote
    );
    let conflicting: ConsensusProposal = network
        .policy
        .engine()
        .propose(
            &initial,
            vec![network.policy.candidate_digest(&other).unwrap()],
            &network.signers[leader],
        )
        .unwrap();
    let conflict: OrderedProposal = OrderedProposal {
        proposal: conflicting,
        candidate: Some(other.clone()),
    };
    assert!(
        process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &conflict,
            &voter
        )
        .is_err()
    );
    assert_eq!(voter.calls(), 1);
    assert_eq!(
        observe(&network, replica, &[&candidate, &other], 1),
        retained_vote
    );
}

#[test]
fn fresh_and_retained_votes_reject_a_committee_valid_different_local_identity() {
    let cases: [(bool, bool); 4] = [(false, false), (false, true), (true, false), (true, true)];
    for (causal, retained) in cases {
        let network: Network = installed_network(causal);
        let leader: usize = network.leader_index(1);
        let replica: usize = (leader + 1) % REPLICAS;
        let other: usize = (replica + 1) % REPLICAS;
        let proposal: OrderedProposal = propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            None,
            &network.signers[leader],
        )
        .unwrap();
        let independent: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[other], SigningResult::Valid);
        let control: ConsensusOutput = network
            .policy
            .engine()
            .on_event(
                &state(&network, replica),
                ConsensusEvent::Proposal(proposal.proposal.clone()),
                &independent,
                &verifier(),
            )
            .unwrap();
        let other_vote: ConsensusVote = engine_vote(&control);
        // This is a valid registered member, not a wrong-key crypto failure.
        network
            .policy
            .engine()
            .verify_vote(&other_vote, &verifier())
            .unwrap();
        assert_eq!(other_vote.validator, network.signers[other].id);
        if retained {
            retain_vote(&network, replica, &other_vote);
        }
        let before: Observation = observe(&network, replica, &[], 1);
        let mut drift: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[other], SigningResult::Valid);
        drift.initial = network.signers[replica].id;
        drift.initial_reads = 1;
        let error: OrderedEconomicsError = process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &proposal,
            &drift,
        )
        .unwrap_err();
        assert_opaque(&error);
        assert_eq!(
            error.to_string(),
            if retained {
                "retained ordered vote signer differs"
            } else {
                "produced ordered vote signer differs"
            }
        );
        assert_eq!(drift.calls(), usize::from(!retained));
        if !retained {
            assert_eq!(
                *drift.frames.borrow(),
                *independent.frames.borrow(),
                "the actual returned signature signs the committee-valid control's frame"
            );
        }
        assert_eq!(observe(&network, replica, &[], 1), before);
        // Stable declared identity independently returns that same valid vote.
        let stable: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[other], SigningResult::Valid);
        let positive: OrderedEventOutput = process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &proposal,
            &stable,
        )
        .unwrap();
        assert_eq!(vote(&positive), other_vote);
        assert_eq!(stable.calls(), usize::from(!retained));
    }
}

#[test]
fn noncausal_fresh_and_retained_proposals_bind_the_gate_identity() {
    for retained in [false, true] {
        let network: Network = setup();
        network.install_ordered();
        let leader: usize = network.leader_index(1);
        let other: usize = (leader + 1) % REPLICAS;
        let control: ConsensusProposal = network
            .policy
            .engine()
            .propose(
                &state(&network, leader),
                Vec::new(),
                &network.signers[leader],
            )
            .unwrap();
        network
            .policy
            .engine()
            .verify_proposal(&control, &verifier())
            .unwrap();
        if retained {
            let original: OrderedProposal = propose(
                &network.stores[leader],
                &network.context,
                &network.env(),
                None,
                &network.signers[leader],
            )
            .unwrap();
            assert_eq!(original.proposal, control);
        }
        let before: Observation = observe(&network, leader, &[], 1);
        let mut drift: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[leader], SigningResult::Valid);
        drift.initial = network.signers[other].id;
        drift.initial_reads = 1;
        let error: OrderedEconomicsError = propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            None,
            &drift,
        )
        .unwrap_err();
        assert_opaque(&error);
        // Both historical branches have already signed; retained reconciliation
        // now receives the captured identity, rather than the later declaration.
        assert_eq!(drift.calls(), 1);
        let expected_frame: Vec<u8> = crypto::frame_signature_message(
            &crypto::SignatureDomain {
                chain_id: control.chain_id.clone(),
                protocol_version: control.protocol_version,
                epoch: control.epoch,
                message_type: crypto::SignatureMessageType::new("shared-consensus-proposal-v1")
                    .unwrap(),
                signature_scheme_id: control.signature_scheme,
            },
            &consensus::encode_proposal_payload(&control).unwrap(),
        )
        .unwrap();
        assert_eq!(drift.frames.borrow().as_slice(), &[expected_frame]);
        assert_eq!(observe(&network, leader, &[], 1), before);
        let stable: OrderedProposal = propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            None,
            &network.signers[leader],
        )
        .unwrap();
        assert_eq!(stable.proposal, control);
    }
}

#[test]
fn noncausal_retained_signature_and_digest_are_verified_without_repair() {
    for wrong_digest in [false, true] {
        let network: Network = setup();
        network.install_ordered();
        let leader: usize = network.leader_index(1);
        let proposal: OrderedProposal = propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            None,
            &network.signers[leader],
        )
        .unwrap();
        let key: Vec<u8> = engine::ordered_leader_record_key_for_tests(&fixture::chain(), 1);
        let (mut record, mut corrupt): (identity::LeaderProposalRecord, ConsensusProposal) =
            identity::decode_leader_proposal_record(&network.value(leader, &key).unwrap()).unwrap();
        if wrong_digest {
            // An independently valid signature over different canonical content,
            // while the row's recorded digest still names the requested proposal.
            corrupt = network
                .policy
                .engine()
                .propose(
                    &state(&network, leader),
                    vec![Digest32::new(HashAlgorithmId::Sha2_256, [0xfa; 32])],
                    &network.signers[leader],
                )
                .unwrap();
            network
                .policy
                .engine()
                .verify_proposal(&corrupt, &verifier())
                .unwrap();
            assert_ne!(
                network.policy.engine().proposal_digest(&corrupt).unwrap(),
                record.proposal_digest
            );
        } else {
            corrupt.signature = vec![0; 64];
            assert!(
                network
                    .policy
                    .engine()
                    .verify_proposal(&corrupt, &verifier())
                    .is_err()
            );
        }
        record.proposal = consensus::encode_proposal(&corrupt).unwrap();
        network.put(
            leader,
            key,
            StateMutation::Put(identity::encode_leader_proposal_record(&record).unwrap()),
        );
        let before: Observation = observe(&network, leader, &[], 1);
        let signer: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[leader], SigningResult::Valid);
        let error: OrderedEconomicsError = propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            None,
            &signer,
        )
        .unwrap_err();
        assert_opaque(&error);
        assert_eq!(
            signer.calls(),
            1,
            "legacy replay retains sign-before-reconciliation order"
        );
        if wrong_digest {
            assert!(matches!(
                error,
                OrderedEconomicsError::Prerequisite("retained ordered proposal digest differs")
            ));
        }
        assert_eq!(observe(&network, leader, &[], 1), before);
        assert_eq!(
            record.proposal_digest,
            network
                .policy
                .engine()
                .proposal_digest(&proposal.proposal)
                .unwrap()
        );
    }
}

#[test]
fn causal_preview_and_retained_proposal_use_the_captured_identity_before_key_use() {
    for retained in [false, true] {
        let network: Network = causal_network();
        let leader: usize = network.leader_index(1);
        let other: usize = (leader + 1) % REPLICAS;
        let control: ConsensusProposal = network
            .policy
            .engine()
            .propose(
                &state(&network, leader),
                Vec::new(),
                &network.signers[leader],
            )
            .unwrap();
        network
            .policy
            .engine()
            .verify_proposal(&control, &verifier())
            .unwrap();
        if retained {
            assert_eq!(
                propose(
                    &network.stores[leader],
                    &network.context,
                    &network.env(),
                    None,
                    &network.signers[leader]
                )
                .unwrap()
                .proposal,
                control
            );
        }
        let before: Observation = observe(&network, leader, &[], 1);
        let mut drift: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[leader], SigningResult::Valid);
        drift.initial = network.signers[other].id;
        drift.initial_reads = 1;
        let error: OrderedEconomicsError = propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            None,
            &drift,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            OrderedEconomicsError::Prerequisite("ordered proposal capacity probe signer differs")
        ));
        assert_eq!(
            drift.calls(),
            0,
            "the probe does not invoke the real signing key"
        );
        assert_eq!(observe(&network, leader, &[], 1), before);
        let stable: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[leader], SigningResult::Valid);
        assert_eq!(
            propose(
                &network.stores[leader],
                &network.context,
                &network.env(),
                None,
                &stable
            )
            .unwrap()
            .proposal,
            control
        );
        assert_eq!(stable.calls(), usize::from(!retained));
    }
}

#[test]
fn causal_actual_proposal_correspondence_still_refuses_late_identity_and_length_drift() {
    let network: Network = causal_network();
    let leader: usize = network.leader_index(1);
    let other: usize = (leader + 1) % REPLICAS;
    let before: Observation = observe(&network, leader, &[], 1);
    // Existing engine proposer reads: gate, three preview getters, actual
    // leadership and scheme getters, then the actual proposal's leader field.
    // Drift only that last field; preserve the old leadership refusal order.
    let mut drift: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[other], SigningResult::Valid);
    drift.initial = network.signers[leader].id;
    drift.initial_reads = 6;
    let error: OrderedEconomicsError = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        None,
        &drift,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        OrderedEconomicsError::Prerequisite("ordered proposal differs from capacity probe")
    ));
    assert_eq!(drift.calls(), 1);
    assert_eq!(observe(&network, leader, &[], 1), before);
    for length in [63usize, 65] {
        let signer: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[leader], SigningResult::Bytes(length));
        let error: OrderedEconomicsError = propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            None,
            &signer,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            OrderedEconomicsError::Prerequisite("ordered proposal differs from capacity probe")
        ));
        assert_eq!(signer.calls(), 1);
        assert_eq!(observe(&network, leader, &[], 1), before);
    }
    // Existing causal crypto must still run once after exact-size parity.
    let invalid: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[leader], SigningResult::Bytes(64));
    let error: OrderedEconomicsError = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        None,
        &invalid,
    )
    .unwrap_err();
    assert_opaque(&error);
    assert_eq!(invalid.calls(), 1);
    assert_eq!(observe(&network, leader, &[], 1), before);
}

#[test]
fn declared_unknown_voter_and_scheme_mismatch_stop_before_signing() {
    let network: Network = setup();
    network.install_ordered();
    let leader: usize = network.leader_index(1);
    let replica: usize = (leader + 1) % REPLICAS;
    let proposal: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        None,
        &network.signers[leader],
    )
    .unwrap();
    let before: Observation = observe(&network, replica, &[], 1);
    for unknown in [false, true] {
        let mut signer: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[replica], SigningResult::Valid);
        if unknown {
            signer.initial = ValidatorId::new([0xf5; 32]);
        } else {
            signer.scheme = SignatureSchemeId::Secp256k1;
        }
        assert_opaque(
            &process_proposal(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &proposal,
                &signer,
            )
            .unwrap_err(),
        );
        assert_eq!(signer.calls(), 0);
        assert_eq!(observe(&network, replica, &[], 1), before);
    }
    let before_leader: Observation = observe(&network, leader, &[], 1);
    let mut signer: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[leader], SigningResult::Valid);
    signer.scheme = SignatureSchemeId::Secp256k1;
    assert_opaque(
        &propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            None,
            &signer,
        )
        .unwrap_err(),
    );
    assert_eq!(signer.calls(), 0);
    assert_eq!(observe(&network, leader, &[], 1), before_leader);
}

#[test]
fn actual_returned_scheme_drift_is_not_the_declared_scheme_zero_call_control() {
    let network: Network = setup();
    network.install_ordered();
    let leader: usize = network.leader_index(1);
    let replica: usize = (leader + 1) % REPLICAS;
    let leader_before: Observation = observe(&network, leader, &[], 1);
    let mut signer: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[leader], SigningResult::Valid);
    signer.scheme = SignatureSchemeId::Secp256k1;
    signer.initial_scheme_reads = 1;
    assert_opaque(
        &propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            None,
            &signer,
        )
        .unwrap_err(),
    );
    assert_eq!(
        signer.calls(),
        1,
        "scheme changes after the existing registered-scheme gate"
    );
    assert_eq!(observe(&network, leader, &[], 1), leader_before);
    let proposal: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        None,
        &network.signers[leader],
    )
    .unwrap();
    let before: Observation = observe(&network, replica, &[], 1);
    let mut voter: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[replica], SigningResult::Valid);
    voter.scheme = SignatureSchemeId::Secp256k1;
    voter.initial_scheme_reads = 1;
    assert_opaque(
        &process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &proposal,
            &voter,
        )
        .unwrap_err(),
    );
    assert_eq!(voter.calls(), 1);
    assert_eq!(observe(&network, replica, &[], 1), before);
}

#[derive(Clone, Copy)]
enum CommitFault {
    None,
    Race,
    UnknownBefore,
    UnknownAfter,
}

/// Bounded faults on existing store ports. Every unaffected read and all
/// actual writes retain MemoryDurableStateStore's normal authority and CAS.
struct FaultStore<'a> {
    inner: &'a MemoryDurableStateStore,
    hidden_vote: Option<Vec<u8>>,
    vote_reads: Cell<usize>,
    fail_applied_after: Option<usize>,
    applied_reads: Cell<usize>,
    fault: Cell<CommitFault>,
    commits: Cell<usize>,
    race: Option<(Vec<u8>, Vec<u8>)>,
}

impl<'a> FaultStore<'a> {
    fn new(inner: &'a MemoryDurableStateStore) -> Self {
        Self {
            inner,
            hidden_vote: None,
            vote_reads: Cell::new(0),
            fail_applied_after: None,
            applied_reads: Cell::new(0),
            fault: Cell::new(CommitFault::None),
            commits: Cell::new(0),
            race: None,
        }
    }

    fn before_commit(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> CommitFault {
        self.commits.set(self.commits.get().checked_add(1).unwrap());
        let fault: CommitFault = self.fault.replace(CommitFault::None);
        if matches!(fault, CommitFault::Race) {
            let (key, value): &(Vec<u8>, Vec<u8>) = self.race.as_ref().unwrap();
            let observed: VersionedStateValue = self
                .inner
                .get_versioned_durable(context, domain, key)
                .unwrap();
            let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
                domain,
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
                ])
                .unwrap(),
                AtomicStateMutationSet::new(vec![
                    StateMutationEntry::new(key.clone(), StateMutation::Put(value.clone()))
                        .unwrap(),
                ])
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                self.inner.commit_durable(context, transaction),
                DurableCommitOutcome::Committed
            );
        }
        fault
    }

    fn after_commit(fault: CommitFault, actual: DurableCommitOutcome) -> DurableCommitOutcome {
        if matches!(fault, CommitFault::UnknownAfter) {
            assert_eq!(actual, DurableCommitOutcome::Committed);
            DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost)
        } else {
            actual
        }
    }
}

impl DurableDomainStateStore for FaultStore<'_> {
    fn get_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::OutgoingBarrier, DurableReadError> {
        self.inner.get_outgoing_barrier(context, domain)
    }
    fn get_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
    }
    fn get_successor_serving(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<runtime::SuccessorServingSlot, DurableReadError> {
        self.inner.get_successor_serving(context, domain)
    }
    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        let observed: VersionedStateValue =
            self.inner.get_versioned_durable(context, domain, key)?;
        if self.hidden_vote.as_deref() == Some(key) {
            let read: usize = self.vote_reads.get();
            self.vote_reads.set(read.checked_add(1).unwrap());
            if read == 0 {
                assert!(
                    observed.value().is_some(),
                    "fault hides a real row, never deletes it"
                );
                return Ok(
                    VersionedStateValue::from_persisted_parts(StateRevision::INITIAL, None)
                        .unwrap(),
                );
            }
        }
        if key == engine::ordered_applied_height_key_for_tests(&fixture::chain()) {
            let read: usize = self.applied_reads.get();
            self.applied_reads.set(read.checked_add(1).unwrap());
            if self.fail_applied_after.is_some_and(|limit| read >= limit) {
                return Err(DurableReadError::Unavailable);
            }
        }
        Ok(observed)
    }
    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        let fault: CommitFault = self.before_commit(context, transaction.domain());
        if matches!(fault, CommitFault::UnknownBefore) {
            return DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost);
        }
        Self::after_commit(fault, self.inner.commit_durable(context, transaction))
    }
}

impl StructuredDurableDomainStateStore for FaultStore<'_> {
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
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.inner
            .get_object_version(context, domain, object_id, version)
    }
    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.inner.get_request_receipt(context, domain, request)
    }
    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        let fault: CommitFault = self.before_commit(context, transaction.domain());
        if matches!(fault, CommitFault::UnknownBefore) {
            return DurableCommitOutcome::Indeterminate(IndeterminateCommitReason::ConnectionLost);
        }
        Self::after_commit(fault, self.inner.commit_invocation(context, transaction))
    }
}

#[test]
fn distinct_final_reread_authenticates_fault_path_without_undoing_confirmed_progress() {
    // This deliberately stale first read is a fault-path control, not a
    // healthy-concurrency, rollback-protection or provider qualification.
    for corrupt in 0u8..3 {
        let network: Network = setup();
        network.install_ordered();
        network.round(1, None);
        network.round(2, None);
        let (_, _, proposal): (Vec<OrderedEventOutput>, QuorumCertificate, OrderedProposal) =
            network.round(3, None);
        let replica: usize = 0;
        let other: usize = 1;
        let key: Vec<u8> = engine::ordered_vote_record_key_for_tests(&fixture::chain(), 3);
        let (_, mut retained): (identity::LocalVoteRecord, ConsensusVote) =
            identity::decode_local_vote_record(&network.value(replica, &key).unwrap()).unwrap();
        if corrupt == 1 {
            retained.signature = vec![0; 64];
            assert!(
                network
                    .policy
                    .engine()
                    .verify_vote(&retained, &verifier())
                    .is_err()
            );
            retain_vote(&network, replica, &retained);
        } else if corrupt == 2 {
            let (_, peer): (identity::LocalVoteRecord, ConsensusVote) =
                identity::decode_local_vote_record(&network.value(other, &key).unwrap()).unwrap();
            network
                .policy
                .engine()
                .verify_vote(&peer, &verifier())
                .unwrap();
            assert_ne!(peer.validator, network.signers[replica].id);
            retained = peer;
            retain_vote(&network, replica, &retained);
        }
        let confirmed: ConsensusState = state(&network, replica);
        assert_eq!(confirmed.committed_height, 1);
        let independent: ConsensusOutput = network
            .policy
            .engine()
            .on_event(
                &confirmed,
                ConsensusEvent::Proposal(proposal.proposal.clone()),
                &network.signers[replica],
                &verifier(),
            )
            .unwrap();
        assert!(
            independent.outbound_messages.is_empty(),
            "genuine certified proposal emits no fresh vote"
        );
        assert_eq!(independent.state, confirmed);
        let before: Observation = observe(&network, replica, &[], 3);
        let mut fault: FaultStore<'_> = FaultStore::new(&network.stores[replica]);
        fault.hidden_vote = Some(key);
        let signer: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[replica], SigningResult::Error);
        let result: Result<OrderedEventOutput, OrderedEconomicsError> =
            process_proposal(&fault, &network.context, &network.env(), &proposal, &signer);
        if corrupt == 0 {
            let output: OrderedEventOutput = result.unwrap();
            assert_eq!(output.messages, vec![ConsensusMessage::Vote(retained)]);
            assert!(output.committed.is_empty());
        } else {
            let error: OrderedEconomicsError = result.unwrap_err();
            assert_opaque(&error);
            if corrupt == 2 {
                assert!(matches!(
                    error,
                    OrderedEconomicsError::Prerequisite("retained ordered vote signer differs")
                ));
            }
        }
        assert!(
            fault.vote_reads.get() >= 3,
            "passes the early lookup and completion to the distinct final reread"
        );
        assert_eq!(
            fault.commits.get(),
            0,
            "the genuine certified replay has an unchanged completion"
        );
        assert_eq!(signer.calls(), 0);
        assert_eq!(state(&network, replica), confirmed);
        assert_eq!(
            observe(&network, replica, &[], 3),
            before,
            "no repair, re-retention or rollback"
        );
    }
}

#[test]
fn causal_capacity_preview_is_not_crypto_approval_or_a_commit() {
    let network: Network = causal_network();
    let leader: usize = network.leader_index(1);
    let replica: usize = (leader + 1) % REPLICAS;
    let candidate: OrderedCandidate = unbond(&network, [0xb5; 32], 11);
    let proposal: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader],
    )
    .unwrap();
    let before: Observation = observe(&network, replica, &[&candidate], 1);
    let mut fault: FaultStore<'_> = FaultStore::new(&network.stores[replica]);
    // The first two reads are existing vote-readiness checks; the third is
    // prepare_event on the unsigned capacity output. A preparation read fault
    // must stop before real signing. This is not a codec-size-limit claim.
    fault.fail_applied_after = Some(2);
    let signer: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[replica], SigningResult::Valid);
    assert!(
        process_proposal(&fault, &network.context, &network.env(), &proposal, &signer).is_err()
    );
    assert_eq!(fault.applied_reads.get(), 3);
    assert!(
        signer.reads.get() >= 3,
        "the real engine's nonauthoritative probe was constructed"
    );
    assert_eq!(signer.calls(), 0);
    assert_eq!(fault.commits.get(), 0);
    assert_eq!(observe(&network, replica, &[&candidate], 1), before);
    let positive: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[replica], SigningResult::Valid);
    let observed: FaultStore<'_> = FaultStore::new(&network.stores[replica]);
    let output: OrderedEventOutput = process_proposal(
        &observed,
        &network.context,
        &network.env(),
        &proposal,
        &positive,
    )
    .unwrap();
    network
        .policy
        .engine()
        .verify_vote(&vote(&output), &verifier())
        .unwrap();
    assert_eq!(
        positive.calls(),
        1,
        "only the actual engine event uses the key"
    );
    assert_eq!(
        observed.commits.get(),
        1,
        "capacity completion was dropped, not confirmed"
    );
    assert!(output.committed.is_empty());
}

#[test]
fn fresh_verified_votes_preserve_real_cas_and_indeterminate_reconciliation() {
    for fault_kind in [
        CommitFault::Race,
        CommitFault::UnknownBefore,
        CommitFault::UnknownAfter,
    ] {
        let network: Network = setup();
        network.install_ordered();
        let leader: usize = network.leader_index(1);
        let replica: usize = (leader + 1) % REPLICAS;
        let candidate: OrderedCandidate = unbond(&network, [0xb6; 32], 11);
        let proposal: OrderedProposal = propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&candidate),
            &network.signers[leader],
        )
        .unwrap();
        let before: Observation = observe(&network, replica, &[&candidate], 1);
        let high_key: Vec<u8> = engine::ordered_vote_high_key_for_tests(&fixture::chain());
        let high_revision: StateRevision = network.revision(replica, &high_key);
        let mut fault: FaultStore<'_> = FaultStore::new(&network.stores[replica]);
        fault.fault.set(fault_kind);
        fault.race = Some((
            high_key.clone(),
            identity::encode_vote_high_water(0).unwrap(),
        ));
        let signer: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[replica], SigningResult::Valid);
        let error: OrderedEconomicsError =
            process_proposal(&fault, &network.context, &network.env(), &proposal, &signer)
                .unwrap_err();
        assert!(matches!(
            error,
            OrderedEconomicsError::Prerequisite(_) | OrderedEconomicsError::Node(_)
        ));
        assert_eq!(signer.calls(), 1);
        assert_eq!(fault.commits.get(), 1);
        let after: Observation = observe(&network, replica, &[&candidate], 1);
        if matches!(fault_kind, CommitFault::UnknownAfter) {
            assert_ne!(
                after, before,
                "unknown acknowledgement can follow an actual atomic commit"
            );
            let retry: ScriptedSigner<'_> =
                ScriptedSigner::stable(&network.signers[replica], SigningResult::Error);
            let output: OrderedEventOutput = process_proposal(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &proposal,
                &retry,
            )
            .unwrap();
            network
                .policy
                .engine()
                .verify_vote(&vote(&output), &verifier())
                .unwrap();
            assert_eq!(
                retry.calls(),
                0,
                "reconciliation reuses the retained verified vote"
            );
            assert_eq!(observe(&network, replica, &[&candidate], 1), after);
        } else {
            if matches!(fault_kind, CommitFault::Race) {
                assert_ne!(network.revision(replica, &high_key), high_revision);
                let mut without_foreign: Observation = after;
                without_foreign.rows.retain(|row| row.0 != high_key);
                let mut prior: Observation = before;
                prior.rows.retain(|row| row.0 != high_key);
                assert_eq!(
                    without_foreign, prior,
                    "only the independently committed racing row survives"
                );
            } else {
                assert_eq!(
                    after, before,
                    "this unknown-before fixture happened not to commit"
                );
            }
            let retry: ScriptedSigner<'_> =
                ScriptedSigner::stable(&network.signers[replica], SigningResult::Valid);
            let output: OrderedEventOutput = process_proposal(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &proposal,
                &retry,
            )
            .unwrap();
            network
                .policy
                .engine()
                .verify_vote(&vote(&output), &verifier())
                .unwrap();
            assert_eq!(retry.calls(), 1);
        }
    }
}

#[test]
fn justified_business_prefix_survives_a_later_invalid_fresh_vote() {
    let network: Network = causal_network();
    let candidate: OrderedCandidate = unbond(&network, [0xb7; 32], 11);
    network.round(1, Some(&candidate));
    network.round(2, None);
    let (certificate, _): (QuorumCertificate, OrderedProposal) = network.certify(3, None);
    let replica: usize = network.non_leader(&[3, 4]);
    for peer in 0..REPLICAS {
        if peer != replica {
            process_certificate(
                &network.stores[peer],
                &network.context,
                &network.env(),
                &certificate,
            )
            .unwrap();
        }
    }
    let leader: usize = network.leader_index(4);
    let proposal: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        None,
        &network.signers[leader],
    )
    .unwrap();
    let prior: ConsensusState = state(&network, replica);
    assert_eq!(prior.committed_height, 0);
    let independently_justified: ConsensusOutput = network
        .policy
        .engine()
        .on_observer_event(
            &prior,
            ConsensusEvent::Certificate(proposal.proposal.justify.clone()),
            &verifier(),
        )
        .unwrap();
    assert_eq!(independently_justified.committed_blocks[0].height, 1);
    assert_eq!(
        independently_justified.committed_blocks[0].transactions,
        vec![network.policy.candidate_digest(&candidate).unwrap()]
    );
    let before: Observation = observe(&network, replica, &[&candidate], 4);
    let high_key: Vec<u8> = engine::ordered_vote_high_key_for_tests(&fixture::chain());
    let high_before: Option<Vec<u8>> = network.value(replica, &high_key);
    let high_revision: StateRevision = network.revision(replica, &high_key);
    let signer: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[replica], SigningResult::Bytes(64));
    let counted: FaultStore<'_> = FaultStore::new(&network.stores[replica]);
    // No fault: count the real earlier prefix commit without intercepting it.
    counted.fault.set(CommitFault::None);
    assert_opaque(
        &process_proposal(
            &counted,
            &network.context,
            &network.env(),
            &proposal,
            &signer,
        )
        .unwrap_err(),
    );
    assert_eq!(signer.calls(), 1);
    assert_eq!(
        counted.commits.get(),
        1,
        "only the authenticated earlier business prefix confirms"
    );
    let confirmed: ConsensusState = state(&network, replica);
    assert_eq!(confirmed, independently_justified.state);
    assert_eq!(
        confirmed.last_voted_view, 3,
        "failed fresh vote does not advance consensus last-vote state"
    );
    assert_eq!(network.value(replica, &high_key), high_before);
    assert_eq!(network.revision(replica, &high_key), high_revision);
    assert!(
        network
            .value(
                replica,
                &engine::ordered_vote_record_key_for_tests(&fixture::chain(), 4)
            )
            .is_none()
    );
    assert_eq!(
        network.committed_bond(replica),
        predicted_unbond(&network.bond, 11, *address_of(0x58).as_bytes())
    );
    assert!(
        network.stores[replica]
            .get_request_receipt(
                &network.context,
                network.domain(),
                DurableRequestId::new(candidate.request_id).unwrap()
            )
            .unwrap()
            .is_some()
    );
    assert!(
        network
            .value(
                replica,
                &engine::ordered_outcome_key_for_tests(&fixture::chain(), &candidate.request_id)
            )
            .is_some()
    );
    let after: Observation = observe(&network, replica, &[&candidate], 4);
    assert_ne!(
        after, before,
        "legitimate committed prefix is not rolled back by refusal"
    );
    let outcome: OrderedOutcome = query_ordered_outcome(
        &network.stores[replica],
        &network.context,
        &network.env(),
        &candidate.request_id,
    )
    .unwrap()
    .unwrap();
    assert_eq!(outcome.block_height, 1);
    // Exact prefix reconciliation is read-only and does not invent a signed
    // response for the rejected view-four vote.
    process_certificate(
        &network.stores[replica],
        &network.context,
        &network.env(),
        &certificate,
    )
    .unwrap();
    assert_eq!(observe(&network, replica, &[&candidate], 4), after);
}

#[test]
fn valid_vote_reserves_its_nonce_and_invalid_retained_vote_does_not_release_or_repair() {
    let network: Network = setup();
    network.install_ordered();
    let leader: usize = network.leader_index(1);
    let replica: usize = (leader + 1) % REPLICAS;
    let candidate: OrderedCandidate = withdraw_candidate(&network, [0xb8; 32], 0);
    let proposal: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader],
    )
    .unwrap();
    let output: OrderedEventOutput = process_proposal(
        &network.stores[replica],
        &network.context,
        &network.env(),
        &proposal,
        &network.signers[replica],
    )
    .unwrap();
    let key: Vec<u8> = fastpath_nonce_lock_key(
        &fixture::chain(),
        &fixture::sender(),
        fixture::protocol().epoch(),
    )
    .unwrap();
    let locked: local_instance_state::FastPathNonceLockRecord =
        decode_fastpath_nonce_lock_record(&network.value(replica, &key).unwrap()).unwrap();
    assert_eq!(locked.request_id, candidate.request_id);
    assert_eq!(locked.nonce, 0);
    let mut corrupt: ConsensusVote = vote(&output);
    network
        .policy
        .engine()
        .verify_vote(&corrupt, &verifier())
        .unwrap();
    corrupt.signature = vec![0; 64];
    retain_vote(&network, replica, &corrupt);
    let before: Observation = observe(&network, replica, &[&candidate], 1);
    let signer: ScriptedSigner<'_> =
        ScriptedSigner::stable(&network.signers[replica], SigningResult::Error);
    assert_opaque(
        &process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &proposal,
            &signer,
        )
        .unwrap_err(),
    );
    assert_eq!(signer.calls(), 0);
    assert_eq!(observe(&network, replica, &[&candidate], 1), before);
    assert_eq!(
        decode_fastpath_nonce_lock_record(&network.value(replica, &key).unwrap()).unwrap(),
        locked
    );
}

#[test]
fn existing_header_authentication_and_writer_fence_refusals_stay_before_key_use() {
    for causal in [false, true] {
        let network: Network = if causal {
            causal_network()
        } else {
            let network: Network = setup();
            network.install_ordered();
            network
        };
        let leader: usize = network.leader_index(1);
        let first: OrderedCandidate = unbond(&network, [0xb9; 32], 11);
        let conflicting: OrderedCandidate = unbond(&network, first.request_id, 12);
        let original: OrderedProposal = propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&first),
            &network.signers[leader],
        )
        .unwrap();
        let before: Observation = observe(&network, leader, &[&first, &conflicting], 1);
        let signer: ScriptedSigner<'_> =
            ScriptedSigner::stable(&network.signers[leader], SigningResult::Error);
        assert!(matches!(
            propose(
                &network.stores[leader],
                &network.context,
                &network.env(),
                Some(&conflicting),
                &signer
            ),
            Err(OrderedEconomicsError::RequestHeaderConflict)
        ));
        assert_eq!(signer.calls(), 0);
        let mut unauthentic: OrderedProposal = original.clone();
        unauthentic.proposal.signature = vec![0; 64];
        assert!(
            process_proposal(
                &network.stores[leader],
                &network.context,
                &network.env(),
                &unauthentic,
                &signer
            )
            .is_err()
        );
        assert_eq!(signer.calls(), 0);
        let fenced: DurableOperationContext = fixture::context(2);
        assert!(
            process_proposal(
                &network.stores[leader],
                &fenced,
                &network.env(),
                &original,
                &signer
            )
            .is_err()
        );
        assert_eq!(signer.calls(), 0);
        assert_eq!(
            observe(&network, leader, &[&first, &conflicting], 1),
            before
        );
    }
}
