//! Fresh causal signing requires actual committed slash evidence. Positive
//! authority comes only from real ordered Evidence producers/three-chains;
//! direct row changes below are explicitly corruption/race negatives.
use super::*;
use crate::bond_lifecycle::slash::{SlashIntent, decode_slash_intent, encode_slash_intent};
use crate::business_reconstruction::SourceBusinessSnapshot;
use crate::equivocation::{
    DecodedEquivocationEvidence, FastPathEquivocationEvidenceRecord, decode_dispatched,
    decode_fastpath_equivocation_evidence_record, encode_fastpath_equivocation_evidence_record,
    normalized_identity_digest,
};
use crate::local_instance_state::{
    fastpath_equivocation_evidence_key, fastpath_evidence_consumed_key, fastpath_validator_set_key,
};
use crate::test_support::capture::{assert_same_records_and_blobs, captured_source};
use objects::{ProtocolCustodyPurpose, ProtocolCustodyScope};
use runtime::{NamespaceLifecycle, OutgoingBarrier, SuccessorServingSlot};
use std::cell::{Cell, RefCell};

const PRODUCER: [u8; 32] = [0xe0; 32];
const SLASH: [u8; 32] = [0xe1; 32];

fn submitter_key() -> SigningKey {
    SigningKey::from([0x77; 32])
}

fn submitter() -> [u8; 32] {
    VerificationKey::from(&submitter_key()).into()
}

fn capture(network: &Network, replica: usize) -> SourceBusinessSnapshot {
    captured_source(
        &network.stores[replica],
        &network.blobs,
        &network.context,
        network.domain(),
    )
}

fn decoded_submission(network: &Network, family: usize) -> DecodedEquivocationEvidence {
    let submission: OrderedEvidenceSubmission = evidence_submissions(network, 11).remove(family);
    crate::ordered_economics::evidence_submission::build_decoded_evidence(
        &submission,
        network.policy.context().chain_id(),
        network.policy.context().protocol_version(),
    )
    .unwrap()
}

fn encode_proof(decoded: &DecodedEquivocationEvidence) -> Vec<u8> {
    match decoded {
        DecodedEquivocationEvidence::FastVote(evidence) => {
            consensus::encode_fast_vote_equivocation_evidence(evidence).unwrap()
        }
        DecodedEquivocationEvidence::ObjectConflict(evidence) => {
            consensus::encode_fast_vote_object_conflict_evidence(evidence).unwrap()
        }
        DecodedEquivocationEvidence::EpochTransition(evidence) => {
            consensus::encode_epoch_transition_equivocation_evidence(evidence).unwrap()
        }
    }
}

fn proof_key(network: &Network, decoded: &DecodedEquivocationEvidence) -> Vec<u8> {
    fastpath_equivocation_evidence_key(
        network.policy.context().chain_id(),
        decoded.epoch(),
        *decoded.validator().as_bytes(),
        normalized_identity_digest(&network.resolver, decoded).unwrap(),
    )
    .unwrap()
}

fn slash_candidate(
    fixture: &CausalFixture,
    decoded: &DecodedEquivocationEvidence,
) -> OrderedCandidate {
    let network: &Network = &fixture.network;
    let bond_key: Vec<u8> =
        fastpath_bond_record_key(&fixture::chain(), &decoded.validator()).unwrap();
    let bond: FastPathBondRecord =
        decode_fastpath_bond_record(&network.value(0, &bond_key).unwrap()).unwrap();
    let custody: Object = current_object(network, 0, bond.custody_object.id);
    let target: ProtocolCustodyScope = ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::ForfeitedCollateral,
        chain_id: fixture::chain(),
        subject: *bond.validator_id.as_bytes(),
        resource: bond.resource,
    };
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &network.resolver,
        &fixture::protocol(),
        custody.id,
        &target,
    )
    .unwrap();
    // The ordinary submitter is NOT the target validator. This signature
    // authorizes only the submitter's exact leg/nonce, not the target bond.
    assert!(network.policy.registered_validator(ValidatorId::new(submitter())).is_none());
    assert_ne!(submitter(), *bond.validator_id.as_bytes());
    let leg: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: network.leg_policy.digest(&network.resolver).unwrap(),
        call: CallIntent {
            context: fixture::protocol(),
            request_id: SLASH,
            sender: submitter(),
            nonce: 0,
            code: fixture.instance.code.clone(),
            instance: instance_target(&network.resolver, &fixture.instance).unwrap(),
            entrypoint: "transfer".into(),
            type_arguments: fixture.manifest.fee_policy.type_arguments.clone(),
            access: abi::AccessManifest {
                entries: vec![abi::AccessEntry {
                    object_ref: object_ref(network, &custody),
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::transfer_arguments(&token).unwrap(),
            gas_limit: 100_000,
        },
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = local_execution_signing_frame(&fixture::protocol(), &leg).unwrap();
    let intent: SlashIntent = SlashIntent {
        context: fixture::protocol(),
        request_id: SLASH,
        validator_id: bond.validator_id,
        resource_id: BondResourceId::new(bond.resource_domain, bond.resource).unwrap(),
        expected_generation: bond.generation,
        evidence_epoch: decoded.epoch(),
        conflict_digest: normalized_identity_digest(&network.resolver, decoded).unwrap(),
        leg: encode_signed_local_execution(&SignedLocalExecutionIntent {
            signature: submitter_key().sign(&frame).into(),
            intent: leg,
        })
        .unwrap(),
    };
    OrderedCandidate {
        context: fixture::protocol(),
        request_id: SLASH,
        kind: OrderedOperationKind::BondSlash,
        intent: encode_slash_intent(&intent).unwrap(),
        created_checkpoint: 20,
    }
}

fn commit_producer(network: &Network, family: usize) -> FastPathEquivocationEvidenceRecord {
    let submission: OrderedEvidenceSubmission = evidence_submissions(network, 11).remove(family);
    let candidate: OrderedCandidate = evidence_candidate(&submission, PRODUCER);
    let decoded: DecodedEquivocationEvidence = decoded_submission(network, family);
    let key: Vec<u8> = proof_key(network, &decoded);
    network.round(1, Some(&candidate));
    assert!(network.value(0, &key).is_none(), "a retained producer is not its effect");
    network.round(2, None);
    assert!(network.value(0, &key).is_none(), "two QCs are not a three-chain commit");
    let (outputs, _, _): (Vec<OrderedEventOutput>, QuorumCertificate, OrderedProposal) =
        network.round(3, None);
    let record: FastPathEquivocationEvidenceRecord = accepted_evidence_record(&outputs[0].committed[0]);
    for replica in 0..REPLICAS {
        assert_eq!(
            decode_fastpath_equivocation_evidence_record(&network.value(replica, &key).unwrap())
                .unwrap(),
            record
        );
        assert!(receipt(network, replica, PRODUCER).is_some());
    }
    record
}

/// An actually signed Byzantine-leader proposal uses the existing public
/// consensus engine, not a fabricated signature or a production bypass hook.
/// It lets the vote test independently challenge honest fresh admission.
fn raw_proposal(network: &Network, candidate: &OrderedCandidate) -> OrderedProposal {
    let status: OrderedStatus =
        query_status(&network.stores[0], &network.context, &network.env()).unwrap();
    let leader: usize = network.leader_index(status.current_view);
    let state: consensus::ConsensusState = consensus::decode_consensus_state(
        &network.value(leader, &engine::ordered_state_key_for_tests(&fixture::chain())).unwrap(),
    )
    .unwrap();
    OrderedProposal {
        proposal: network.policy.engine().propose(
            &state,
            vec![network.policy.candidate_digest(candidate).unwrap()],
            &network.signers[leader],
        )
        .unwrap(),
        candidate: Some(candidate.clone()),
    }
}

#[derive(Clone, Copy)]
enum RaceAt {
    Commit,
    SecondRead,
}

/// Count real forwarded durable calls, and optionally perform one fenced,
/// byte-identical deciding-row rewrite before the challenged read/commit.
/// This never acknowledges a fake commit or supplies a positive business row.
struct AttemptStore<'a> {
    network: &'a Network,
    replica: usize,
    commit_calls: Cell<usize>,
    invocation_calls: Cell<usize>,
    reads: RefCell<BTreeMap<Vec<u8>, usize>>,
    race: Option<(RaceAt, Vec<u8>)>,
    raced: Cell<bool>,
    after_race: RefCell<Option<SourceBusinessSnapshot>>,
    committed_reads: RefCell<Vec<StateReadAssertion>>,
}

impl<'a> AttemptStore<'a> {
    fn new(network: &'a Network, replica: usize) -> Self {
        Self {
            network,
            replica,
            commit_calls: Cell::new(0),
            invocation_calls: Cell::new(0),
            reads: RefCell::new(BTreeMap::new()),
            race: None,
            raced: Cell::new(false),
            after_race: RefCell::new(None),
            committed_reads: RefCell::new(Vec::new()),
        }
    }

    fn count_commits(&self) -> usize {
        self.commit_calls.get() + self.invocation_calls.get()
    }

    fn rewrite(&self, key: &[u8]) {
        assert!(!self.raced.replace(true));
        let value: Vec<u8> = self.network.value(self.replica, key).unwrap();
        self.network.put(self.replica, key.to_vec(), StateMutation::Put(value));
        *self.after_race.borrow_mut() = Some(capture(self.network, self.replica));
    }

    fn before_commit(&self, reads: &[StateReadAssertion]) {
        *self.committed_reads.borrow_mut() = reads.to_vec();
        if let Some((RaceAt::Commit, key)) = &self.race {
            self.rewrite(key);
        }
    }
}

impl DurableDomainStateStore for AttemptStore<'_> {
    fn get_namespace_lifecycle(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<NamespaceLifecycle, DurableReadError> {
        self.network.stores[self.replica].get_namespace_lifecycle(context, domain)
    }

    fn get_outgoing_barrier(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<OutgoingBarrier, DurableReadError> {
        self.network.stores[self.replica].get_outgoing_barrier(context, domain)
    }

    fn get_successor_serving(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
    ) -> Result<SuccessorServingSlot, DurableReadError> {
        self.network.stores[self.replica].get_successor_serving(context, domain)
    }

    fn get_versioned_durable(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        key: &[u8],
    ) -> Result<VersionedStateValue, DurableReadError> {
        let count: usize = {
            let mut reads: std::cell::RefMut<'_, BTreeMap<Vec<u8>, usize>> = self.reads.borrow_mut();
            let count: &mut usize = reads.entry(key.to_vec()).or_default();
            *count = count.checked_add(1).unwrap();
            *count
        };
        if let Some((RaceAt::SecondRead, selected)) = &self.race
            && selected.as_slice() == key
            && count == 2
        {
            self.rewrite(key);
        }
        self.network.stores[self.replica].get_versioned_durable(context, domain, key)
    }

    fn commit_durable(
        &self,
        context: &DurableOperationContext,
        transaction: AtomicStateTransaction,
    ) -> DurableCommitOutcome {
        self.commit_calls.set(self.commit_calls.get().checked_add(1).unwrap());
        self.before_commit(transaction.reads());
        self.network.stores[self.replica].commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for AttemptStore<'_> {
    fn get_object_head(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object: ObjectId,
    ) -> Result<DurableObjectHead, DurableReadError> {
        self.network.stores[self.replica].get_object_head(context, domain, object)
    }

    fn get_object_version(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        object: ObjectId,
        version: DurableObjectVersion,
    ) -> Result<Option<DurableObjectVersionRecord>, DurableReadError> {
        self.network.stores[self.replica].get_object_version(context, domain, object, version)
    }

    fn get_request_receipt(
        &self,
        context: &DurableOperationContext,
        domain: AtomicityDomainId,
        request: DurableRequestId,
    ) -> Result<Option<DurableRequestReceipt>, DurableReadError> {
        self.network.stores[self.replica].get_request_receipt(context, domain, request)
    }

    fn commit_invocation(
        &self,
        context: &DurableOperationContext,
        transaction: DurableInvocationTransaction,
    ) -> DurableCommitOutcome {
        self.invocation_calls.set(self.invocation_calls.get().checked_add(1).unwrap());
        self.before_commit(transaction.state().unwrap().reads());
        self.network.stores[self.replica].commit_invocation(context, transaction)
    }
}

fn assert_fresh_rejected(
    network: &Network,
    candidate: &OrderedCandidate,
) -> [OrderedEconomicsError; 2] {
    authenticate_candidate(&network.env(), candidate).unwrap();
    let proposal: OrderedProposal = raw_proposal(network, candidate);
    let leader: usize = network.leader_index(proposal.proposal.view);
    let voter: usize = (leader + 1) % REPLICAS;
    let mut errors: Vec<OrderedEconomicsError> = Vec::new();
    for (vote, replica) in [(false, leader), (true, voter)] {
        let store: AttemptStore<'_> = AttemptStore::new(network, replica);
        let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
            signer: &network.signers[replica],
            calls: Cell::new(0),
        };
        let before: SourceBusinessSnapshot = capture(network, replica);
        let error: OrderedEconomicsError = if vote {
            process_proposal(&store, &network.context, &network.env(), &proposal, &signer)
                .unwrap_err()
        } else {
            propose(&store, &network.context, &network.env(), Some(candidate), &signer)
                .unwrap_err()
        };
        assert!(matches!(
            error,
            OrderedEconomicsError::Prerequisite(_) | OrderedEconomicsError::Node(_)
        ));
        assert_eq!(signer.calls.get(), 0, "no real proposal/vote signing on fresh rejection");
        assert_eq!(store.count_commits(), 0, "no forwarded fresh durable commit");
        assert_same_records_and_blobs(&capture(network, replica), &before);
        assert!(receipt(network, replica, SLASH).is_none());
        errors.push(error);
    }
    errors.try_into().unwrap()
}

#[test]
fn absent_and_only_retained_producer_evidence_stop_fresh_propose_and_vote() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let decoded: DecodedEquivocationEvidence = decoded_submission(network, 0);
    let candidate: OrderedCandidate = slash_candidate(&fixture, &decoded);
    assert!(network.value(0, &proof_key(network, &decoded)).is_none());
    assert_fresh_rejected(network, &candidate);

    // A genuinely retained, quorum-certified producer remains uncommitted
    // before its third QC. Retaining its authentic proposal/header on fresh
    // observer replicas supplies no evidence effect or slash authority.
    let submission: OrderedEvidenceSubmission = evidence_submissions(network, 11).remove(0);
    let producer: OrderedCandidate = evidence_candidate(&submission, PRODUCER);
    let (_, _, retained): (Vec<OrderedEventOutput>, QuorumCertificate, OrderedProposal) =
        network.round(1, Some(&producer));
    assert!(network.value(0, &proof_key(network, &decoded)).is_none());
    let missing: CausalFixture = fresh_fixture();
    for replica in 0..REPLICAS {
        observe_proposal(
            &missing.network.stores[replica],
            &missing.network.context,
            &missing.network.env(),
            &retained,
        )
        .unwrap();
        assert!(missing.network.value(replica, &engine::ordered_request_header_key_for_tests(
            &fixture::chain(), &PRODUCER,
        )).is_some());
        assert!(missing.network.value(replica, &proof_key(&missing.network, &decoded)).is_none());
    }
    assert_eq!(
        encode_ordered_candidate(&slash_candidate(&missing, &decoded)).unwrap(),
        encode_ordered_candidate(&candidate).unwrap()
    );
    assert_fresh_rejected(&missing.network, &candidate);
}

#[test]
fn actual_causal_ordered_evidence_authorizes_full_slash_for_every_family_and_completed_replay() {
    for family in 0..3usize {
        let fixture: CausalFixture = fresh_fixture();
        let network: &Network = &fixture.network;
        let record: FastPathEquivocationEvidenceRecord = commit_producer(network, family);
        let decoded: DecodedEquivocationEvidence = decode_dispatched(&record.evidence_bytes).unwrap();
        let candidate: OrderedCandidate = slash_candidate(&fixture, &decoded);
        let intent: SlashIntent = decode_slash_intent(&candidate.intent).unwrap();
        let key: Vec<u8> = proof_key(network, &decoded);
        let evidence_revision: StateRevision = network.revision(0, &key);
        let bond_key: Vec<u8> = fastpath_bond_record_key(&fixture::chain(), &intent.validator_id).unwrap();
        let previous: FastPathBondRecord =
            decode_fastpath_bond_record(&network.value(0, &bond_key).unwrap()).unwrap();
        network.round(4, Some(&candidate));
        network.round(5, None);
        let (outputs, terminal, proposal): (Vec<OrderedEventOutput>, QuorumCertificate, OrderedProposal) =
            network.round(6, None);
        for (replica, output) in outputs.iter().enumerate() {
            assert_eq!(output.committed[0].request_id, SLASH);
            assert_eq!(output.committed[0].output.responses()[0].status(), NodeResponseStatus::Accepted);
            let bond: FastPathBondRecord =
                decode_fastpath_bond_record(&network.value(replica, &bond_key).unwrap()).unwrap();
            assert!(matches!(bond.state, FastPathBondState::Jailed { .. }));
            assert_eq!(bond.generation, previous.generation + 1);
            assert_eq!(bond.amount, previous.amount);
            assert_eq!(bond.required_minimum, previous.required_minimum);
            let custody: Object = current_object(network, replica, previous.custody_object.id);
            assert!(matches!(custody.owner, Owner::ProtocolCustody(ref scope)
                if scope.purpose == ProtocolCustodyPurpose::ForfeitedCollateral
                    && scope.subject == *intent.validator_id.as_bytes()
                    && scope.resource == previous.resource));
            assert!(network.value(replica, &fastpath_evidence_consumed_key(
                &fixture::chain(), intent.evidence_epoch, *intent.validator_id.as_bytes(), intent.conflict_digest,
            ).unwrap()).is_some());
            assert_eq!(query_sender_next_nonce(
                &network.stores[replica], &network.context, network.domain(), fixture::chain(),
                fixture::protocol().protocol_version(), fixture::protocol().epoch(),
                submitter(),
            ).unwrap(), 1);
            assert_eq!(network.value(replica, &key).unwrap(), encode_fastpath_equivocation_evidence_record(&record).unwrap());
            assert_eq!(network.revision(replica, &key), evidence_revision);
        }

        // Completed-first replay does not need a fresh evidence read, nonce
        // or reservation. Evidence loss here must not undo the known answer.
        let leader: usize = network.leader_index(7);
        network.put(leader, key.clone(), StateMutation::Delete);
        let before: SourceBusinessSnapshot = capture(network, leader);
        let store: AttemptStore<'_> = AttemptStore::new(network, leader);
        let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
            signer: &network.signers[leader], calls: Cell::new(0),
        };
        let error: OrderedEconomicsError =
            propose(&store, &network.context, &network.env(), Some(&candidate), &signer).unwrap_err();
        assert_eq!(error.completed_outcome().unwrap(), &outputs[leader].committed[0]);
        observe_proposal(&store, &network.context, &network.env(), &proposal).unwrap();
        process_certificate(&store, &network.context, &network.env(), &terminal).unwrap();
        assert_eq!(signer.calls.get(), 0);
        assert_eq!(store.count_commits(), 0);
        assert!(!store.reads.borrow().contains_key(&key));
        assert_same_records_and_blobs(&capture(network, leader), &before);
    }
}

#[test]
fn malformed_record_and_both_bad_signatures_for_all_families_stop_before_signing() {
    for family in 0..3usize {
        let fixture: CausalFixture = fresh_fixture();
        let network: &Network = &fixture.network;
        let original: FastPathEquivocationEvidenceRecord = commit_producer(network, family);
        let decoded: DecodedEquivocationEvidence = decode_dispatched(&original.evidence_bytes).unwrap();
        let candidate: OrderedCandidate = slash_candidate(&fixture, &decoded);
        let key: Vec<u8> = proof_key(network, &decoded);
        // Negative corruption only, after the real producer committed.
        network.put(0, key.clone(), StateMutation::Put(vec![0]));
        let leader: usize = network.leader_index(4);
        for replica in 0..REPLICAS {
            if replica != 0 {
                network.put(replica, key.clone(), StateMutation::Put(vec![0]));
            }
        }
        assert_eq!(network.value(leader, &key).unwrap(), vec![0]);
        assert_fresh_rejected(network, &candidate);
        for high in [false, true] {
            let mut changed: DecodedEquivocationEvidence = decode_dispatched(&original.evidence_bytes).unwrap();
            let signature: &mut Vec<u8> = match &mut changed {
                DecodedEquivocationEvidence::FastVote(evidence) => {
                    if high { &mut evidence.high.signature } else { &mut evidence.low.signature }
                }
                DecodedEquivocationEvidence::ObjectConflict(evidence) => {
                    if high { &mut evidence.high.signature } else { &mut evidence.low.signature }
                }
                DecodedEquivocationEvidence::EpochTransition(evidence) => {
                    if high { &mut evidence.high.signature } else { &mut evidence.low.signature }
                }
            };
            signature[0] ^= 1;
            assert_eq!(normalized_identity_digest(&network.resolver, &changed).unwrap(),
                decode_slash_intent(&candidate.intent).unwrap().conflict_digest,
                "signatures are not the normalized selector authority");
            let record: FastPathEquivocationEvidenceRecord = FastPathEquivocationEvidenceRecord {
                evidence_bytes: encode_proof(&changed),
                recorded_at_checkpoint: original.recorded_at_checkpoint,
            };
            for replica in 0..REPLICAS {
                network.put(replica, key.clone(), StateMutation::Put(
                    encode_fastpath_equivocation_evidence_record(&record).unwrap(),
                ));
            }
            assert_fresh_rejected(network, &candidate);
        }
    }
}

#[test]
fn both_object_conflict_preimages_must_hash_to_their_own_signed_digests() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let original: FastPathEquivocationEvidenceRecord = commit_producer(network, 1);
    let decoded: DecodedEquivocationEvidence = decode_dispatched(&original.evidence_bytes).unwrap();
    let candidate: OrderedCandidate = slash_candidate(&fixture, &decoded);
    let key: Vec<u8> = proof_key(network, &decoded);
    for high in [false, true] {
        let DecodedEquivocationEvidence::ObjectConflict(mut proof) = decode_dispatched(&original.evidence_bytes).unwrap() else {
            panic!("real ObjectConflict producer");
        };
        let preimage: &mut consensus::LockedObjectSetPreimage =
            if high { &mut proof.high_preimage } else { &mut proof.low_preimage };
        // Keep the overlapping (id, version) and all real signatures intact.
        // Consensus structural/signature verification alone still succeeds.
        preimage.entries.last_mut().unwrap().digest = digest32(0xf7);
        consensus::verify_fast_vote_object_conflict_evidence(
            &proof, validator_set(&network.signers),
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
            ),
        ).unwrap();
        let record: FastPathEquivocationEvidenceRecord = FastPathEquivocationEvidenceRecord {
            evidence_bytes: consensus::encode_fast_vote_object_conflict_evidence(&proof).unwrap(),
            recorded_at_checkpoint: original.recorded_at_checkpoint,
        };
        for replica in 0..REPLICAS {
            network.put(replica, key.clone(), StateMutation::Put(
                encode_fastpath_equivocation_evidence_record(&record).unwrap(),
            ));
        }
        assert_fresh_rejected(network, &candidate);
    }
}

#[test]
fn full_typed_digest_and_actual_pinned_committee_are_not_presence_checks() {
    for corrupt_set in [false, true] {
        let fixture: CausalFixture = fresh_fixture();
        let network: &Network = &fixture.network;
        let record: FastPathEquivocationEvidenceRecord = commit_producer(network, 0);
        let decoded: DecodedEquivocationEvidence = decode_dispatched(&record.evidence_bytes).unwrap();
        let mut candidate: OrderedCandidate = slash_candidate(&fixture, &decoded);
        if corrupt_set {
            let key: Vec<u8> = fastpath_validator_set_key(&fixture::protocol()).unwrap();
            let mut set: FastPathValidatorSetRecord =
                fast_path::records::decode_fastpath_validator_set_record(&network.value(0, &key).unwrap()).unwrap();
            let target: &mut FastPathValidatorEntry = set.validators.iter_mut()
                .find(|entry| entry.id == decoded.validator()).unwrap();
            target.public_key = network.signers[0].id.as_bytes().to_vec();
            for replica in 0..REPLICAS {
                network.put(replica, key.clone(), StateMutation::Put(
                    fast_path::records::encode_fastpath_validator_set_record(&set).unwrap(),
                ));
            }
        } else {
            let mut intent: SlashIntent = decode_slash_intent(&candidate.intent).unwrap();
            intent.conflict_digest = Digest32::new(HashAlgorithmId::Sha3_256, intent.conflict_digest.bytes());
            candidate.intent = encode_slash_intent(&intent).unwrap();
            let key: Vec<u8> = fastpath_equivocation_evidence_key(
                &fixture::chain(), intent.evidence_epoch, *intent.validator_id.as_bytes(), intent.conflict_digest,
            ).unwrap();
            // Negative-only counterfeit selector: equal payload hash bytes
            // with a different algorithm must not validate the real proof.
            for replica in 0..REPLICAS {
                network.put(replica, key.clone(), StateMutation::Put(
                    encode_fastpath_equivocation_evidence_record(&record).unwrap(),
                ));
            }
        }
        assert_fresh_rejected(network, &candidate);
    }
}

#[test]
fn correctly_signed_foreign_protocol_evidence_is_rejected_only_by_fresh_protocol_gate() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    commit_producer(network, 0);
    let foreign: ProtocolVersion = ProtocolVersion::new(fixture::protocol().protocol_version().get() + 1);
    let certifier: consensus::FastPathCertifier = consensus::FastPathCertifier::new(
        fixture::chain(), foreign, fixture::protocol().epoch(), validator_set(&network.signers),
    ).unwrap();
    let a: consensus::FastVote = certifier.cast_vote(
        digest32(1), digest32(2), digest32(3), &network.signers[1],
    ).unwrap();
    let b: consensus::FastVote = certifier.cast_vote(
        digest32(1), digest32(4), digest32(3), &network.signers[1],
    ).unwrap();
    let proof: DecodedEquivocationEvidence = DecodedEquivocationEvidence::FastVote(
        consensus::build_fast_vote_equivocation_evidence(&a, &b).unwrap(),
    );
    let candidate: OrderedCandidate = slash_candidate(&fixture, &proof);
    let intent: SlashIntent = decode_slash_intent(&candidate.intent).unwrap();
    let record: FastPathEquivocationEvidenceRecord = FastPathEquivocationEvidenceRecord {
        evidence_bytes: encode_proof(&proof), recorded_at_checkpoint: 11,
    };
    // Prove this negative is not a bad signature or an accidental new
    // restriction in historical execution's shared pure helpers.
    let historical: DecodedEquivocationEvidence =
        bond_lifecycle::slash::verify_evidence_identity(&network.resolver, &intent, &record).unwrap();
    bond_lifecycle::slash::verify_evidence_proof(&historical, validator_set(&network.signers)).unwrap();
    let key: Vec<u8> = proof_key(network, &proof);
    for replica in 0..REPLICAS {
        // Deliberately foreign authority is injected only as a refusal
        // fixture; the real ordered Evidence producer would reject it.
        network.put(replica, key.clone(), StateMutation::Put(
            encode_fastpath_equivocation_evidence_record(&record).unwrap(),
        ));
    }
    for error in assert_fresh_rejected(network, &candidate) {
        assert!(matches!(error, OrderedEconomicsError::Prerequisite(
            "fresh bond slash evidence protocol is not the pinned profile protocol"
        )));
    }
}

#[test]
fn justified_real_evidence_prefix_completes_before_fresh_slash_vote_gate() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let submission: OrderedEvidenceSubmission = evidence_submissions(network, 11).remove(0);
    let producer: OrderedCandidate = evidence_candidate(&submission, PRODUCER);
    let proof: DecodedEquivocationEvidence = decoded_submission(network, 0);
    network.round(1, Some(&producer));
    network.round(2, None);
    let (terminal, _): (QuorumCertificate, OrderedProposal) = network.certify(3, None);
    let leader: usize = network.leader_index(4);
    let delayed: usize = (leader + 1) % REPLICAS;
    for replica in 0..REPLICAS {
        if replica != delayed {
            process_certificate(&network.stores[replica], &network.context, &network.env(), &terminal).unwrap();
        }
    }
    let key: Vec<u8> = proof_key(network, &proof);
    assert!(network.value(delayed, &key).is_none());
    assert!(receipt(network, delayed, PRODUCER).is_none());
    let candidate: OrderedCandidate = slash_candidate(&fixture, &proof);
    let proposal: OrderedProposal = propose(
        &network.stores[leader], &network.context, &network.env(), Some(&candidate), &network.signers[leader],
    ).unwrap();
    let store: AttemptStore<'_> = AttemptStore::new(network, delayed);
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[delayed], calls: Cell::new(0),
    };
    let output: OrderedEventOutput =
        process_proposal(&store, &network.context, &network.env(), &proposal, &signer).unwrap();
    assert_eq!(output.committed.len(), 1);
    assert_eq!(output.committed[0].request_id, PRODUCER);
    assert_eq!(signer.calls.get(), 1);
    assert!(store.count_commits() >= 2, "actual prior completion and fresh admission are distinct");
    assert!(receipt(network, delayed, PRODUCER).is_some());
    assert!(network.value(delayed, &key).is_some());
    assert!(receipt(network, delayed, SLASH).is_none());
    assert!(output.messages.iter().any(|message| matches!(message, ConsensusMessage::Vote(_))));
}

#[test]
fn every_deciding_revision_race_rejects_actual_commit_without_exposing_new_signature() {
    for vote in [false, true] {
        for deciding in 0..3usize {
            let fixture: CausalFixture = fresh_fixture();
            let network: &Network = &fixture.network;
            let record: FastPathEquivocationEvidenceRecord = commit_producer(network, 0);
            let proof: DecodedEquivocationEvidence = decode_dispatched(&record.evidence_bytes).unwrap();
            let candidate: OrderedCandidate = slash_candidate(&fixture, &proof);
            let proposal: OrderedProposal = raw_proposal(network, &candidate);
            let leader: usize = network.leader_index(4);
            let replica: usize = if vote { (leader + 1) % REPLICAS } else { leader };
            let key: Vec<u8> = match deciding {
                0 => proof_key(network, &proof),
                1 => fastpath_epoch_record_key(&fixture::chain()).unwrap(),
                _ => fastpath_validator_set_key(&fixture::protocol()).unwrap(),
            };
            let revision: StateRevision = network.revision(replica, &key);
            let mut store: AttemptStore<'_> = AttemptStore::new(network, replica);
            store.race = Some((RaceAt::Commit, key.clone()));
            let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
                signer: &network.signers[replica], calls: Cell::new(0),
            };
            let error: OrderedEconomicsError = if vote {
                process_proposal(&store, &network.context, &network.env(), &proposal, &signer).unwrap_err()
            } else {
                propose(&store, &network.context, &network.env(), Some(&candidate), &signer).unwrap_err()
            };
            assert!(matches!(error, OrderedEconomicsError::Node(NodeCoreError::DurableCommitRejected(_))));
            assert_eq!(signer.calls.get(), 1, "private real signing can precede a CAS rejection");
            assert_eq!(store.count_commits(), 1);
            assert!(store.committed_reads.borrow().iter().any(|read|
                read.key() == key.as_slice() && read.expected_revision() == revision));
            assert!(store.raced.get());
            assert_same_records_and_blobs(&capture(network, replica), store.after_race.borrow().as_ref().unwrap());
            assert!(receipt(network, replica, SLASH).is_none());
        }
    }
}

#[test]
fn repeated_epoch_observation_conflict_remains_sticky_over_committee_prerequisite_error() {
    for vote in [false, true] {
        let fixture: CausalFixture = fresh_fixture();
        let network: &Network = &fixture.network;
        let record: FastPathEquivocationEvidenceRecord = commit_producer(network, 0);
        let proof: DecodedEquivocationEvidence = decode_dispatched(&record.evidence_bytes).unwrap();
        let candidate: OrderedCandidate = slash_candidate(&fixture, &proof);
        let proposal: OrderedProposal = raw_proposal(network, &candidate);
        let leader: usize = network.leader_index(4);
        let replica: usize = if vote { (leader + 1) % REPLICAS } else { leader };
        let mut store: AttemptStore<'_> = AttemptStore::new(network, replica);
        store.race = Some((RaceAt::SecondRead, fastpath_epoch_record_key(&fixture::chain()).unwrap()));
        let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
            signer: &network.signers[replica], calls: Cell::new(0),
        };
        let error: OrderedEconomicsError = if vote {
            process_proposal(&store, &network.context, &network.env(), &proposal, &signer).unwrap_err()
        } else {
            propose(&store, &network.context, &network.env(), Some(&candidate), &signer).unwrap_err()
        };
        assert!(matches!(error, OrderedEconomicsError::Node(NodeCoreError::StateConflict)));
        assert!(store.raced.get());
        assert_eq!(signer.calls.get(), 0);
        assert_eq!(store.count_commits(), 0);
        assert_same_records_and_blobs(&capture(network, replica), store.after_race.borrow().as_ref().unwrap());
    }
}

#[test]
fn retained_signatures_replay_after_evidence_loss_but_committed_slash_apply_still_stops() {
    let fixture: CausalFixture = fresh_fixture();
    let network: &Network = &fixture.network;
    let record: FastPathEquivocationEvidenceRecord = commit_producer(network, 0);
    let proof: DecodedEquivocationEvidence = decode_dispatched(&record.evidence_bytes).unwrap();
    let candidate: OrderedCandidate = slash_candidate(&fixture, &proof);
    let key: Vec<u8> = proof_key(network, &proof);
    let leader: usize = network.leader_index(4);
    // Keep the leader at view four until its retained proposal is replayed.
    // A complete certify() first would advance its local view past this record.
    let proposal4: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader],
    )
    .unwrap();
    network.put(leader, key.clone(), StateMutation::Delete);
    let before: SourceBusinessSnapshot = capture(network, leader);
    let store: AttemptStore<'_> = AttemptStore::new(network, leader);
    let signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[leader], calls: Cell::new(0),
    };
    assert_eq!(propose(&store, &network.context, &network.env(), Some(&candidate), &signer).unwrap(), proposal4);
    assert_eq!(signer.calls.get(), 0);
    assert_eq!(store.count_commits(), 0);
    assert!(!store.reads.borrow().contains_key(&key));
    assert_same_records_and_blobs(&capture(network, leader), &before);

    // Only the other three healthy replicas make fresh votes. Each signature
    // below comes from its actual signer after verifying genuine evidence.
    let mut votes: Vec<consensus::ConsensusVote> = Vec::new();
    for replica in 0..REPLICAS {
        if replica == leader {
            continue;
        }
        let output: OrderedEventOutput = process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &proposal4,
            &network.signers[replica],
        )
        .unwrap();
        let vote: consensus::ConsensusVote = output
            .messages
            .iter()
            .find_map(|message| match message {
                ConsensusMessage::Vote(vote) => Some(vote.clone()),
                _ => None,
            })
            .unwrap();
        votes.push(vote);
    }
    let voter: usize = (leader + 1) % REPLICAS;
    network.put(voter, key.clone(), StateMutation::Delete);
    let before_vote: SourceBusinessSnapshot = capture(network, voter);
    let vote_store: AttemptStore<'_> = AttemptStore::new(network, voter);
    let vote_signer: CountingConsensusSigner<'_> = CountingConsensusSigner {
        signer: &network.signers[voter], calls: Cell::new(0),
    };
    let replayed: OrderedEventOutput =
        process_proposal(&vote_store, &network.context, &network.env(), &proposal4, &vote_signer).unwrap();
    assert!(replayed.messages.iter().any(|message| matches!(message, ConsensusMessage::Vote(_))));
    assert_eq!(vote_signer.calls.get(), 0);
    assert_eq!(vote_store.count_commits(), 0);
    assert!(!vote_store.reads.borrow().contains_key(&key));
    assert_same_records_and_blobs(&capture(network, voter), &before_vote);
    let certificate4: QuorumCertificate = network
        .policy
        .engine()
        .certificate_from_votes(
            &proposal4.proposal,
            &votes,
            &consensus::Ed25519ConsensusVerifier::new(
                consensus::UnsupportedSignatureSchemeResponse::InvalidSignature,
            ),
        )
        .unwrap()
        .unwrap();
    for replica in 0..REPLICAS {
        process_certificate(&network.stores[replica], &network.context, &network.env(), &certificate4).unwrap();
    }
    network.round(5, None);
    let (terminal, _): (QuorumCertificate, OrderedProposal) = network.certify(6, None);
    let before_apply: SourceBusinessSnapshot = capture(network, leader);
    let apply_store: AttemptStore<'_> = AttemptStore::new(network, leader);
    let error: OrderedEconomicsError =
        process_certificate(&apply_store, &network.context, &network.env(), &terminal).unwrap_err();
    assert!(matches!(error, OrderedEconomicsError::Prerequisite(
        "bond slash names evidence that is not recorded locally"
    )));
    assert_eq!(apply_store.count_commits(), 0);
    assert_same_records_and_blobs(&capture(network, leader), &before_apply);
    assert!(receipt(network, leader, SLASH).is_none());
    assert!(query_ordered_outcome(&apply_store, &network.context, &network.env(), &SLASH).unwrap().is_none());
    assert!(network.value(leader, &engine::ordered_reservation_key_for_tests(&fixture::chain(), &SLASH)).is_some());
}

#[test]
fn signerless_reconciliation_keeps_authentic_slash_bytes_without_fresh_evidence_grant() {
    let source: CausalFixture = fresh_fixture();
    let target: CausalFixture = fresh_fixture();
    let proof: DecodedEquivocationEvidence = decoded_submission(&source.network, 0);
    let candidate: OrderedCandidate = slash_candidate(&source, &proof);
    let proposal: OrderedProposal = raw_proposal(&source.network, &candidate);
    let network: &Network = &target.network;
    let store: AttemptStore<'_> = AttemptStore::new(network, 0);
    let observed: OrderedEventOutput =
        observe_proposal(&store, &network.context, &network.env(), &proposal).unwrap();
    assert!(observed.messages.is_empty());
    assert!(observed.committed.is_empty());
    assert_eq!(store.count_commits(), 1, "actual authenticated metadata retention only");
    assert!(network.value(0, &proof_key(network, &proof)).is_none());
    assert!(receipt(network, 0, SLASH).is_none());
    assert!(network.value(0, &engine::ordered_reservation_key_for_tests(&fixture::chain(), &SLASH)).is_none());
    let before: SourceBusinessSnapshot = capture(network, 0);
    let replay: AttemptStore<'_> = AttemptStore::new(network, 0);
    observe_proposal(&replay, &network.context, &network.env(), &proposal).unwrap();
    assert_eq!(replay.count_commits(), 0);
    assert_same_records_and_blobs(&capture(network, 0), &before);
}

#[test]
fn actual_certified_evidence_and_slash_prefix_recovers_without_a_local_signer_for_every_family() {
    for family in 0..3usize {
        let source: CausalFixture = fresh_fixture();
        let target: CausalFixture = fresh_fixture();
        let network: &Network = &source.network;
        let proof: DecodedEquivocationEvidence = decoded_submission(network, family);
        let submission: OrderedEvidenceSubmission = evidence_submissions(network, 11).remove(family);
        let producer: OrderedCandidate = evidence_candidate(&submission, PRODUCER);
        let slash: OrderedCandidate = slash_candidate(&source, &proof);
        let mut artifacts: Vec<(OrderedProposal, QuorumCertificate)> = Vec::new();
        for view in 1..=6u64 {
            let candidate: Option<&OrderedCandidate> = match view {
                1 => Some(&producer),
                4 => Some(&slash),
                _ => None,
            };
            let (_, certificate, proposal): (Vec<OrderedEventOutput>, QuorumCertificate, OrderedProposal) =
                network.round(view, candidate);
            artifacts.push((proposal, certificate));
        }
        let recovering: &Network = &target.network;
        let store: AttemptStore<'_> = AttemptStore::new(recovering, 0);
        for (proposal, certificate) in &artifacts {
            let observed: OrderedEventOutput =
                observe_proposal(&store, &recovering.context, &recovering.env(), proposal).unwrap();
            assert!(observed.messages.is_empty());
            let completed: OrderedEventOutput =
                process_certificate(&store, &recovering.context, &recovering.env(), certificate).unwrap();
            assert!(completed.messages.is_empty());
        }
        let source_outcome: OrderedOutcome = query_ordered_outcome(
            &network.stores[0], &network.context, &network.env(), &SLASH,
        ).unwrap().unwrap();
        let recovered_outcome: OrderedOutcome = query_ordered_outcome(
            &store, &recovering.context, &recovering.env(), &SLASH,
        ).unwrap().unwrap();
        assert_eq!(source_outcome, recovered_outcome);
        assert_eq!(receipt(network, 0, PRODUCER), receipt(recovering, 0, PRODUCER));
        assert_eq!(receipt(network, 0, SLASH), receipt(recovering, 0, SLASH));
        let intent: SlashIntent = decode_slash_intent(&slash.intent).unwrap();
        let key: Vec<u8> = fastpath_bond_record_key(&fixture::chain(), &intent.validator_id).unwrap();
        let bond: FastPathBondRecord =
            decode_fastpath_bond_record(&network.value(0, &key).unwrap()).unwrap();
        assert_eq!(network.value(0, &key), recovering.value(0, &key));
        assert_eq!(current_object(network, 0, bond.custody_object.id),
            current_object(recovering, 0, bond.custody_object.id));
        // These signerless APIs have no signer parameter. Their actual
        // persisted completion must not install any local signing identity.
        for view in 1..=6u64 {
            assert!(recovering.value(0, &engine::ordered_leader_record_key_for_tests(&fixture::chain(), view)).is_none());
            assert!(recovering.value(0, &engine::ordered_vote_record_key_for_tests(&fixture::chain(), view)).is_none());
        }
        let before: SourceBusinessSnapshot = capture(recovering, 0);
        let replay: AttemptStore<'_> = AttemptStore::new(recovering, 0);
        for (proposal, certificate) in &artifacts {
            observe_proposal(&replay, &recovering.context, &recovering.env(), proposal).unwrap();
            process_certificate(&replay, &recovering.context, &recovering.env(), certificate).unwrap();
        }
        assert_eq!(replay.count_commits(), 0);
        assert_same_records_and_blobs(&capture(recovering, 0), &before);
    }
}
