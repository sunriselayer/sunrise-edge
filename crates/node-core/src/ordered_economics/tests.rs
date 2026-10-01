//! Real-key, four-independent-store coverage for the DR-0153 orchestrator.
//!
//! Nothing here mocks a handler body, stubs a consensus transition or skips.
//! Each of the four replicas is its own [`MemoryDurableStateStore`] with the
//! same independently signed genesis manifest installed, and every proposal,
//! vote and certificate is produced by the real
//! `consensus::ChainedHotStuff` from real Ed25519 signers whose registered
//! keys are exactly the keys that authorize the committed bond rows. Business
//! effects come from the unmodified `bond_lifecycle`/`fee_claims` handlers.
use super::*;
use bond_lifecycle::{
    BondLifecycleIntent, BondLifecycleOperation, SignedBondLifecycleIntent,
    bond_lifecycle_intent_digest, bond_lifecycle_signing_frame, bond_row_digest,
    encode_signed_bond_lifecycle_intent,
};
use bonds::BondResourceId;
use consensus::{ConsensusMessage, ConsensusSigner, ConsensusVote, QuorumCertificate};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::LocalWasmExecutionEngine;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy, SignedLocalExecutionIntent,
    encode_signed_local_execution, local_execution_signing_frame,
};
use execution::publication::PublicationContext;
use fast_path::records::{
    FastPathBondRecord, FastPathBondState, FastPathFeeShare, FastPathSettlementRecord,
    decode_fastpath_bond_record, decode_fastpath_settlement_record, encode_fastpath_bond_record,
    encode_fastpath_settlement_record,
};
use fast_path::{FastPathValidatorEntry, FastPathValidatorSetRecord};
use genesis::{GenesisManifest, GenesisObjectEntry, tests as fixture};
use local_instance_state::{
    decode_fastpath_nonce_lock_record, fastpath_bond_record_key, fastpath_epoch_record_key,
    fastpath_nonce_lock_key,
};
use objects::{Address, ObjectId};
use protocol_types::{Digest32, HashAlgorithmId, SignatureSchemeId, ValidatorId};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableDomainStateStore,
    MemoryBlobStore, MemoryDurableStateStore, StateMutation, StateMutationEntry,
    StateReadAssertion, WriterFenceGeneration,
};
use validator_set::{ValidatorInfo, ValidatorSet};

const REPLICAS: usize = 4;
#[path = "tests/causal_placement.rs"]
mod causal_placement;
#[path = "tests/drain_boundaries.rs"]
mod drain_boundaries;
#[path = "tests/freeze_boundaries.rs"]
mod freeze_boundaries;
#[path = "tests/ordered_history.rs"]
mod ordered_history_tests;
/// The trusted local clock value the operator installs genesis with. Never a
/// remote timestamp and never a storage deadline.
const TRUSTED_NOW_MILLIS: u64 = 1_700_000_000_000;

struct TestSigner {
    id: ValidatorId,
    key: SigningKey,
}

impl ConsensusSigner for TestSigner {
    fn validator_id(&self) -> ValidatorId {
        self.id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.key.sign(framed).into();
        Ok(signature.to_vec())
    }
}

/// Four real Ed25519 identities. Validator zero is the genesis fixture's own
/// signer, so its *registered consensus key is the same key that authorizes
/// its committed bond row* -- which is exactly what lets
/// `authenticate_candidate` verify a bond-lifecycle outer signature purely
/// against the pinned set, and what `preflight` re-checks against the
/// committed row before any fresh work.
fn signers() -> Vec<TestSigner> {
    let mut signers: Vec<TestSigner> = vec![TestSigner {
        id: ValidatorId::new(fixture::sender()),
        key: fixture::key(),
    }];
    for index in 1u8..REPLICAS as u8 {
        let key: SigningKey = SigningKey::from([0x90 + index; 32]);
        let public: [u8; 32] = VerificationKey::from(&key).into();
        signers.push(TestSigner {
            id: ValidatorId::new(public),
            key,
        });
    }
    signers
}

fn validator_set(signers: &[TestSigner]) -> ValidatorSet {
    ValidatorSet::new(
        Epoch::new(0),
        signers
            .iter()
            .map(|signer| ValidatorInfo {
                id: signer.id,
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: signer.id.as_bytes().to_vec(),
            })
            .collect(),
    )
    .unwrap()
}

/// One signed genesis manifest whose FastVote validator set is exactly the
/// four consensus identities, each with its own genesis bond custody object
/// (DR-0136 requires exactly one per validator).
fn four_validator_manifest(signers: &[TestSigner]) -> GenesisManifest {
    let (mut manifest, _, _, _, _) = fixture::build_fixture();
    let mut entries: Vec<FastPathValidatorEntry> = signers
        .iter()
        .map(|signer| FastPathValidatorEntry {
            id: signer.id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: signer.id.as_bytes().to_vec(),
        })
        .collect();
    entries.sort_by_key(|entry| entry.id);
    manifest.validator_set = FastPathValidatorSetRecord {
        context: fixture::protocol(),
        validators: entries,
    };
    let mut custody: Vec<GenesisObjectEntry> = Vec::new();
    for (index, signer) in signers.iter().enumerate() {
        let mut entry = fixture::custody_object_entry(
            &manifest,
            ObjectId::new([0x40 + index as u8; 32]),
            fixture::chain(),
        );
        // `custody_object_entry` scopes to the first validator; retarget the
        // scope subject to this validator so genesis derives its own bond.
        if let objects::Owner::ProtocolCustody(scope) = &mut entry.object.owner {
            scope.subject = *signer.id.as_bytes();
        }
        custody.push(entry);
    }
    manifest.objects.extend(custody);
    fixture::resign_manifest(&mut manifest);
    manifest
}

/// Every borrowed dependency, owned so each test builds its own
/// [`OrderedEconomicsEnvironment`] against local bindings.
struct Network {
    stores: Vec<MemoryDurableStateStore>,
    context: DurableOperationContext,
    policy: OrderedEconomicsPolicy,
    leg_policy: LocalExecutionPolicy,
    engine: LocalWasmExecutionEngine,
    blobs: MemoryBlobStore,
    resolver: HashSuiteResolver,
    history: Vec<HashSuiteResolver>,
    signers: Vec<TestSigner>,
    /// Validator zero's committed genesis bond, identical on every replica.
    bond: FastPathBondRecord,
}

fn setup() -> Network {
    setup_with_freeze_height(0)
}

fn setup_with_freeze_height(minimum_freeze_block_height: u64) -> Network {
    let signers: Vec<TestSigner> = signers();
    let mut manifest: GenesisManifest = four_validator_manifest(&signers);
    if minimum_freeze_block_height != 0 {
        manifest.commitment_profile =
            crate::logical_generation::CommitmentProfile::LogicalGenerationV2;
        manifest.minimum_freeze_block_height = minimum_freeze_block_height;
        fixture::resign_manifest(&mut manifest);
    }
    let context: DurableOperationContext = fixture::context(1);
    let mut stores: Vec<MemoryDurableStateStore> = Vec::with_capacity(REPLICAS);
    for _ in 0..REPLICAS {
        let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
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
    let bond_key: Vec<u8> =
        fastpath_bond_record_key(&fixture::chain(), &ValidatorId::new(fixture::sender())).unwrap();
    let bond: FastPathBondRecord = decode_fastpath_bond_record(
        stores[0]
            .get_versioned_durable(&context, fixture::domain(), &bond_key)
            .unwrap()
            .value()
            .unwrap(),
    )
    .unwrap();
    let policy: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
        fixture::protocol(),
        fixture::domain(),
        genesis::genesis_manifest_commitment(&fixture::resolver(), &manifest).unwrap(),
        Some(&manifest),
        validator_set(&signers),
        fixture::resolver(),
    )
    .unwrap();
    Network {
        stores,
        context,
        policy,
        leg_policy: LocalExecutionPolicy::generic_object_results(fixture::protocol()),
        engine: LocalWasmExecutionEngine::new(),
        blobs: MemoryBlobStore::default(),
        resolver: fixture::resolver(),
        history: Vec::new(),
        signers,
        bond,
    }
}

impl Network {
    fn env(&self) -> OrderedEconomicsEnvironment<'_> {
        OrderedEconomicsEnvironment {
            policy: &self.policy,
            resolver: &self.resolver,
            history: &self.history,
            leg_policy: &self.leg_policy,
            engine: &self.engine,
            blobs: &self.blobs,
        }
    }

    fn install_ordered(&self) {
        for store in &self.stores {
            install_ordered_genesis(store, &self.context, &self.env(), TRUSTED_NOW_MILLIS).unwrap();
        }
    }

    fn leader_index(&self, view: u64) -> usize {
        let leader = self.policy.engine().validator_set().leader(view).unwrap();
        self.signers
            .iter()
            .position(|signer| signer.id == leader)
            .unwrap()
    }

    fn domain(&self) -> AtomicityDomainId {
        self.policy.domain()
    }

    fn value(&self, replica: usize, key: &[u8]) -> Option<Vec<u8>> {
        self.stores[replica]
            .get_versioned_durable(&self.context, self.domain(), key)
            .unwrap()
            .value()
            .map(<[u8]>::to_vec)
    }

    fn revision(&self, replica: usize, key: &[u8]) -> StateRevision {
        self.stores[replica]
            .get_versioned_durable(&self.context, self.domain(), key)
            .unwrap()
            .revision()
    }

    fn bond_key(&self) -> Vec<u8> {
        fastpath_bond_record_key(&fixture::chain(), &self.bond.validator_id).unwrap()
    }

    fn committed_bond(&self, replica: usize) -> FastPathBondRecord {
        decode_fastpath_bond_record(&self.value(replica, &self.bond_key()).unwrap()).unwrap()
    }

    /// Every durable row this feature can touch, plus the business rows it
    /// must not touch, as `(key, revision, value)` triples -- the snapshot an
    /// exact-replay test compares.
    fn snapshot(
        &self,
        replica: usize,
        request_ids: &[[u8; 32]],
        views: u64,
    ) -> Vec<(Vec<u8>, StateRevision, Option<Vec<u8>>)> {
        let chain = fixture::chain();
        let mut keys: Vec<Vec<u8>> = vec![
            engine::ordered_state_key_for_tests(&chain),
            engine::ordered_applied_height_key_for_tests(&chain),
            engine::ordered_vote_high_key_for_tests(&chain),
            self.bond_key(),
            fastpath_epoch_record_key(&chain).unwrap(),
        ];
        for view in 1..=views {
            keys.push(engine::ordered_leader_record_key_for_tests(&chain, view));
            keys.push(engine::ordered_vote_record_key_for_tests(&chain, view));
        }
        for request_id in request_ids {
            keys.push(engine::ordered_request_header_key_for_tests(
                &chain, request_id,
            ));
            keys.push(engine::ordered_reservation_key_for_tests(
                &chain, request_id,
            ));
        }
        keys.into_iter()
            .map(|key| {
                let revision = self.revision(replica, &key);
                let value = self.value(replica, &key);
                (key, revision, value)
            })
            .collect()
    }

    /// Proposes for `view` on the real leader's own store, has every replica
    /// process the proposal (which is the only path that signs a vote), and
    /// aggregates the real votes into a real quorum certificate -- without
    /// applying it anywhere yet.
    fn certify(
        &self,
        view: u64,
        candidate: Option<&OrderedCandidate>,
    ) -> (QuorumCertificate, OrderedProposal) {
        let voters: Vec<usize> = (0..REPLICAS).collect();
        self.certify_on(&voters, view, candidate)
    }

    /// [`Self::certify`] restricted to `voters`, for a test in which one
    /// replica is expected to fail closed and must therefore not vote.
    fn certify_on(
        &self,
        voters: &[usize],
        view: u64,
        candidate: Option<&OrderedCandidate>,
    ) -> (QuorumCertificate, OrderedProposal) {
        let leader = self.leader_index(view);
        let ordered_proposal: OrderedProposal = propose(
            &self.stores[leader],
            &self.context,
            &self.env(),
            candidate,
            &self.signers[leader],
        )
        .unwrap();
        assert_eq!(ordered_proposal.proposal.view, view);
        let mut votes: Vec<ConsensusVote> = Vec::new();
        for &replica in voters {
            let output = process_proposal(
                &self.stores[replica],
                &self.context,
                &self.env(),
                &ordered_proposal,
                &self.signers[replica],
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
        let certificate: QuorumCertificate = self
            .policy
            .engine()
            .certificate_from_votes(
                &ordered_proposal.proposal,
                &votes,
                &super::policy::Ed25519ConsensusVerifier,
            )
            .unwrap()
            .expect("four independent votes reach quorum");
        (certificate, ordered_proposal)
    }

    /// Drives one complete propose/vote/certify/apply round across all four
    /// replicas using the real engine, and returns each replica's output from
    /// applying the resulting real quorum certificate.
    fn round(
        &self,
        view: u64,
        candidate: Option<&OrderedCandidate>,
    ) -> (Vec<OrderedEventOutput>, QuorumCertificate, OrderedProposal) {
        let (certificate, ordered_proposal) = self.certify(view, candidate);
        let outputs: Vec<OrderedEventOutput> = (0..REPLICAS)
            .map(|replica| {
                process_certificate(
                    &self.stores[replica],
                    &self.context,
                    &self.env(),
                    &certificate,
                )
                .unwrap()
            })
            .collect();
        (outputs, certificate, ordered_proposal)
    }

    /// A replica that leads none of `views`, so a test can use it as an
    /// offline/observer peer without accidentally having it write the very
    /// rows the test asserts are absent.
    fn non_leader(&self, views: &[u64]) -> usize {
        (0..REPLICAS)
            .find(|replica| {
                !views
                    .iter()
                    .any(|view| self.leader_index(*view) == *replica)
            })
            .expect("four replicas and at most two leader views leave one spare")
    }

    fn put(&self, replica: usize, key: Vec<u8>, mutation: StateMutation) {
        let revision = self.revision(replica, &key);
        let transaction = AtomicStateTransaction::new(
            self.domain(),
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), revision).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()])
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            self.stores[replica].commit_durable(&self.context, transaction),
            DurableCommitOutcome::Committed
        );
    }
}

/// Predicts the exact next row a real `Unbond` against `bond` commits. The
/// fixture's committed economics policy sets `unbonding_epochs = 7`.
fn predicted_unbond(
    bond: &FastPathBondRecord,
    checkpoint: u64,
    recipient: [u8; 32],
) -> FastPathBondRecord {
    let mut next = bond.clone();
    next.generation = bond.generation.checked_add(1).unwrap();
    next.committed_at_checkpoint = checkpoint;
    next.lifecycle_epoch = fixture::protocol().epoch();
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient,
    };
    next
}

fn sign_bond_lifecycle(
    resolver: &HashSuiteResolver,
    intent: BondLifecycleIntent,
) -> SignedBondLifecycleIntent {
    let digest = bond_lifecycle_intent_digest(resolver, &intent).unwrap();
    let frame = bond_lifecycle_signing_frame(&intent.context, digest).unwrap();
    SignedBondLifecycleIntent {
        signature: fixture::key().sign(&frame).into(),
        intent,
    }
}

fn unbond_candidate(
    network: &Network,
    previous: &FastPathBondRecord,
    next: &FastPathBondRecord,
    request_id: [u8; 32],
    recipient: Address,
    created_checkpoint: u64,
) -> OrderedCandidate {
    let resolver = &network.resolver;
    let intent = BondLifecycleIntent {
        context: fixture::protocol(),
        request_id,
        validator_id: previous.validator_id,
        resource_id: BondResourceId::new(previous.resource_domain, previous.resource).unwrap(),
        expected_generation: previous.generation,
        expected_previous_row_digest: bond_row_digest(
            resolver,
            previous.lifecycle_epoch,
            &encode_fastpath_bond_record(previous).unwrap(),
        )
        .unwrap(),
        expected_next_row_digest: bond_row_digest(
            resolver,
            next.lifecycle_epoch,
            &encode_fastpath_bond_record(next).unwrap(),
        )
        .unwrap(),
        operation: BondLifecycleOperation::Unbond { recipient },
    };
    OrderedCandidate {
        context: fixture::protocol(),
        request_id,
        kind: OrderedOperationKind::BondLifecycle,
        intent: encode_signed_bond_lifecycle_intent(&sign_bond_lifecycle(resolver, intent))
            .unwrap(),
        created_checkpoint,
    }
}

/// A syntactically valid, really signed local-execution release leg. It is
/// authenticated (signature, request id, context, policy digest) but this
/// candidate is refused before execution, so the leg is never run -- which is
/// exactly the property under test.
fn release_leg(request_id: [u8; 32], nonce: u64) -> Vec<u8> {
    let (_, origin, _, _, coin_id) = fixture::build_fixture();
    let policy = LocalExecutionPolicy::generic_object_results(fixture::protocol());
    let code = execution::publication::UnverifiedDependencyRef::new(
        origin.clone(),
        1,
        fixture::protocol(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]),
    )
    .unwrap();
    let intent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&fixture::resolver()).unwrap(),
        call: execution::call::CallIntent {
            context: fixture::protocol(),
            request_id,
            sender: fixture::sender(),
            nonce,
            code: code.clone(),
            instance: execution::call::InstanceTarget {
                creator: fixture::sender(),
                seed: [2; 32],
                revision: 1,
                record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x44; 32]),
            },
            entrypoint: "transfer".into(),
            type_arguments: Vec::new(),
            access: abi::AccessManifest {
                entries: vec![abi::AccessEntry {
                    object_ref: objects::ObjectRef {
                        id: coin_id,
                        version: 1,
                        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]),
                    },
                    mode: objects::AccessMode::Write,
                }],
            },
            arguments: Vec::new(),
            gas_limit: 100_000,
        },
        authorizations: Vec::new(),
    };
    let frame = local_execution_signing_frame(&fixture::protocol(), &intent).unwrap();
    encode_signed_local_execution(&SignedLocalExecutionIntent {
        signature: fixture::key().sign(&frame).into(),
        intent,
    })
    .unwrap()
}

/// A `Withdraw` candidate against an `Active` bond: really signed, really
/// authenticated, and guaranteed to be refused as `IneligibleState` -- so it
/// exercises admission-time reservation plus a typed refusal that releases it.
fn withdraw_candidate(network: &Network, request_id: [u8; 32], nonce: u64) -> OrderedCandidate {
    let previous = &network.bond;
    let intent = BondLifecycleIntent {
        context: fixture::protocol(),
        request_id,
        validator_id: previous.validator_id,
        resource_id: BondResourceId::new(previous.resource_domain, previous.resource).unwrap(),
        expected_generation: previous.generation,
        expected_previous_row_digest: bond_row_digest(
            &network.resolver,
            previous.lifecycle_epoch,
            &encode_fastpath_bond_record(previous).unwrap(),
        )
        .unwrap(),
        // Never reached: the operation is refused on the committed row's own
        // state before any resulting row is derived.
        expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
        operation: BondLifecycleOperation::Withdraw {
            leg: release_leg(request_id, nonce),
        },
    };
    OrderedCandidate {
        context: fixture::protocol(),
        request_id,
        kind: OrderedOperationKind::BondLifecycle,
        intent: encode_signed_bond_lifecycle_intent(&sign_bond_lifecycle(
            &network.resolver,
            intent,
        ))
        .unwrap(),
        created_checkpoint: 11,
    }
}

fn refusal_of(outcome: &OrderedOutcome) -> OrderedRefusal {
    assert_eq!(
        outcome.output.responses()[0].status(),
        NodeResponseStatus::Rejected
    );
    decode_ordered_refusal_payload(outcome.output.responses()[0].payload().unwrap()).unwrap()
}

/// A canonical prime-order Ed25519 owner address, which is what every signed
/// payout/release recipient must be.
fn address_of(seed: u8) -> Address {
    Address::new(VerificationKey::from(&SigningKey::from([seed; 32])).into())
}

// --- authority anchor -----------------------------------------------------

#[test]
fn authority_anchor_binds_domain_genesis_epoch_and_validator_set_identity() {
    let signers = signers();
    let set = validator_set(&signers);
    let resolver = fixture::resolver();
    let genesis = Digest32::new(HashAlgorithmId::Sha2_256, [1; 32]);
    let base = ordered_economics_authority_anchor(
        &resolver,
        &fixture::protocol(),
        fixture::domain(),
        genesis,
        0,
        &set,
    )
    .unwrap();

    // The raw genesis digest alone is never the anchor.
    assert_ne!(base, genesis);

    // A different atomicity domain, genesis digest or validator set all
    // produce a different anchor, so two profiles cannot share a genesis
    // block and accept one another's certificates.
    let other_domain = ordered_economics_authority_anchor(
        &resolver,
        &fixture::protocol(),
        AtomicityDomainId::new([9; 32]).unwrap(),
        genesis,
        0,
        &set,
    )
    .unwrap();
    assert_ne!(base, other_domain);
    let other_genesis = ordered_economics_authority_anchor(
        &resolver,
        &fixture::protocol(),
        fixture::domain(),
        Digest32::new(HashAlgorithmId::Sha2_256, [2; 32]),
        0,
        &set,
    )
    .unwrap();
    assert_ne!(base, other_genesis);
    let smaller = ValidatorSet::new(
        Epoch::new(0),
        vec![ValidatorInfo {
            id: signers[0].id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: signers[0].id.as_bytes().to_vec(),
        }],
    )
    .unwrap();
    let other_set = ordered_economics_authority_anchor(
        &resolver,
        &fixture::protocol(),
        fixture::domain(),
        genesis,
        0,
        &smaller,
    )
    .unwrap();
    assert_ne!(base, other_set);

    // The policy actually installs the derived anchor as its genesis block,
    // never the raw manifest digest.
    let policy = OrderedEconomicsPolicy::new(
        fixture::protocol(),
        fixture::domain(),
        genesis,
        None,
        set,
        fixture::resolver(),
    )
    .unwrap();
    assert_eq!(policy.anchor(), base);
    assert_eq!(policy.genesis_digest(), genesis);
    assert_ne!(policy.anchor(), policy.genesis_digest());
}

#[test]
fn policy_new_fails_closed_on_validator_set_epoch_mismatch() {
    let signers = signers();
    let mismatched = ValidatorSet::new(
        Epoch::new(1),
        vec![ValidatorInfo {
            id: signers[0].id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: signers[0].id.as_bytes().to_vec(),
        }],
    )
    .unwrap();
    let result = OrderedEconomicsPolicy::new(
        fixture::protocol(),
        fixture::domain(),
        Digest32::new(HashAlgorithmId::Sha2_256, [1; 32]),
        None,
        mismatched,
        fixture::resolver(),
    );
    assert!(matches!(result, Err(OrderedEconomicsError::Policy(_))));
}

#[test]
fn freeze_height_cannot_be_enabled_without_the_matching_signed_genesis_manifest() {
    let signers: Vec<TestSigner> = signers();
    let mut manifest: GenesisManifest = four_validator_manifest(&signers);
    manifest.commitment_profile = crate::logical_generation::CommitmentProfile::LogicalGenerationV2;
    manifest.minimum_freeze_block_height = 4;
    fixture::resign_manifest(&mut manifest);
    let digest: Digest32 =
        genesis::genesis_manifest_commitment(&fixture::resolver(), &manifest).unwrap();
    let selected: ValidatorSet = validator_set(&signers);
    let valid: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
        fixture::protocol(),
        fixture::domain(),
        digest,
        Some(&manifest),
        selected.clone(),
        fixture::resolver(),
    )
    .unwrap();
    assert_eq!(valid.minimum_freeze_block_height(), 4);

    let mut changed: GenesisManifest = manifest.clone();
    changed.minimum_freeze_block_height = 1;
    assert!(matches!(
        OrderedEconomicsPolicy::new(
            fixture::protocol(),
            fixture::domain(),
            digest,
            Some(&changed),
            selected.clone(),
            fixture::resolver(),
        ),
        Err(OrderedEconomicsError::Policy(_))
    ));
    let changed_digest: Digest32 =
        genesis::genesis_manifest_commitment(&fixture::resolver(), &changed).unwrap();
    assert!(matches!(
        OrderedEconomicsPolicy::new(
            fixture::protocol(),
            fixture::domain(),
            changed_digest,
            Some(&changed),
            selected.clone(),
            fixture::resolver(),
        ),
        Err(OrderedEconomicsError::Policy(_))
    ));
    let smaller: ValidatorSet = ValidatorSet::new(
        fixture::protocol().epoch(),
        vec![selected.validators()[0].clone()],
    )
    .unwrap();
    assert!(matches!(
        OrderedEconomicsPolicy::new(
            fixture::protocol(),
            fixture::domain(),
            digest,
            Some(&manifest),
            smaller,
            fixture::resolver(),
        ),
        Err(OrderedEconomicsError::Policy(_))
    ));

    let unwarranted: OrderedEconomicsPolicy = OrderedEconomicsPolicy::new(
        fixture::protocol(),
        fixture::domain(),
        digest,
        None,
        selected,
        fixture::resolver(),
    )
    .unwrap();
    assert_eq!(unwarranted.minimum_freeze_block_height(), 0);
}

// --- pure authentication --------------------------------------------------

#[test]
fn authenticate_candidate_verifies_the_outer_bond_lifecycle_signature_purely() {
    let network = setup();
    let recipient = address_of(0x50);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let candidate = unbond_candidate(&network, &network.bond, &next, [0x61; 32], recipient, 11);
    // Zero storage reads: the pinned registered key is enough.
    authenticate_candidate(&network.env(), &candidate).unwrap();

    // Flipping one signature byte must fail closed as `Unauthenticated`.
    let mut forged: SignedBondLifecycleIntent =
        bond_lifecycle::decode_signed_bond_lifecycle_intent(&candidate.intent).unwrap();
    forged.signature[0] ^= 0xff;
    let tampered = OrderedCandidate {
        intent: encode_signed_bond_lifecycle_intent(&forged).unwrap(),
        ..candidate.clone()
    };
    assert!(matches!(
        authenticate_candidate(&network.env(), &tampered),
        Err(OrderedEconomicsError::Unauthenticated(_))
    ));

    // An outer request id disagreeing with the embedded envelope fails too.
    let mut mismatched = candidate.clone();
    mismatched.request_id = [0x62; 32];
    assert!(matches!(
        authenticate_candidate(&network.env(), &mismatched),
        Err(OrderedEconomicsError::Unauthenticated(_))
    ));

    // A candidate from a non-pinned epoch context fails closed.
    let stale_context = PublicationContext::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        Epoch::new(1),
    )
    .unwrap();
    let stale = OrderedCandidate {
        context: stale_context,
        ..candidate
    };
    assert!(matches!(
        authenticate_candidate(&network.env(), &stale),
        Err(OrderedEconomicsError::Unauthenticated(_))
    ));
}

// --- genesis installation -------------------------------------------------

#[test]
fn install_ordered_genesis_is_idempotent_and_never_resets_a_tombstoned_row() {
    let network = setup();
    let chain = fixture::chain();
    let state_key = engine::ordered_state_key_for_tests(&chain);
    install_ordered_genesis(
        &network.stores[0],
        &network.context,
        &network.env(),
        TRUSTED_NOW_MILLIS,
    )
    .unwrap();
    let installed = network.value(0, &state_key).unwrap();
    let revision = network.revision(0, &state_key);

    // Verified existing: a second install with a *different* clock value
    // re-verifies and keeps the retained row byte-for-byte.
    install_ordered_genesis(
        &network.stores[0],
        &network.context,
        &network.env(),
        TRUSTED_NOW_MILLIS + 999_999,
    )
    .unwrap();
    assert_eq!(network.value(0, &state_key).unwrap(), installed);
    assert_eq!(network.revision(0, &state_key), revision);

    // A tombstoned row is corruption, not an invitation to reset to genesis.
    network.put(1, state_key.clone(), StateMutation::Put(installed.clone()));
    network.put(1, state_key.clone(), StateMutation::Delete);
    assert!(network.value(1, &state_key).is_none());
    assert!(matches!(
        install_ordered_genesis(
            &network.stores[1],
            &network.context,
            &network.env(),
            TRUSTED_NOW_MILLIS
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert!(network.value(1, &state_key).is_none());
}

// --- real business commit + exact replay ----------------------------------

#[test]
fn unbond_commits_identically_on_four_stores_and_exact_replay_writes_nothing() {
    let network = setup();
    network.install_ordered();
    let recipient = address_of(0x50);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0x61; 32];
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);

    // Height 1 carries the candidate; chained HotStuff commits it only once
    // two further heights are certified on top.
    let (round1, _, _) = network.round(1, Some(&candidate));
    assert!(round1.iter().all(|output| output.committed.is_empty()));
    let (round2, _, _) = network.round(2, None);
    assert!(round2.iter().all(|output| output.committed.is_empty()));
    let (round3, certificate3, _) = network.round(3, None);

    for (replica, outputs) in round3.iter().enumerate() {
        assert_eq!(outputs.committed.len(), 1, "replica {replica}");
        let outcome = &outputs.committed[0];
        assert_eq!(outcome.request_id, request_id);
        assert_eq!(outcome.block_height, 1);
        assert_eq!(
            outcome.output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        // Real business effect, identical on every independent store.
        assert_eq!(network.committed_bond(replica), next, "replica {replica}");
        assert_eq!(
            query_status(&network.stores[replica], &network.context, &network.env())
                .unwrap()
                .committed_height,
            1
        );
    }
    // Every replica produced byte-identical outcomes.
    for replica in 1..REPLICAS {
        assert_eq!(
            encode_ordered_outcome(&round3[replica].committed[0]).unwrap(),
            encode_ordered_outcome(&round3[0].committed[0]).unwrap()
        );
    }

    // Exact replay of the identical round-3 certificate: read-only across
    // every row this feature owns plus the business row it already applied.
    for replica in 0..REPLICAS {
        let before = network.snapshot(replica, &[request_id], 3);
        let replay = process_certificate(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &certificate3,
        )
        .unwrap();
        assert!(replay.committed.is_empty(), "replica {replica}");
        assert!(replay.messages.is_empty(), "replica {replica}");
        assert_eq!(network.snapshot(replica, &[request_id], 3), before);
    }
}

#[test]
fn stale_generation_candidate_is_refused_with_a_typed_reason_and_moves_nothing() {
    let network = setup();
    network.install_ordered();

    // Advance the committed row out from under the candidate on every
    // replica, exactly as an earlier ordered transition would have.
    let mut advanced = network.bond.clone();
    advanced.generation = advanced.generation.checked_add(1).unwrap();
    for replica in 0..REPLICAS {
        network.put(
            replica,
            network.bond_key(),
            StateMutation::Put(encode_fastpath_bond_record(&advanced).unwrap()),
        );
    }

    let recipient = address_of(0x51);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0x62; 32];
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);

    network.round(1, Some(&candidate));
    network.round(2, None);
    let (round3, _, _) = network.round(3, None);
    for (replica, output) in round3.iter().enumerate() {
        assert_eq!(output.committed.len(), 1);
        assert_eq!(
            refusal_of(&output.committed[0]),
            OrderedRefusal::StaleGeneration,
            "replica {replica}"
        );
        // The refusal moved nothing: the row is exactly the advanced one.
        assert_eq!(network.committed_bond(replica), advanced);
    }
}

// --- DR-0154 Freeze --------------------------------------------------------

fn freeze_candidate(request_id: [u8; 32]) -> OrderedCandidate {
    let mut validators: Vec<FastPathValidatorEntry> = signers()
        .into_iter()
        .map(|signer: TestSigner| FastPathValidatorEntry {
            id: signer.id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: signer.id.as_bytes().to_vec(),
        })
        .collect();
    validators.sort_by_key(|entry: &FastPathValidatorEntry| entry.id);
    let intent = FreezeIntent {
        context: fixture::protocol(),
        request_id,
        advisory_next_set: FastPathValidatorSetRecord {
            context: PublicationContext::new(
                fixture::chain(),
                fixture::protocol().protocol_version(),
                Epoch::new(fixture::protocol().epoch().get() + 1),
            )
            .unwrap(),
            validators,
        },
    };
    OrderedCandidate {
        context: fixture::protocol(),
        request_id,
        kind: OrderedOperationKind::Freeze,
        intent: encode_freeze_intent(&intent).unwrap(),
        created_checkpoint: 11,
    }
}

#[test]
fn freeze_cannot_be_proposed_or_voted_before_the_signed_minimum_height() {
    let network: Network = setup_with_freeze_height(4);
    network.install_ordered();
    let candidate: OrderedCandidate = freeze_candidate([0x6e; 32]);
    let leader: usize = network.leader_index(1);
    assert!(matches!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&candidate),
            &network.signers[leader],
        ),
        Err(OrderedEconomicsError::Refused(
            OrderedRefusal::PrematureFreeze
        ))
    ));
    let header_key: Vec<u8> =
        engine::ordered_request_header_key_for_tests(&fixture::chain(), &candidate.request_id);
    assert!(network.value(leader, &header_key).is_none());

    // A malicious leader could attach candidate bytes to a different signed
    // proposal shell. An honest peer still refuses before signing a vote.
    let empty: OrderedProposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        None,
        &network.signers[leader],
    )
    .unwrap();
    let other: usize = (0..REPLICAS)
        .find(|index: &usize| *index != leader)
        .unwrap();
    assert!(matches!(
        process_proposal(
            &network.stores[other],
            &network.context,
            &network.env(),
            &OrderedProposal {
                proposal: empty.proposal,
                candidate: Some(candidate),
            },
            &network.signers[other],
        ),
        Err(OrderedEconomicsError::Refused(
            OrderedRefusal::PrematureFreeze
        ))
    ));
    let vote_key: Vec<u8> = engine::ordered_vote_record_key_for_tests(&fixture::chain(), 1);
    assert!(network.value(other, &vote_key).is_none());
}

#[test]
fn freeze_at_the_first_eligible_economic_height_closes_on_all_four_replicas() {
    let network: Network = setup_with_freeze_height(4);
    network.install_ordered();
    network.round(1, None);
    network.round(2, None);
    network.round(3, None);
    let candidate: OrderedCandidate = freeze_candidate([0x69; 32]);
    network.round(4, Some(&candidate));
    network.round(5, None);
    let (commits, _, _) = network.round(6, None);
    let closure_key: Vec<u8> =
        engine::admission_closure_key_for_tests(&fixture::chain(), fixture::protocol().epoch());
    for (replica, commit) in commits.iter().enumerate() {
        assert_eq!(commit.committed.len(), 1);
        assert_eq!(commit.committed[0].block_height, 4);
        assert_eq!(
            commit.committed[0].output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let closure: AdmissionClosureRecord =
            decode_admission_closure_record(&network.value(replica, &closure_key).unwrap())
                .unwrap();
        assert_eq!(closure.closed_at_block_height, 4);
        assert_eq!(closure.request_id, candidate.request_id);
    }
}

#[test]
fn committed_freeze_yields_four_durable_empty_frontier_votes_without_resigning() {
    let network: Network = setup_with_freeze_height(4);
    network.install_ordered();
    let chain = fixture::chain();
    let epoch = fixture::protocol().epoch();
    let expected = fixture::protocol();
    let signer_set: ValidatorSet = validator_set(&network.signers);
    let certifier = consensus::FrozenFrontierCertifier::new(
        chain.clone(),
        expected.protocol_version(),
        epoch,
        signer_set,
    )
    .unwrap();

    // No local signature is possible before an actual ordered Freeze commit.
    for replica in 0..REPLICAS {
        assert!(
            advance_frozen_frontier(
                &network.stores[replica],
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &expected,
                &network.signers[replica],
            )
            .is_err()
        );
        assert!(
            read_frozen_frontier_page(
                &network.stores[replica],
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &expected,
                network.signers[replica].validator_id(),
                None,
                std::num::NonZeroUsize::new(1).unwrap(),
            )
            .is_err()
        );
    }
    network.round(1, None);
    network.round(2, None);
    network.round(3, None);
    let freeze: OrderedCandidate = freeze_candidate([0x79; 32]);
    network.round(4, Some(&freeze));
    network.round(5, None);
    network.round(6, None);

    let mut first_identity: Option<consensus::FrozenFrontierIdentity> = None;
    for replica in 0..REPLICAS {
        let step: FrozenFrontierStep = advance_frozen_frontier(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &network.signers[replica],
        )
        .unwrap();
        let vote: Box<consensus::FrozenFrontierVote> = match step {
            FrozenFrontierStep::Finalized(vote) => vote,
            FrozenFrontierStep::Advanced { .. } => panic!("empty publication log must finalize"),
        };
        assert_eq!(vote.identity.entry_count, 0);
        assert_eq!(vote.identity.closure_request_id, freeze.request_id);
        assert_eq!(vote.identity.closure_height, 4);
        certifier
            .verify_vote(&vote, &super::policy::Ed25519ConsensusVerifier)
            .unwrap();
        let (served_vote, page) = read_frozen_frontier_page(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            network.signers[replica].validator_id(),
            None,
            std::num::NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
        assert_eq!(served_vote, *vote);
        assert!(page.terminal);
        assert!(page.entries.is_empty());
        let mut page_verifier = consensus::FrozenFrontierPageVerifier::new(
            &network.resolver,
            &certifier,
            served_vote.clone(),
            &super::policy::Ed25519ConsensusVerifier,
        )
        .unwrap();
        page_verifier.push_page(&network.resolver, &page).unwrap();
        assert_eq!(page_verifier.finish().unwrap(), served_vote);
        if let Some(identity) = &first_identity {
            assert_eq!(&vote.identity, identity);
        } else {
            first_identity = Some(vote.identity.clone());
        }
        let final_key: Vec<u8> = frontier::key(&chain, epoch, b"frontier/").unwrap();
        let before: Option<Vec<u8>> = network.value(replica, &final_key);
        let before_revision: StateRevision = network.revision(replica, &final_key);
        assert!(before.is_some());
        let replay: FrozenFrontierStep = advance_frozen_frontier(
            &network.stores[replica],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &network.signers[replica],
        )
        .unwrap();
        assert_eq!(replay, FrozenFrontierStep::Finalized(vote));
        assert_eq!(network.value(replica, &final_key), before);
        assert_eq!(network.revision(replica, &final_key), before_revision);
        let different_signer: usize = (replica + 1) % REPLICAS;
        assert!(
            advance_frozen_frontier(
                &network.stores[replica],
                &network.context,
                network.domain(),
                &network.resolver,
                &network.history,
                &expected,
                &network.signers[different_signer],
            )
            .is_err()
        );
    }
    let final_key: Vec<u8> = frontier::key(&chain, epoch, b"frontier/").unwrap();
    network.put(0, final_key, StateMutation::Delete);
    assert!(
        read_frozen_frontier_page(
            &network.stores[0],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            network.signers[0].validator_id(),
            None,
            std::num::NonZeroUsize::new(1).unwrap(),
        )
        .is_err()
    );
    assert!(
        advance_frozen_frontier(
            &network.stores[0],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &expected,
            &network.signers[0],
        )
        .is_err()
    );
}

#[test]
fn historical_profile_cannot_sign_a_frozen_frontier() {
    let network: Network = setup();
    assert!(
        advance_frozen_frontier(
            &network.stores[0],
            &network.context,
            network.domain(),
            &network.resolver,
            &network.history,
            &fixture::protocol(),
            &network.signers[0],
        )
        .is_err()
    );
}

#[test]
fn freeze_advisory_set_requires_the_exact_next_epoch_and_unique_members() {
    let candidate: OrderedCandidate = freeze_candidate([0x6f; 32]);
    let mut intent: FreezeIntent = decode_freeze_intent(&candidate.intent).unwrap();
    intent.advisory_next_set.context = fixture::protocol();
    assert!(encode_freeze_intent(&intent).is_err());
    intent.advisory_next_set.context = PublicationContext::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        Epoch::new(1),
    )
    .unwrap();
    let duplicated: FastPathValidatorEntry = intent.advisory_next_set.validators[0].clone();
    intent.advisory_next_set.validators.insert(0, duplicated);
    assert!(encode_freeze_intent(&intent).is_err());
}

#[test]
fn freeze_refuses_a_healthy_but_ineligible_advisory_member_before_signing() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let mut ineligible: FastPathBondRecord = network.committed_bond(0);
    ineligible.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient: [0x30; 32],
    };
    let key: Vec<u8> = network.bond_key();
    for replica in 0..REPLICAS {
        network.put(
            replica,
            key.clone(),
            StateMutation::Put(encode_fastpath_bond_record(&ineligible).unwrap()),
        );
    }
    let candidate: OrderedCandidate = freeze_candidate([0x6d; 32]);
    let leader: usize = network.leader_index(1);
    assert!(matches!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&candidate),
            &network.signers[leader],
        ),
        Err(OrderedEconomicsError::Refused(
            OrderedRefusal::IneligibleNextSet
        ))
    ));
    let closure_key: Vec<u8> =
        engine::admission_closure_key_for_tests(&fixture::chain(), fixture::protocol().epoch());
    assert!(network.value(leader, &closure_key).is_none());
}

#[test]
fn freeze_rechecks_eligibility_at_commit_and_retains_a_no_closure_refusal() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let candidate: OrderedCandidate = freeze_candidate([0x6c; 32]);
    network.round(1, Some(&candidate));

    // The proposal was legal when voted on. The committed bond changes before
    // the three-chain commit; no replica may turn that older vote into a
    // successful closure against the later ordered state.
    let mut ineligible: FastPathBondRecord = network.committed_bond(0);
    ineligible.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(7),
        recipient: [0x31; 32],
    };
    let bond_key: Vec<u8> = network.bond_key();
    let bond_bytes: Vec<u8> = encode_fastpath_bond_record(&ineligible).unwrap();
    for replica in 0..REPLICAS {
        network.put(
            replica,
            bond_key.clone(),
            StateMutation::Put(bond_bytes.clone()),
        );
    }
    network.round(2, None);
    let (commits, certificate, _) = network.round(3, None);
    let closure_key: Vec<u8> =
        engine::admission_closure_key_for_tests(&fixture::chain(), fixture::protocol().epoch());
    for (replica, commit) in commits.iter().enumerate() {
        assert_eq!(commit.committed.len(), 1);
        assert_eq!(
            refusal_of(&commit.committed[0]),
            OrderedRefusal::IneligibleNextSet
        );
        assert!(network.value(replica, &closure_key).is_none());
        assert_eq!(network.value(replica, &bond_key), Some(bond_bytes.clone()));
        let first: Vec<u8> = encode_ordered_outcome(&commit.committed[0]).unwrap();
        assert!(
            process_certificate(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &certificate,
            )
            .unwrap()
            .committed
            .is_empty()
        );
        let retained: OrderedOutcome = query_ordered_outcome(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &candidate.request_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(encode_ordered_outcome(&retained).unwrap(), first);
    }
}

#[test]
fn a_committed_freeze_closes_admission_identically_on_every_replica_and_blocks_a_fresh_business_candidate()
 {
    let network = setup_with_freeze_height(1);
    network.install_ordered();
    let chain = fixture::chain();
    let closure_key = engine::admission_closure_key_for_tests(&chain, fixture::protocol().epoch());
    let request_id = [0x70; 32];
    let candidate = freeze_candidate(request_id);

    // Height 1 carries the candidate; chained HotStuff commits it only once
    // two further heights are certified on top, exactly like a business
    // candidate.
    let (round1, _, _) = network.round(1, Some(&candidate));
    assert!(round1.iter().all(|output| output.committed.is_empty()));
    let (round2, _, _) = network.round(2, None);
    assert!(round2.iter().all(|output| output.committed.is_empty()));
    let (round3, certificate3, _) = network.round(3, None);

    for (replica, outputs) in round3.iter().enumerate() {
        assert_eq!(outputs.committed.len(), 1, "replica {replica}");
        let outcome = &outputs.committed[0];
        assert_eq!(outcome.request_id, request_id);
        assert_eq!(outcome.block_height, 1);
        assert_eq!(
            outcome.output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        let record: AdmissionClosureRecord =
            decode_admission_closure_record(&network.value(replica, &closure_key).unwrap())
                .unwrap();
        assert_eq!(record.request_id, request_id);
        assert_eq!(record.closed_epoch, fixture::protocol().epoch());
        assert_eq!(record.closed_at_block_height, 1);
    }
    // Byte-identical across every independent store.
    for replica in 1..REPLICAS {
        assert_eq!(
            network.value(replica, &closure_key),
            network.value(0, &closure_key)
        );
    }

    // Exact replay of the identical round-3 certificate writes nothing new.
    for replica in 0..REPLICAS {
        let before = network.value(replica, &closure_key);
        let replay = process_certificate(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &certificate3,
        )
        .unwrap();
        assert!(replay.committed.is_empty(), "replica {replica}");
        assert_eq!(network.value(replica, &closure_key), before);
    }

    // DR-0154: "Stop new ... construction of fresh economic candidates." A
    // fresh business candidate proposed at the next economic height (4) is
    // refused before it ever enters a block -- not merely refused once
    // committed.
    let recipient = address_of(0x71);
    let next = predicted_unbond(&network.bond, 12, *recipient.as_bytes());
    let business_request_id = [0x73; 32];
    let business = unbond_candidate(
        &network,
        &network.bond,
        &next,
        business_request_id,
        recipient,
        12,
    );
    let leader4 = network.leader_index(4);
    assert!(matches!(
        propose(
            &network.stores[leader4],
            &network.context,
            &network.env(),
            Some(&business),
            &network.signers[leader4],
        ),
        Err(OrderedEconomicsError::Refused(OrderedRefusal::ClosedEpoch))
    ));
    // Nothing was placed: no header, no candidate bytes, no reservation.
    let header_key = engine::ordered_request_header_key_for_tests(&chain, &business_request_id);
    assert!(network.value(leader4, &header_key).is_none());

    // A replica asked to vote for someone else's (e.g. a byzantine leader's)
    // business proposal at that same height refuses identically, before any
    // consensus metadata is recorded. Since an honest `propose` already
    // refuses to build this proposal (proven above), construct its shell
    // directly from an honest empty proposal for the same view/height,
    // exactly the shape a byzantine leader would otherwise need to forge.
    let empty4 = propose(
        &network.stores[leader4],
        &network.context,
        &network.env(),
        None,
        &network.signers[leader4],
    )
    .unwrap();
    let other_replica = (0..REPLICAS).find(|&r| r != leader4).unwrap();
    assert!(matches!(
        process_proposal(
            &network.stores[other_replica],
            &network.context,
            &network.env(),
            &OrderedProposal {
                proposal: empty4.proposal,
                candidate: Some(business.clone()),
            },
            &network.signers[other_replica],
        ),
        Err(OrderedEconomicsError::Refused(OrderedRefusal::ClosedEpoch))
    ));
}

#[test]
fn a_second_freeze_candidate_is_refused_as_already_frozen_and_does_not_rewrite_the_closure_record()
{
    let network = setup_with_freeze_height(1);
    network.install_ordered();
    let chain = fixture::chain();
    let closure_key = engine::admission_closure_key_for_tests(&chain, fixture::protocol().epoch());
    let first_request_id = [0x74; 32];
    let first = freeze_candidate(first_request_id);

    network.round(1, Some(&first));
    network.round(2, None);
    network.round(3, None);
    let original: Vec<Option<Vec<u8>>> = (0..REPLICAS)
        .map(|replica| network.value(replica, &closure_key))
        .collect();

    let second_request_id = [0x75; 32];
    let second = freeze_candidate(second_request_id);
    // A second `Freeze` is still structurally admissible (the vote-level
    // gate only refuses *business* kinds once closed) and reaches a
    // deterministic outcome rather than stalling the shared order.
    network.round(4, Some(&second));
    network.round(5, None);
    let (round6, _, _) = network.round(6, None);

    for (replica, outputs) in round6.iter().enumerate() {
        assert_eq!(outputs.committed.len(), 1, "replica {replica}");
        assert_eq!(
            refusal_of(&outputs.committed[0]),
            OrderedRefusal::AlreadyFrozen,
            "replica {replica}"
        );
        // The original closure record is untouched.
        assert_eq!(
            network.value(replica, &closure_key),
            original[replica],
            "replica {replica}"
        );
    }
}

/// The vote-level `ClosedEpoch` gate (`admit_candidate_for_signer`) must never
/// reach declared, signerless recovery: `observe_proposal` has to remain able
/// to record an authentic *pre-freeze* business proposal's bytes during
/// catch-up regardless of whether this replica already closed admission
/// locally, since that is how an already-justified inherited business suffix
/// reaches the deterministic commit-time closed-epoch refusal at all. Only
/// the signer-side `propose`/`process_proposal` path refuses on sight.
#[test]
fn observe_proposal_recovery_still_records_a_business_candidate_after_admission_is_closed() {
    let network: Network = setup_with_freeze_height(1);
    network.install_ordered();
    let chain = fixture::chain();
    let closure_key = engine::admission_closure_key_for_tests(&chain, fixture::protocol().epoch());

    // Simulate this replica having already locally closed admission (as if a
    // `Freeze` had committed here), without driving the full three-chain
    // Freeze commit: `observe_proposal`'s own admission path never consults
    // `require_vote_readiness` or any consensus progress, so this directly
    // isolates the one behavior under test.
    let closure = AdmissionClosureRecord {
        closed_epoch: fixture::protocol().epoch(),
        request_id: [0x76; 32],
        closed_at_block_height: 1,
    };
    network.put(
        0,
        closure_key.clone(),
        StateMutation::Put(encode_admission_closure_record(&closure).unwrap()),
    );
    assert!(network.value(0, &closure_key).is_some());

    let leader1 = network.leader_index(1);
    let recipient = address_of(0x77);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0x78; 32];
    let business = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);

    // The signer-side path still refuses on sight, on this same replica.
    assert!(matches!(
        propose(
            &network.stores[0],
            &network.context,
            &network.env(),
            Some(&business),
            &network.signers[leader1],
        ),
        Err(OrderedEconomicsError::Refused(OrderedRefusal::ClosedEpoch))
    ));

    // But an authentic proposal produced elsewhere (here, a fresh store that
    // never closed admission, standing in for a pre-freeze leader) is still
    // recordable through declared recovery on the closed replica.
    let elsewhere: Network = setup_with_freeze_height(1);
    elsewhere.install_ordered();
    let carrying = propose(
        &elsewhere.stores[network.leader_index(1)],
        &elsewhere.context,
        &elsewhere.env(),
        Some(&business),
        &elsewhere.signers[network.leader_index(1)],
    )
    .unwrap();

    let header_key = engine::ordered_request_header_key_for_tests(&chain, &request_id);
    assert!(network.value(0, &header_key).is_none());
    observe_proposal(
        &network.stores[0],
        &network.context,
        &network.env(),
        &carrying,
    )
    .unwrap();
    assert!(network.value(0, &header_key).is_some());
    // Recording the proposal did not touch the closure record.
    assert_eq!(
        network.value(0, &closure_key),
        Some(encode_admission_closure_record(&closure).unwrap())
    );
}

#[test]
fn competing_candidates_both_reach_an_outcome_without_wedging_the_shared_row() {
    let network = setup();
    network.install_ordered();
    let recipient_a = address_of(0x52);
    let next_a = predicted_unbond(&network.bond, 11, *recipient_a.as_bytes());
    let a = unbond_candidate(
        &network,
        &network.bond,
        &next_a,
        [0x63; 32],
        recipient_a,
        11,
    );
    // A second, independently legitimate claimant against the *same*
    // generation, with its own distinct request id.
    let recipient_b = address_of(0x53);
    let next_b = predicted_unbond(&network.bond, 11, *recipient_b.as_bytes());
    let b = unbond_candidate(
        &network,
        &network.bond,
        &next_b,
        [0x64; 32],
        recipient_b,
        11,
    );

    network.round(1, Some(&a));
    network.round(2, None);
    let (round3, _, _) = network.round(3, None);
    assert_eq!(
        round3[0].committed[0].output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );

    // The shared row is not locked to the first claimant: B is orderable and
    // reaches its own deterministic outcome at the next economic height.
    network.round(4, Some(&b));
    network.round(5, None);
    let (round6, _, _) = network.round(6, None);
    for (replica, output) in round6.iter().enumerate() {
        assert_eq!(output.committed.len(), 1);
        assert_eq!(
            refusal_of(&output.committed[0]),
            OrderedRefusal::StaleGeneration
        );
        // A's effect stands untouched by B's refusal.
        assert_eq!(network.committed_bond(replica), next_a);
    }
}

// --- reservations and FastVote fences -------------------------------------

#[test]
fn admission_reserves_the_leg_nonce_under_the_fastvote_key_and_refusal_releases_it_exactly() {
    let network = setup();
    network.install_ordered();
    let request_id = [0x65; 32];
    let candidate = withdraw_candidate(&network, request_id, 0);
    let chain = fixture::chain();
    let nonce_lock_key =
        fastpath_nonce_lock_key(&chain, &fixture::sender(), Epoch::new(0)).unwrap();
    let reservation_key = engine::ordered_reservation_key_for_tests(&chain, &request_id);
    let nonce_key =
        runtime::PersistenceLayout::new(chain.clone(), fixture::protocol().protocol_version())
            .sender_nonce_key(fixture::sender(), Epoch::new(0));
    let nonce_before = network.value(0, &nonce_key);

    network.round(1, Some(&candidate));

    // Admission created the reservation using the *same* FastVote lock key
    // and record layout, owned by this exact request.
    for replica in 0..REPLICAS {
        let held =
            decode_fastpath_nonce_lock_record(&network.value(replica, &nonce_lock_key).unwrap())
                .unwrap();
        assert_eq!(held.request_id, request_id);
        assert_eq!(held.sender, fixture::sender());
        assert_eq!(held.epoch, Epoch::new(0));
        assert_eq!(held.nonce, 0);
        assert!(network.value(replica, &reservation_key).is_some());
    }

    // While held, an ordinary FastVote-fenced path for the same sender/epoch
    // fails closed -- the ordered leg is not racing a fast transaction.
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    assert!(matches!(
        crate::mutation_fence::fence_sender_nonce_lock(
            &network.stores[0],
            &network.context,
            network.domain(),
            &chain,
            &fixture::sender(),
            Epoch::new(0),
            &[0x99; 32],
            0,
            crate::mutation_fence::LockMode::Fresh,
            &mut reads,
        ),
        Err(NodeCoreError::PersistenceInvariant(
            "sender nonce locked by a pending fast path"
        ))
    ));

    network.round(2, None);
    let (round3, _, _) = network.round(3, None);
    for (replica, output) in round3.iter().enumerate() {
        // A healthy but ineligible operation is a typed refusal.
        assert_eq!(
            refusal_of(&output.committed[0]),
            OrderedRefusal::IneligibleState
        );
        // Precisely released: the lock row and the reservation record are
        // gone, and nothing else was masked or deleted.
        assert!(network.value(replica, &nonce_lock_key).is_none());
        assert!(network.value(replica, &reservation_key).is_none());
        // No nonce movement on a refused candidate.
        assert_eq!(network.value(replica, &nonce_key), nonce_before);
        // No value movement either.
        assert_eq!(network.committed_bond(replica), network.bond);
    }
}

#[test]
fn a_held_fastvote_nonce_lock_stops_ordered_admission_instead_of_refusing_it() {
    let network = setup();
    network.install_ordered();
    let chain = fixture::chain();
    let nonce_lock_key =
        fastpath_nonce_lock_key(&chain, &fixture::sender(), Epoch::new(0)).unwrap();
    // A live FastVote prepare already owns this sender/epoch nonce.
    network.put(
        0,
        nonce_lock_key.clone(),
        StateMutation::Put(
            local_instance_state::encode_fastpath_nonce_lock_record(
                &local_instance_state::FastPathNonceLockRecord {
                    request_id: [0x77; 32],
                    sender: fixture::sender(),
                    epoch: Epoch::new(0),
                    nonce: 0,
                },
            )
            .unwrap(),
        ),
    );
    let candidate = withdraw_candidate(&network, [0x66; 32], 0);
    let leader = network.leader_index(1);
    // Contention with a live prepare is a fence, not a semantic outcome: it
    // stops without recording anything.
    let result = propose(
        &network.stores[0],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader],
    );
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert!(
        network
            .value(
                0,
                &engine::ordered_request_header_key_for_tests(&chain, &[0x66; 32])
            )
            .is_none()
    );
}

// --- header reuse and leader/vote identity --------------------------------

#[test]
fn request_header_reuse_is_a_conflict_before_any_metadata_is_written() {
    let network = setup();
    network.install_ordered();
    let chain = fixture::chain();
    let recipient = address_of(0x54);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0x67; 32];
    let first = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);
    let leader = network.leader_index(1);
    propose(
        &network.stores[0],
        &network.context,
        &network.env(),
        Some(&first),
        &network.signers[leader],
    )
    .unwrap();
    let header_key = engine::ordered_request_header_key_for_tests(&chain, &request_id);
    let header_revision = network.revision(0, &header_key);
    let leader_key = engine::ordered_leader_record_key_for_tests(&chain, 1);
    let leader_revision = network.revision(0, &leader_key);

    // Same request id, different signed creation checkpoint: a boundary
    // conflict, not another committed semantic rejection.
    let mut second_next = next.clone();
    second_next.committed_at_checkpoint = 12;
    let second = unbond_candidate(
        &network,
        &network.bond,
        &second_next,
        request_id,
        recipient,
        12,
    );
    assert!(matches!(
        propose(
            &network.stores[0],
            &network.context,
            &network.env(),
            Some(&second),
            &network.signers[leader],
        ),
        Err(OrderedEconomicsError::RequestHeaderConflict)
    ));
    // Nothing was rewritten -- not the header, not the leader identity.
    assert_eq!(network.revision(0, &header_key), header_revision);
    assert_eq!(network.revision(0, &leader_key), leader_revision);
}

#[test]
fn an_honest_leader_never_signs_two_different_proposals_in_one_view() {
    let network = setup();
    network.install_ordered();
    let chain = fixture::chain();
    let leader = network.leader_index(1);
    let recipient = address_of(0x55);
    let next_a = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let a = unbond_candidate(&network, &network.bond, &next_a, [0x68; 32], recipient, 11);
    let first = propose(
        &network.stores[0],
        &network.context,
        &network.env(),
        Some(&a),
        &network.signers[leader],
    )
    .unwrap();

    // Exact repeated work replays the retained proposal and writes nothing.
    let leader_key = engine::ordered_leader_record_key_for_tests(&chain, 1);
    let revision = network.revision(0, &leader_key);
    let replay = propose(
        &network.stores[0],
        &network.context,
        &network.env(),
        Some(&a),
        &network.signers[leader],
    )
    .unwrap();
    assert_eq!(replay.proposal, first.proposal);
    assert_eq!(network.revision(0, &leader_key), revision);

    // A *different* candidate in the same view must not produce a second
    // signed proposal.
    let next_b = predicted_unbond(&network.bond, 12, *recipient.as_bytes());
    let b = unbond_candidate(&network, &network.bond, &next_b, [0x69; 32], recipient, 12);
    assert!(matches!(
        propose(
            &network.stores[0],
            &network.context,
            &network.env(),
            Some(&b),
            &network.signers[leader],
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert_eq!(network.revision(0, &leader_key), revision);
}

#[test]
fn a_vote_is_durably_recorded_once_and_replayed_from_its_retained_bytes() {
    let network = setup();
    network.install_ordered();
    let chain = fixture::chain();
    let leader = network.leader_index(1);
    let proposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        None,
        &network.signers[leader],
    )
    .unwrap();
    let first = process_proposal(
        &network.stores[1],
        &network.context,
        &network.env(),
        &proposal,
        &network.signers[1],
    )
    .unwrap();
    let vote_key = engine::ordered_vote_record_key_for_tests(&chain, 1);
    let high_key = engine::ordered_vote_high_key_for_tests(&chain);
    assert!(network.value(1, &vote_key).is_some());
    let revision = network.revision(1, &vote_key);
    let high_revision = network.revision(1, &high_key);

    // Replaying the same proposal re-emits the exact retained vote and
    // rewrites nothing -- an old proposal replayed after pruning cannot grow
    // the log or bump a revision.
    let replay = process_proposal(
        &network.stores[1],
        &network.context,
        &network.env(),
        &proposal,
        &network.signers[1],
    )
    .unwrap();
    assert_eq!(replay.messages, first.messages);
    assert_eq!(network.revision(1, &vote_key), revision);
    assert_eq!(network.revision(1, &high_key), high_revision);
}

// --- voting readiness -----------------------------------------------------

#[test]
fn a_replica_refuses_to_vote_when_an_ancestor_candidate_payload_is_missing() {
    let network = setup();
    network.install_ordered();
    let chain = fixture::chain();
    // Pick a replica that leads neither view under test, so nothing but the
    // test itself ever writes to its store.
    let observer = network.non_leader(&[1, 2]);
    let recipient = address_of(0x56);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0x6a; 32];
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);

    // The observer misses the candidate bytes entirely but receives the
    // authentic signed proposal shell: an authentic ancestor QC without its
    // payload, not a malformed signature.
    let leader1 = network.leader_index(1);
    let carrying = propose(
        &network.stores[leader1],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader1],
    )
    .unwrap();
    let shell = OrderedProposal {
        proposal: carrying.proposal.clone(),
        candidate: None,
    };
    let vote_key = engine::ordered_vote_record_key_for_tests(&chain, 1);
    let candidate_key = engine::ordered_candidate_record_key_for_tests(
        &chain,
        engine::ordered_candidate_digest_for_tests(&network.resolver, &candidate),
    );
    assert!(network.value(observer, &candidate_key).is_none());

    // Voting on a proposal whose named candidate bytes were never delivered
    // fails closed instead of committing content this replica cannot execute.
    assert!(matches!(
        process_proposal(
            &network.stores[observer],
            &network.context,
            &network.env(),
            &shell,
            &network.signers[observer],
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert!(network.value(observer, &vote_key).is_none());

    // Declared observer recovery may record the authentic proposal shell: it
    // signs nothing and reserves nothing.
    observe_proposal(
        &network.stores[observer],
        &network.context,
        &network.env(),
        &shell,
    )
    .unwrap();
    assert!(network.value(observer, &vote_key).is_none());
    assert!(
        network
            .value(
                observer,
                &engine::ordered_reservation_key_for_tests(&chain, &request_id)
            )
            .is_none()
    );
    assert!(network.value(observer, &candidate_key).is_none());

    // The rest of the network certifies height 1 normally.
    let mut votes: Vec<ConsensusVote> = Vec::new();
    for replica in 0..REPLICAS {
        if replica == observer {
            continue;
        }
        let output = process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &carrying,
            &network.signers[replica],
        )
        .unwrap();
        votes.push(
            output
                .messages
                .iter()
                .find_map(|message| match message {
                    ConsensusMessage::Vote(vote) => Some(vote.clone()),
                    _ => None,
                })
                .unwrap(),
        );
    }
    let certificate1 = network
        .policy
        .engine()
        .certificate_from_votes(
            &carrying.proposal,
            &votes,
            &super::policy::Ed25519ConsensusVerifier,
        )
        .unwrap()
        .unwrap();
    // Every replica -- including the observer -- applies the real height-1
    // certificate. One certified height alone commits nothing (chained
    // HotStuff's three-chain rule), so no economic effect is applied yet.
    for replica in 0..REPLICAS {
        let output = process_certificate(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &certificate1,
        )
        .unwrap();
        assert!(output.committed.is_empty());
    }

    // Now an empty descendant whose certified ancestor is known locally but
    // whose candidate bytes are still absent: a cryptographically valid QC
    // over unknown parent content is not local execution readiness.
    let leader2 = network.leader_index(2);
    let descendant = propose(
        &network.stores[leader2],
        &network.context,
        &network.env(),
        None,
        &network.signers[leader2],
    )
    .unwrap();
    assert_eq!(descendant.proposal.justify.height, 1);
    let before = network.snapshot(observer, &[request_id], 2);
    assert!(matches!(
        process_proposal(
            &network.stores[observer],
            &network.context,
            &network.env(),
            &descendant,
            &network.signers[observer],
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    assert_eq!(network.snapshot(observer, &[request_id], 2), before);

    // Once declared recovery delivers the exact candidate bytes, the same
    // replica becomes ready and votes normally -- catch-up, not a permanent
    // refusal.
    observe_proposal(
        &network.stores[observer],
        &network.context,
        &network.env(),
        &carrying,
    )
    .unwrap();
    assert!(network.value(observer, &candidate_key).is_some());
    let recovered = process_proposal(
        &network.stores[observer],
        &network.context,
        &network.env(),
        &descendant,
        &network.signers[observer],
    )
    .unwrap();
    assert!(
        recovered
            .messages
            .iter()
            .any(|message| matches!(message, ConsensusMessage::Vote(_)))
    );
}

// --- missing/corrupt prerequisites ----------------------------------------

#[test]
fn a_missing_business_prerequisite_stops_apply_without_advancing_the_prefix() {
    let network = setup();
    network.install_ordered();
    let recipient = address_of(0x57);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0x6b; 32];
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);
    network.round(1, Some(&candidate));
    network.round(2, None);

    // Every replica certifies height 3, which commits height 1.
    let (certificate, _) = network.certify(3, None);
    let chain = fixture::chain();
    let applied_key = engine::ordered_applied_height_key_for_tests(&chain);

    // One replica's committed bond row disappears before it applies that
    // certificate: a missing prerequisite, not a stale candidate.
    let victim = network.non_leader(&[1, 2, 3]);
    network.put(victim, network.bond_key(), StateMutation::Delete);
    let applied_before = network.value(victim, &applied_key);
    let state_before = network.value(victim, &engine::ordered_state_key_for_tests(&chain));

    let result = process_certificate(
        &network.stores[victim],
        &network.context,
        &network.env(),
        &certificate,
    );
    assert!(matches!(
        result,
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
    // The applied prefix did not advance past an operation whose outcome is
    // unknown, the consensus state was not rewritten, and no receipt exists.
    assert_eq!(network.value(victim, &applied_key), applied_before);
    assert_eq!(
        network.value(victim, &engine::ordered_state_key_for_tests(&chain)),
        state_before
    );
    assert!(
        network.stores[victim]
            .get_request_receipt(
                &network.context,
                network.domain(),
                DurableRequestId::new(request_id).unwrap()
            )
            .unwrap()
            .is_none()
    );

    // The other three replicas commit normally, proving the stop is local and
    // recoverable rather than a protocol-wide rejection.
    for replica in 0..REPLICAS {
        if replica == victim {
            continue;
        }
        let output = process_certificate(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &certificate,
        )
        .unwrap();
        assert_eq!(output.committed.len(), 1, "replica {replica}");
        assert_eq!(
            output.committed[0].output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        assert_eq!(network.committed_bond(replica), next);
    }
}

#[test]
fn a_diverging_installed_live_validator_set_stops_instead_of_refusing() {
    let network = setup();
    network.install_ordered();
    let recipient = address_of(0x58);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let candidate = unbond_candidate(&network, &network.bond, &next, [0x6c; 32], recipient, 11);
    // The candidate authenticates purely against the pinned authority...
    authenticate_candidate(&network.env(), &candidate).unwrap();
    // ...but the committed epoch record is removed, so the fresh runtime
    // authority check cannot confirm the installed live set still agrees.
    network.put(
        0,
        fastpath_epoch_record_key(&fixture::chain()).unwrap(),
        StateMutation::Delete,
    );
    assert!(matches!(
        preflight::preflight(
            &network.stores[0],
            &network.context,
            &network.env(),
            &candidate,
            1
        ),
        Err(OrderedEconomicsError::Prerequisite(_))
    ));
}

// --- ambiguous commit reconciliation --------------------------------------

/// Wraps a real store and forces the first `commit_invocation` to report an
/// indeterminate outcome, exactly as a lost durable acknowledgement does.
/// Reads and every other operation are forwarded unchanged to the real store.
struct FlakyStore<'a> {
    inner: &'a MemoryDurableStateStore,
    fail_next_invocation: std::cell::Cell<bool>,
}

impl DurableDomainStateStore for FlakyStore<'_> {
    fn get_namespace_lifecycle(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, runtime::DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
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
        self.inner.commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for FlakyStore<'_> {
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
        if self.fail_next_invocation.replace(false) {
            return DurableCommitOutcome::Indeterminate(
                IndeterminateCommitReason::DeadlineExceeded,
            );
        }
        self.inner.commit_invocation(context, transaction)
    }
}

#[test]
fn an_ambiguous_business_commit_exposes_no_output_and_reconciles_on_retry() {
    let network = setup();
    network.install_ordered();
    let recipient = address_of(0x59);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0x6d; 32];
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);
    network.round(1, Some(&candidate));
    network.round(2, None);

    // Build the real round-3 certificate through the honest replicas.
    let leader = network.leader_index(3);
    let proposal = propose(
        &network.stores[leader],
        &network.context,
        &network.env(),
        None,
        &network.signers[leader],
    )
    .unwrap();
    let mut votes: Vec<ConsensusVote> = Vec::new();
    for replica in 0..REPLICAS {
        let output = process_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &proposal,
            &network.signers[replica],
        )
        .unwrap();
        votes.push(
            output
                .messages
                .iter()
                .find_map(|message| match message {
                    ConsensusMessage::Vote(vote) => Some(vote.clone()),
                    _ => None,
                })
                .unwrap(),
        );
    }
    let certificate = network
        .policy
        .engine()
        .certificate_from_votes(
            &proposal.proposal,
            &votes,
            &super::policy::Ed25519ConsensusVerifier,
        )
        .unwrap()
        .unwrap();

    let chain = fixture::chain();
    let before = network.snapshot(0, &[request_id], 3);
    let flaky = FlakyStore {
        inner: &network.stores[0],
        fail_next_invocation: std::cell::Cell::new(true),
    };
    // The commit is ambiguous: no new output, and nothing durable changed.
    assert!(matches!(
        process_certificate(&flaky, &network.context, &network.env(), &certificate),
        Err(OrderedEconomicsError::Node(
            NodeCoreError::DurableCommitIndeterminate(_)
        ))
    ));
    assert_eq!(network.snapshot(0, &[request_id], 3), before);
    assert_eq!(network.committed_bond(0), network.bond);
    assert_eq!(
        network.value(0, &engine::ordered_applied_height_key_for_tests(&chain)),
        before[1].2
    );

    // Retrying the exact same certificate now reconciles to the one real
    // outcome, with the same accepted business effect the other replicas get.
    let retried = process_certificate(
        &network.stores[0],
        &network.context,
        &network.env(),
        &certificate,
    )
    .unwrap();
    assert_eq!(retried.committed.len(), 1);
    assert_eq!(
        retried.committed[0].output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    assert_eq!(network.committed_bond(0), next);
}

// --- trusted-clock pacemaker ----------------------------------------------

#[test]
fn a_trusted_clock_tick_advances_the_view_without_authorizing_any_mutation() {
    let network = setup();
    network.install_ordered();
    let chain = fixture::chain();

    // Below the real configured genesis view timeout (10s): no advance, and
    // not a single row written.
    let before = network.snapshot(0, &[], 1);
    for replica in 0..REPLICAS {
        let output = process_tick(
            &network.stores[replica],
            &network.context,
            &network.env(),
            TRUSTED_NOW_MILLIS + 9_999,
            &network.signers[replica],
        )
        .unwrap();
        assert!(output.messages.is_empty());
        assert!(output.committed.is_empty());
    }
    assert_eq!(network.snapshot(0, &[], 1), before);
    assert_eq!(
        query_status(&network.stores[0], &network.context, &network.env())
            .unwrap()
            .current_view,
        1
    );

    // View 1's selected leader never proposes. At the configured timeout a
    // trusted local clock tick advances every replica's view -- and commits
    // no business operation, records no receipt and produces no vote.
    for replica in 0..REPLICAS {
        let output = process_tick(
            &network.stores[replica],
            &network.context,
            &network.env(),
            TRUSTED_NOW_MILLIS + 10_000,
            &network.signers[replica],
        )
        .unwrap();
        assert!(output.committed.is_empty());
        assert!(output.messages.is_empty());
        assert!(
            network
                .value(
                    replica,
                    &engine::ordered_vote_record_key_for_tests(&chain, 1)
                )
                .is_none()
        );
    }
    for replica in 0..REPLICAS {
        assert_eq!(
            query_status(&network.stores[replica], &network.context, &network.env())
                .unwrap()
                .current_view,
            2
        );
    }

    // Real liveness: progress resumes under the next selected leader, at the
    // same height the unavailable leader would have proposed.
    let recipient = address_of(0x5b);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0x6f; 32];
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);
    let (_, _, proposal) = network.round(2, Some(&candidate));
    assert_eq!(proposal.proposal.height, 1);
    network.round(3, None);
    let (round4, _, _) = network.round(4, None);
    for (replica, output) in round4.iter().enumerate() {
        assert_eq!(output.committed.len(), 1, "replica {replica}");
        assert_eq!(
            output.committed[0].output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        assert_eq!(network.committed_bond(replica), next);
    }
}

// --- real fee-claim handler success ---------------------------------------

/// Seeds one charged fee-escrow settlement row on every replica.
///
/// The row is the *input* an already-applied paid certificate produces; the
/// parent E2E creates it through the real CLI/paid flow. Everything the claim
/// itself does below -- outer signature verification against the pinned
/// registered key, the typed preflight, the unmodified `handle_fee_claim`
/// state machine, its own receipt and its retained claim row -- is real.
fn seed_charged_settlement(
    network: &Network,
    escrow_request_id: [u8; 32],
) -> FastPathSettlementRecord {
    let mut shares: Vec<FastPathFeeShare> = network
        .signers
        .iter()
        .enumerate()
        .map(|(index, signer)| FastPathFeeShare {
            validator_id: signer.id,
            // Validator zero's entitlement is exactly zero, so its claim is
            // the closed `ZeroShare` operation.
            amount: if index == 0 { 0 } else { 100 },
            claimed: false,
        })
        .collect();
    shares.sort_by_key(|share| share.validator_id);
    let total: u64 = shares.iter().map(|share| share.amount).sum();
    let settlement = FastPathSettlementRecord {
        context: fixture::protocol(),
        request_id: escrow_request_id,
        generation: 1,
        resource_id: Some(
            BondResourceId::new(network.bond.resource_domain, network.bond.resource).unwrap(),
        ),
        fee_output: Some(objects::ObjectRef {
            id: ObjectId::new([0x7a; 32]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x7b; 32]),
        }),
        fee_output_epoch: Some(Epoch::new(0)),
        total_amount: Some(total),
        shares,
    };
    let key = local_instance_state::fastpath_settlement_key(&fixture::chain(), &escrow_request_id)
        .unwrap();
    let bytes = encode_fastpath_settlement_record(&settlement).unwrap();
    for replica in 0..REPLICAS {
        network.put(replica, key.clone(), StateMutation::Put(bytes.clone()));
    }
    settlement
}

/// Mirrors `fee_claims::preparation::advance_claim_row` for the zero-share
/// case: bump the generation and mark exactly this validator's share claimed.
fn predicted_claim_row(
    settlement: &FastPathSettlementRecord,
    validator_id: ValidatorId,
) -> FastPathSettlementRecord {
    let mut next = settlement.clone();
    next.generation = settlement.generation.checked_add(1).unwrap();
    let index = next
        .shares
        .iter()
        .position(|share| share.validator_id == validator_id)
        .unwrap();
    next.shares[index].claimed = true;
    next
}

fn zero_share_claim_candidate(
    network: &Network,
    settlement: &FastPathSettlementRecord,
    next: &FastPathSettlementRecord,
    request_id: [u8; 32],
) -> OrderedCandidate {
    let resolver = &network.resolver;
    let previous_bytes = encode_fastpath_settlement_record(settlement).unwrap();
    let next_bytes = encode_fastpath_settlement_record(next).unwrap();
    let intent = fee_claims::codec::FeeClaimIntent {
        context: fixture::protocol(),
        request_id,
        escrow_request_id: settlement.request_id,
        certificate_epoch: Epoch::new(0),
        validator_id: network.bond.validator_id,
        resource_id: settlement.resource_id.unwrap(),
        expected_generation: settlement.generation,
        expected_fee_output: settlement.fee_output.clone().unwrap(),
        expected_previous_row_digest: fee_claims::fee_claim_row_digest(
            resolver,
            settlement.context.epoch(),
            &previous_bytes,
        )
        .unwrap(),
        expected_next_row_digest: fee_claims::fee_claim_row_digest(
            resolver,
            next.context.epoch(),
            &next_bytes,
        )
        .unwrap(),
        share_amount: 0,
        recipient: address_of(0x5c),
        operation: fee_claims::codec::FeeClaimOperation::ZeroShare,
    };
    let digest = fee_claims::fee_claim_intent_digest(resolver, &intent).unwrap();
    let frame = fee_claims::fee_claim_signing_frame(&intent.context, digest).unwrap();
    let signed = fee_claims::codec::SignedFeeClaimIntent {
        signature: fixture::key().sign(&frame).into(),
        intent,
    };
    OrderedCandidate {
        context: fixture::protocol(),
        request_id,
        kind: OrderedOperationKind::FeeClaim,
        intent: fee_claims::codec::encode_signed_fee_claim_intent(&signed).unwrap(),
        created_checkpoint: 11,
    }
}

#[test]
fn a_real_zero_share_fee_claim_commits_through_the_ordered_path_on_every_replica() {
    let network = setup();
    network.install_ordered();
    let escrow_request_id = [0x7c; 32];
    let settlement = seed_charged_settlement(&network, escrow_request_id);
    let next = predicted_claim_row(&settlement, network.bond.validator_id);
    let request_id = [0x7d; 32];
    let candidate = zero_share_claim_candidate(&network, &settlement, &next, request_id);

    // The outer fee-claim signature verifies purely against the pinned
    // registered key, with no storage read at all.
    authenticate_candidate(&network.env(), &candidate).unwrap();

    network.round(1, Some(&candidate));
    network.round(2, None);
    let (round3, certificate3, _) = network.round(3, None);

    let settlement_key =
        local_instance_state::fastpath_settlement_key(&fixture::chain(), &escrow_request_id)
            .unwrap();
    let claim_key = local_instance_state::fastpath_fee_claim_key(
        &fixture::chain(),
        &escrow_request_id,
        next.generation,
    )
    .unwrap();
    for (replica, output) in round3.iter().enumerate() {
        assert_eq!(output.committed.len(), 1, "replica {replica}");
        let outcome = &output.committed[0];
        assert_eq!(outcome.request_id, request_id);
        assert_eq!(
            outcome.output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
        // The real handler advanced the settlement row and retained its own
        // signed claim row -- the ordered path added no shortcut of its own.
        assert_eq!(
            decode_fastpath_settlement_record(&network.value(replica, &settlement_key).unwrap())
                .unwrap(),
            next
        );
        assert_eq!(
            network.value(replica, &claim_key).unwrap(),
            candidate.intent
        );
        // The handler's own original request receipt is the one that landed.
        assert!(
            network.stores[replica]
                .get_request_receipt(
                    &network.context,
                    network.domain(),
                    DurableRequestId::new(request_id).unwrap()
                )
                .unwrap()
                .is_some()
        );
    }

    // A second, stale claim for the same share is refused, not re-executed.
    let stale = zero_share_claim_candidate(&network, &settlement, &next, [0x7e; 32]);
    network.round(4, Some(&stale));
    network.round(5, None);
    let (round6, _, _) = network.round(6, None);
    for (replica, output) in round6.iter().enumerate() {
        assert_eq!(
            refusal_of(&output.committed[0]),
            OrderedRefusal::StaleGeneration
        );
        assert_eq!(
            decode_fastpath_settlement_record(&network.value(replica, &settlement_key).unwrap())
                .unwrap(),
            next
        );
    }

    // Exact replay of the accepting certificate remains read-only.
    for replica in 0..REPLICAS {
        let before = network.snapshot(replica, &[request_id], 6);
        let replay = process_certificate(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &certificate3,
        )
        .unwrap();
        assert!(replay.committed.is_empty());
        assert_eq!(network.snapshot(replica, &[request_id], 6), before);
        assert_eq!(
            decode_fastpath_settlement_record(&network.value(replica, &settlement_key).unwrap())
                .unwrap(),
            next
        );
    }
}

// --- profile shape --------------------------------------------------------

// --- follow-up 1: the rows that decided a refusal are CAS-asserted --------

/// Wraps a real store and, exactly once, lands a foreign write on one named row
/// inside `commit_invocation` immediately before forwarding it.
///
/// That is precisely the race the staged read assertions exist for: another
/// writer moves the row whose healthy revision decided this invocation's answer
/// after the decision was taken but before it commits.
struct RaceStore<'a> {
    inner: &'a MemoryDurableStateStore,
    context: DurableOperationContext,
    domain: AtomicityDomainId,
    race_key: Vec<u8>,
    race_value: Vec<u8>,
    raced: std::cell::Cell<bool>,
}

impl RaceStore<'_> {
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

impl DurableDomainStateStore for RaceStore<'_> {
    fn get_namespace_lifecycle(
        &self,
        context: &runtime::DurableOperationContext,
        domain: runtime::AtomicityDomainId,
    ) -> Result<runtime::NamespaceLifecycle, runtime::DurableReadError> {
        self.inner.get_namespace_lifecycle(context, domain)
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
        self.inner.commit_durable(context, transaction)
    }
}

impl StructuredDurableDomainStateStore for RaceStore<'_> {
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
        if !self.raced.replace(true) {
            self.land_foreign_write();
        }
        self.inner.commit_invocation(context, transaction)
    }
}

#[test]
fn a_refusal_asserts_the_row_that_decided_it_so_a_concurrent_change_rejects_the_commit() {
    let network = setup();
    network.install_ordered();

    // Advance the committed bond row so the candidate below is genuinely stale.
    let mut advanced = network.bond.clone();
    advanced.generation = advanced.generation.checked_add(1).unwrap();
    for replica in 0..REPLICAS {
        network.put(
            replica,
            network.bond_key(),
            StateMutation::Put(encode_fastpath_bond_record(&advanced).unwrap()),
        );
    }
    let recipient = address_of(0x5d);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0x81; 32];
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);
    network.round(1, Some(&candidate));
    network.round(2, None);
    let (certificate, _) = network.certify(3, None);

    // A third generation lands on the bond row inside the refusing commit.
    let mut raced_row = advanced.clone();
    raced_row.generation = advanced.generation.checked_add(1).unwrap();
    let victim = 0usize;
    let race = RaceStore {
        inner: &network.stores[victim],
        context: network.context,
        domain: network.domain(),
        race_key: network.bond_key(),
        race_value: encode_fastpath_bond_record(&raced_row).unwrap(),
        raced: std::cell::Cell::new(false),
    };
    let chain = fixture::chain();
    let outcome_key = engine::ordered_outcome_key_for_tests(&chain, &request_id);

    // The bond row whose healthy revision decided `StaleGeneration` is a CAS
    // assertion, so the whole invocation is rejected rather than retaining a
    // refusal against state that no longer justifies it.
    let result = process_certificate(&race, &network.context, &network.env(), &certificate);
    assert!(
        matches!(
            result,
            Err(OrderedEconomicsError::Node(
                NodeCoreError::DurableCommitRejected(_)
            ))
        ),
        "expected a rejected commit, got {result:?}"
    );
    // Nothing was retained: no receipt, no outcome row, no advanced prefix.
    assert!(
        network.stores[victim]
            .get_request_receipt(
                &network.context,
                network.domain(),
                DurableRequestId::new(request_id).unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert!(network.value(victim, &outcome_key).is_none());
    assert!(
        network
            .value(
                victim,
                &engine::ordered_applied_height_key_for_tests(&chain)
            )
            .is_none()
    );
    assert_eq!(network.committed_bond(victim), raced_row);

    // Retrying against the settled store re-decides from the row as it now
    // stands and commits one refusal.
    let retried = process_certificate(
        &network.stores[victim],
        &network.context,
        &network.env(),
        &certificate,
    )
    .unwrap();
    assert_eq!(
        refusal_of(&retried.committed[0]),
        OrderedRefusal::StaleGeneration
    );
    assert!(network.value(victim, &outcome_key).is_some());
    assert_eq!(network.committed_bond(victim), raced_row);
}

// --- follow-up 3: a completed candidate is never re-placed or re-executed --

#[test]
fn a_completed_candidate_is_answered_from_its_retained_outcome_and_never_re_placed() {
    use consensus::{ConsensusEngine, ConsensusEvent};

    let network = setup();
    network.install_ordered();
    let chain = fixture::chain();
    let recipient = address_of(0x5e);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0xb1; 32];
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);
    let digest = engine::ordered_candidate_digest_for_tests(&network.resolver, &candidate);

    network.round(1, Some(&candidate));
    network.round(2, None);
    let (round3, _, _) = network.round(3, None);
    let original: OrderedOutcome = round3[0].committed[0].clone();
    assert_eq!(original.block_height, 1);
    assert_eq!(
        original.output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );

    // 1. The bounded read-only query returns the exact retained outcome on
    //    every independent store.
    for replica in 0..REPLICAS {
        let queried = query_ordered_outcome(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &request_id,
        )
        .unwrap()
        .expect("a completed request retains its outcome");
        assert_eq!(
            encode_ordered_outcome(&queried).unwrap(),
            encode_ordered_outcome(&original).unwrap(),
            "replica {replica}"
        );
    }
    // A request that never ran has no outcome, and absence is not completion.
    assert!(
        query_ordered_outcome(
            &network.stores[0],
            &network.context,
            &network.env(),
            &[0xb2; 32]
        )
        .unwrap()
        .is_none()
    );

    // 2. A signing leader refuses to place it a second time, writes nothing,
    //    and re-acquires no lock.
    let leader4 = network.leader_index(4);
    let before = network.snapshot(leader4, &[request_id], 4);
    let nonce_lock_key =
        fastpath_nonce_lock_key(&chain, &fixture::sender(), Epoch::new(0)).unwrap();
    let result = propose(
        &network.stores[leader4],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader4],
    );
    match &result {
        Err(error @ OrderedEconomicsError::AlreadyCompleted(_)) => {
            let completed = error.completed_outcome().expect("typed completed outcome");
            assert_eq!(
                encode_ordered_outcome(completed).unwrap(),
                encode_ordered_outcome(&original).unwrap()
            );
            assert!(!error.is_semantic_rejection());
            assert!(!error.requires_reconciliation());
        }
        other => panic!("expected AlreadyCompleted, got {other:?}"),
    }
    assert_eq!(network.snapshot(leader4, &[request_id], 4), before);
    assert!(network.value(leader4, &nonce_lock_key).is_none());

    // 3. Same request id, changed signed bytes: still a boundary conflict,
    //    never answered from the foreign completed outcome.
    let mut other_next = next.clone();
    other_next.committed_at_checkpoint = 12;
    let changed = unbond_candidate(
        &network,
        &network.bond,
        &other_next,
        request_id,
        recipient,
        12,
    );
    assert!(matches!(
        propose(
            &network.stores[leader4],
            &network.context,
            &network.env(),
            Some(&changed),
            &network.signers[leader4],
        ),
        Err(OrderedEconomicsError::RequestHeaderConflict)
    ));

    // 4. A byzantine leader places the completed candidate again at the next
    //    economic height, bypassing `propose` with the raw engine.
    let leader_state = consensus::decode_consensus_state(
        &network
            .value(leader4, &engine::ordered_state_key_for_tests(&chain))
            .unwrap(),
    )
    .unwrap();
    let duplicate = network
        .policy
        .engine()
        .propose(&leader_state, vec![digest], &network.signers[leader4])
        .unwrap();
    assert_eq!(duplicate.height, 4);
    let duplicate_ordered = OrderedProposal {
        proposal: duplicate.clone(),
        candidate: Some(candidate.clone()),
    };

    // An honest voter refuses: it will not vote to place a finished operation.
    let honest = network.non_leader(&[4]);
    assert!(matches!(
        process_proposal(
            &network.stores[honest],
            &network.context,
            &network.env(),
            &duplicate_ordered,
            &network.signers[honest],
        ),
        Err(OrderedEconomicsError::AlreadyCompleted(_))
    ));
    assert!(
        network
            .value(
                honest,
                &engine::ordered_vote_record_key_for_tests(&chain, 4)
            )
            .is_none()
    );

    // Declared recovery may still record the authentic proposal so it can keep
    // replaying artifacts in dependency order. It reserves nothing.
    for replica in 0..REPLICAS {
        observe_proposal(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &duplicate_ordered,
        )
        .unwrap();
        assert!(network.value(replica, &nonce_lock_key).is_none());
        assert!(
            network
                .value(
                    replica,
                    &engine::ordered_reservation_key_for_tests(&chain, &request_id)
                )
                .is_none()
        );
    }

    // A quorum of byzantine replicas certifies the duplicate placement.
    let genesis_state = network.policy.engine().genesis_state(TRUSTED_NOW_MILLIS);
    let votes: Vec<ConsensusVote> = network
        .signers
        .iter()
        .map(|signer| {
            let output = network
                .policy
                .engine()
                .on_event(
                    &genesis_state,
                    ConsensusEvent::Proposal(duplicate.clone()),
                    signer,
                    &super::policy::Ed25519ConsensusVerifier,
                )
                .unwrap();
            output
                .outbound_messages
                .iter()
                .find_map(|message| match message {
                    ConsensusMessage::Vote(vote) => Some(vote.clone()),
                    _ => None,
                })
                .unwrap()
        })
        .collect();
    let duplicate_certificate = network
        .policy
        .engine()
        .certificate_from_votes(&duplicate, &votes, &super::policy::Ed25519ConsensusVerifier)
        .unwrap()
        .unwrap();
    for replica in 0..REPLICAS {
        process_certificate(
            &network.stores[replica],
            &network.context,
            &network.env(),
            &duplicate_certificate,
        )
        .unwrap();
    }

    // 5. Two further certified heights commit the duplicate placement. Every
    //    replica answers with the EXACT original outcome: nothing is
    //    re-executed, the business row is untouched, and the receipt and
    //    outcome rows keep their original revisions.
    let bond_revision_before = network.revision(0, &network.bond_key());
    let outcome_key = engine::ordered_outcome_key_for_tests(&chain, &request_id);
    let outcome_revision_before = network.revision(0, &outcome_key);
    network.round(5, None);
    let (round6, _, _) = network.round(6, None);
    for (replica, output) in round6.iter().enumerate() {
        assert_eq!(output.committed.len(), 1, "replica {replica}");
        assert_eq!(
            encode_ordered_outcome(&output.committed[0]).unwrap(),
            encode_ordered_outcome(&original).unwrap(),
            "replica {replica} must answer with the exact original outcome"
        );
        // Still the one applied effect, at its original height.
        assert_eq!(output.committed[0].block_height, 1);
        assert_eq!(network.committed_bond(replica), next);
    }
    assert_eq!(
        network.revision(0, &network.bond_key()),
        bond_revision_before
    );
    assert_eq!(network.revision(0, &outcome_key), outcome_revision_before);
    assert_eq!(
        query_ordered_outcome(
            &network.stores[0],
            &network.context,
            &network.env(),
            &request_id
        )
        .unwrap()
        .map(|outcome| encode_ordered_outcome(&outcome).unwrap()),
        Some(encode_ordered_outcome(&original).unwrap())
    );
}

#[test]
fn a_completion_query_fails_closed_when_its_own_receipt_is_missing_or_disagrees() {
    let network = setup();
    network.install_ordered();
    let chain = fixture::chain();
    let recipient = address_of(0x5f);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0xc1; 32];
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);
    network.round(1, Some(&candidate));
    network.round(2, None);
    let (round3, _, _) = network.round(3, None);
    let original: OrderedOutcome = round3[0].committed[0].clone();

    // Healthy: the retained outcome agrees with its own committed receipt.
    assert!(
        query_ordered_outcome(
            &network.stores[0],
            &network.context,
            &network.env(),
            &request_id
        )
        .unwrap()
        .is_some()
    );

    // An outcome row with no committed receipt at all is persisted
    // inconsistency, never an answer: the query must fail closed rather than
    // fabricate a completion for a request that never produced one.
    let orphan_id = [0xc2; 32];
    let orphan = OrderedOutcome {
        candidate_digest: original.candidate_digest,
        request_id: orphan_id,
        block_height: original.block_height,
        block_digest: original.block_digest,
        output: NodeOutput::new(
            vec![
                NodeResponse::new(
                    RequestId::new(orphan_id).unwrap(),
                    NodeResponseStatus::Accepted,
                    None,
                )
                .unwrap(),
            ],
            Vec::new(),
        )
        .unwrap(),
    };
    network.put(
        0,
        engine::ordered_outcome_key_for_tests(&chain, &orphan_id),
        StateMutation::Put(engine::encode_retained_outcome_for_tests(&orphan)),
    );
    let orphan_result = query_ordered_outcome(
        &network.stores[0],
        &network.context,
        &network.env(),
        &orphan_id,
    );
    assert!(
        matches!(orphan_result, Err(OrderedEconomicsError::Prerequisite(_))),
        "expected a fail-closed stop, got {orphan_result:?}"
    );

    // An outcome row that disagrees with the responses its own receipt retained
    // also fails closed, on every path that consults it.
    let tampered = OrderedOutcome {
        output: NodeOutput::new(
            vec![
                NodeResponse::new(
                    RequestId::new(request_id).unwrap(),
                    NodeResponseStatus::Rejected,
                    Some(encode_ordered_refusal_payload(OrderedRefusal::StaleGeneration).unwrap()),
                )
                .unwrap(),
            ],
            Vec::new(),
        )
        .unwrap(),
        ..original.clone()
    };
    network.put(
        0,
        engine::ordered_outcome_key_for_tests(&chain, &request_id),
        StateMutation::Put(engine::encode_retained_outcome_for_tests(&tampered)),
    );
    let tampered_result = query_ordered_outcome(
        &network.stores[0],
        &network.context,
        &network.env(),
        &request_id,
    );
    assert!(
        matches!(tampered_result, Err(OrderedEconomicsError::Prerequisite(_))),
        "expected a fail-closed stop, got {tampered_result:?}"
    );

    // The admission path must not answer AlreadyCompleted from an inconsistent
    // row, and must not treat it as a fresh placement either.
    let leader = network.leader_index(4);
    let admission = propose(
        &network.stores[0],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader],
    );
    assert!(
        matches!(admission, Err(OrderedEconomicsError::Prerequisite(_))),
        "expected a fail-closed stop, got {admission:?}"
    );
    assert!(
        network
            .value(0, &engine::ordered_leader_record_key_for_tests(&chain, 4))
            .is_none()
    );
}

// --- tombstones are corruption, never virgin absence ----------------------

/// One committed Unbond plus the exact outcome it retained, so a tombstone
/// regression can start from genuinely healthy completed state.
fn completed_network(
    request_id: [u8; 32],
    recipient_seed: u8,
) -> (Network, OrderedOutcome, OrderedCandidate) {
    let network = setup();
    network.install_ordered();
    let recipient = address_of(recipient_seed);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);
    network.round(1, Some(&candidate));
    network.round(2, None);
    let (round3, _, _) = network.round(3, None);
    let outcome = round3[0].committed[0].clone();
    (network, outcome, candidate)
}

#[test]
fn a_tombstoned_outcome_row_stops_instead_of_reading_as_not_completed() {
    let (network, original, candidate) = completed_network([0xd1; 32], 0x61);
    let chain = fixture::chain();
    let outcome_key = engine::ordered_outcome_key_for_tests(&chain, &candidate.request_id);

    // Healthy first: the completion is visible.
    assert!(
        query_ordered_outcome(
            &network.stores[0],
            &network.context,
            &network.env(),
            &candidate.request_id
        )
        .unwrap()
        .is_some()
    );

    // Delete the retained outcome. Its revision is now non-initial, so this is
    // a tombstone: reporting it as `None` would let a finished request be
    // placed and executed a second time.
    network.put(0, outcome_key.clone(), StateMutation::Delete);
    let queried = query_ordered_outcome(
        &network.stores[0],
        &network.context,
        &network.env(),
        &candidate.request_id,
    );
    assert!(
        matches!(queried, Err(OrderedEconomicsError::Prerequisite(_))),
        "expected a stop, got {queried:?}"
    );

    // Every signing path stops too, and rewrites nothing.
    let leader = network.leader_index(4);
    let before = network.snapshot(0, &[candidate.request_id], 4);
    let proposed = propose(
        &network.stores[0],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader],
    );
    assert!(
        matches!(proposed, Err(OrderedEconomicsError::Prerequisite(_))),
        "expected a stop, got {proposed:?}"
    );
    assert_eq!(network.snapshot(0, &[candidate.request_id], 4), before);
    assert!(network.value(0, &outcome_key).is_none());
    assert_eq!(network.committed_bond(0), network.committed_bond(1));

    // A replica whose row is intact is unaffected: the stop is local.
    assert!(
        query_ordered_outcome(
            &network.stores[1],
            &network.context,
            &network.env(),
            &candidate.request_id
        )
        .unwrap()
        .map(|outcome| encode_ordered_outcome(&outcome).unwrap())
            == Some(encode_ordered_outcome(&original).unwrap())
    );
}

#[test]
fn a_tombstoned_applied_height_marker_stops_instead_of_reading_as_genesis() {
    let (network, _, candidate) = completed_network([0xd2; 32], 0x62);
    let chain = fixture::chain();
    let applied_key = engine::ordered_applied_height_key_for_tests(&chain);
    assert!(network.value(0, &applied_key).is_some());
    let bond_before = network.committed_bond(0);

    // Deleting the marker must not read back as height zero: that would
    // re-execute an already applied economic prefix.
    network.put(0, applied_key.clone(), StateMutation::Delete);
    let state_before = network.value(0, &engine::ordered_state_key_for_tests(&chain));

    let status = query_status(&network.stores[0], &network.context, &network.env());
    assert!(status.is_ok(), "status is a pure consensus read");
    let leader = network.leader_index(4);
    let proposed = propose(
        &network.stores[0],
        &network.context,
        &network.env(),
        None,
        &network.signers[leader],
    );
    // `propose` itself does not read the marker; the applying paths do.
    let _ = proposed;
    let (certificate, ordered) = network.certify_on(&[1, 2, 3], 4, None);
    let applied = process_proposal(
        &network.stores[0],
        &network.context,
        &network.env(),
        &ordered,
        &network.signers[0],
    );
    assert!(
        matches!(applied, Err(OrderedEconomicsError::Prerequisite(_))),
        "expected a stop, got {applied:?}"
    );
    let certified = process_certificate(
        &network.stores[0],
        &network.context,
        &network.env(),
        &certificate,
    );
    assert!(
        matches!(certified, Err(OrderedEconomicsError::Prerequisite(_))),
        "expected a stop, got {certified:?}"
    );
    // Nothing moved: no marker recreated at zero, no state rewrite, no
    // re-executed business effect.
    assert!(network.value(0, &applied_key).is_none());
    assert_eq!(
        network.value(0, &engine::ordered_state_key_for_tests(&chain)),
        state_before
    );
    assert_eq!(network.committed_bond(0), bond_before);
    assert!(
        network
            .value(0, &engine::ordered_vote_record_key_for_tests(&chain, 4))
            .is_none()
    );
    let _ = candidate;
}

#[test]
fn tombstoned_immutable_order_rows_stop_instead_of_being_recreated() {
    // A header tombstone for a request that was proposed but never completed.
    let network = setup();
    network.install_ordered();
    let chain = fixture::chain();
    let recipient = address_of(0x63);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let request_id = [0xd3; 32];
    let candidate = unbond_candidate(&network, &network.bond, &next, request_id, recipient, 11);
    let leader = network.leader_index(1);
    propose(
        &network.stores[0],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader],
    )
    .unwrap();
    let header_key = engine::ordered_request_header_key_for_tests(&chain, &request_id);
    let candidate_key = engine::ordered_candidate_record_key_for_tests(
        &chain,
        engine::ordered_candidate_digest_for_tests(&network.resolver, &candidate),
    );
    assert!(network.value(0, &header_key).is_some());
    assert!(network.value(0, &candidate_key).is_some());

    network.put(0, header_key.clone(), StateMutation::Delete);
    let leader2 = network.leader_index(2);
    let after_header_tombstone = propose(
        &network.stores[0],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[leader2],
    );
    assert!(
        matches!(
            after_header_tombstone,
            Err(OrderedEconomicsError::Prerequisite(_))
        ),
        "expected a stop, got {after_header_tombstone:?}"
    );
    // The immutable header was not recreated.
    assert!(network.value(0, &header_key).is_none());

    // Same for a deleted content-addressed candidate record, on a replica whose
    // header is still intact.
    propose(
        &network.stores[1],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[network.leader_index(1)],
    )
    .unwrap();
    network.put(1, candidate_key.clone(), StateMutation::Delete);
    let after_candidate_tombstone = propose(
        &network.stores[1],
        &network.context,
        &network.env(),
        Some(&candidate),
        &network.signers[network.leader_index(2)],
    );
    assert!(
        matches!(
            after_candidate_tombstone,
            Err(OrderedEconomicsError::Prerequisite(_))
        ),
        "expected a stop, got {after_candidate_tombstone:?}"
    );
    assert!(network.value(1, &candidate_key).is_none());
}

#[test]
fn a_retained_outcome_must_agree_with_its_immutable_request_header() {
    let (network, original, candidate) = completed_network([0xd4; 32], 0x64);
    let chain = fixture::chain();
    let header_key = engine::ordered_request_header_key_for_tests(&chain, &candidate.request_id);

    // Rewrite the header so it names a different candidate digest. The outcome
    // row is now an orphan: it must not be reported on its own authority.
    network.put(
        0,
        header_key,
        StateMutation::Put(engine::encode_request_header_for_tests(
            digest32(0xee),
            candidate.kind,
            candidate.created_checkpoint,
        )),
    );
    let queried = query_ordered_outcome(
        &network.stores[0],
        &network.context,
        &network.env(),
        &candidate.request_id,
    );
    assert!(
        matches!(queried, Err(OrderedEconomicsError::Prerequisite(_))),
        "expected a stop, got {queried:?}"
    );

    // And a completion with no header at all is equally refused.
    let orphan_id = [0xd5; 32];
    let orphan = OrderedOutcome {
        request_id: orphan_id,
        output: NodeOutput::new(
            vec![
                NodeResponse::new(
                    RequestId::new(orphan_id).unwrap(),
                    NodeResponseStatus::Accepted,
                    None,
                )
                .unwrap(),
            ],
            Vec::new(),
        )
        .unwrap(),
        ..original
    };
    network.put(
        0,
        engine::ordered_outcome_key_for_tests(&chain, &orphan_id),
        StateMutation::Put(engine::encode_retained_outcome_for_tests(&orphan)),
    );
    let orphan_result = query_ordered_outcome(
        &network.stores[0],
        &network.context,
        &network.env(),
        &orphan_id,
    );
    assert!(
        matches!(orphan_result, Err(OrderedEconomicsError::Prerequisite(_))),
        "expected a stop, got {orphan_result:?}"
    );
}

#[test]
fn a_receipt_whose_two_event_digests_disagree_fails_a_completion_closed() {
    let (network, original, candidate) = completed_network([0xd6; 32], 0x65);
    let chain = fixture::chain();

    // A fresh request whose header and outcome row agree perfectly, but whose
    // receipt carries one event digest in its outer field and a different one
    // inside its own `NodeDedupRecord` projection. Which digest a path records
    // (intent for an accepted handler, candidate for a refusal) is free; the
    // receipt disagreeing with itself is corruption.
    let forged_id = [0xd7; 32];
    let responses = vec![
        NodeResponse::new(
            RequestId::new(forged_id).unwrap(),
            NodeResponseStatus::Accepted,
            None,
        )
        .unwrap(),
    ];
    let outer_digest = digest32(0xa1);
    let inner_digest = digest32(0xa2);
    assert_ne!(outer_digest, inner_digest);
    let dedup = NodeDedupRecord::new(
        RequestId::new(forged_id).unwrap(),
        inner_digest,
        responses.clone(),
    )
    .unwrap();
    let receipt = DurableRequestReceipt::new(
        DurableRequestId::new(forged_id).unwrap(),
        outer_digest,
        dedup.encode().unwrap(),
    )
    .unwrap();
    assert_eq!(
        network.stores[0].commit_invocation(
            &network.context,
            DurableInvocationTransaction::new(
                network.domain(),
                None,
                runtime::DurableObjectChanges::empty(),
                receipt,
                None,
            )
            .unwrap(),
        ),
        DurableCommitOutcome::Committed
    );

    let forged_outcome = OrderedOutcome {
        request_id: forged_id,
        output: NodeOutput::new(responses, Vec::new()).unwrap(),
        ..original
    };
    network.put(
        0,
        engine::ordered_request_header_key_for_tests(&chain, &forged_id),
        StateMutation::Put(engine::encode_request_header_for_tests(
            forged_outcome.candidate_digest,
            candidate.kind,
            candidate.created_checkpoint,
        )),
    );
    network.put(
        0,
        engine::ordered_outcome_key_for_tests(&chain, &forged_id),
        StateMutation::Put(engine::encode_retained_outcome_for_tests(&forged_outcome)),
    );

    let queried = query_ordered_outcome(
        &network.stores[0],
        &network.context,
        &network.env(),
        &forged_id,
    );
    assert!(
        matches!(queried, Err(OrderedEconomicsError::Prerequisite(_))),
        "expected a stop, got {queried:?}"
    );
}

// --- follow-up 2: already-recorded evidence under a fresh request id ------

fn fast_vote_pair(network: &Network, signer_index: usize) -> (Vec<u8>, Vec<u8>) {
    let certifier = consensus::FastPathCertifier::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        Epoch::new(0),
        validator_set(&network.signers),
    )
    .unwrap();
    let signer = &network.signers[signer_index];
    // The same validator signing two different payloads for one tx_hash: the
    // DR-0133 class (a) conflict, built with real keys and the real certifier.
    let a = certifier
        .cast_vote(digest32(0x01), digest32(0x02), digest32(0x03), signer)
        .unwrap();
    let b = certifier
        .cast_vote(digest32(0x01), digest32(0x04), digest32(0x03), signer)
        .unwrap();
    (
        consensus::encode_fast_vote(&a).unwrap(),
        consensus::encode_fast_vote(&b).unwrap(),
    )
}

fn digest32(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}

fn object_ref_at(id: u8, digest_byte: u8) -> objects::ObjectRef {
    objects::ObjectRef {
        id: ObjectId::new([id; 32]),
        version: 1,
        digest: digest32(digest_byte),
    }
}

fn preimage_of(entries: Vec<objects::ObjectRef>) -> consensus::LockedObjectSetPreimage {
    consensus::LockedObjectSetPreimage {
        chain_id: fixture::chain(),
        protocol_version: fixture::protocol().protocol_version(),
        epoch: Epoch::new(0),
        entries,
    }
}

fn preimage_digest(preimage: &consensus::LockedObjectSetPreimage) -> Digest32 {
    fixture::resolver()
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::ExecutionEffects,
            &consensus::encode_locked_object_set_preimage(preimage).unwrap(),
        )
        .unwrap()
}

/// One submission per DR-0133 family, all with real signatures from a genesis
/// validator, and all carrying `checkpoint`.
fn evidence_submissions(network: &Network, checkpoint: u64) -> Vec<OrderedEvidenceSubmission> {
    let (fast_a, fast_b) = fast_vote_pair(network, 1);

    let certifier = consensus::FastPathCertifier::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        Epoch::new(0),
        validator_set(&network.signers),
    )
    .unwrap();
    let shared = object_ref_at(0x10, 0x20);
    let low = preimage_of(vec![shared.clone(), object_ref_at(0x30, 0x40)]);
    let high = preimage_of(vec![shared, object_ref_at(0x50, 0x60)]);
    let conflict_a = certifier
        .cast_vote(
            digest32(0x71),
            digest32(0x72),
            preimage_digest(&low),
            &network.signers[2],
        )
        .unwrap();
    let conflict_b = certifier
        .cast_vote(
            digest32(0x73),
            digest32(0x74),
            preimage_digest(&high),
            &network.signers[2],
        )
        .unwrap();

    let epoch_certifier = consensus::EpochTransitionCertifier::new(
        fixture::chain(),
        fixture::protocol().protocol_version(),
        Epoch::new(0),
        validator_set(&network.signers),
    )
    .unwrap();
    let transition_a = epoch_certifier
        .cast_vote(
            Epoch::new(1),
            digest32(0x81),
            digest32(0x82),
            digest32(0x83),
            &network.signers[3],
        )
        .unwrap();
    let transition_b = epoch_certifier
        .cast_vote(
            Epoch::new(1),
            digest32(0x81),
            digest32(0x84),
            digest32(0x83),
            &network.signers[3],
        )
        .unwrap();

    vec![
        OrderedEvidenceSubmission::FastVote {
            statement_a: fast_a,
            statement_b: fast_b,
            checkpoint,
        },
        OrderedEvidenceSubmission::ObjectConflict {
            statement_a: consensus::encode_fast_vote(&conflict_a).unwrap(),
            statement_b: consensus::encode_fast_vote(&conflict_b).unwrap(),
            preimage_a: consensus::encode_locked_object_set_preimage(&low).unwrap(),
            preimage_b: consensus::encode_locked_object_set_preimage(&high).unwrap(),
            checkpoint,
        },
        OrderedEvidenceSubmission::EpochTransition {
            statement_a: consensus::encode_epoch_transition_vote(&transition_a).unwrap(),
            statement_b: consensus::encode_epoch_transition_vote(&transition_b).unwrap(),
            checkpoint,
        },
    ]
}

fn evidence_candidate(
    submission: &OrderedEvidenceSubmission,
    request_id: [u8; 32],
) -> OrderedCandidate {
    OrderedCandidate {
        context: fixture::protocol(),
        request_id,
        kind: OrderedOperationKind::Evidence,
        intent: encode_ordered_evidence_submission(submission).unwrap(),
        created_checkpoint: 11,
    }
}

fn accepted_evidence_record(
    outcome: &OrderedOutcome,
) -> equivocation::FastPathEquivocationEvidenceRecord {
    assert_eq!(
        outcome.output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    equivocation::decode_fastpath_equivocation_evidence_record(
        outcome.output.responses()[0].payload().unwrap(),
    )
    .unwrap()
}

#[test]
fn already_recorded_evidence_accepts_under_a_fresh_request_id_for_every_family() {
    // One independent four-store network per DR-0133 family, so each family is
    // exercised against a clean genesis rather than sharing a prefix.
    for family in 0..3usize {
        let network = setup();
        network.install_ordered();
        let first_submission = evidence_submissions(&network, 11).remove(family);
        // Same statements, different envelope checkpoint: the normalized
        // identity is unchanged, so the second placement must find the row
        // already recorded rather than rewrite it.
        let second_submission = evidence_submissions(&network, 21).remove(family);
        assert_ne!(
            encode_ordered_evidence_submission(&first_submission).unwrap(),
            encode_ordered_evidence_submission(&second_submission).unwrap()
        );

        let first_id = [0x90 + family as u8; 32];
        let second_id = [0xa0 + family as u8; 32];
        let first = evidence_candidate(&first_submission, first_id);
        let second = evidence_candidate(&second_submission, second_id);

        // Placement one: records the permanent one-time row.
        network.round(1, Some(&first));
        network.round(2, None);
        let (round3, _, _) = network.round(3, None);
        let recorded = accepted_evidence_record(&round3[0].committed[0]);
        assert_eq!(recorded.recorded_at_checkpoint, 11, "family {family}");

        // Placement two, fresh request id, identical normalized evidence. This
        // used to wedge the prefix: the handler accepts read-only and stages no
        // transaction at all.
        network.round(4, Some(&second));
        network.round(5, None);
        let (round6, certificate6, _) = network.round(6, None);
        for (replica, output) in round6.iter().enumerate() {
            assert_eq!(
                output.committed.len(),
                1,
                "family {family} replica {replica}"
            );
            let outcome = &output.committed[0];
            assert_eq!(outcome.request_id, second_id);
            let replayed = accepted_evidence_record(outcome);
            // The immutable one-time row was read, not rewritten: it still
            // reports the FIRST placement checkpoint and identical bytes.
            assert_eq!(replayed.recorded_at_checkpoint, 11);
            assert_eq!(replayed.evidence_bytes, recorded.evidence_bytes);
            // Both requests carry their own receipt and retained outcome.
            for request_id in [first_id, second_id] {
                assert!(
                    network.stores[replica]
                        .get_request_receipt(
                            &network.context,
                            network.domain(),
                            DurableRequestId::new(request_id).unwrap()
                        )
                        .unwrap()
                        .is_some()
                );
                assert!(
                    query_ordered_outcome(
                        &network.stores[replica],
                        &network.context,
                        &network.env(),
                        &request_id
                    )
                    .unwrap()
                    .is_some()
                );
            }
        }

        // Exact replay of the accepting certificate stays read-only.
        for replica in 0..REPLICAS {
            let before = network.snapshot(replica, &[first_id, second_id], 6);
            let replay = process_certificate(
                &network.stores[replica],
                &network.context,
                &network.env(),
                &certificate6,
            )
            .unwrap();
            assert!(replay.committed.is_empty(), "family {family}");
            assert_eq!(network.snapshot(replica, &[first_id, second_id], 6), before);
        }
    }
}

// --- follow-up 4: bounded decode before large copies ---------------------

#[test]
fn oversized_candidate_and_evidence_frames_are_rejected_by_their_own_bound() {
    // An oversized intent field is rejected without the decoder first being
    // made to copy it.
    let mut frame = CanonicalStruct::new(0x6440, 1);
    frame
        .field_bytes(
            1,
            execution::publication::encode_publication_context(&fixture::protocol()).unwrap(),
        )
        .unwrap();
    frame.field_bytes(2, [9u8; 32].to_vec()).unwrap();
    frame.field_u16(3, 1).unwrap();
    frame
        .field_bytes(4, vec![7u8; MAX_ORDERED_CANDIDATE_INTENT_BYTES + 1])
        .unwrap();
    frame.field_u64(5, 11).unwrap();
    let oversized: Vec<u8> = frame.finish().unwrap();
    assert!(decode_ordered_candidate(&oversized).is_err());

    // An empty intent is still rejected by the same bound.
    let mut empty = CanonicalStruct::new(0x6440, 1);
    empty
        .field_bytes(
            1,
            execution::publication::encode_publication_context(&fixture::protocol()).unwrap(),
        )
        .unwrap();
    empty.field_bytes(2, [9u8; 32].to_vec()).unwrap();
    empty.field_u16(3, 1).unwrap();
    empty.field_bytes(4, Vec::new()).unwrap();
    empty.field_u64(5, 11).unwrap();
    assert!(decode_ordered_candidate(&empty.finish().unwrap()).is_err());

    // The evidence envelope enforces the same closed-profile cap at its own
    // decoder entry, before any statement is copied out.
    let mut evidence = CanonicalStruct::new(0x6449, 1);
    evidence.field_u16(1, 1).unwrap();
    evidence
        .field_bytes(2, vec![1u8; MAX_ORDERED_EVIDENCE_SUBMISSION_BYTES])
        .unwrap();
    evidence.field_bytes(3, vec![2u8; 16]).unwrap();
    evidence.field_u64(4, 7).unwrap();
    let oversized_evidence: Vec<u8> = evidence.finish().unwrap();
    assert!(oversized_evidence.len() > MAX_ORDERED_EVIDENCE_SUBMISSION_BYTES);
    assert!(evidence_submission::decode_ordered_evidence_submission(&oversized_evidence).is_err());
}

#[test]
fn a_candidate_at_a_non_economic_height_is_rejected_and_shape_is_enforced_on_receipt() {
    let network = setup();
    network.install_ordered();
    let recipient = address_of(0x5a);
    let next = predicted_unbond(&network.bond, 11, *recipient.as_bytes());
    let candidate = unbond_candidate(&network, &network.bond, &next, [0x6e; 32], recipient, 11);
    network.round(1, Some(&candidate));

    // Height 2 is an empty descendant: offering a candidate there fails.
    let leader = network.leader_index(2);
    assert!(matches!(
        propose(
            &network.stores[leader],
            &network.context,
            &network.env(),
            Some(&candidate),
            &network.signers[leader],
        ),
        Err(OrderedEconomicsError::Unauthenticated(_))
    ));
}
