//! DR-0189 genuine ABCD -> ABCE replacement: the outgoing ABCD committee
//! accepts a terminal Seal over ABC/E readiness actually signed on four
//! separate imports, those same files activate, and e+1 runs. Retired D keeps
//! verified predecessor ownership of its imported bond and fee shares only.
use super::*;
use consensus::{ConsensusEngine, ConsensusEvent};
use std::cell::Cell;

/// Counts every consensus signature a refused signer would expose.
struct CountingSigner<'a> {
    inner: &'a TestSigner,
    created: Cell<usize>,
}

impl<'a> CountingSigner<'a> {
    fn new(inner: &'a TestSigner) -> Self {
        Self {
            inner,
            created: Cell::new(0),
        }
    }
}

impl consensus::ConsensusSigner for CountingSigner<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.inner.id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        self.created.set(self.created.get().checked_add(1).unwrap());
        consensus::ConsensusSigner::sign_framed(self.inner, framed)
    }
}

/// The single genesis member absent from the verified successor set.
fn retired(world: &SuccessorWorld) -> &TestSigner {
    let mut outgoing = world
        .network()
        .signers
        .iter()
        .filter(|signer: &&TestSigner| world.policy.registered_validator(signer.id).is_none());
    let retired: &TestSigner = outgoing.next().expect("D is retired");
    assert!(outgoing.next().is_none(), "exactly one member retires");
    retired
}

/// The single successor member absent from the genesis committee.
fn incoming(world: &SuccessorWorld) -> usize {
    let original: &OrderedEconomicsPolicy = &world.network().policy;
    let mut fresh = (0..world.members.len()).filter(|index: &usize| {
        original
            .registered_validator(world.members[*index].id)
            .is_none()
    });
    let incoming: usize = fresh.next().expect("E is incoming");
    assert!(fresh.next().is_none(), "exactly one member is incoming");
    incoming
}

fn leader_of(world: &SuccessorWorld, view: u64) -> usize {
    let leader: ValidatorId = world.policy.engine().validator_set().leader(view).unwrap();
    world
        .members
        .iter()
        .position(|member: &TestSigner| member.id == leader)
        .unwrap()
}

fn current_view(world: &SuccessorWorld, env: &OrderedEconomicsEnvironment<'_>) -> u64 {
    crate::ordered_economics::query_status_successor(&world.warrant(0), &world.targets[0].0, env)
        .unwrap()
        .current_view
}

/// Places `candidate` through genuine successor rounds until it commits.
pub(super) fn commit_through_rounds(
    world: &SuccessorWorld,
    env: &OrderedEconomicsEnvironment<'_>,
    candidate: &OrderedCandidate,
) -> OrderedOutcome {
    let mut placed: Option<&OrderedCandidate> = Some(candidate);
    for _ in 0..6 {
        let (outputs, _): (Vec<OrderedEventOutput>, consensus::QuorumCertificate) =
            successor_round(world, env, placed.take());
        if let Some(found) = outputs[0]
            .committed
            .iter()
            .find(|item: &&OrderedOutcome| item.request_id == candidate.request_id)
        {
            return found.clone();
        }
    }
    panic!("the candidate commits within two economic windows")
}

pub(super) fn committed_bond_row(
    world: &SuccessorWorld,
    index: usize,
    id: ValidatorId,
) -> (FastPathBondRecord, Vec<u8>) {
    let bytes: Vec<u8> = world
        .value(
            index,
            &fastpath_bond_record_key(&fixture::chain(), &id).unwrap(),
        )
        .1
        .unwrap();
    (decode_fastpath_bond_record(&bytes).unwrap(), bytes)
}

/// The exact next row the real `Unbond` handler commits at e+1, using the
/// imported resource policy's own unbonding delay.
pub(super) fn predicted_unbond(
    world: &SuccessorWorld,
    bond: &FastPathBondRecord,
    created_checkpoint: u64,
    recipient: [u8; 32],
) -> FastPathBondRecord {
    let policy: crate::economics::FastPathEconomicsPolicy =
        crate::economics::decode_fastpath_economics_policy(
            &world
                .value(
                    0,
                    &crate::local_instance_state::fastpath_economics_policy_key(&bond.context)
                        .unwrap(),
                )
                .1
                .unwrap(),
        )
        .unwrap();
    let resource: BondResourceId =
        BondResourceId::new(bond.resource_domain, bond.resource).unwrap();
    let delay: u64 = policy
        .resources
        .iter()
        .find(
            |entry: &&crate::economics::FastPathEconomicsResourcePolicy| {
                entry.resource_id == resource
            },
        )
        .unwrap()
        .bond
        .as_ref()
        .unwrap()
        .unbonding_epochs;
    let current: Epoch = world.policy.context().epoch();
    let mut next: FastPathBondRecord = bond.clone();
    next.generation = bond.generation.checked_add(1).unwrap();
    next.committed_at_checkpoint = created_checkpoint;
    next.lifecycle_epoch = current;
    next.state = FastPathBondState::Unbonding {
        unlock_epoch: Epoch::new(current.get().checked_add(delay).unwrap()),
        recipient,
    };
    next
}

/// `owner`'s own genuinely signed e+1 bond lifecycle candidate over the
/// exact committed `bond_bytes` and the claimed next row.
pub(super) fn bond_candidate(
    world: &SuccessorWorld,
    owner: &TestSigner,
    request_id: [u8; 32],
    bond_bytes: &[u8],
    next_row: &FastPathBondRecord,
    operation: BondLifecycleOperation,
    created_checkpoint: u64,
) -> OrderedCandidate {
    let resolver: &HashSuiteResolver = &world.network().resolver;
    bond_candidate_for_scope(
        resolver,
        world.policy.context(),
        owner,
        request_id,
        bond_bytes,
        next_row,
        operation,
        created_checkpoint,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn bond_candidate_for_scope(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    owner: &TestSigner,
    request_id: [u8; 32],
    bond_bytes: &[u8],
    next_row: &FastPathBondRecord,
    operation: BondLifecycleOperation,
    created_checkpoint: u64,
) -> OrderedCandidate {
    let next: PublicationContext = context.clone();
    let bond: FastPathBondRecord = decode_fastpath_bond_record(bond_bytes).unwrap();
    let intent: BondLifecycleIntent = BondLifecycleIntent {
        context: next.clone(),
        request_id,
        validator_id: owner.id,
        resource_id: BondResourceId::new(bond.resource_domain, bond.resource).unwrap(),
        expected_generation: bond.generation,
        expected_previous_row_digest: bond_row_digest(resolver, bond.lifecycle_epoch, bond_bytes)
            .unwrap(),
        expected_next_row_digest: bond_row_digest(
            resolver,
            next_row.lifecycle_epoch,
            &encode_fastpath_bond_record(next_row).unwrap(),
        )
        .unwrap(),
        operation,
    };
    let digest: Digest32 = bond_lifecycle_intent_digest(resolver, &intent).unwrap();
    let frame: Vec<u8> = bond_lifecycle_signing_frame(&intent.context, digest).unwrap();
    OrderedCandidate {
        context: next,
        request_id,
        kind: OrderedOperationKind::BondLifecycle,
        intent: encode_signed_bond_lifecycle_intent(&SignedBondLifecycleIntent {
            signature: owner.key.sign(&frame).into(),
            intent,
        })
        .unwrap(),
        created_checkpoint,
    }
}

/// `owner`'s own signed release leg moving `custody` to `recipient`.
pub(super) fn release_leg(
    world: &SuccessorWorld,
    owner: &TestSigner,
    request_id: [u8; 32],
    custody: &ObjectRef,
    recipient: [u8; 32],
) -> Vec<u8> {
    release_leg_for_scope(
        world,
        world.policy.context(),
        &world.next_base,
        owner,
        request_id,
        custody,
        recipient,
    )
}

pub(super) fn release_leg_for_scope(
    world: &SuccessorWorld,
    context: &PublicationContext,
    policy: &LocalExecutionPolicy,
    owner: &TestSigner,
    request_id: [u8; 32],
    custody: &ObjectRef,
    recipient: [u8; 32],
) -> Vec<u8> {
    let source: &CausalFixture = world.source();
    let network: &Network = &source.network;
    let next: PublicationContext = context.clone();
    let leg: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&network.resolver).unwrap(),
        call: CallIntent {
            context: next.clone(),
            request_id,
            sender: *owner.id.as_bytes(),
            nonce: 0,
            code: source.instance.code.clone(),
            instance: instance_target(&network.resolver, &source.instance).unwrap(),
            entrypoint: "transfer".into(),
            type_arguments: source.manifest.fee_policy.type_arguments.clone(),
            access: abi::AccessManifest {
                entries: vec![abi::AccessEntry {
                    object_ref: custody.clone(),
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::transfer_arguments(&recipient).unwrap(),
            gas_limit: 500_000,
        },
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = local_execution_signing_frame(&next, &leg).unwrap();
    encode_signed_local_execution(&SignedLocalExecutionIntent {
        signature: owner.key.sign(&frame).into(),
        intent: leg,
    })
    .unwrap()
}

/// Real ABCE activation: E's actually registered bond and key are admitted,
/// every member resolves a live warrant and a genuine e+1 round certifies on
/// all four independent files. E's Serving import refuses readiness.
#[test]
fn replacement_abce_activates_registered_e_and_certifies_an_e1_round() {
    let world: SuccessorWorld = replacement_world();
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    let e: usize = incoming(&world);
    let d: &TestSigner = retired(&world);
    assert_eq!(world.members.len(), REPLICAS);
    assert!(
        world
            .policy
            .registered_validator(world.members[e].id)
            .is_some()
    );
    assert!(world.policy.registered_validator(d.id).is_none());
    let bond: FastPathBondRecord = decode_fastpath_bond_record(
        &world
            .value(
                e,
                &fastpath_bond_record_key(&fixture::chain(), &world.members[e].id).unwrap(),
            )
            .1
            .unwrap(),
    )
    .unwrap();
    assert_eq!(bond.authorization_key, world.public_key(e));
    assert_eq!(bond.state, FastPathBondState::Active);
    for index in 0..REPLICAS {
        assert!(matches!(
            world.resolve(index).unwrap(),
            LiveAuthority::Successor(_)
        ));
        assert!(matches!(
            world.reactivate(index).unwrap(),
            SuccessorActivationOutcome::AlreadyActivated { .. }
        ));
    }
    let (_, certificate): (Vec<OrderedEventOutput>, consensus::QuorumCertificate) =
        successor_round(&world, &env, None);
    assert!(
        certificate
            .votes
            .iter()
            .any(|vote: &consensus::ConsensusVote| vote.validator == world.members[e].id),
        "incoming E signs with its registered key"
    );
    for index in 0..REPLICAS {
        let status: OrderedStatus = crate::ordered_economics::query_status_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &env,
        )
        .unwrap();
        assert_eq!(status.high_qc, certificate);
    }
    let entries: Vec<FastPathValidatorEntry> = world
        .members
        .iter()
        .map(|member: &TestSigner| FastPathValidatorEntry {
            id: member.id,
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: member.id.as_bytes().to_vec(),
        })
        .collect();
    let signer: ReadinessSigningKey =
        ReadinessSigningKey::new(world.members[e].id, world.members[e].key);
    assert!(matches!(
        retain_conditional_readiness(
            reconstruction_plan(world.source(), &world.cut_history),
            &world.saved,
            &world.targets[e].0,
            &world.targets[e].1,
            &world.operation,
            &entries,
            &signer,
        ),
        Err(ConditionalReadinessError::UnsupportedSuccessorControl)
    ));
    assert_eq!(signer.signatures_created(), 0);
}

/// Retired D: its own separately completed import never activates or
/// resolves, and it can neither propose, vote nor tick on any successor
/// target. Every refusal precedes any signature and any vote/state write.
#[test]
fn retired_d_is_refused_activation_resolution_and_consensus_signing() {
    let world: SuccessorWorld = replacement_world();
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    let d: &TestSigner = retired(&world);
    let domain: AtomicityDomainId = world.network().domain();
    let plan: VerifiedImportPlan = verify_saved_business_import(
        reconstruction_plan(world.source(), &world.cut_history),
        &world.saved,
    )
    .unwrap();
    let files: conditional_readiness::Files = conditional_readiness::Files::new();
    let (target, blobs): (SqliteImportTarget, SqliteBlobStore) =
        member_import(&plan, domain, d.id, &files, &world.operation, "retired-d");
    let signer: ReadinessSigningKey = ReadinessSigningKey::new(d.id, d.key);
    let mut artifacts: Artifacts<'_> = world.artifacts();
    assert!(
        activate_successor(
            reconstruction_plan(world.source(), &world.cut_history),
            &world.sealed_history,
            &mut artifacts,
            &target,
            &blobs,
            &world.operation,
            &signer,
            1,
        )
        .is_err(),
        "a retired outgoing member is not a successor member"
    );
    assert_eq!(signer.signatures_created(), 0);
    assert_eq!(
        target
            .get_successor_serving(&world.operation, domain)
            .unwrap(),
        SuccessorServingSlot::Inactive
    );
    assert!(!matches!(
        resolve_live_authority(
            &target,
            &world.operation,
            domain,
            reconstruction_plan(world.source(), &world.cut_history),
            &world.sealed_history,
            &mut artifacts,
            signer.public_key(),
        ),
        Ok(LiveAuthority::Successor(_))
    ));

    let view: u64 = current_view(&world, &env);
    let leader: usize = leader_of(&world, view);
    let counted: CountingSigner<'_> = CountingSigner::new(d);
    assert!(
        crate::ordered_economics::propose_successor(
            &world.warrant(leader),
            &world.targets[leader].0,
            &env,
            None,
            &counted,
        )
        .is_err()
    );
    let proposal: OrderedProposal = crate::ordered_economics::propose_successor(
        &world.warrant(leader),
        &world.targets[leader].0,
        &env,
        None,
        &world.members[leader],
    )
    .unwrap();
    let chain: protocol_types::ChainId = fixture::chain();
    let vote_key: Vec<u8> = crate::ordered_economics::identity::scoped_vote_record_key(
        world.policy.key_scope(),
        &chain,
        view,
    )
    .unwrap();
    let state_key: Vec<u8> = engine::scoped_state_key(world.policy.key_scope(), &chain).unwrap();
    for index in 0..REPLICAS {
        let before: [(StateRevision, Option<Vec<u8>>); 2] = [
            world.value(index, &vote_key),
            world.value(index, &state_key),
        ];
        assert!(
            crate::ordered_economics::process_proposal_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &env,
                &proposal,
                &counted,
            )
            .is_err()
        );
        assert!(
            process_tick_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &env,
                u64::MAX / 2,
                &counted,
            )
            .is_err()
        );
        assert_eq!(
            [
                world.value(index, &vote_key),
                world.value(index, &state_key)
            ],
            before
        );
    }
    assert_eq!(counted.created.get(), 0, "D exposes no consensus signature");
}

/// The real certified A->E paid escrow the registered cut imports.
fn funded_escrow(world: &SuccessorWorld) -> [u8; 32] {
    match &world.source {
        WorldSource::Replacement(fixture) => fixture.funded_escrow(),
        WorldSource::SameCommittee(_) => panic!("only the registered-E world funds E"),
    }
}

/// Every local observation a refused FastVote/ACK signer must leave intact.
type FastVoteObservation = (
    Vec<(StateRevision, Option<Vec<u8>>)>,
    DurableObjectHead,
    bool,
);

fn fastvote_observation(
    world: &SuccessorWorld,
    index: usize,
    keys: &[Vec<u8>],
    coin: ObjectId,
    request_id: [u8; 32],
) -> FastVoteObservation {
    let rows: Vec<(StateRevision, Option<Vec<u8>>)> = keys
        .iter()
        .map(|key: &Vec<u8>| world.value(index, key))
        .collect();
    let head: DurableObjectHead = world.targets[index]
        .0
        .get_object_head(&world.operation, world.network().domain(), coin)
        .unwrap();
    let receipt: bool = matches!(
        crate::serving_authority::query_request_receipt_successor(
            &world.warrant(index),
            &world.targets[index].0,
            crate::RequestId::new(request_id).unwrap(),
        )
        .unwrap(),
        crate::ReceiptQueryResult::Present { .. }
    );
    (rows, head, receipt)
}

/// Retired D is never the local signer of a FastVote prepare or an
/// availability ACK under any genuine ABC/E warrant. The paid request is an
/// ordinary member's genuinely signed e+1 transfer of the real imported
/// coin on the imported instance; every member then genuinely prepares and
/// retains it, proving the refusal is the local signer alone.
#[test]
fn retired_d_cannot_sign_fastvote_prepare_or_availability_ack() {
    let world: SuccessorWorld = replacement_world();
    let network: &Network = world.network();
    let domain: AtomicityDomainId = network.domain();
    let chain: protocol_types::ChainId = fixture::chain();
    let next: PublicationContext = world.policy.context().clone();
    let d: &TestSigner = retired(&world);
    let fee_policy: PaidFeePolicy = execution::paid_execution::decode_paid_fee_policy(
        &world
            .value(
                0,
                &crate::local_instance_state::paid_fee_policy_key(&next).unwrap(),
            )
            .1
            .unwrap(),
    )
    .unwrap();
    let coin_id: ObjectId = world.source().claimant_coin.id;
    let (version, digest): (DurableObjectVersion, Digest32) = match world.targets[0]
        .0
        .get_object_head(&world.operation, domain, coin_id)
        .unwrap()
    {
        DurableObjectHead::Current {
            object_version,
            digest,
            ..
        } => (object_version, digest),
        DurableObjectHead::Absent | DurableObjectHead::Tombstoned { .. } => {
            panic!("the imported claimant coin is live")
        }
    };
    let record: DurableObjectVersionRecord = world.targets[0]
        .0
        .get_object_version(&world.operation, domain, coin_id, version)
        .unwrap()
        .unwrap();
    let coin: Object = match record.payload() {
        DurableObjectPayload::Inline(inline) => {
            objects::decode_object(inline.canonical_bytes()).unwrap()
        }
        DurableObjectPayload::BlobReference(_) => panic!("standard asset coins are inline"),
    };
    let owner: [u8; 32] = match &coin.owner {
        Owner::Address(address) => *address.as_bytes(),
        _ => panic!("the claimant coin is address-owned"),
    };
    let sender: usize = network
        .signers
        .iter()
        .position(|signer: &TestSigner| *signer.id.as_bytes() == owner)
        .unwrap();
    let request_id: [u8; 32] = [0x7d; 32];
    let signed: Vec<u8> =
        successor_paid_transfer(&world, sender, &coin, digest, request_id, &fee_policy);
    let keys: Vec<Vec<u8>> = vec![
        crate::local_instance_state::fastpath_prepared_record_key(&chain, &request_id).unwrap(),
        crate::local_instance_state::fastpath_nonce_lock_key(&chain, &owner, next.epoch()).unwrap(),
        crate::fast_path::publication::fastpath_availability_ack_key(&chain, &request_id).unwrap(),
    ];
    let counted: CountingSigner<'_> = CountingSigner::new(d);
    for index in 0..REPLICAS {
        let before: FastVoteObservation =
            fastvote_observation(&world, index, &keys, coin_id, request_id);
        let refused: Result<consensus::FastVote, crate::fast_path::FastPathError> =
            crate::serving_authority::prepare_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &composition(&world, index, &fee_policy),
                &counted,
                &signed,
                1,
            );
        assert!(
            matches!(
                &refused,
                Err(crate::fast_path::FastPathError::Node(
                    crate::NodeCoreError::PersistenceInvariant(
                        "local signer is not the namespace successor member"
                    )
                ))
            ),
            "retired D is refused as local FastVote signer: {refused:?}"
        );
        assert_eq!(
            fastvote_observation(&world, index, &keys, coin_id, request_id),
            before
        );
    }
    let votes: Vec<consensus::FastVote> = (0..REPLICAS)
        .map(|index: usize| {
            crate::serving_authority::prepare_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &composition(&world, index, &fee_policy),
                &world.members[index],
                &signed,
                1,
            )
            .unwrap()
        })
        .collect();
    let certificate: consensus::FastCertificate = consensus::FastPathCertifier::new(
        chain.clone(),
        next.protocol_version(),
        next.epoch(),
        world.policy.engine().validator_set().clone(),
    )
    .unwrap()
    .try_form_certificate(
        votes[0].tx_hash,
        votes[0].execution_effects_hash,
        votes[0].locked_objects_digest,
        &votes,
        &crate::fast_path::FastPathEd25519Verifier,
    )
    .unwrap()
    .unwrap();
    let certificate_bytes: Vec<u8> = consensus::encode_fast_certificate(&certificate).unwrap();
    let bundle: PublicationBundle = crate::fast_path::publication::assemble_publication_bundle(
        &world.targets[0].0,
        &world.operation,
        domain,
        &network.resolver,
        &network.history,
        &next,
        &signed,
        &certificate_bytes,
    )
    .unwrap();
    let bundle_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
    for index in 0..REPLICAS {
        let before: FastVoteObservation =
            fastvote_observation(&world, index, &keys, coin_id, request_id);
        let refused: Result<
            consensus::AvailabilityVote,
            crate::fast_path::publication::PublicationRetentionError,
        > = crate::serving_authority::retain_publication_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &network.resolver,
            &network.history,
            &bundle_bytes,
            &counted,
        );
        assert!(
            matches!(
                &refused,
                Err(
                    crate::fast_path::publication::PublicationRetentionError::Node(
                        crate::NodeCoreError::PersistenceInvariant(
                            "local signer is not the namespace successor member"
                        )
                    )
                )
            ),
            "retired D is refused as local availability signer: {refused:?}"
        );
        assert_eq!(
            fastvote_observation(&world, index, &keys, coin_id, request_id),
            before
        );
        crate::serving_authority::retain_publication_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &network.resolver,
            &network.history,
            &bundle_bytes,
            &world.members[index],
        )
        .expect("the same bundle is genuinely retained by the namespace member");
    }
    assert_eq!(
        counted.created.get(),
        0,
        "D exposes no FastVote or ACK signature"
    );
}

/// Retired D keeps exactly its verified predecessor ownership: it claims its
/// imported epoch-e fee share and unbonds its imported bond through the
/// ordinary e+1 handlers, while Deposit, unknown keys and the original
/// genesis scope are refused purely. Its first-successor Withdraw is refused
/// by the genuine unlock rule (not membership) with no signature or write.
#[test]
fn retired_d_keeps_verified_predecessor_bond_and_claim_ownership_only() {
    let world: SuccessorWorld = replacement_world();
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    let network: &Network = world.network();
    let d: &TestSigner = retired(&world);
    let outgoing: Epoch = network.root.genesis_context().epoch();
    let current: Epoch = world.policy.context().epoch();
    let recipient: [u8; 32] = *d.id.as_bytes();
    let d_key: [u8; 32] = VerificationKey::from(&d.key).into();
    assert!(world.policy.registered_validator(d.id).is_none());

    // Imported epoch-e fee share: D's own claim and leg, verified committee.
    let escrow: [u8; 32] = funded_escrow(&world);
    let settlement: FastPathSettlementRecord = imported_settlement(&world, 0, escrow);
    assert_eq!(settlement.context.epoch(), outgoing);
    let share: u64 = settlement
        .shares
        .iter()
        .find(|share| share.validator_id == d.id)
        .expect("the ABCD certificate pays D a share")
        .amount;
    assert!(share > 0, "D's imported share is positive");
    let claim: [u8; 32] = [0xd7; 32];
    let (candidate, prepared): (OrderedCandidate, crate::fee_claims::PreparedFeeClaim) =
        successor_claim(&world, escrow, claim, d);
    assert_eq!(prepared.intent.certificate_epoch, outgoing);
    world.policy.authenticate_candidate(&candidate).unwrap();
    let outcome: OrderedOutcome = commit_through_rounds(&world, &env, &candidate);
    assert_eq!(
        outcome.output.responses()[0].status(),
        crate::NodeResponseStatus::Accepted
    );
    for index in 0..REPLICAS {
        assert_eq!(
            imported_settlement(&world, index, escrow),
            prepared.next_settlement
        );
    }

    // Imported bond: D's own Unbond, checked against the imported row key,
    // generation, previous row, custody and amount by the real handler.
    let (bond, bond_bytes): (FastPathBondRecord, Vec<u8>) = committed_bond_row(&world, 0, d.id);
    assert_eq!(bond.authorization_key, d_key);
    assert_eq!(bond.state, FastPathBondState::Active);
    let unbond_operation = || BondLifecycleOperation::Unbond {
        recipient: Address::new(recipient),
    };
    assert!(
        world
            .policy
            .bond_owner_authority(d.id, &unbond_operation())
            .is_some()
    );
    let checkpoint: u64 = 13;
    let next_row: FastPathBondRecord = predicted_unbond(&world, &bond, checkpoint, recipient);
    let unbond: OrderedCandidate = bond_candidate(
        &world,
        d,
        [0xd8; 32],
        &bond_bytes,
        &next_row,
        unbond_operation(),
        checkpoint,
    );
    world.policy.authenticate_candidate(&unbond).unwrap();
    let foreign_key: SigningKey = SigningKey::from([0x9d; 32]);
    let foreign: TestSigner = TestSigner {
        id: ValidatorId::new(VerificationKey::from(&foreign_key).into()),
        key: foreign_key,
    };
    let unknown: OrderedCandidate = bond_candidate(
        &world,
        &foreign,
        [0xd8; 32],
        &bond_bytes,
        &next_row,
        unbond_operation(),
        checkpoint,
    );
    assert!(matches!(
        world.policy.authenticate_candidate(&unknown),
        Err(OrderedEconomicsError::Unauthenticated(_))
    ));
    let deposit: OrderedCandidate = bond_candidate(
        &world,
        d,
        [0xd9; 32],
        &bond_bytes,
        &next_row,
        BondLifecycleOperation::Deposit {
            leg: release_leg(&world, d, [0xd9; 32], &bond.custody_object, recipient),
        },
        checkpoint,
    );
    assert!(matches!(
        world.policy.authenticate_candidate(&deposit),
        Err(OrderedEconomicsError::Unauthenticated(
            "ordered candidate names a validator outside the pinned validator set"
        ))
    ));
    let original: OrderedEconomicsPolicy =
        OrderedEconomicsPolicy::from_genesis_root(&network.root, network.domain()).unwrap();
    assert!(original.authenticate_candidate(&unbond).is_err());
    let outcome: OrderedOutcome = commit_through_rounds(&world, &env, &unbond);
    assert_eq!(
        outcome.output.responses()[0].status(),
        crate::NodeResponseStatus::Accepted
    );
    for index in 0..REPLICAS {
        assert_eq!(committed_bond_row(&world, index, d.id).0, next_row);
    }

    // Withdraw at the first successor: purely authenticated as D, refused
    // by the genuine unlock rule while D is already absent from the set.
    let (unbonded, unbonded_bytes): (FastPathBondRecord, Vec<u8>) =
        committed_bond_row(&world, 0, d.id);
    let unlock: Epoch = match unbonded.state {
        FastPathBondState::Unbonding { unlock_epoch, .. } => unlock_epoch,
        _ => panic!("D is unbonding"),
    };
    assert!(unlock.get() > current.get());
    let withdraw_request: [u8; 32] = [0xda; 32];
    let mut exited: FastPathBondRecord = unbonded.clone();
    exited.generation = unbonded.generation.checked_add(1).unwrap();
    exited.committed_at_checkpoint = checkpoint;
    exited.lifecycle_epoch = current;
    exited.state = FastPathBondState::Exited;
    let mut release: SignedLocalExecutionIntent =
        execution::local_execution::decode_signed_local_execution(&release_leg(
            &world,
            d,
            withdraw_request,
            &unbonded.custody_object,
            recipient,
        ))
        .unwrap();
    release.intent.call.nonce = crate::query_sender_next_nonce(
        &world.targets[0].0,
        &world.operation,
        network.domain(),
        world.policy.context().chain_id().clone(),
        world.policy.context().protocol_version(),
        current,
        *d.id.as_bytes(),
    )
    .unwrap();
    let release_frame: Vec<u8> =
        local_execution_signing_frame(world.policy.context(), &release.intent).unwrap();
    release.signature = d.key.sign(&release_frame).into();
    let withdraw: OrderedCandidate = bond_candidate(
        &world,
        d,
        withdraw_request,
        &unbonded_bytes,
        &exited,
        BondLifecycleOperation::Withdraw {
            leg: encode_signed_local_execution(&release).unwrap(),
        },
        checkpoint,
    );
    world.policy.authenticate_candidate(&withdraw).unwrap();
    let bond_key: Vec<u8> = fastpath_bond_record_key(&fixture::chain(), &d.id).unwrap();
    let before: Vec<(StateRevision, Option<Vec<u8>>)> = (0..REPLICAS)
        .map(|index: usize| world.value(index, &bond_key))
        .collect();
    let nonce_key: Vec<u8> = runtime::PersistenceLayout::new(
        world.policy.context().chain_id().clone(),
        world.policy.context().protocol_version(),
    )
    .sender_nonce_key(*d.id.as_bytes(), current);
    let lock_key: Vec<u8> = crate::local_instance_state::fastpath_nonce_lock_key(
        world.policy.context().chain_id(),
        d.id.as_bytes(),
        current,
    )
    .unwrap();
    let reservation_key: Vec<u8> =
        reservation::ordered_reservation_key(world.policy.context().chain_id(), &withdraw_request)
            .unwrap();
    let captured = |index: usize| {
        crate::test_support::capture::captured_source(
            &world.targets[index].0,
            &network.blobs,
            &world.operation,
            network.domain(),
        )
    };
    let captures: Vec<crate::business_reconstruction::SourceBusinessSnapshot> =
        (0..REPLICAS).map(captured).collect();
    let nonce_before: Vec<(StateRevision, Option<Vec<u8>>)> = (0..REPLICAS)
        .map(|index: usize| world.value(index, &nonce_key))
        .collect();
    let business = |snapshot: &crate::business_reconstruction::SourceBusinessSnapshot| -> Vec<crate::business_reconstruction::SourceSnapshotRecord> {
        snapshot.records.iter().filter(|row| match row.descriptor.key() {
            runtime::portable::DurableRecordKey::ObjectHead(_) | runtime::portable::DurableRecordKey::ObjectVersion(_, _) => true,
            runtime::portable::DurableRecordKey::State(key) => key.starts_with(crate::local_instance_state::FASTPATH_STATE_PREFIX) && key != &lock_key,
            runtime::portable::DurableRecordKey::Receipt(_) => false,
        }).cloned().collect()
    };
    let status: OrderedStatus = crate::ordered_economics::query_status_successor(
        &world.warrant(0),
        &world.targets[0].0,
        &env,
    )
    .unwrap();
    for (index, capture) in captures.iter().enumerate() {
        assert!(matches!(
            crate::ordered_economics::preflight::preflight(
                &world.targets[index].0,
                &world.operation,
                &env,
                &withdraw,
                status.high_qc.height.checked_add(1).unwrap(),
            ),
            Err(OrderedEconomicsError::Refused(
                OrderedRefusal::IneligibleState
            ))
        ));
        assert_eq!(
            captured(index),
            *capture,
            "writer-free eligibility check changes no physical rows"
        );
    }
    // Authentic business is proposed/reserved normally and deterministically
    // refused at committed execution. Only Seal has a pre-sign semantic gate.
    let refusal: OrderedOutcome = commit_through_rounds(&world, &env, &withdraw);
    assert_eq!(
        refusal.output.responses()[0].status(),
        crate::NodeResponseStatus::Rejected
    );
    assert_eq!(
        decode_ordered_refusal_payload(refusal.output.responses()[0].payload().unwrap()).unwrap(),
        OrderedRefusal::IneligibleState
    );
    for index in 0..REPLICAS {
        assert_eq!(business(&captured(index)), business(&captures[index]));
        assert_eq!(world.value(index, &nonce_key), nonce_before[index]);
        assert!(world.value(index, &lock_key).1.is_none());
        assert!(world.value(index, &reservation_key).1.is_none());
        assert_eq!(
            query_ordered_outcome(
                &world.targets[index].0,
                &world.operation,
                &env,
                &withdraw_request
            )
            .unwrap(),
            Some(refusal.clone())
        );
        let receipt: runtime::DurableRequestReceipt = world.targets[index]
            .0
            .get_request_receipt(
                &world.operation,
                network.domain(),
                runtime::DurableRequestId::new(withdraw_request).unwrap(),
            )
            .unwrap()
            .unwrap();
        let record: crate::NodeDedupRecord =
            crate::NodeDedupRecord::decode(receipt.canonical_bytes()).unwrap();
        assert_eq!(record.responses(), refusal.output.responses());
        assert_eq!(receipt.event_digest(), refusal.candidate_digest);
    }
    let replay_status: OrderedStatus = crate::ordered_economics::query_status_successor(
        &world.warrant(0),
        &world.targets[0].0,
        &env,
    )
    .unwrap();
    let leader: usize = leader_of(&world, replay_status.current_view);
    let counted: CountingSigner<'_> = CountingSigner::new(&world.members[leader]);
    let retained: Vec<crate::business_reconstruction::SourceBusinessSnapshot> =
        (0..REPLICAS).map(captured).collect();
    assert!(
        matches!(crate::ordered_economics::propose_successor(&world.warrant(leader), &world.targets[leader].0, &env, Some(&withdraw), &counted),
        Err(OrderedEconomicsError::AlreadyCompleted(outcome)) if *outcome == refusal)
    );
    assert_eq!(counted.created.get(), 0);
    assert_eq!(
        (0..REPLICAS)
            .map(captured)
            .collect::<Vec<crate::business_reconstruction::SourceBusinessSnapshot>>(),
        retained
    );
    let after: Vec<(StateRevision, Option<Vec<u8>>)> = (0..REPLICAS)
        .map(|index: usize| world.value(index, &bond_key))
        .collect();
    assert_eq!(after, before);
}

/// A Byzantine quorum (every member except `honest`) extends its own
/// genuinely validated stored e+1 states through the owning consensus
/// engine only, bypassing every ordered admission owner, signing with the
/// members' real keys. A view the honest member leads is skipped by each
/// Byzantine member's own trusted-clock timeout (`Tick`), exactly the
/// engine's pacemaker; the next proposal then justifies the last quorum.
/// Returns each signed proposal and its quorum.
fn byzantine_chain(
    world: &SuccessorWorld,
    honest: usize,
    blocks: &[Vec<Digest32>],
) -> Vec<(consensus::ConsensusProposal, consensus::QuorumCertificate)> {
    let hotstuff: &consensus::ChainedHotStuff = world.policy.engine();
    let verifier: crate::ordered_economics::policy::Ed25519ConsensusVerifier =
        crate::ordered_economics::policy::Ed25519ConsensusVerifier;
    let key: Vec<u8> =
        engine::scoped_state_key(world.policy.key_scope(), &fixture::chain()).unwrap();
    let byzantine: Vec<usize> = (0..world.members.len())
        .filter(|index: &usize| *index != honest)
        .collect();
    let mut states: Vec<consensus::ConsensusState> = byzantine
        .iter()
        .map(|index: &usize| {
            let state: consensus::ConsensusState =
                consensus::decode_consensus_state(&world.value(*index, &key).1.unwrap()).unwrap();
            hotstuff.validate_state(&state, &verifier).unwrap();
            state
        })
        .collect();
    let mut chain: Vec<(consensus::ConsensusProposal, consensus::QuorumCertificate)> = Vec::new();
    for transactions in blocks {
        while hotstuff
            .validator_set()
            .leader(states[0].current_view)
            .unwrap()
            == world.members[honest].id
        {
            for (slot, index) in byzantine.iter().enumerate() {
                let now: u64 = states[slot].view_deadline_unix_millis;
                let output: consensus::ConsensusOutput = hotstuff
                    .on_event(
                        &states[slot],
                        ConsensusEvent::Tick {
                            now_unix_millis: now,
                        },
                        &world.members[*index],
                        &verifier,
                    )
                    .unwrap();
                assert!(output.view_advanced);
                states[slot] = output.state;
            }
        }
        let leader_id: ValidatorId = hotstuff
            .validator_set()
            .leader(states[0].current_view)
            .unwrap();
        let leader: usize = byzantine
            .iter()
            .position(|index: &usize| world.members[*index].id == leader_id)
            .expect("every chained view has a Byzantine leader");
        let proposal: consensus::ConsensusProposal = hotstuff
            .propose(
                &states[leader],
                transactions.clone(),
                &world.members[byzantine[leader]],
            )
            .unwrap();
        let mut votes: Vec<consensus::ConsensusVote> = Vec::new();
        for (slot, index) in byzantine.iter().enumerate() {
            let output: consensus::ConsensusOutput = hotstuff
                .on_event(
                    &states[slot],
                    ConsensusEvent::Proposal(proposal.clone()),
                    &world.members[*index],
                    &verifier,
                )
                .unwrap();
            states[slot] = output.state;
            votes.push(
                output
                    .outbound_messages
                    .into_iter()
                    .find_map(|message: ConsensusMessage| match message {
                        ConsensusMessage::Vote(vote) => Some(vote),
                        _ => None,
                    })
                    .unwrap(),
            );
        }
        let certificate: consensus::QuorumCertificate = hotstuff
            .certificate_from_votes(&proposal, &votes, &verifier)
            .unwrap()
            .expect("three Byzantine members reach quorum");
        for (slot, index) in byzantine.iter().enumerate() {
            states[slot] = hotstuff
                .on_event(
                    &states[slot],
                    ConsensusEvent::Certificate(certificate.clone()),
                    &world.members[*index],
                    &verifier,
                )
                .unwrap()
                .state;
        }
        chain.push((proposal, certificate));
    }
    chain
}

/// Adversarial storage through the existing raw protected port: writes the
/// exact canonical control candidate bytes under their own digest row.
fn store_control_bytes(world: &SuccessorWorld, index: usize, control: &OrderedCandidate) {
    let digest: Digest32 = world.policy.candidate_digest(control).unwrap();
    let key: Vec<u8> = engine::ordered_candidate_record_key(&fixture::chain(), digest).unwrap();
    let (revision, absent): (StateRevision, Option<Vec<u8>>) = world.value(index, &key);
    assert!(absent.is_none());
    let transaction: runtime::AtomicStateTransaction = runtime::AtomicStateTransaction::new(
        world.network().domain(),
        runtime::AtomicStateReadSet::new(vec![
            runtime::StateReadAssertion::new(key.clone(), revision).unwrap(),
        ])
        .unwrap(),
        runtime::AtomicStateMutationSet::new(vec![
            runtime::StateMutationEntry::new(
                key,
                runtime::StateMutation::Put(encode_ordered_candidate(control).unwrap()),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    let warrant: crate::serving_authority::LiveWarrant<'_> = world.warrant(index);
    assert!(matches!(
        crate::serving_authority::ServingGate::Successor(&warrant).commit_durable(
            &world.targets[index].0,
            &world.operation,
            transaction,
        ),
        runtime::DurableCommitOutcome::Committed
    ));
}

/// DR-0189 permanent control refusal against a genuinely certified Byzantine
/// chain. Carriers of a fresh e+1 Freeze, the replayed accepted origin Seal
/// and the replayed original E registration are refused purely and by the
/// honest member's vote and declared observation before any signature or
/// write. Committed recovery of the certified Freeze block first stops on
/// missing bytes, then, after an attacker stores the exact control bytes
/// through the raw protected port, refuses with the typed control error;
/// neither attempt advances the honest state or applied height.
#[test]
fn successor_refuses_certified_byzantine_controls_in_vote_observation_and_committed_recovery() {
    let world: SuccessorWorld = replacement_world();
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    assert!(world.policy.is_causal());
    let chain: protocol_types::ChainId = fixture::chain();
    let next: PublicationContext = world.policy.context().clone();
    let view: u64 = current_view(&world, &env);
    let leaders: [usize; 3] = [
        leader_of(&world, view),
        leader_of(&world, view.checked_add(1).unwrap()),
        leader_of(&world, view.checked_add(2).unwrap()),
    ];
    let honest: usize = (0..REPLICAS)
        .find(|index: &usize| !leaders.contains(index))
        .unwrap();
    let freeze_request: [u8; 32] = [0xf7; 32];
    let freeze: OrderedCandidate = OrderedCandidate {
        context: next.clone(),
        request_id: freeze_request,
        kind: OrderedOperationKind::Freeze,
        intent: encode_freeze_intent(&FreezeIntent {
            context: next.clone(),
            request_id: freeze_request,
            advisory_next_set: FastPathValidatorSetRecord {
                context: PublicationContext::new(
                    chain.clone(),
                    next.protocol_version(),
                    Epoch::new(next.epoch().get().checked_add(1).unwrap()),
                )
                .unwrap(),
                validators: world
                    .members
                    .iter()
                    .map(|member: &TestSigner| FastPathValidatorEntry {
                        id: member.id,
                        voting_power: 1,
                        signature_scheme: SignatureSchemeId::Ed25519,
                        public_key: member.id.as_bytes().to_vec(),
                    })
                    .collect(),
            },
        })
        .unwrap(),
        created_checkpoint: 13,
    };
    let registration: OrderedCandidate = match &world.source {
        WorldSource::Replacement(fixture) => fixture.registration().clone(),
        WorldSource::SameCommittee(_) => panic!("the replacement world registered E"),
    };
    let state_key: Vec<u8> = engine::scoped_state_key(world.policy.key_scope(), &chain).unwrap();
    let applied_key: Vec<u8> =
        engine::scoped_applied_height_key(world.policy.key_scope(), &chain).unwrap();
    let vote_key: Vec<u8> = crate::ordered_economics::identity::scoped_vote_record_key(
        world.policy.key_scope(),
        &chain,
        view,
    )
    .unwrap();
    let snapshot = |keys: &[&Vec<u8>]| -> Vec<(StateRevision, Option<Vec<u8>>)> {
        keys.iter()
            .map(|key: &&Vec<u8>| world.value(honest, key))
            .collect()
    };
    let counted: CountingSigner<'_> = CountingSigner::new(&world.members[honest]);
    for control in [&freeze, &world.seal, &registration] {
        assert!(matches!(
            world.policy.authenticate_candidate(control),
            Err(OrderedEconomicsError::UnsupportedSuccessorControl)
        ));
        let digest: Digest32 = world.policy.candidate_digest(control).unwrap();
        let (proposal, _): (consensus::ConsensusProposal, consensus::QuorumCertificate) =
            byzantine_chain(&world, honest, &[vec![digest]]).remove(0);
        assert_eq!(proposal.height % 3, 1);
        let carrier: OrderedProposal = OrderedProposal {
            proposal,
            candidate: Some(control.clone()),
        };
        let before: Vec<(StateRevision, Option<Vec<u8>>)> =
            snapshot(&[&state_key, &applied_key, &vote_key]);
        assert!(matches!(
            crate::ordered_economics::process_proposal_successor(
                &world.warrant(honest),
                &world.targets[honest].0,
                &env,
                &carrier,
                &counted,
            ),
            Err(OrderedEconomicsError::UnsupportedSuccessorControl)
        ));
        assert!(matches!(
            crate::ordered_economics::observe_proposal_successor(
                &world.warrant(honest),
                &world.targets[honest].0,
                &env,
                &carrier,
            ),
            Err(OrderedEconomicsError::UnsupportedSuccessorControl)
        ));
        assert_eq!(snapshot(&[&state_key, &applied_key, &vote_key]), before);
    }
    assert_eq!(counted.created.get(), 0, "no honest vote is signed");

    // Signerless recovery of the genuinely certified Freeze chain. The fourth
    // block, proposed by a Byzantine leader after the honest member's view
    // times out, carries retired D's genuinely authenticated Unbond and
    // justifies the third quorum, so voting on it would commit the Freeze.
    let d: &TestSigner = retired(&world);
    let (bond, bond_bytes): (FastPathBondRecord, Vec<u8>) =
        committed_bond_row(&world, honest, d.id);
    let unbond: OrderedCandidate = bond_candidate(
        &world,
        d,
        [0xdb; 32],
        &bond_bytes,
        &predicted_unbond(&world, &bond, 13, *d.id.as_bytes()),
        BondLifecycleOperation::Unbond {
            recipient: Address::new(*d.id.as_bytes()),
        },
        13,
    );
    world.policy.authenticate_candidate(&unbond).unwrap();
    let freeze_digest: Digest32 = world.policy.candidate_digest(&freeze).unwrap();
    let unbond_digest: Digest32 = world.policy.candidate_digest(&unbond).unwrap();
    let blocks: Vec<(consensus::ConsensusProposal, consensus::QuorumCertificate)> = byzantine_chain(
        &world,
        honest,
        &[
            vec![freeze_digest],
            Vec::new(),
            Vec::new(),
            vec![unbond_digest],
        ],
    );
    for (position, (proposal, certificate)) in blocks.iter().take(3).enumerate() {
        crate::ordered_economics::observe_proposal_successor(
            &world.warrant(honest),
            &world.targets[honest].0,
            &env,
            &OrderedProposal {
                proposal: proposal.clone(),
                candidate: None,
            },
        )
        .unwrap();
        if position < 2 {
            crate::ordered_economics::process_certificate_successor(
                &world.warrant(honest),
                &world.targets[honest].0,
                &env,
                certificate,
            )
            .unwrap();
        }
    }
    let terminal: &consensus::QuorumCertificate = &blocks[2].1;
    let preview: OrderedProposal = OrderedProposal {
        proposal: blocks[3].0.clone(),
        candidate: Some(unbond.clone()),
    };
    assert_eq!(preview.proposal.height % 3, 1);
    assert_eq!(preview.proposal.justify, *terminal);
    assert_ne!(leader_of(&world, preview.proposal.view), honest);
    let preview_vote_key: Vec<u8> = crate::ordered_economics::identity::scoped_vote_record_key(
        world.policy.key_scope(),
        &chain,
        preview.proposal.view,
    )
    .unwrap();
    let before: Vec<(StateRevision, Option<Vec<u8>>)> = snapshot(&[&state_key, &applied_key]);
    let vote_before: (StateRevision, Option<Vec<u8>>) = world.value(honest, &preview_vote_key);
    // Vote-time prefix completion without the certified ancestor bytes stops
    // for declared catch-up before any signature.
    let unready: Result<OrderedEventOutput, OrderedEconomicsError> =
        crate::ordered_economics::process_proposal_successor(
            &world.warrant(honest),
            &world.targets[honest].0,
            &env,
            &preview,
            &counted,
        );
    assert!(
        matches!(unready, Err(OrderedEconomicsError::Prerequisite(_))),
        "missing ancestor bytes stop the vote: {unready:?}"
    );
    assert_eq!(snapshot(&[&state_key, &applied_key]), before);
    let missing: Result<OrderedEventOutput, OrderedEconomicsError> =
        crate::ordered_economics::process_certificate_successor(
            &world.warrant(honest),
            &world.targets[honest].0,
            &env,
            terminal,
        );
    assert!(
        matches!(missing, Err(OrderedEconomicsError::Prerequisite(_))),
        "absent committed bytes stop for declared catch-up: {missing:?}"
    );
    assert_eq!(snapshot(&[&state_key, &applied_key]), before);
    store_control_bytes(&world, honest, &freeze);
    assert!(matches!(
        crate::ordered_economics::process_certificate_successor(
            &world.warrant(honest),
            &world.targets[honest].0,
            &env,
            terminal,
        ),
        Err(OrderedEconomicsError::UnsupportedSuccessorControl)
    ));
    assert_eq!(snapshot(&[&state_key, &applied_key]), before);
    // Vote-time committed prefix over the stored, quorum-certified control:
    // the honest consumer refuses independently, before any vote signature.
    assert!(matches!(
        crate::ordered_economics::process_proposal_successor(
            &world.warrant(honest),
            &world.targets[honest].0,
            &env,
            &preview,
            &counted,
        ),
        Err(OrderedEconomicsError::UnsupportedSuccessorControl)
    ));
    assert!(matches!(
        crate::ordered_economics::observe_proposal_successor(
            &world.warrant(honest),
            &world.targets[honest].0,
            &env,
            &preview,
        ),
        Err(OrderedEconomicsError::UnsupportedSuccessorControl)
    ));
    assert_eq!(snapshot(&[&state_key, &applied_key]), before);
    assert_eq!(world.value(honest, &preview_vote_key), vote_before);
    assert!(!matches!(
        crate::serving_authority::query_request_receipt_successor(
            &world.warrant(honest),
            &world.targets[honest].0,
            crate::RequestId::new(freeze_request).unwrap(),
        ),
        Ok(crate::ReceiptQueryResult::Present { .. })
    ));
    assert_eq!(counted.created.get(), 0);
}
