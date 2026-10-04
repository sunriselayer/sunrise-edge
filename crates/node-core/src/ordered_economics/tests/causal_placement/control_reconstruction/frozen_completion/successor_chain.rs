//! Genuine file-backed recurring Seal and complete verified-chain evidence.
use super::*;
use crate::business_reconstruction::BusinessReconstructionPlan;
use crate::serving_authority::{
    CommitteeProvenance, OwnerProvenance, SuccessorActivationError, SuccessorChainArtifacts,
    SuccessorChainBudget, SuccessorLinkPins, VerifiedSuccessorAuthority,
    verify_successor_chain_authority,
};
use protocol_types::Epoch;
use std::cell::Cell;
use std::num::NonZeroU32;

struct RefusalSigner<'a> {
    inner: &'a TestSigner,
    signatures: Cell<usize>,
}

impl consensus::ConsensusSigner for RefusalSigner<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.inner.id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        self.signatures
            .set(self.signatures.get().checked_add(1).unwrap());
        consensus::ConsensusSigner::sign_framed(self.inner, framed)
    }
}

pub(super) fn never_member_g() -> TestSigner {
    let key: SigningKey = SigningKey::from([0xe9; 32]);
    TestSigner {
        id: ValidatorId::new(VerificationKey::from(&key).into()),
        key,
    }
}

/// G collateral is an ordinary address-owned object in the genuinely
/// signed genesis, not a seeded registration, bond, receipt or transition.
pub(super) fn recurring_world() -> SuccessorWorld {
    let g: TestSigner = never_member_g();
    let source: crate::ordered_economics::RegisteredCutFixture =
        crate::ordered_economics::tests::causal_placement::registration::registered_cut_fixture_configure(
            |manifest: &mut GenesisManifest| {
                for byte in [0x23u8, 0x24u8] {
                    let mut entry: GenesisObjectEntry = manifest.objects[1].clone();
                    entry.object.id = ObjectId::new([byte; 32]);
                    entry.object.owner = Owner::Address(Address::new(*g.id.as_bytes()));
                    entry.object.data = abi::call_values::encode_call_value(
                        &public_standard_asset::coin_body_layout(),
                        &abi::call_values::CallValue::U64(10_000),
                    ).unwrap();
                    entry.authority.object_id = entry.object.id;
                    manifest.objects.push(entry);
                }
            },
        );
    let mut world: SuccessorWorld = activate(replacement_source_from(source));
    world.policy = chain_authority(&world)
        .ordered_policy(&world.network().root)
        .unwrap();
    world
}

fn current_imported_object(world: &SuccessorWorld, id: ObjectId) -> (Object, ObjectRef) {
    let store: &SqliteImportTarget = &world.targets[0].0;
    let head: DurableObjectHead = store
        .get_object_head(&world.operation, world.network().domain(), id)
        .unwrap();
    let version: DurableObjectVersion = head.object_version().unwrap();
    let record: DurableObjectVersionRecord = store
        .get_object_version(&world.operation, world.network().domain(), id, version)
        .unwrap()
        .unwrap();
    let object: Object = match record.payload() {
        DurableObjectPayload::Inline(inline) => inline.object().clone(),
        DurableObjectPayload::BlobReference(_) => panic!("the actual fixture coin is inline"),
    };
    let reference: ObjectRef = ObjectRef {
        id,
        version: object.version,
        digest: head.digest().unwrap(),
    };
    (object, reference)
}

fn g_registration(
    world: &SuccessorWorld,
    id: ObjectId,
    request_id: [u8; 32],
    nonce: u64,
) -> (OrderedCandidate, FastPathBondRecord) {
    use crate::bond_lifecycle::registration::{
        BondRegistrationPreparationRequest, PreparedBondRegistration, SignedBondRegistrationIntent,
        encode_signed_bond_registration_intent, prepare_bond_registration_successor,
    };
    let g: TestSigner = never_member_g();
    let network: &Network = world.network();
    let live: PublicationContext = world.policy.context().clone();
    let (source, reference): (Object, ObjectRef) = current_imported_object(world, id);
    assert_eq!(source.owner, Owner::Address(Address::new(*g.id.as_bytes())));
    let resource: &crate::economics::FastPathEconomicsResourcePolicy =
        &network.root.manifest().economics_policy.resources[0];
    let scope: objects::ProtocolCustodyScope = objects::ProtocolCustodyScope {
        purpose: objects::ProtocolCustodyPurpose::BondCollateral,
        chain_id: live.chain_id().clone(),
        subject: *g.id.as_bytes(),
        resource: *resource.resource_id.value(),
    };
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &network.resolver,
        &live,
        source.id,
        &scope,
    )
    .unwrap();
    let leg: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: world.next_base.digest(&network.resolver).unwrap(),
        call: CallIntent {
            context: live.clone(),
            request_id,
            sender: *g.id.as_bytes(),
            nonce,
            code: resource.code.clone(),
            instance: resource.instance.clone(),
            entrypoint: resource.transfer_entrypoint.clone(),
            type_arguments: world.source().manifest.fee_policy.type_arguments.clone(),
            access: abi::AccessManifest {
                entries: vec![abi::AccessEntry {
                    object_ref: reference,
                    mode: AccessMode::Write,
                }],
            },
            arguments: public_standard_asset::transfer_arguments(&token).unwrap(),
            gas_limit: 500_000,
        },
        authorizations: Vec::new(),
    };
    let frame: Vec<u8> = local_execution_signing_frame(&live, &leg).unwrap();
    let signed_leg: Vec<u8> = encode_signed_local_execution(&SignedLocalExecutionIntent {
        signature: g.key.sign(&frame).into(),
        intent: leg,
    })
    .unwrap();
    let authority_bytes: Vec<u8> = world
        .value(
            0,
            &crate::local_instance_state::object_authority_key(source.id),
        )
        .1
        .unwrap();
    let authority: execution::local_execution::ObjectAuthority =
        execution::local_execution::decode_object_authority(&authority_bytes).unwrap();
    let mut predicted: Object = source;
    predicted.version = predicted.version.checked_add(1).unwrap();
    predicted.owner = Owner::ProtocolCustody(scope);
    let row: FastPathBondRecord = FastPathBondRecord {
        context: resource.context.clone(),
        validator_id: g.id,
        resource_domain: resource.resource_id.domain(),
        resource: *resource.resource_id.value(),
        custody_object: ObjectRef {
            id: predicted.id,
            version: predicted.version,
            digest: network
                .resolver
                .hash_for_purpose(
                    live.epoch(),
                    HashPurpose::Object,
                    &objects::encode_object(&predicted).unwrap(),
                )
                .unwrap(),
        },
        custody_object_epoch: live.epoch(),
        authority,
        amount: 10_000,
        committed_at_checkpoint: 20,
        generation: 1,
        lifecycle_epoch: live.epoch(),
        slashable_from_epoch: Epoch::new(live.epoch().get().checked_add(1).unwrap()),
        required_minimum: resource.bond.as_ref().unwrap().min_bond.get(),
        state: FastPathBondState::Active,
        authorization_scheme: SignatureSchemeId::Ed25519,
        authorization_key: *g.id.as_bytes(),
    };
    let prepared: PreparedBondRegistration = prepare_bond_registration_successor(
        &network.root,
        &chain_authority(world),
        BondRegistrationPreparationRequest {
            context: live.clone(),
            request_id,
            authorization_key: *g.id.as_bytes(),
            resource_context: resource.context.clone(),
            resource: resource.resource_id,
            leg: signed_leg,
            predicted_initial_row: row.clone(),
        },
    )
    .unwrap();
    let signed: SignedBondRegistrationIntent = SignedBondRegistrationIntent {
        intent: prepared.intent,
        signature: g.key.sign(&prepared.signing_frame).into(),
    };
    (
        OrderedCandidate {
            context: live,
            request_id,
            kind: OrderedOperationKind::BondRegistration,
            intent: encode_signed_bond_registration_intent(&signed).unwrap(),
            created_checkpoint: 20,
        },
        row,
    )
}

/// A current-e1 registrant may exit through its real anchor and bond chain
/// although G has never appeared in either verified committee.
pub(super) fn register_and_unbond_g(world: &SuccessorWorld) -> Vec<u8> {
    use super::successor_replacement::{
        bond_candidate, commit_through_rounds, committed_bond_row, predicted_unbond,
    };
    let g: TestSigner = never_member_g();
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    assert!(world.policy.registered_validator(g.id).is_none());
    let (registration, initial): (OrderedCandidate, FastPathBondRecord) =
        g_registration(world, ObjectId::new([0x23; 32]), [0xea; 32], 0);
    world.policy.authenticate_candidate(&registration).unwrap();
    let outcome: OrderedOutcome = commit_through_rounds(world, &env, &registration);
    assert_eq!(
        outcome.output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    for index in 0..world.members.len() {
        assert_eq!(committed_bond_row(world, index, g.id).0, initial);
    }
    let anchor_key: Vec<u8> = crate::bond_lifecycle::registration::bond_registration_anchor_key(
        world.policy.context().chain_id(),
        &g.id,
    )
    .unwrap();
    let anchor: Vec<u8> = world.value(0, &anchor_key).1.unwrap();
    let authority: VerifiedSuccessorAuthority = chain_authority(world);
    let own = crate::bond_lifecycle::registration::verify_registration_identity(
        &world.network().root,
        Some((authority.committees(), authority.owners())),
        &anchor,
    )
    .unwrap();
    assert_eq!(own.anchor_epoch, world.policy.context().epoch());
    let (duplicate, _): (OrderedCandidate, FastPathBondRecord) =
        g_registration(world, ObjectId::new([0x24; 32]), [0xeb; 32], 1);
    let before: crate::business_reconstruction::SourceBusinessSnapshot =
        crate::test_support::capture::captured_source(
            &world.targets[0].0,
            &world.targets[0].1,
            &world.operation,
            world.network().domain(),
        );
    assert!(matches!(
        crate::ordered_economics::preflight::preflight(
            &world.targets[0].0,
            &world.operation,
            &env,
            &duplicate,
            4,
        ),
        Err(OrderedEconomicsError::Refused(
            OrderedRefusal::AlreadyRegistered
        ))
    ));
    let after: crate::business_reconstruction::SourceBusinessSnapshot =
        crate::test_support::capture::captured_source(
            &world.targets[0].0,
            &world.targets[0].1,
            &world.operation,
            world.network().domain(),
        );
    assert_eq!(
        before, after,
        "a new request cannot overwrite G's own committed registration"
    );
    let (bond, bytes): (FastPathBondRecord, Vec<u8>) = committed_bond_row(world, 0, g.id);
    let next: FastPathBondRecord = predicted_unbond(world, &bond, 21, *g.id.as_bytes());
    assert!(
        matches!(next.state, FastPathBondState::Unbonding { unlock_epoch, .. }
        if unlock_epoch.get() == world.policy.context().epoch().get().checked_add(7).unwrap())
    );
    let unbond: OrderedCandidate = bond_candidate(
        world,
        &g,
        [0xec; 32],
        &bytes,
        &next,
        BondLifecycleOperation::Unbond {
            recipient: Address::new(*g.id.as_bytes()),
        },
        21,
    );
    world.policy.authenticate_candidate(&unbond).unwrap();
    let outcome: OrderedOutcome = commit_through_rounds(world, &env, &unbond);
    assert_eq!(
        outcome.output.responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    for index in 0..world.members.len() {
        assert_eq!(committed_bond_row(world, index, g.id).0, next);
        assert_eq!(world.value(index, &anchor_key).1, Some(anchor.clone()));
    }
    anchor
}

/// The genuine single-link archive seen through the chain transport,
/// counting every artifact access and the link it names.
struct CountingChain<'a> {
    inner: Artifacts<'a>,
    links: Vec<u32>,
}

impl<'a> CountingChain<'a> {
    fn new(inner: Artifacts<'a>) -> Self {
        Self {
            inner,
            links: Vec::new(),
        }
    }
}

impl SuccessorChainArtifacts for CountingChain<'_> {
    fn saved_business_cut(
        &mut self,
        link: u32,
        _plan: &BusinessReconstructionPlan<'_>,
    ) -> Result<SavedBusinessCut, SuccessorArtifactError> {
        self.links.push(link);
        self.inner.saved_business_cut()
    }
    fn history_height(
        &mut self,
        link: u32,
        _policy: &OrderedEconomicsPolicy,
        identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError> {
        self.links.push(link);
        self.inner.history_height(identity, height)
    }
    fn readiness_certificate(
        &mut self,
        link: u32,
        length: u32,
    ) -> Result<Vec<u8>, SuccessorArtifactError> {
        self.links.push(link);
        self.inner.readiness_certificate(length)
    }
}

fn budget(links: u32) -> SuccessorChainBudget {
    SuccessorChainBudget::new(NonZeroU32::new(links).unwrap())
}

fn link_zero(world: &SuccessorWorld) -> SuccessorLinkPins {
    SuccessorLinkPins {
        cut_identity: world.cut_history.clone(),
        manifest_identity: world.sealed_history.clone(),
    }
}

fn verify_chain(
    world: &SuccessorWorld,
    pins: &[SuccessorLinkPins],
    budget: SuccessorChainBudget,
    transport: &mut CountingChain<'_>,
) -> Result<VerifiedSuccessorAuthority, SuccessorActivationError> {
    verify_successor_chain_authority(
        reconstruction_plan(world.source(), &world.cut_history),
        pins,
        budget,
        transport,
    )
}

#[test]
fn chain_owner_verifies_genuine_abce_link_with_committee_and_registered_owner_history() {
    let world: SuccessorWorld = replacement_world();
    let root: &VerifiedGenesisRoot = &world.network().root;
    let e0: Epoch = root.genesis_context().epoch();
    let e1: Epoch = Epoch::new(e0.get().checked_add(1).unwrap());
    let mut transport: CountingChain<'_> = CountingChain::new(world.artifacts());
    let authority: VerifiedSuccessorAuthority =
        verify_chain(&world, &[link_zero(&world)], budget(8), &mut transport)
            .expect("the genuine ABCE link verifies through the chain owner");
    assert!(!transport.links.is_empty());
    assert!(transport.links.iter().all(|link: &u32| *link == 0));
    assert_eq!(authority.link_count(), 1);

    // The existing single-link entry is the same owner with budget 1.
    let mut single: Artifacts<'_> = world.artifacts();
    let existing: VerifiedSuccessorAuthority = verify_successor_authority(
        reconstruction_plan(world.source(), &world.cut_history),
        &world.sealed_history,
        &mut single,
    )
    .unwrap();
    assert_eq!(existing.link_count(), 1);
    assert_eq!(authority.subject_digest(), existing.subject_digest());
    assert_eq!(authority.manifest_digest(), existing.manifest_digest());
    assert_eq!(
        authority.validator_set(),
        world.policy.engine().validator_set()
    );

    // Committee history: genesis ABCD at e_0, certified ABCE at e_1.
    let committees = authority.committees();
    assert_eq!(committees.len(), 2);
    assert_eq!(
        committees.provenance(e0),
        Some(CommitteeProvenance::Genesis)
    );
    let (outgoing, outgoing_digest): (&ValidatorSet, Digest32) = committees.get(e0).unwrap();
    assert_eq!(outgoing, root.genesis_committee());
    assert_eq!(
        outgoing_digest,
        authority.policy_inputs().predecessor_set_digest()
    );
    assert_eq!(
        committees.provenance(e1),
        Some(CommitteeProvenance::Link {
            index: 0,
            subject_digest: authority.subject_digest(),
        })
    );
    assert_eq!(committees.get(e1).unwrap().0, authority.validator_set());
    assert!(committees.get(Epoch::new(e1.get() + 1)).is_none());

    // Owner registry: every genesis owner, including retired D, plus E from
    // its verified e_0 anchor. Membership never stands in for provenance.
    let owners = authority.owners();
    assert_eq!(
        owners.len(),
        root.genesis_committee().validators().len() + 1
    );
    for validator in root.genesis_committee().validators() {
        assert_eq!(
            owners.owner(validator.id).unwrap().provenance(),
            &OwnerProvenance::Genesis {
                genesis_digest: root.digest(),
            }
        );
    }
    let original: &OrderedEconomicsPolicy = &world.network().policy;
    let e: usize = (0..world.members.len())
        .find(|index: &usize| {
            original
                .registered_validator(world.members[*index].id)
                .is_none()
        })
        .expect("E is incoming");
    let registered = owners
        .owner(world.members[e].id)
        .expect("E is a verified registered owner");
    assert_eq!(registered.key(), &world.public_key(e));
    assert!(matches!(
        registered.provenance(),
        OwnerProvenance::Registration { anchor_epoch, .. } if *anchor_epoch == e0
    ));
}

#[test]
fn chain_owner_refuses_budget_and_first_pins_before_any_artifact_access() {
    let world: SuccessorWorld = activated_world();
    let pin: SuccessorLinkPins = link_zero(&world);
    let refused = |pins: &[SuccessorLinkPins], budget: SuccessorChainBudget| {
        let mut transport: CountingChain<'_> = CountingChain::new(world.artifacts());
        let result: Result<VerifiedSuccessorAuthority, SuccessorActivationError> =
            verify_chain(&world, pins, budget, &mut transport);
        assert!(
            transport.links.is_empty(),
            "refused before any artifact call"
        );
        match result {
            Ok(_) => panic!("a refused chain verified"),
            Err(error) => error,
        }
    };
    assert!(matches!(
        refused(&[pin.clone(), pin.clone()], budget(1)),
        SuccessorActivationError::ChainBudgetExceeded {
            links: 2,
            budget: 1
        }
    ));
    assert!(matches!(
        refused(&[], budget(1)),
        SuccessorActivationError::Invalid(_)
    ));
    let mut foreign_cut: SuccessorLinkPins = pin.clone();
    foreign_cut.cut_identity.through_height += 1;
    assert!(matches!(
        refused(&[foreign_cut], budget(1)),
        SuccessorActivationError::Invalid(_)
    ));
    // Reordered pins: the Seal history named as the cut.
    let reordered: SuccessorLinkPins = SuccessorLinkPins {
        cut_identity: pin.manifest_identity.clone(),
        manifest_identity: pin.cut_identity.clone(),
    };
    assert!(matches!(
        refused(&[reordered], budget(1)),
        SuccessorActivationError::Invalid(_)
    ));
    // A plausible e1 pin cannot authenticate another copy of the e0 saved
    // cut. Its failed artifact read must not be silently skipped.
    let mut two: CountingChain<'_> = CountingChain::new(world.artifacts());
    let second: SuccessorLinkPins = SuccessorLinkPins {
        cut_identity: OrderedHistoryIdentity {
            context: world.policy.context().clone(),
            ..pin.cut_identity.clone()
        },
        manifest_identity: pin.manifest_identity.clone(),
    };
    assert!(verify_chain(&world, &[pin.clone(), second.clone()], budget(2), &mut two).is_err());
    assert!(!two.links.is_empty());
    assert!(two.links.contains(&1));
    // A later pin that does not continue at e_1 refuses as non-contiguous.
    let mut gap: CountingChain<'_> = CountingChain::new(world.artifacts());
    assert!(matches!(
        verify_chain(&world, &[pin.clone(), pin.clone()], budget(2), &mut gap),
        Err(SuccessorActivationError::Invalid(_))
    ));

    // A foreign Seal history pin reaches the artifacts and still refuses.
    let mut foreign_seal: SuccessorLinkPins = pin;
    foreign_seal.manifest_identity.through_height += 1;
    let mut transport: CountingChain<'_> = CountingChain::new(world.artifacts());
    assert!(verify_chain(&world, &[foreign_seal], budget(1), &mut transport).is_err());
    assert!(!transport.links.is_empty());
}

fn chain_authority(world: &SuccessorWorld) -> VerifiedSuccessorAuthority {
    let mut transport: CountingChain<'_> = CountingChain::new(world.artifacts());
    verify_chain(world, &[link_zero(world)], budget(1), &mut transport).unwrap()
}

struct RecurringArtifacts<'a> {
    first: Artifacts<'a>,
    second: Artifacts<'a>,
    accesses: Vec<u32>,
}

impl<'a> RecurringArtifacts<'a> {
    fn link(&mut self, link: u32) -> Result<&mut Artifacts<'a>, SuccessorArtifactError> {
        self.accesses.push(link);
        match link {
            0 => Ok(&mut self.first),
            1 => Ok(&mut self.second),
            _ => Err(SuccessorArtifactError::Missing),
        }
    }
}

impl SuccessorChainArtifacts for RecurringArtifacts<'_> {
    fn saved_business_cut(
        &mut self,
        link: u32,
        _plan: &BusinessReconstructionPlan<'_>,
    ) -> Result<SavedBusinessCut, SuccessorArtifactError> {
        self.link(link)?.saved_business_cut()
    }
    fn history_height(
        &mut self,
        link: u32,
        _policy: &OrderedEconomicsPolicy,
        identity: &OrderedHistoryIdentity,
        height: u64,
    ) -> Result<OrderedHistoryHeightMaterial, SuccessorArtifactError> {
        self.link(link)?.history_height(identity, height)
    }
    fn readiness_certificate(
        &mut self,
        link: u32,
        length: u32,
    ) -> Result<Vec<u8>, SuccessorArtifactError> {
        self.link(link)?.readiness_certificate(length)
    }
}

fn current_history(
    world: &SuccessorWorld,
) -> (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) {
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    let store: &SqliteImportTarget = &world.targets[0].0;
    let identity: OrderedHistoryIdentity =
        query_ordered_history_summary(store, &world.operation, &env)
            .unwrap()
            .identity;
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(world.policy.clone(), identity.clone()).unwrap();
    let mut history: Vec<OrderedHistoryHeightMaterial> = Vec::new();
    for height in 1..=identity.through_height {
        let descriptor: OrderedHistoryHeightDescriptor = read_ordered_history_height_descriptor(
            store,
            &world.operation,
            &env,
            &identity,
            height,
        )
        .unwrap();
        let descriptor_digest: Digest32 =
            ordered_history_descriptor_digest(&world.policy, &descriptor).unwrap();
        let mut components: Vec<(OrderedHistoryComponentKind, Vec<u8>)> = Vec::new();
        for reference in &descriptor.components {
            let mut bytes: Vec<u8> = Vec::new();
            let mut offset: u64 = 0;
            while offset < reference.length {
                let limit: u32 =
                    u32::try_from(1024.min(reference.length.checked_sub(offset).unwrap())).unwrap();
                let chunk: Vec<u8> = read_ordered_history_component_chunk(
                    store,
                    &world.operation,
                    &env,
                    &identity,
                    height,
                    descriptor_digest,
                    reference.kind,
                    offset,
                    limit,
                )
                .unwrap();
                offset = offset.checked_add(u64::from(limit)).unwrap();
                bytes.extend(chunk);
            }
            components.push((reference.kind, bytes));
        }
        let material: OrderedHistoryHeightMaterial = OrderedHistoryHeightMaterial {
            descriptor,
            components,
        };
        verifier.verify_next_height(&material).unwrap();
        history.push(material);
    }
    assert_eq!(verifier.finish().unwrap().identity(), &identity);
    (identity, history)
}

/// Genuine current-epoch Freeze, signed empty frontiers and DrainSet. The
/// earlier publication log remains in the SQLite files unchanged; it is
/// carried by exact verified-base provenance, never by decoded epoch alone.
fn recurring_preseal(world: &SuccessorWorld) {
    let env: OrderedEconomicsEnvironment<'_> = world.env();
    let current: PublicationContext = world.policy.context().clone();
    let next: PublicationContext = PublicationContext::new(
        current.chain_id().clone(),
        current.protocol_version(),
        Epoch::new(current.epoch().get().checked_add(1).unwrap()),
    )
    .unwrap();
    let entries: Vec<FastPathValidatorEntry> = world
        .policy
        .engine()
        .validator_set()
        .validators()
        .iter()
        .map(
            |entry: &validator_set::ValidatorInfo| FastPathValidatorEntry {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            },
        )
        .collect();
    let freeze_request: [u8; 32] = [0xcd; 32];
    let freeze: OrderedCandidate = OrderedCandidate {
        context: current.clone(),
        request_id: freeze_request,
        kind: OrderedOperationKind::Freeze,
        intent: encode_freeze_intent(&FreezeIntent {
            context: current.clone(),
            request_id: freeze_request,
            advisory_next_set: FastPathValidatorSetRecord {
                context: next,
                validators: entries,
            },
        })
        .unwrap(),
        created_checkpoint: 1,
    };
    successor_round(world, &env, Some(&freeze));
    successor_round(world, &env, None);
    let (outputs, _): (Vec<OrderedEventOutput>, consensus::QuorumCertificate) =
        successor_round(world, &env, None);
    assert!(
        outputs[0]
            .committed
            .iter()
            .any(
                |outcome: &OrderedOutcome| outcome.request_id == freeze_request
                    && outcome.output.responses()[0].status() == NodeResponseStatus::Accepted
            )
    );
    let network: &Network = world.network();
    let mut selected: Vec<(FrozenFrontierVote, FrozenFrontierPage)> = Vec::new();
    for index in 0..3 {
        let step: FrozenFrontierStep = advance_frozen_frontier_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &world.operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &current,
            &world.members[index],
        )
        .unwrap();
        assert!(matches!(step, FrozenFrontierStep::Finalized(_)));
        let pair: (FrozenFrontierVote, FrozenFrontierPage) = read_frozen_frontier_page_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &world.operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &current,
            world.members[index].id,
            None,
            NonZeroUsize::MIN,
        )
        .unwrap();
        assert!(pair.1.terminal && pair.1.entries.is_empty());
        selected.push(pair);
    }
    selected.sort_by_key(|(vote, _)| vote.validator);
    let votes: Vec<FrozenFrontierVote> = selected.iter().map(|(vote, _)| vote.clone()).collect();
    let mut union: Option<DrainUnionIdentity> = None;
    for index in 0..world.members.len() {
        for (vote, page) in &selected {
            ingest_drain_signer_page_successor(
                &world.warrant(index),
                &world.targets[index].0,
                &world.operation,
                network.domain(),
                &network.resolver,
                &current,
                vote.validator,
                vote.clone(),
                page.clone(),
            )
            .unwrap();
        }
        let step: DrainUnionStep = advance_drain_union_successor(
            &world.warrant(index),
            &world.targets[index].0,
            &world.operation,
            network.domain(),
            &network.resolver,
            &network.history,
            &current,
            &votes,
        )
        .unwrap();
        let DrainUnionStep::Ready(identity) = step else {
            panic!("genuinely empty union is complete");
        };
        assert_eq!(identity.member_count, 0);
        if let Some(expected) = &union {
            assert_eq!(identity.as_ref(), expected);
        } else {
            union = Some(*identity);
        }
    }
    let drain_request: [u8; 32] = [0xce; 32];
    let drain: OrderedCandidate = OrderedCandidate {
        context: current.clone(),
        request_id: drain_request,
        kind: OrderedOperationKind::DrainSet,
        intent: encode_drain_set_intent(&DrainSetIntent {
            context: current,
            request_id: drain_request,
            selected_votes: votes,
            drain_union_identity: union.unwrap(),
        })
        .unwrap(),
        created_checkpoint: 4,
    };
    successor_round(world, &env, Some(&drain));
    successor_round(world, &env, None);
    let (outputs, _): (Vec<OrderedEventOutput>, consensus::QuorumCertificate) =
        successor_round(world, &env, None);
    assert!(
        outputs[0]
            .committed
            .iter()
            .any(
                |outcome: &OrderedOutcome| outcome.request_id == drain_request
                    && outcome.output.responses()[0].status() == NodeResponseStatus::Accepted
            )
    );
    for _ in 0..3 {
        successor_round(world, &env, None);
    }
}

#[test]
fn genuine_file_backed_e0_e1_e2_seal_import_activate_reopen_and_fence() {
    let world: SuccessorWorld = recurring_world();
    let g_anchor: Vec<u8> = register_and_unbond_g(&world);
    recurring_preseal(&world);
    let network: &Network = world.network();
    let prior: VerifiedSuccessorAuthority = chain_authority(&world);
    let (cut_identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        current_history(&world);
    let mut source_plan: BusinessReconstructionPlan<'_> =
        reconstruction_plan(world.source(), &world.cut_history);
    source_plan.operation_context = world.operation;
    source_plan.ordered_history_identity = &cut_identity;
    let cut: crate::business_reconstruction::cut::VerifiedBusinessCut =
        crate::business_reconstruction::cut::derive_successor_source_business_cut(
            source_plan,
            &world.warrant(0),
            &world.targets[0].0,
            &network.blobs,
            &ordered,
        )
        .unwrap();
    let saved: SavedBusinessCut = preseal_cut::transfer(&cut, &network.resolver);
    let operation: DurableOperationContext = fixture::context(61);
    let import: VerifiedImportPlan =
        crate::business_reconstruction::inactive_import::verify_saved_business_import_chain(
            reconstruction_plan(world.source(), &world.cut_history),
            &prior,
            &cut_identity,
            &saved,
        )
        .unwrap();
    let files: conditional_readiness::Files = conditional_readiness::Files::new();
    let targets: Vec<(SqliteImportTarget, SqliteBlobStore)> = member_imports(
        &import,
        network.domain(),
        &world.members,
        &files,
        &operation,
    );
    let entries: Vec<FastPathValidatorEntry> = prior
        .validator_set()
        .validators()
        .iter()
        .map(
            |entry: &validator_set::ValidatorInfo| FastPathValidatorEntry {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            },
        )
        .collect();
    let votes: Vec<ReadinessVote> = targets
        .iter()
        .zip(&world.members)
        .map(|((target, blobs), member)| {
            let signer: ReadinessSigningKey = ReadinessSigningKey::new(member.id, member.key);
            let vote: ReadinessVote =
                crate::conditional_readiness::retain_conditional_readiness_chain(
                    reconstruction_plan(world.source(), &world.cut_history),
                    &prior,
                    &cut_identity,
                    &saved,
                    target,
                    blobs,
                    &operation,
                    &entries,
                    &signer,
                )
                .unwrap();
            assert_eq!(signer.signatures_created(), 1);
            let replay: ReadinessVote =
                crate::conditional_readiness::retain_conditional_readiness_chain(
                    reconstruction_plan(world.source(), &world.cut_history),
                    &prior,
                    &cut_identity,
                    &saved,
                    target,
                    blobs,
                    &operation,
                    &entries,
                    &signer,
                )
                .unwrap();
            assert_eq!(replay, vote);
            assert_eq!(signer.signatures_created(), 1);
            vote
        })
        .collect();
    let subject: ReadinessSubject = votes[0].subject.clone();
    let next_set: ValidatorSet = ValidatorSet::new(
        subject.next_epoch,
        prior.validator_set().validators().to_vec(),
    )
    .unwrap();
    let (digest, length): (Digest32, u32) =
        seal_signing::stage_votes(network, &subject, &next_set, &votes);
    let target: Digest32 = seal_target_digest(
        &network.resolver,
        world.policy.context(),
        subject.identity(&network.resolver).unwrap(),
        SEAL_PREDECESSOR_TAG_SUCCESSOR,
        prior.subject_digest(),
    )
    .unwrap();
    let request_id: [u8; 32] =
        seal_request_id(&network.resolver, world.policy.context(), target, digest).unwrap();
    let seal: OrderedCandidate = OrderedCandidate {
        context: world.policy.context().clone(),
        request_id,
        kind: OrderedOperationKind::Seal,
        created_checkpoint: cut_identity.through_height,
        intent: encode_seal_intent(&SealIntent {
            readiness_subject: subject,
            cut_identity_bytes: crate::business_reconstruction::cut::encode_business_cut_identity(
                cut.identity(),
            )
            .unwrap(),
            predecessor_tag: SEAL_PREDECESSOR_TAG_SUCCESSOR,
            predecessor_digest: prior.subject_digest(),
            certificate_digest: digest,
            certificate_length: length,
        })
        .unwrap(),
    };
    let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        seal: Some(OrderedSealComposition {
            genesis_root: &network.root,
            paid_base_policy: &world.next_base,
            paid_engine: &network.engine,
            blobs: &network.blobs,
        }),
        ..world.env()
    };
    // A later Seal cannot substitute the genesis identity or the previous
    // transport manifest for the previously verified 0xD054 subject. Both
    // refusals happen before a signature and leave every persisted row,
    // receipt, object and referenced body unchanged.
    let view: u64 = query_status(&world.targets[0].0, &world.operation, &env)
        .unwrap()
        .current_view;
    let leader_id: ValidatorId = world.policy.engine().validator_set().leader(view).unwrap();
    let leader: usize = world
        .members
        .iter()
        .position(|member: &TestSigner| member.id == leader_id)
        .unwrap();
    let signer: RefusalSigner<'_> = RefusalSigner {
        inner: &world.members[leader],
        signatures: Cell::new(0),
    };
    let before: crate::business_reconstruction::SourceBusinessSnapshot =
        crate::test_support::capture::captured_source(
            &world.targets[leader].0,
            &world.targets[leader].1,
            &world.operation,
            network.domain(),
        );
    for (tag, predecessor) in [
        (SEAL_PREDECESSOR_TAG_GENESIS, network.root.digest()),
        (SEAL_PREDECESSOR_TAG_SUCCESSOR, prior.manifest_digest()),
    ] {
        let mut bad: OrderedCandidate = seal.clone();
        let mut intent: SealIntent = decode_seal_intent(&bad.intent).unwrap();
        intent.predecessor_tag = tag;
        intent.predecessor_digest = predecessor;
        let bad_target: Digest32 = seal_target_digest(
            &network.resolver,
            world.policy.context(),
            intent
                .readiness_subject
                .identity(&network.resolver)
                .unwrap(),
            tag,
            predecessor,
        )
        .unwrap();
        bad.request_id = seal_request_id(
            &network.resolver,
            world.policy.context(),
            bad_target,
            digest,
        )
        .unwrap();
        bad.intent = encode_seal_intent(&intent).unwrap();
        assert!(
            propose_successor(
                &world.warrant(leader),
                &world.targets[leader].0,
                &env,
                Some(&bad),
                &signer,
            )
            .is_err()
        );
        assert_eq!(signer.signatures.get(), 0);
        assert_eq!(
            crate::test_support::capture::captured_source(
                &world.targets[leader].0,
                &world.targets[leader].1,
                &world.operation,
                network.domain(),
            ),
            before
        );
        assert_eq!(
            world.targets[leader]
                .0
                .get_outgoing_barrier(&world.operation, network.domain())
                .unwrap(),
            runtime::OutgoingBarrier::Unsealed
        );
    }
    successor_round(&world, &env, Some(&seal));
    successor_round(&world, &env, None);
    let (outputs, _): (Vec<OrderedEventOutput>, consensus::QuorumCertificate) =
        successor_round(&world, &env, None);
    assert!(
        outputs[0]
            .committed
            .iter()
            .any(|outcome: &OrderedOutcome| outcome.request_id == request_id
                && outcome.output.responses()[0].status() == NodeResponseStatus::Accepted)
    );
    assert!(
        world.resolve(0).is_err(),
        "real outgoing Seal fences the old live namespace"
    );
    let (manifest_identity, history): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        current_history(&world);
    let certificate: Vec<u8> = network.blobs.get_blob(&digest).unwrap().unwrap();
    let pins: [SuccessorLinkPins; 2] = [
        link_zero(&world),
        SuccessorLinkPins {
            cut_identity,
            manifest_identity,
        },
    ];
    let mut artifacts: RecurringArtifacts<'_> = RecurringArtifacts {
        first: world.artifacts(),
        second: Artifacts {
            saved: &saved,
            history: &history,
            certificate: &certificate,
        },
        accesses: Vec::new(),
    };
    let authority: VerifiedSuccessorAuthority = verify_successor_chain_authority(
        reconstruction_plan(world.source(), &world.cut_history),
        &pins,
        budget(2),
        &mut artifacts,
    )
    .unwrap();
    assert_eq!(authority.link_count(), 2);
    assert_eq!(authority.import_binding(), import.binding());
    assert_eq!(authority.committees().len(), 3);
    let g: TestSigner = never_member_g();
    let g_owner = authority
        .owners()
        .owner(g.id)
        .expect("G's own e1 registration is carried forward");
    assert_eq!(g_owner.key(), g.id.as_bytes());
    assert!(
        matches!(g_owner.provenance(), OwnerProvenance::Registration { anchor_epoch, .. }
        if *anchor_epoch == world.policy.context().epoch())
    );
    assert!(
        authority.validator_set().get(g.id).is_none(),
        "G never became a member"
    );
    let g_identity = crate::bond_lifecycle::registration::verify_registration_identity(
        &network.root,
        Some((authority.committees(), authority.owners())),
        &g_anchor,
    )
    .unwrap();
    assert_eq!(g_identity.validator_id, g.id);
    assert_eq!(g_identity.anchor_epoch, world.policy.context().epoch());
    assert!(
        crate::bond_lifecycle::registration::verify_signed_bond_registration_successor(
            &network.root,
            &authority,
            &crate::bond_lifecycle::registration::decode_bond_registration_anchor(&g_anchor)
                .unwrap()
                .signed_registration,
        )
        .is_err(),
        "the same committed anchor is not a new e2 registration"
    );
    assert!(artifacts.accesses.contains(&0) && artifacts.accesses.contains(&1));
    for (index, ((target, blobs), member)) in targets.iter().zip(&world.members).enumerate() {
        let signer: ReadinessSigningKey = ReadinessSigningKey::new(member.id, member.key);
        assert!(matches!(
            crate::serving_authority::activate_successor_chain(
                reconstruction_plan(world.source(), &world.cut_history),
                &pins,
                budget(2),
                &mut artifacts,
                target,
                blobs,
                &operation,
                &signer,
                1
            )
            .unwrap(),
            SuccessorActivationOutcome::Activated { .. }
        ));
        assert_eq!(signer.signatures_created(), 0);
        let policy: OrderedEconomicsPolicy = authority.ordered_policy(&network.root).unwrap();
        let genesis_epoch: Epoch = network.root.genesis_context().epoch();
        assert_eq!(
            policy.certificate_set(genesis_epoch),
            Some(network.root.genesis_committee())
        );
        assert_eq!(
            policy.certificate_set(world.policy.context().epoch()),
            Some(world.policy.engine().validator_set())
        );
        assert!(
            policy
                .certificate_set(Epoch::new(
                    policy.context().epoch().get().checked_add(1).unwrap()
                ))
                .is_none()
        );
        let base: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(policy.context().clone());
        let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
            policy: &policy,
            leg_policy: &base,
            history: &network.history,
            engine: &network.engine,
            blobs: &network.blobs,
            seal: None,
        };
        let bond_key: Vec<u8> =
            fastpath_bond_record_key(policy.context().chain_id(), &g.id).unwrap();
        let observed: VersionedStateValue = target
            .get_versioned_durable(&operation, network.domain(), &bond_key)
            .unwrap();
        let bond_bytes: &[u8] = observed.value().unwrap();
        let bond: FastPathBondRecord = decode_fastpath_bond_record(bond_bytes).unwrap();
        assert!(
            matches!(bond.state, FastPathBondState::Unbonding { unlock_epoch, .. }
            if unlock_epoch.get() == world.policy.context().epoch().get().checked_add(7).unwrap())
        );
        let mut exited: FastPathBondRecord = bond.clone();
        exited.generation = exited.generation.checked_add(1).unwrap();
        exited.lifecycle_epoch = policy.context().epoch();
        exited.committed_at_checkpoint = 22;
        exited.state = FastPathBondState::Exited;
        let request_id: [u8; 32] = [0xed; 32];
        let leg: Vec<u8> = super::successor_replacement::release_leg_for_scope(
            &world,
            policy.context(),
            &base,
            &g,
            request_id,
            &bond.custody_object,
            *g.id.as_bytes(),
        );
        let withdraw: OrderedCandidate = super::successor_replacement::bond_candidate_for_scope(
            &network.resolver,
            policy.context(),
            &g,
            request_id,
            bond_bytes,
            &exited,
            BondLifecycleOperation::Withdraw { leg },
            22,
        );
        policy.authenticate_candidate(&withdraw).unwrap();
        let untouched: crate::business_reconstruction::SourceBusinessSnapshot =
            crate::test_support::capture::captured_source(
                target,
                blobs,
                &operation,
                network.domain(),
            );
        assert!(matches!(
            crate::ordered_economics::preflight::preflight(target, &operation, &env, &withdraw, 1,),
            Err(OrderedEconomicsError::Refused(
                OrderedRefusal::IneligibleState
            ))
        ));
        assert_eq!(
            crate::test_support::capture::captured_source(
                target,
                blobs,
                &operation,
                network.domain()
            ),
            untouched,
            "G's own e2 withdrawal cannot shorten the configured seven-epoch unlock"
        );
        let live: LiveAuthority<'_> = crate::serving_authority::resolve_live_authority_chain(
            target,
            &operation,
            network.domain(),
            reconstruction_plan(world.source(), &world.cut_history),
            &pins,
            budget(2),
            &mut artifacts,
            signer.public_key(),
        )
        .unwrap();
        let LiveAuthority::Successor(warrant) = live else {
            panic!("e2 is a verified successor");
        };
        process_tick_successor(&warrant, target, &env, 20_001, &world.members[index]).unwrap();
        drop(warrant);
        let before: OrderedStatus = query_status(target, &operation, &env).unwrap();
        let old: DurableOperationContext = operation;
        let new: DurableOperationContext = fixture::context(62);
        let reopened: SqliteImportTarget = SqliteImportTarget::open_existing(
            files.path(&format!("serving-{index}-state.db")),
            SqliteNamespace::new(fixture::chain(), member.id, network.domain()),
            authority.import_binding(),
        )
        .unwrap();
        reopened
            .advance_writer_fence(old.writer_fence(), new.writer_fence())
            .unwrap();
        assert!(
            crate::serving_authority::resolve_live_authority_chain(
                target,
                &old,
                network.domain(),
                reconstruction_plan(world.source(), &world.cut_history),
                &pins,
                budget(2),
                &mut artifacts,
                signer.public_key()
            )
            .is_err()
        );
        assert!(matches!(
            crate::serving_authority::activate_successor_chain(
                reconstruction_plan(world.source(), &world.cut_history),
                &pins,
                budget(2),
                &mut artifacts,
                &reopened,
                blobs,
                &new,
                &signer,
                1
            )
            .unwrap(),
            SuccessorActivationOutcome::AlreadyActivated { .. }
        ));
        assert_eq!(query_status(&reopened, &new, &env).unwrap(), before);
        let mut corrupt: Vec<u8> = certificate.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let mut bad: RecurringArtifacts<'_> = RecurringArtifacts {
            first: world.artifacts(),
            second: Artifacts {
                saved: &saved,
                history: &history,
                certificate: &corrupt,
            },
            accesses: Vec::new(),
        };
        assert!(
            crate::serving_authority::resolve_live_authority_chain(
                &reopened,
                &new,
                network.domain(),
                reconstruction_plan(world.source(), &world.cut_history),
                &pins,
                budget(2),
                &mut bad,
                signer.public_key()
            )
            .is_err()
        );
        assert_eq!(
            query_status(&reopened, &new, &env).unwrap(),
            before,
            "corrupt later-link evidence has no durable effect"
        );
    }
}

/// E's genuine committed e_0 registration anchor, as imported by every
/// activated ABCE target.
fn registered_anchor(
    world: &SuccessorWorld,
    e: usize,
) -> crate::bond_lifecycle::registration::BondRegistrationAnchor {
    let chain: &ChainId = world.network().root.genesis_context().chain_id();
    let key: Vec<u8> = crate::bond_lifecycle::registration::bond_registration_anchor_key(
        chain,
        &world.members[e].id,
    )
    .unwrap();
    let (_, bytes): (StateRevision, Option<Vec<u8>>) = world.value(0, &key);
    crate::bond_lifecycle::registration::decode_bond_registration_anchor(&bytes.unwrap()).unwrap()
}

fn incoming_index(world: &SuccessorWorld) -> usize {
    let original: &OrderedEconomicsPolicy = &world.network().policy;
    (0..world.members.len())
        .find(|index: &usize| {
            original
                .registered_validator(world.members[*index].id)
                .is_none()
        })
        .unwrap()
}

#[test]
fn chain_policy_keeps_verified_history_owners_and_scoped_registration() {
    let world: SuccessorWorld = replacement_world();
    let root: &VerifiedGenesisRoot = &world.network().root;
    let e0: Epoch = root.genesis_context().epoch();
    let authority: VerifiedSuccessorAuthority = chain_authority(&world);
    let policy: OrderedEconomicsPolicy = authority.ordered_policy(root).unwrap();
    // Same consensus identity as the single-link successor policy.
    assert_eq!(policy.anchor(), world.policy.anchor());
    assert_eq!(policy.context(), world.policy.context());
    assert!(policy.key_scope().is_successor());
    // Historical certificate scope: the verified e_0 committee only.
    assert_eq!(policy.certificate_set(e0), Some(root.genesis_committee()));
    assert_eq!(
        policy.certificate_set(policy.context().epoch()),
        Some(policy.engine().validator_set())
    );
    assert!(
        policy
            .certificate_set(Epoch::new(policy.context().epoch().get() + 1))
            .is_none()
    );

    // Retired D keeps owner exit authority from its verified genesis key,
    // never as a member; Deposit stays members-only.
    let d: &TestSigner = world
        .network()
        .signers
        .iter()
        .find(|signer: &&TestSigner| policy.registered_validator(signer.id).is_none())
        .unwrap();
    let unbond: BondLifecycleOperation = BondLifecycleOperation::Unbond {
        recipient: Address::new([0x5d; 32]),
    };
    let owner = policy.bond_owner_authority(d.id, &unbond).unwrap();
    assert_eq!(
        owner.source,
        crate::ordered_economics::policy::BondOwnerSource::Verified
    );
    let d_key: [u8; 32] = ReadinessSigningKey::new(d.id, d.key).public_key();
    assert_eq!(owner.key.as_ref(), d_key.as_slice());
    // A never-registered, never-member id is only a pure same-epoch claim
    // that preflight must still prove from a committed anchor.
    let stranger: ValidatorId = ValidatorId::new([0x5e; 32]);
    assert_eq!(
        policy
            .bond_owner_authority(stranger, &unbond)
            .unwrap()
            .source,
        crate::ordered_economics::policy::BondOwnerSource::SameEpochRegistrant
    );

    // Registration scope at e_1: E's genuine e_0 envelope is a replay
    // across epochs and refuses; its anchor carries forward in Existing mode.
    let e: usize = incoming_index(&world);
    let anchor = registered_anchor(&world, e);
    assert!(
        crate::bond_lifecycle::registration::verify_signed_bond_registration_successor(
            root,
            &authority,
            &anchor.signed_registration,
        )
        .is_err()
    );
    let identity = crate::bond_lifecycle::registration::verify_registration_identity(
        root,
        Some((authority.committees(), authority.owners())),
        &crate::bond_lifecycle::registration::encode_bond_registration_anchor(&anchor).unwrap(),
    )
    .expect("E's own anchor is its carried-forward identity");
    assert_eq!(identity.validator_id, world.members[e].id);
    assert_eq!(identity.anchor_epoch, e0);
}
