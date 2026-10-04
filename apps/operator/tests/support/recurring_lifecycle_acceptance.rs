//! Current-context registration and historical-owner lifecycle through the
//! existing SDK preparation, CLI wrapping and real ordered TCP handlers.
//! Physical reads are untrusted construction inputs only; no row is seeded.

use super::*;
use node_core::bond_lifecycle::{
    BondLifecycleIntent, BondLifecycleOperation, SignedBondLifecycleIntent,
    bond_lifecycle_intent_digest, bond_lifecycle_signing_frame, bond_row_digest,
    encode_signed_bond_lifecycle_intent,
};
use node_core::fast_path::records::{
    FastPathBondRecord, FastPathBondState, decode_fastpath_bond_record, encode_fastpath_bond_record,
};
use objects::{
    Address, Object, ObjectId, ObjectRef, Owner, ProtocolCustodyPurpose, ProtocolCustodyScope,
};
use protocol_types::{HashPurpose, SignatureSchemeId};
use runtime::VersionedStateReader;

pub(super) struct ExitOwner {
    pub(super) member: SuccessorProcessMember,
    pub(super) unlock: Epoch,
}

fn state(fixture: &Fixture, targets: &CurrentTargets, index: usize, key: &[u8]) -> Option<Vec<u8>> {
    let store: SqliteDurableStore = SqliteDurableStore::open_historical(
        targets.paths[index].join("state.db"),
        SqliteNamespace::new(
            fixture.network.chain_id.clone(),
            targets.members[index].validator_id,
            fixture.network.domain,
        ),
    )
    .unwrap();
    let operation: runtime::DurableOperationContext = runtime::DurableOperationContext::new(
        store.writer_fence().unwrap(),
        runtime::StorageDeadline::new(u64::MAX / 2).unwrap(),
        runtime::StorageCorrelationId::new([0xcd; 16]).unwrap(),
    );
    store
        .read_versioned_state(&operation, fixture.network.domain, key)
        .unwrap()
        .value()
        .map(<[u8]>::to_vec)
}

fn bond(fixture: &Fixture, targets: &CurrentTargets, validator: ValidatorId) -> FastPathBondRecord {
    let key: Vec<u8> = node_core::local_instance_state::fastpath_bond_record_key(
        &fixture.network.chain_id,
        &validator,
    )
    .unwrap();
    let first: Vec<u8> = state(fixture, targets, 0, &key).expect("real committed bond row");
    for index in 1..targets.paths.len() {
        assert_eq!(
            state(fixture, targets, index, &key).as_deref(),
            Some(first.as_slice())
        );
    }
    decode_fastpath_bond_record(&first).unwrap()
}

fn resource(
    fixture: &Fixture,
    targets: &CurrentTargets,
    context: &execution::publication::PublicationContext,
    id: bonds::BondResourceId,
) -> node_core::economics::FastPathEconomicsResourcePolicy {
    let key: Vec<u8> =
        node_core::local_instance_state::fastpath_economics_policy_key(context).unwrap();
    let bytes: Vec<u8> =
        state(fixture, targets, 0, &key).expect("installed original economics row");
    let policy: node_core::economics::FastPathEconomicsPolicy =
        node_core::economics::decode_fastpath_economics_policy(&bytes).unwrap();
    assert_eq!(
        policy,
        fixture.root.manifest().economics_policy,
        "the original signed economics remains unchanged"
    );
    policy
        .resources
        .into_iter()
        .find(|resource| resource.resource_id == id)
        .unwrap()
}

fn object(host: &HostProcess, id: ObjectId) -> (Object, ObjectRef) {
    let result: sunrise_edge_client::HttpObjectQueryResult = Client::new(transport(host.address))
        .query_object(id)
        .unwrap();
    let reference: ObjectRef = sunrise_edge_client::current_inline_object_ref(&result)
        .expect("live independently verified object");
    let sunrise_edge_client::HttpObjectQueryResult::CurrentInline {
        canonical_object_bytes,
        ..
    } = result
    else {
        panic!("the actual custody input is not a live inline object");
    };
    (
        objects::decode_object(&canonical_object_bytes).unwrap(),
        reference,
    )
}

fn nonce(host: &HostProcess, public: [u8; 32]) -> u64 {
    Client::new(transport(host.address))
        .query_next_nonce(Address::new(public))
        .unwrap()
        .next_nonce()
}

fn private_seed(path: &Path, seed: [u8; 32]) {
    std::fs::write(path, hex(&seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[allow(clippy::too_many_arguments)]
fn signed_leg(
    fixture: &Fixture,
    current: &SuccessorWorkflowAuthority,
    host: &HostProcess,
    member: &SuccessorProcessMember,
    request: [u8; 32],
    resource: &node_core::economics::FastPathEconomicsResourcePolicy,
    input: ObjectRef,
    recipient: [u8; 32],
) -> Vec<u8> {
    let context: execution::publication::PublicationContext = current.expected_context().clone();
    current.require_signing_context(&context).unwrap();
    let policy: execution::local_execution::LocalExecutionPolicy =
        execution::local_execution::LocalExecutionPolicy::generic_object_results(context.clone());
    let intent: execution::local_execution::LocalExecutionIntent =
        execution::local_execution::LocalExecutionIntent {
            mode: execution::local_execution::LocalExecutionMode::Call,
            policy_digest: policy.digest(&fixture.network.resolver).unwrap(),
            call: execution::call::CallIntent {
                context: context.clone(),
                request_id: request,
                sender: *member.validator_id.as_bytes(),
                nonce: nonce(host, *member.validator_id.as_bytes()),
                code: resource.code.clone(),
                instance: resource.instance.clone(),
                entrypoint: resource.transfer_entrypoint.clone(),
                type_arguments: resource.ty.args().to_vec(),
                access: abi::AccessManifest {
                    entries: vec![abi::AccessEntry {
                        object_ref: input,
                        mode: objects::AccessMode::Write,
                    }],
                },
                arguments: public_standard_asset::transfer_arguments(&recipient).unwrap(),
                gas_limit: 500_000,
            },
            authorizations: Vec::new(),
        };
    let frame: Vec<u8> =
        execution::local_execution::local_execution_signing_frame(&context, &intent).unwrap();
    let key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from(member.seed);
    execution::local_execution::encode_signed_local_execution(
        &execution::local_execution::SignedLocalExecutionIntent {
            intent,
            signature: key.sign(&frame).into(),
        },
    )
    .unwrap()
}

pub(super) fn request(epoch: Epoch, tag: u8, member: &SuccessorProcessMember) -> [u8; 32] {
    let mut id: [u8; 32] = epoch_request_id(epoch.get(), tag);
    id[9..25].copy_from_slice(&member.validator_id.as_bytes()[..16]);
    id
}

#[allow(clippy::too_many_arguments)]
fn wrap(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    directory: &Path,
    bytes: &[u8],
    request: [u8; 32],
    kind: &str,
    label: &str,
) -> PathBuf {
    let signed: PathBuf = directory.join(format!("{label}.signed"));
    let candidate: PathBuf = directory.join(format!("{label}.candidate"));
    std::fs::write(&signed, bytes).unwrap();
    let mut flags: Vec<String> = ordered_pins(fixture, links, current);
    flags.extend([
        "--intent".into(),
        signed.to_str().unwrap().into(),
        "--kind".into(),
        kind.into(),
        "--request-id".into(),
        hex(&request),
        "--created-checkpoint".into(),
        HOST_CHECKPOINT.to_string(),
        "--out".into(),
        candidate.to_str().unwrap().into(),
    ]);
    cli(&["economics", "candidate-wrap"], flags);
    candidate
}

#[allow(clippy::too_many_arguments)]
pub(super) fn register(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    targets: &CurrentTargets,
    hosts: &[HostProcess],
    network: &Path,
    directory: &Path,
    seed: [u8; 32],
    coin_byte: u8,
) -> SuccessorProcessMember {
    let member: SuccessorProcessMember = member_from_seed(seed);
    assert!(
        current
            .fastvote_certifier()
            .validator_set()
            .get(member.validator_id)
            .is_none()
    );
    let anchor: Vec<u8> = node_core::bond_lifecycle::registration::bond_registration_anchor_key(
        &fixture.network.chain_id,
        &member.validator_id,
    )
    .unwrap();
    for index in 0..targets.paths.len() {
        assert!(state(fixture, targets, index, &anchor).is_none());
    }
    let entry: &node_core::GenesisObjectEntry = fixture
        .root
        .manifest()
        .objects
        .iter()
        .find(|entry| entry.object.id == ObjectId::new([coin_byte; 32]))
        .unwrap();
    let (source, reference): (Object, ObjectRef) = object(&hosts[0], entry.object.id);
    assert_eq!(
        source, entry.object,
        "ordinary signed genesis funding has not been substituted"
    );
    assert_eq!(
        source.owner,
        Owner::Address(Address::new(*member.validator_id.as_bytes()))
    );
    let resource: &node_core::economics::FastPathEconomicsResourcePolicy =
        &fixture.root.manifest().economics_policy.resources[0];
    let installed: node_core::economics::FastPathEconomicsResourcePolicy =
        self::resource(fixture, targets, &resource.context, resource.resource_id);
    assert_eq!(&installed, resource);
    let context: execution::publication::PublicationContext = current.expected_context().clone();
    current.require_signing_context(&context).unwrap();
    let scope: ProtocolCustodyScope = ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::BondCollateral,
        chain_id: fixture.network.chain_id.clone(),
        subject: *member.validator_id.as_bytes(),
        resource: *resource.resource_id.value(),
    };
    let token: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &fixture.network.resolver,
        &context,
        source.id,
        &scope,
    )
    .unwrap();
    let id: [u8; 32] = request(context.epoch(), 0x41, &member);
    let leg: Vec<u8> = signed_leg(
        fixture, current, &hosts[0], &member, id, resource, reference, token,
    );
    let mut predicted_object: Object = source;
    predicted_object.version = predicted_object.version.checked_add(1).unwrap();
    predicted_object.owner = Owner::ProtocolCustody(scope);
    let predicted: FastPathBondRecord = FastPathBondRecord {
        context: resource.context.clone(),
        validator_id: member.validator_id,
        resource_domain: resource.resource_id.domain(),
        resource: *resource.resource_id.value(),
        custody_object: ObjectRef {
            id: predicted_object.id,
            version: predicted_object.version,
            digest: fixture
                .network
                .resolver
                .hash_for_purpose(
                    context.epoch(),
                    HashPurpose::Object,
                    &objects::encode_object(&predicted_object).unwrap(),
                )
                .unwrap(),
        },
        custody_object_epoch: context.epoch(),
        authority: entry.authority.clone(),
        amount: 10_000,
        committed_at_checkpoint: HOST_CHECKPOINT,
        generation: 1,
        lifecycle_epoch: context.epoch(),
        slashable_from_epoch: Epoch::new(context.epoch().get().checked_add(1).unwrap()),
        required_minimum: resource.bond.as_ref().unwrap().min_bond.get(),
        state: FastPathBondState::Active,
        authorization_scheme: SignatureSchemeId::Ed25519,
        authorization_key: *member.validator_id.as_bytes(),
    };
    let signer: sunrise_edge_client::LocalSigner =
        sunrise_edge_client::LocalSigner::from_seed(seed);
    let prepared: sunrise_edge_client::bond_registration::PreparedSuccessorBondRegistration<'_> =
        sunrise_edge_client::bond_registration::prepare_successor_bond_registration(
            current,
            &context,
            &signer,
            id,
            leg.clone(),
            predicted.clone(),
        )
        .unwrap();
    assert_eq!(prepared.validator_id(), member.validator_id);
    let sdk_signed: Vec<u8> = prepared.sign(&signer, &context).unwrap();
    assert!(
        prepared.sign(&signer, &fixture.network.context).is_err(),
        "a retained preparation never signs in an old context"
    );
    assert!(
        sunrise_edge_client::bond_registration::prepare_successor_bond_registration(
            current,
            &fixture.network.context,
            &signer,
            id,
            leg.clone(),
            predicted.clone()
        )
        .is_err(),
        "a genesis context cannot authorize a current registration signature"
    );
    let leg_path: PathBuf = directory.join(format!("registration-{coin_byte}.leg"));
    let row_path: PathBuf = directory.join(format!("registration-{coin_byte}.row"));
    let seed_path: PathBuf = directory.join(format!("registration-{coin_byte}.seed"));
    let signed_path: PathBuf = directory.join(format!("registration-{coin_byte}.signed"));
    std::fs::write(&leg_path, &leg).unwrap();
    std::fs::write(&row_path, encode_fastpath_bond_record(&predicted).unwrap()).unwrap();
    private_seed(&seed_path, seed);
    let mut flags: Vec<String> = ordered_pins(fixture, links, current);
    flags.extend([
        "--request-id".into(),
        hex(&id),
        "--signed-leg".into(),
        leg_path.to_str().unwrap().into(),
        "--expected-bond-row".into(),
        row_path.to_str().unwrap().into(),
        "--seed-file".into(),
        seed_path.to_str().unwrap().into(),
        "--out".into(),
        signed_path.to_str().unwrap().into(),
    ]);
    cli(&["economics", "bond-registration-prepare"], flags);
    let encoded: Vec<u8> = std::fs::read(&signed_path).unwrap();
    assert_eq!(
        encoded, sdk_signed,
        "SDK and CLI use the same current registration owner"
    );
    node_core::bond_lifecycle::registration::verify_signed_bond_registration_successor(
        current.genesis_root(),
        current.authority(),
        &encoded,
    )
    .unwrap();
    let candidate: PathBuf = wrap(
        fixture,
        links,
        current,
        directory,
        &encoded,
        id,
        "bond-registration",
        &format!("registration-{coin_byte}-wrapped"),
    );
    submit(
        fixture,
        links,
        current,
        network,
        &candidate,
        &directory.join(format!("registration-{coin_byte}-submission")),
    );
    committed_outcome(hosts, id);
    assert_eq!(
        bond(fixture, targets, member.validator_id),
        predicted,
        "actual generic VM custody produced the predicted row"
    );
    for index in 0..targets.paths.len() {
        assert!(state(fixture, targets, index, &anchor).is_some());
    }
    member
}

fn sign_lifecycle(
    fixture: &Fixture,
    current: &SuccessorWorkflowAuthority,
    member: &SuccessorProcessMember,
    previous: &FastPathBondRecord,
    next: &FastPathBondRecord,
    id: [u8; 32],
    operation: BondLifecycleOperation,
) -> Vec<u8> {
    let context: execution::publication::PublicationContext = current.expected_context().clone();
    current.require_signing_context(&context).unwrap();
    assert_eq!(previous.authorization_key, *member.validator_id.as_bytes());
    let intent: BondLifecycleIntent = BondLifecycleIntent {
        context: context.clone(),
        request_id: id,
        validator_id: member.validator_id,
        resource_id: bonds::BondResourceId::new(previous.resource_domain, previous.resource)
            .unwrap(),
        expected_generation: previous.generation,
        expected_previous_row_digest: bond_row_digest(
            &fixture.network.resolver,
            previous.lifecycle_epoch,
            &encode_fastpath_bond_record(previous).unwrap(),
        )
        .unwrap(),
        expected_next_row_digest: bond_row_digest(
            &fixture.network.resolver,
            next.lifecycle_epoch,
            &encode_fastpath_bond_record(next).unwrap(),
        )
        .unwrap(),
        operation,
    };
    let frame: Vec<u8> = bond_lifecycle_signing_frame(
        &context,
        bond_lifecycle_intent_digest(&fixture.network.resolver, &intent).unwrap(),
    )
    .unwrap();
    let key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from(member.seed);
    encode_signed_bond_lifecycle_intent(&SignedBondLifecycleIntent {
        intent,
        signature: key.sign(&frame).into(),
    })
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn start_exits(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    targets: &CurrentTargets,
    hosts: &[HostProcess],
    network: &Path,
    directory: &Path,
) -> Vec<ExitOwner> {
    let d: SuccessorProcessMember = member_from_seed([0xa4; 32]);
    assert_eq!(
        fixture.network.validators[original_member_index(fixture, [0xa4; 32])].validator_id,
        d.validator_id
    );
    assert!(
        current
            .fastvote_certifier()
            .validator_set()
            .get(d.validator_id)
            .is_none()
    );
    let g: SuccessorProcessMember = register(
        fixture, links, current, targets, hosts, network, directory, [0xe9; 32], 0x1b,
    );
    let mut owners: Vec<ExitOwner> = Vec::new();
    for member in [d, g] {
        assert!(
            current
                .fastvote_certifier()
                .validator_set()
                .get(member.validator_id)
                .is_none()
        );
        let previous: FastPathBondRecord = bond(fixture, targets, member.validator_id);
        assert_eq!(previous.state, FastPathBondState::Active);
        let installed: node_core::economics::FastPathEconomicsResourcePolicy = resource(
            fixture,
            targets,
            &previous.context,
            bonds::BondResourceId::new(previous.resource_domain, previous.resource).unwrap(),
        );
        let delay: u64 = installed.bond.unwrap().unbonding_epochs;
        assert_eq!(
            delay, 7,
            "the actual installed original signed delay is not shortened"
        );
        let expected: Epoch = Epoch::new(
            current
                .expected_context()
                .epoch()
                .get()
                .checked_add(delay)
                .unwrap(),
        );
        let mut next: FastPathBondRecord = previous.clone();
        next.generation = next.generation.checked_add(1).unwrap();
        next.lifecycle_epoch = current.expected_context().epoch();
        next.committed_at_checkpoint = HOST_CHECKPOINT;
        next.state = FastPathBondState::Unbonding {
            unlock_epoch: expected,
            recipient: *member.validator_id.as_bytes(),
        };
        let id: [u8; 32] = request(current.expected_context().epoch(), 0x42, &member);
        let bytes: Vec<u8> = sign_lifecycle(
            fixture,
            current,
            &member,
            &previous,
            &next,
            id,
            BondLifecycleOperation::Unbond {
                recipient: Address::new(*member.validator_id.as_bytes()),
            },
        );
        let label: String = format!("unbond-{}", hex(member.validator_id.as_bytes()));
        let candidate: PathBuf = wrap(
            fixture,
            links,
            current,
            directory,
            &bytes,
            id,
            "bond-lifecycle",
            &label,
        );
        submit(
            fixture,
            links,
            current,
            network,
            &candidate,
            &directory.join(format!("{label}-submission")),
        );
        committed_outcome(hosts, id);
        let actual: FastPathBondRecord = bond(fixture, targets, member.validator_id);
        assert_eq!(actual, next);
        let FastPathBondState::Unbonding { unlock_epoch, .. } = actual.state else {
            panic!("Unbond did not commit");
        };
        assert_eq!(
            unlock_epoch.get(),
            actual.lifecycle_epoch.get().checked_add(delay).unwrap()
        );
        owners.push(ExitOwner {
            member,
            unlock: unlock_epoch,
        });
    }
    owners
}

#[allow(clippy::too_many_arguments)]
pub(super) fn withdrawals(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    targets: &CurrentTargets,
    hosts: &[HostProcess],
    network: &Path,
    directory: &Path,
    owners: &[ExitOwner],
) {
    for owner in owners {
        let member: &SuccessorProcessMember = &owner.member;
        assert!(
            current
                .fastvote_certifier()
                .validator_set()
                .get(member.validator_id)
                .is_none()
        );
        let previous: FastPathBondRecord = bond(fixture, targets, member.validator_id);
        assert!(
            matches!(previous.state, FastPathBondState::Unbonding { unlock_epoch, .. } if unlock_epoch == owner.unlock)
        );
        let installed: node_core::economics::FastPathEconomicsResourcePolicy = resource(
            fixture,
            targets,
            &previous.context,
            bonds::BondResourceId::new(previous.resource_domain, previous.resource).unwrap(),
        );
        let (before_object, reference): (Object, ObjectRef) =
            object(&hosts[0], previous.custody_object.id);
        assert_eq!(reference, previous.custody_object);
        let before_nonce: u64 = nonce(&hosts[0], *member.validator_id.as_bytes());
        let id: [u8; 32] = request(current.expected_context().epoch(), 0x43, member);
        let leg: Vec<u8> = signed_leg(
            fixture,
            current,
            &hosts[0],
            member,
            id,
            &installed,
            reference,
            *member.validator_id.as_bytes(),
        );
        let mut after_object: Object = before_object.clone();
        after_object.version = after_object.version.checked_add(1).unwrap();
        after_object.owner = Owner::Address(Address::new(*member.validator_id.as_bytes()));
        let mut next: FastPathBondRecord = previous.clone();
        next.generation = next.generation.checked_add(1).unwrap();
        next.lifecycle_epoch = current.expected_context().epoch();
        next.committed_at_checkpoint = HOST_CHECKPOINT;
        next.custody_object_epoch = current.expected_context().epoch();
        next.custody_object = ObjectRef {
            id: after_object.id,
            version: after_object.version,
            digest: fixture
                .network
                .resolver
                .hash_for_purpose(
                    current.expected_context().epoch(),
                    HashPurpose::Object,
                    &objects::encode_object(&after_object).unwrap(),
                )
                .unwrap(),
        };
        next.state = FastPathBondState::Exited;
        let bytes: Vec<u8> = sign_lifecycle(
            fixture,
            current,
            member,
            &previous,
            &next,
            id,
            BondLifecycleOperation::Withdraw { leg },
        );
        let label: String = format!("withdraw-{}", hex(member.validator_id.as_bytes()));
        let candidate: PathBuf = wrap(
            fixture,
            links,
            current,
            directory,
            &bytes,
            id,
            "bond-lifecycle",
            &label,
        );
        if current.expected_context().epoch() < owner.unlock {
            let mut flags: Vec<String> = ordered_network_pins(fixture, links, current, network);
            flags.extend([
                "--candidate".into(),
                candidate.to_str().unwrap().into(),
                "--out".into(),
                directory
                    .join(format!("{label}-refused"))
                    .to_str()
                    .unwrap()
                    .into(),
            ]);
            let mut arguments: Vec<OsString> = vec!["economics".into(), "network-submit".into()];
            arguments.extend(flags.into_iter().map(OsString::from));
            assert!(
                tokio::task::block_in_place(|| sunrise_edge_cli::run(arguments)).is_err(),
                "actual ordered owner must refuse before unlock"
            );
            assert_eq!(bond(fixture, targets, member.validator_id), previous);
            for host in hosts {
                assert_eq!(object(host, previous.custody_object.id).0, before_object);
                assert_eq!(nonce(host, *member.validator_id.as_bytes()), before_nonce);
                let response: WireResponse = raw(
                    host.address,
                    Method::Get,
                    &format!(
                        "{}{}",
                        node_wire::ordered_economics::ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX,
                        hex(&id)
                    ),
                    None,
                    Vec::new(),
                );
                assert_eq!(
                    response.status, 204,
                    "premature withdrawal creates no ordered outcome"
                );
            }
        } else {
            assert_eq!(
                current.expected_context().epoch(),
                owner.unlock,
                "withdraw at the computed unlock, not a guessed epoch"
            );
            submit(
                fixture,
                links,
                current,
                network,
                &candidate,
                &directory.join(format!("{label}-submission")),
            );
            committed_outcome(hosts, id);
            assert_eq!(bond(fixture, targets, member.validator_id), next);
            for host in hosts {
                assert_eq!(object(host, previous.custody_object.id).0, after_object);
                assert_eq!(
                    nonce(host, *member.validator_id.as_bytes()),
                    before_nonce.checked_add(1).unwrap()
                );
            }
        }
    }
}
