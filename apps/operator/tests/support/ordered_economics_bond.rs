//! Test-controlled signed genesis funding and genuine two-leg bond flows.
use super::*;
use node_core::bond_lifecycle::{
    self, BondLifecycleIntent, BondLifecycleOperation, SignedBondLifecycleIntent,
};
use node_core::fast_path::records::{
    FastPathBondRecord, FastPathBondState, decode_fastpath_bond_record, encode_fastpath_bond_record,
};
use objects::{Object, ObjectId, ObjectRef, Owner, ProtocolCustodyPurpose, ProtocolCustodyScope};
use protocol_types::{Digest32, HashPurpose};

pub(super) fn fund_source(fixture: &mut FastVoteGenesisFixture) -> node_core::GenesisObjectEntry {
    let mut manifest = node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let mut source = manifest
        .objects
        .iter()
        .find(|entry| matches!(entry.object.owner, Owner::ProtocolCustody(_)))
        .unwrap()
        .clone();
    let id: ObjectId = ObjectId::new([0xEA; 32]);
    assert!(manifest.objects.iter().all(|entry| entry.object.id != id));
    source.object.id = id;
    source.object.owner = Owner::Address(Address::new(
        VerificationKey::from(&SigningKey::from([0x77; 32])).into(),
    ));
    source.authority.object_id = id;
    // This is a dev Standard Asset genesis fixture ONLY, never a runtime
    // balance or asset-id exception. Its signed supply includes this funding.
    let amount: u64 = public_standard_asset::coin_amount(&source.object.data).unwrap();
    let treasury = &mut manifest.objects[1];
    let supply: u64 = public_standard_asset::treasury_supply(&treasury.object.data)
        .unwrap()
        .checked_add(amount)
        .unwrap();
    treasury.object.data = encode_call_value(
        &public_standard_asset::treasury_cap_body_layout(),
        &CallValue::U64(supply),
    )
    .unwrap();
    manifest.objects.push(source.clone());
    let genesis_key: SigningKey = SigningKey::from(sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED);
    manifest.signature = genesis_key
        .sign(&node_core::genesis::genesis_manifest_signing_frame(&manifest).unwrap())
        .into();
    fixture.manifest_digest =
        node_core::genesis::genesis_manifest_commitment(&fixture.resolver, &manifest)
            .unwrap()
            .bytes();
    fixture.manifest_bytes = node_core::encode_genesis_manifest(&manifest).unwrap();
    source
}

fn object_ref(fixture: &FastVoteGenesisFixture, object: &Object) -> ObjectRef {
    ObjectRef {
        id: object.id,
        version: object.version,
        digest: fixture
            .resolver
            .hash_for_purpose(
                fixture.epoch,
                HashPurpose::Object,
                &objects::encode_object(object).unwrap(),
            )
            .unwrap(),
    }
}

pub(super) fn current_bond(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    validator: ValidatorId,
) -> FastPathBondRecord {
    let key =
        node_core::local_instance_state::fastpath_bond_record_key(&fixture.chain_id, &validator)
            .unwrap();
    let observed = store(pool, namespace)
        .get_versioned_durable(&cli::read_context(pool, namespace), fixture.domain, &key)
        .unwrap();
    decode_fastpath_bond_record(observed.value().unwrap()).unwrap()
}

fn candidate(
    fixture: &FastVoteGenesisFixture,
    previous: &FastPathBondRecord,
    next: &FastPathBondRecord,
    request: [u8; 32],
    resource_id: bonds::BondResourceId,
    operation: BondLifecycleOperation,
) -> OrderedCandidate {
    let intent = BondLifecycleIntent {
        context: fixture.context.clone(),
        request_id: request,
        validator_id: previous.validator_id,
        resource_id,
        expected_generation: previous.generation,
        expected_previous_row_digest: bond_lifecycle::bond_row_digest(
            &fixture.resolver,
            previous.lifecycle_epoch,
            &encode_fastpath_bond_record(previous).unwrap(),
        )
        .unwrap(),
        expected_next_row_digest: bond_lifecycle::bond_row_digest(
            &fixture.resolver,
            next.lifecycle_epoch,
            &encode_fastpath_bond_record(next).unwrap(),
        )
        .unwrap(),
        operation,
    };
    let key: &SigningKey = &fixture
        .validators
        .iter()
        .find(|v| v.validator_id == previous.validator_id)
        .unwrap()
        .signing_key;
    let digest: Digest32 =
        bond_lifecycle::bond_lifecycle_intent_digest(&fixture.resolver, &intent).unwrap();
    let frame: Vec<u8> =
        bond_lifecycle::bond_lifecycle_signing_frame(&fixture.context, digest).unwrap();
    OrderedCandidate {
        context: fixture.context.clone(),
        request_id: request,
        kind: OrderedOperationKind::BondLifecycle,
        intent: bond_lifecycle::encode_signed_bond_lifecycle_intent(&SignedBondLifecycleIntent {
            intent,
            signature: key.sign(&frame).into(),
        })
        .unwrap(),
        created_checkpoint: 2,
    }
}

pub(super) fn prepare_replace(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    source: &node_core::GenesisObjectEntry,
    validator: ValidatorId,
) -> (OrderedCandidate, FastPathBondRecord, Object) {
    let previous: FastPathBondRecord = current_bond(pool, namespace, fixture, validator);
    let manifest = node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let resource = manifest
        .economics_policy
        .resources
        .iter()
        .find(|r| {
            r.resource_id.domain() == previous.resource_domain
                && r.resource_id.value() == &previous.resource
        })
        .unwrap();
    let scope: ProtocolCustodyScope = ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::BondCollateral,
        chain_id: previous.context.chain_id().clone(),
        subject: *validator.as_bytes(),
        resource: previous.resource,
    };
    let recipient: Address =
        Address::new(VerificationKey::from(&SigningKey::from([0x77; 32])).into());
    let deposit_operand: [u8; 32] = execution::protocol_custody::derive_deposit_owner_token(
        &fixture.resolver,
        &fixture.context,
        source.object.id,
        &scope,
    )
    .unwrap();
    let policy = LocalExecutionPolicy::generic_object_results(fixture.context.clone());
    let sender = *recipient.as_bytes();
    let next_nonce: u64 = node_core::query_sender_next_nonce(
        &store(pool, namespace),
        &cli::read_context(pool, namespace),
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        sender,
    )
    .unwrap();
    let publication = manifest.publication.request().artifact();
    let authenticated = execution::publication::authenticate_publication_submission(
        &fixture.resolver,
        &fixture.context,
        publication.semantics(),
        manifest.publication.clone(),
    )
    .unwrap();
    let interface =
        execution::publication::verify_publication_interface(authenticated, Vec::new()).unwrap();
    let request: [u8; 32] = [0xE0; 32];
    let build_leg = |object_ref: ObjectRef, nonce: u64, operand: [u8; 32]| -> Vec<u8> {
        let arguments = encode_call_value(
            interface
                .argument_layout(&resource.transfer_entrypoint)
                .unwrap(),
            &CallValue::Tuple(vec![CallValue::Bytes(operand.to_vec())]),
        )
        .unwrap();
        let intent = LocalExecutionIntent {
            mode: LocalExecutionMode::Call,
            policy_digest: policy.digest(&fixture.resolver).unwrap(),
            call: CallIntent {
                context: fixture.context.clone(),
                request_id: request,
                sender,
                nonce,
                code: resource.code.clone(),
                instance: resource.instance.clone(),
                entrypoint: resource.transfer_entrypoint.clone(),
                type_arguments: resource.ty.args().to_vec(),
                access: AccessManifest {
                    entries: vec![AccessEntry {
                        object_ref,
                        mode: AccessMode::Write,
                    }],
                },
                arguments,
                gas_limit: 500_000,
            },
            authorizations: Vec::new(),
        };
        let frame = local_execution_signing_frame(&fixture.context, &intent).unwrap();
        let key = SigningKey::from([0x77; 32]);
        encode_signed_local_execution(&SignedLocalExecutionIntent {
            intent,
            signature: key.sign(&frame).into(),
        })
        .unwrap()
    };
    let deposit_leg = build_leg(
        object_ref(fixture, &source.object),
        next_nonce,
        deposit_operand,
    );
    let release_leg = build_leg(
        previous.custody_object.clone(),
        next_nonce.checked_add(1).unwrap(),
        sender,
    );
    let mut deposited: Object = source.object.clone();
    deposited.version = deposited.version.checked_add(1).unwrap();
    deposited.owner = Owner::ProtocolCustody(scope);
    let mut next: FastPathBondRecord = previous.clone();
    next.custody_object = object_ref(fixture, &deposited);
    next.custody_object_epoch = fixture.epoch;
    next.authority = source.authority.clone();
    next.generation += 1;
    next.lifecycle_epoch = fixture.epoch;
    next.required_minimum = resource.bond.as_ref().unwrap().min_bond.get();
    next.committed_at_checkpoint = 2;
    let amount = execution::publication::observe_nominal_value(
        &interface,
        &source.authority.ty,
        source.object.schema_version,
        &source.object.data,
    )
    .unwrap();
    let CallValue::U64(amount) = amount else {
        panic!("pinned bond observation must be u64")
    };
    next.amount = amount;
    let mut released: Object = manifest
        .objects
        .iter()
        .find(|entry| entry.object.id == previous.custody_object.id)
        .unwrap()
        .object
        .clone();
    released.version += 1;
    released.owner = Owner::Address(recipient);
    (
        candidate(
            fixture,
            &previous,
            &next,
            request,
            resource.resource_id,
            BondLifecycleOperation::Replace {
                deposit_leg,
                release_leg,
                release_recipient: recipient,
            },
        ),
        next,
        released,
    )
}

pub(super) fn prepare_reactivate(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    source: &Object,
    validator: ValidatorId,
) -> (OrderedCandidate, FastPathBondRecord) {
    let previous = current_bond(pool, namespace, fixture, validator);
    assert!(matches!(previous.state, FastPathBondState::Jailed { .. }));
    let manifest = node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let resource = manifest
        .economics_policy
        .resources
        .iter()
        .find(|r| {
            r.resource_id.domain() == previous.resource_domain
                && r.resource_id.value() == &previous.resource
        })
        .unwrap();
    let scope = ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::BondCollateral,
        chain_id: previous.context.chain_id().clone(),
        subject: *validator.as_bytes(),
        resource: previous.resource,
    };
    let operand = execution::protocol_custody::derive_deposit_owner_token(
        &fixture.resolver,
        &fixture.context,
        source.id,
        &scope,
    )
    .unwrap();
    let policy = LocalExecutionPolicy::generic_object_results(fixture.context.clone());
    let key = SigningKey::from([0x77; 32]);
    let sender: [u8; 32] = VerificationKey::from(&key).into();
    let nonce = node_core::query_sender_next_nonce(
        &store(pool, namespace),
        &cli::read_context(pool, namespace),
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        sender,
    )
    .unwrap();
    assert_eq!(
        nonce, 2,
        "the two-leg Replace consumed exactly its consecutive nonce range"
    );
    let publication = manifest.publication.request().artifact();
    let authenticated = execution::publication::authenticate_publication_submission(
        &fixture.resolver,
        &fixture.context,
        publication.semantics(),
        manifest.publication.clone(),
    )
    .unwrap();
    let interface =
        execution::publication::verify_publication_interface(authenticated, Vec::new()).unwrap();
    let arguments = encode_call_value(
        interface
            .argument_layout(&resource.transfer_entrypoint)
            .unwrap(),
        &CallValue::Tuple(vec![CallValue::Bytes(operand.to_vec())]),
    )
    .unwrap();
    let request = [0xD6; 32];
    let intent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&fixture.resolver).unwrap(),
        call: CallIntent {
            context: fixture.context.clone(),
            request_id: request,
            sender,
            nonce,
            code: resource.code.clone(),
            instance: resource.instance.clone(),
            entrypoint: resource.transfer_entrypoint.clone(),
            type_arguments: resource.ty.args().to_vec(),
            access: AccessManifest {
                entries: vec![AccessEntry {
                    object_ref: object_ref(fixture, source),
                    mode: AccessMode::Write,
                }],
            },
            arguments,
            gas_limit: 500_000,
        },
        authorizations: Vec::new(),
    };
    let frame = local_execution_signing_frame(&fixture.context, &intent).unwrap();
    let leg = encode_signed_local_execution(&SignedLocalExecutionIntent {
        intent,
        signature: key.sign(&frame).into(),
    })
    .unwrap();
    let mut deposited = source.clone();
    deposited.version += 1;
    deposited.owner = Owner::ProtocolCustody(scope);
    let mut next = previous.clone();
    next.custody_object = object_ref(fixture, &deposited);
    next.custody_object_epoch = fixture.epoch;
    next.authority = manifest
        .objects
        .iter()
        .find(|entry| entry.object.id == source.id)
        .unwrap()
        .authority
        .clone();
    next.amount = match execution::publication::observe_nominal_value(
        &interface,
        &next.authority.ty,
        source.schema_version,
        &source.data,
    )
    .unwrap()
    {
        CallValue::U64(amount) => amount,
        _ => panic!("bond nominal observation"),
    };
    next.generation += 1;
    next.committed_at_checkpoint = 2;
    next.lifecycle_epoch = fixture.epoch;
    next.slashable_from_epoch = protocol_types::Epoch::new(fixture.epoch.get() + 1);
    next.required_minimum = resource.bond.as_ref().unwrap().min_bond.get();
    next.state = FastPathBondState::Active;
    (
        candidate(
            fixture,
            &previous,
            &next,
            request,
            resource.resource_id,
            BondLifecycleOperation::Reactivate { leg },
        ),
        next,
    )
}
