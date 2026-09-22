use abi::call_values::{CallValue, encode_call_value};
use abi::package_types::{PackageOrigin, derive_scoped_type_id};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{
    InstanceRecord, LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy,
    ObjectAuthority, SignedLocalExecutionIntent, generic_object_result_semantics, instance_target,
    local_execution_signing_frame,
};
use execution::paid_execution::{MIN_RESERVE_ALLOWANCE, MIN_SETTLE_ALLOWANCE, PaidFeePolicy};
use execution::publication::{
    ArtifactParts, BindingError, BodyError, CodeArtifact, PublicationContext, PublicationRequest,
    PublicationSubmission, UnverifiedDependencyRef, artifact_commitment,
    publication_submission_signing_frame,
};
use fees::GasSchedule;
use hashing::HashSuiteResolver;
use objects::{
    Address, Object, ObjectId, Owner, ProtocolCustodyPurpose, ProtocolCustodyScope, encode_object,
};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashPurpose, HashSuite, HashSuiteSchedule,
    ProtocolVersion, SignatureSchemeId, ValidatorId,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, AtomicityDomainId,
    DurableCommitOutcome, DurableCommitRejection, DurableDomainStateStore,
    DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead, DurableObjectHeadRead,
    DurableObjectMutation, DurableObjectMutationEntry, DurableObjectOwnerProjection,
    DurableObjectProvenance, DurableObjectRoutingProjection, DurableObjectVersion,
    DurableObjectVersionRecord, DurableOperationContext, DurableReadError, DurableRequestId,
    DurableRequestReceipt, MemoryDurableStateStore, StateMutation, StateMutationEntry,
    StateReadAssertion, StorageCorrelationId, StorageDeadline, StructuredDurableDomainStateStore,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use sha2::{Digest, Sha256};

use super::*;
use crate::economics::{FastPathEconomicsPolicy, FastPathEconomicsResourcePolicy};
use crate::fast_path::records::{
    FastPathBondRecord, FastPathBondState, decode_fastpath_bond_record,
};
use crate::fast_path::{FastPathValidatorEntry, FastPathValidatorSetRecord};
use crate::local_instance_state::fastpath_bond_record_key;
use bonds::{BondResourceConfig, BondResourceId};
use fees::Amount;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key() -> SigningKey {
    SigningKey::from([7; 32])
}

fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}

fn chain() -> ChainId {
    ChainId::new("genesis-test").unwrap()
}

fn protocol() -> PublicationContext {
    PublicationContext::new(chain(), ProtocolVersion::new(3), Epoch::new(0)).unwrap()
}

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        chain(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}

fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([1; 32]).unwrap()
}

fn context(generation: u64) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(generation).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([1; 16]).unwrap(),
    )
}

fn build_fixture() -> (
    GenesisManifest,
    PackageOrigin,
    InstanceRecord,
    ObjectId,
    ObjectId,
) {
    let origin = PackageOrigin::unverified(chain(), sender(), [1; 32]).unwrap();
    let package = public_standard_asset::build_package(&origin).unwrap();
    let semantics = generic_object_result_semantics(&resolver(), &protocol()).unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: protocol(),
        origin: origin.clone(),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: Vec::new(),
    })
    .unwrap();

    let digest = artifact_commitment(&resolver(), &protocol(), &artifact).unwrap();
    let frame =
        publication_submission_signing_frame(&resolver(), &protocol(), &artifact, 0, [1; 32])
            .unwrap();
    let submission = PublicationSubmission::new(
        [1; 32],
        PublicationRequest::new(artifact, 0, digest, key().sign(&frame).into()),
    )
    .unwrap();

    let code_ref = UnverifiedDependencyRef::new(origin.clone(), 1, protocol(), digest).unwrap();
    let instance_record = InstanceRecord {
        context: protocol(),
        creator: sender(),
        seed: [2; 32],
        code: code_ref.clone(),
        revision: 1,
        initializer: "init".into(),
    };
    let target = instance_target(&resolver(), &instance_record).unwrap();

    let base_policy = LocalExecutionPolicy::generic_object_results(protocol());
    let base_policy_digest = base_policy.digest(&resolver()).unwrap();

    let call = CallIntent {
        context: protocol(),
        request_id: [2; 32],
        sender: sender(),
        nonce: 0,
        code: code_ref.clone(),
        instance: target.clone(),
        entrypoint: "init".into(),
        type_arguments: Vec::new(),
        access: abi::AccessManifest {
            entries: Vec::new(),
        },
        arguments: Vec::new(),
        gas_limit: 500_000,
    };
    let init_intent = LocalExecutionIntent {
        mode: LocalExecutionMode::Instantiate,
        policy_digest: base_policy_digest,
        call,
        authorizations: Vec::new(),
    };
    let init_frame = local_execution_signing_frame(&protocol(), &init_intent).unwrap();
    let signed_init = SignedLocalExecutionIntent {
        intent: init_intent,
        signature: key().sign(&init_frame).into(),
    };

    let def_id = ObjectId::new([0x10; 32]);
    let coin_id = ObjectId::new([0x20; 32]);

    let def_tag = public_standard_asset::definition_type_tag(&origin).unwrap();
    let coin_tag = public_standard_asset::coin_type_tag(&origin, &def_id).unwrap();

    let fee_policy = PaidFeePolicy {
        context: protocol(),
        base_policy_digest,
        instance: target.clone(),
        code: code_ref.clone(),
        reserve_entrypoint: "reserve".into(),
        reserve_all_entrypoint: "reserve_all".into(),
        settle_entrypoint: "settle".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&def_id)],
        asset_type: coin_tag.clone(),
        reservation_type: public_standard_asset::reservation_type_tag(&origin, &def_id).unwrap(),
        schema: public_standard_asset::SCHEMA_VERSION,
        fee_recipient: sender(),
        gas_schedule: GasSchedule {
            base_fee: 100,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        conversion_divisor: 1_000,
        reserve_allowance: MIN_RESERVE_ALLOWANCE,
        settle_allowance: MIN_SETTLE_ALLOWANCE,
        calls: 8,
        handles: 16,
        creations: 4,
        events: 16,
        memory_bytes: 8 * 1024 * 1024,
        output_bytes: 1024 * 1024,
        publish_artifact_byte_price: 1,
        publish_closure_node_price: 1,
    };
    let (resource_domain, resource): (u16, [u8; 32]) = match coin_tag.args() {
        [abi::package_types::ScopedTypeArg::Opaque { domain, value }] => (*domain, *value),
        _ => panic!("fixture coin type must carry one opaque resource"),
    };
    let resource_id: BondResourceId = BondResourceId::new(resource_domain, resource).unwrap();
    let economics_policy: FastPathEconomicsPolicy = FastPathEconomicsPolicy {
        context: protocol(),
        resources: vec![FastPathEconomicsResourcePolicy {
            resource_id,
            context: protocol(),
            instance: target.clone(),
            code: code_ref.clone(),
            ty: coin_tag.clone(),
            schema: public_standard_asset::SCHEMA_VERSION,
            split_entrypoint: "split".to_owned(),
            transfer_entrypoint: "transfer".to_owned(),
            bond: Some(BondResourceConfig {
                resource_id,
                min_bond: Amount::new(100),
                enabled: true,
                unbonding_epochs: 7,
                max_validator_exposure: None,
            }),
            fee_escrow: true,
        }],
    };

    let def_type_hash = derive_scoped_type_id(&resolver(), Epoch::new(0), &def_tag).unwrap();
    let coin_type_hash = derive_scoped_type_id(&resolver(), Epoch::new(0), &coin_tag).unwrap();

    let def_obj = Object {
        id: def_id,
        version: 1,
        owner: Owner::Address(Address::new(sender())),
        type_hash: def_type_hash,
        schema_version: public_standard_asset::SCHEMA_VERSION,
        data: encode_call_value(
            &public_standard_asset::definition_body_layout(),
            &CallValue::Tuple(Vec::new()),
        )
        .unwrap(),
    };
    let def_auth = ObjectAuthority {
        object_id: def_id,
        instance_context: protocol(),
        instance: target.clone(),
        code: code_ref.clone(),
        ty: def_tag,
    };

    let coin_data = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(1_000_000),
    )
    .unwrap();
    let coin_obj = Object {
        id: coin_id,
        version: 1,
        owner: Owner::Address(Address::new(sender())),
        type_hash: coin_type_hash,
        schema_version: public_standard_asset::SCHEMA_VERSION,
        data: coin_data,
    };
    let coin_auth = ObjectAuthority {
        object_id: coin_id,
        instance_context: protocol(),
        instance: target,
        code: code_ref,
        ty: coin_tag,
    };

    let mut manifest = GenesisManifest {
        genesis_authority: sender(),
        publication: submission,
        initialization: signed_init,
        fee_policy,
        economics_policy,
        objects: vec![
            GenesisObjectEntry {
                object: def_obj,
                authority: def_auth,
            },
            GenesisObjectEntry {
                object: coin_obj,
                authority: coin_auth,
            },
        ],
        validator_set: FastPathValidatorSetRecord {
            context: protocol(),
            validators: vec![FastPathValidatorEntry {
                id: ValidatorId::new(sender()),
                voting_power: 1,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: sender().to_vec(),
            }],
        },
        signature: [0; 64],
    };
    manifest.signature = key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();

    (manifest, origin, instance_record, def_id, coin_id)
}

/// Builds a `ProtocolCustody`-owned genesis object entry (DR-0135) sharing
/// its authority template (instance, code, type) with the fixture's coin
/// entry, so only ownership and identity differ from an already-admitted
/// object.
fn custody_object_entry(
    manifest: &GenesisManifest,
    object_id: ObjectId,
    chain_id: ChainId,
) -> GenesisObjectEntry {
    let template = &manifest.objects[1];
    let validator = manifest
        .validator_set
        .validators
        .first()
        .expect("fixture validator");
    let resource: [u8; 32] = match template.authority.ty.args() {
        [abi::package_types::ScopedTypeArg::Opaque { value, .. }] => *value,
        _ => panic!("fixture coin type must carry one opaque resource"),
    };
    let scope = ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::BondCollateral,
        chain_id,
        subject: *validator.id.as_bytes(),
        resource,
    };
    GenesisObjectEntry {
        object: Object {
            id: object_id,
            version: 1,
            owner: Owner::ProtocolCustody(scope),
            type_hash: template.object.type_hash,
            schema_version: template.object.schema_version,
            data: template.object.data.clone(),
        },
        authority: ObjectAuthority {
            object_id,
            instance_context: template.authority.instance_context.clone(),
            instance: template.authority.instance.clone(),
            code: template.authority.code.clone(),
            ty: template.authority.ty.clone(),
        },
    }
}

fn resign_manifest(manifest: &mut GenesisManifest) {
    manifest.signature = key()
        .sign(&genesis_manifest_signing_frame(manifest).unwrap())
        .into();
}

fn manifest_with_custody(object_id: ObjectId) -> GenesisManifest {
    let (mut manifest, _, _, _, _) = build_fixture();
    let custody: GenesisObjectEntry = custody_object_entry(&manifest, object_id, chain());
    manifest.objects.push(custody);
    resign_manifest(&mut manifest);
    manifest
}

/// DR-0135: a signed genesis manifest may install a `ProtocolCustody` object
/// whose scope chain equals the manifest chain, and a verify-only restart
/// must reach `VerifiedExisting` for it exactly like any other genesis
/// object.
#[test]
fn genesis_installs_protocol_custody_object_for_matching_chain() {
    let (mut manifest, _, _, _, _) = build_fixture();
    let custody_id = ObjectId::new([0x30; 32]);
    manifest
        .objects
        .push(custody_object_entry(&manifest, custody_id, chain()));
    manifest.signature = key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();

    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let outcome =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    assert!(matches!(
        outcome,
        GenesisInstallOutcome::FreshInstall { .. }
    ));
    assert!(matches!(
        store
            .get_object_head(&context(1), domain(), custody_id)
            .unwrap(),
        DurableObjectHead::Current { .. }
    ));
    let bond_key = fastpath_bond_record_key(&chain(), &ValidatorId::new(sender())).unwrap();
    let bond_bytes = store
        .get_versioned_durable(&context(1), domain(), &bond_key)
        .unwrap()
        .value()
        .unwrap()
        .to_vec();
    let bond: FastPathBondRecord = decode_fastpath_bond_record(&bond_bytes).unwrap();
    assert_eq!(bond.validator_id, ValidatorId::new(sender()));
    assert_eq!(bond.custody_object.id, custody_id);
    assert_eq!(bond.amount, 1_000_000);
    assert_eq!(bond.committed_at_checkpoint, 10);
    assert_eq!(bond.generation, 1);
    assert_eq!(bond.lifecycle_epoch, Epoch::new(0));
    assert_eq!(bond.required_minimum, 100);
    assert_eq!(bond.state, FastPathBondState::Active);

    let restart_outcome =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    assert!(matches!(
        restart_outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));
    let replayed_bond_bytes = store
        .get_versioned_durable(&context(1), domain(), &bond_key)
        .unwrap()
        .value()
        .unwrap()
        .to_vec();
    assert_eq!(replayed_bond_bytes, bond_bytes);
}

/// DR-0135: a `ProtocolCustody` scope bound to a chain other than the exact
/// manifest chain must fail closed before any state is written.
#[test]
fn genesis_rejects_protocol_custody_object_bound_to_another_chain() {
    let (mut manifest, _, _, _, _) = build_fixture();
    let custody_id = ObjectId::new([0x31; 32]);
    let other_chain = ChainId::new("a-different-genesis-chain").unwrap();
    manifest
        .objects
        .push(custody_object_entry(&manifest, custody_id, other_chain));
    manifest.signature = key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();

    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("protocol custody scope chain does not match the manifest chain")
    ));
    assert!(matches!(
        store
            .get_object_head(&context(1), domain(), custody_id)
            .unwrap(),
        DurableObjectHead::Absent
    ));
}

#[test]
fn genesis_rejects_derived_protocol_custody_purposes() {
    let purposes: [ProtocolCustodyPurpose; 2] = [
        ProtocolCustodyPurpose::FeeEscrow,
        ProtocolCustodyPurpose::ForfeitedCollateral,
    ];
    for (index, purpose) in purposes.into_iter().enumerate() {
        let suffix: u8 = u8::try_from(index).unwrap();
        let custody_id: ObjectId = ObjectId::new([0x40_u8 + suffix; 32]);
        let mut manifest: GenesisManifest = manifest_with_custody(custody_id);
        let scope: &mut ProtocolCustodyScope =
            match &mut manifest.objects.last_mut().unwrap().object.owner {
                Owner::ProtocolCustody(scope) => scope,
                _ => panic!("expected protocol custody owner"),
            };
        scope.purpose = purpose;
        resign_manifest(&mut manifest);

        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        let error: GenesisError =
            install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
        assert!(matches!(
            error,
            GenesisError::Invalid("protocol custody purpose cannot be installed at genesis")
        ));
        assert_eq!(
            store
                .get_object_head(&context(1), domain(), custody_id)
                .unwrap(),
            DurableObjectHead::Absent
        );
    }
}

#[test]
fn genesis_bond_commitment_rejects_unknown_validator_resource_mismatch_and_zero_value() {
    let custody_id: ObjectId = ObjectId::new([0x33; 32]);

    let mut unknown_validator: GenesisManifest = manifest_with_custody(custody_id);
    let unknown_scope: &mut ProtocolCustodyScope =
        match &mut unknown_validator.objects.last_mut().unwrap().object.owner {
            Owner::ProtocolCustody(scope) => scope,
            _ => panic!("expected protocol custody owner"),
        };
    unknown_scope.subject = [0x99; 32];
    resign_manifest(&mut unknown_validator);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &unknown_validator,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("bond custody subject is not a genesis validator")
    ));
    assert_eq!(
        store
            .get_object_head(&context(1), domain(), custody_id)
            .unwrap(),
        DurableObjectHead::Absent
    );

    let mut mismatched_resource: GenesisManifest = manifest_with_custody(custody_id);
    let mismatched_scope: &mut ProtocolCustodyScope =
        match &mut mismatched_resource.objects.last_mut().unwrap().object.owner {
            Owner::ProtocolCustody(scope) => scope,
            _ => panic!("expected protocol custody owner"),
        };
    mismatched_scope.resource = [0x98; 32];
    resign_manifest(&mut mismatched_resource);
    let mismatch_store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &mismatch_store,
        &context(1),
        domain(),
        &resolver(),
        &mismatched_resource,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("bond custody resource does not match the nominal type")
    ));

    let mut zero_value: GenesisManifest = manifest_with_custody(custody_id);
    zero_value.objects.last_mut().unwrap().object.data = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(0),
    )
    .unwrap();
    resign_manifest(&mut zero_value);
    let zero_store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &zero_store,
        &context(1),
        domain(),
        &resolver(),
        &zero_value,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("bond amount must be positive")
    ));
}

#[test]
fn genesis_bond_commitment_rejects_non_resource_type_and_duplicate_validator() {
    let (mut non_resource, _, _, _, _) = build_fixture();
    let definition_template: GenesisObjectEntry = non_resource.objects[0].clone();
    let definition_id: ObjectId = ObjectId::new([0x34; 32]);
    let mut definition_custody: GenesisObjectEntry = definition_template;
    definition_custody.object.id = definition_id;
    definition_custody.object.owner = Owner::ProtocolCustody(ProtocolCustodyScope {
        purpose: ProtocolCustodyPurpose::BondCollateral,
        chain_id: chain(),
        subject: sender(),
        resource: [0x77; 32],
    });
    definition_custody.authority.object_id = definition_id;
    non_resource.objects.push(definition_custody);
    resign_manifest(&mut non_resource);
    let non_resource_store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &non_resource_store,
        &context(1),
        domain(),
        &resolver(),
        &non_resource,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("bond custody type must carry one opaque resource")
    ));

    let (mut non_scalar, origin, _, definition_id, _) = build_fixture();
    let mut reservation_custody: GenesisObjectEntry =
        custody_object_entry(&non_scalar, ObjectId::new([0x39; 32]), chain());
    let reservation_type =
        public_standard_asset::reservation_type_tag(&origin, &definition_id).unwrap();
    reservation_custody.object.type_hash =
        derive_scoped_type_id(&resolver(), Epoch::new(0), &reservation_type).unwrap();
    reservation_custody.object.data = encode_call_value(
        &public_standard_asset::reservation_body_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(1),
            CallValue::Bytes(vec![
                0x01;
                public_standard_asset::ENCODED_DIGEST32_BYTES as usize
            ]),
            CallValue::Bytes(vec![
                0x02;
                public_standard_asset::ENCODED_DIGEST32_BYTES as usize
            ]),
            CallValue::Bytes(vec![0x03; 32]),
            CallValue::Bytes(vec![0x04; 32]),
        ]),
    )
    .unwrap();
    reservation_custody.authority.ty = reservation_type;
    non_scalar.objects.push(reservation_custody);
    resign_manifest(&mut non_scalar);
    let non_scalar_store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &non_scalar_store,
        &context(1),
        domain(),
        &resolver(),
        &non_scalar,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("bond custody value must be a scalar u64")
    ));

    let (mut duplicate, _, _, _, _) = build_fixture();
    let first: GenesisObjectEntry =
        custody_object_entry(&duplicate, ObjectId::new([0x35; 32]), chain());
    let second: GenesisObjectEntry =
        custody_object_entry(&duplicate, ObjectId::new([0x36; 32]), chain());
    duplicate.objects.extend([first, second]);
    resign_manifest(&mut duplicate);
    let duplicate_store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &duplicate_store,
        &context(1),
        domain(),
        &resolver(),
        &duplicate,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("duplicate genesis bond for validator")
    ));
}

#[test]
fn genesis_bond_commitment_rejects_partial_and_tampered_durable_rows() {
    let manifest: GenesisManifest = manifest_with_custody(ObjectId::new([0x37; 32]));
    let bond_key: Vec<u8> =
        fastpath_bond_record_key(&chain(), &ValidatorId::new(sender())).unwrap();

    let partial_store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let initial: VersionedStateValue = partial_store
        .get_versioned_durable(&context(1), domain(), &bond_key)
        .unwrap();
    let partial_tx: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(bond_key.clone(), initial.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(bond_key.clone(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        partial_store.commit_durable(&context(1), partial_tx),
        DurableCommitOutcome::Committed
    );
    let error: GenesisError = install_genesis(
        &partial_store,
        &context(1),
        domain(),
        &resolver(),
        &manifest,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::PartialPriorState("fast-path bond record")
    ));

    let installed_store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    install_genesis(
        &installed_store,
        &context(1),
        domain(),
        &resolver(),
        &manifest,
        10,
    )
    .unwrap();
    let installed: VersionedStateValue = installed_store
        .get_versioned_durable(&context(1), domain(), &bond_key)
        .unwrap();
    let mut tampered: Vec<u8> = installed.value().unwrap().to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;
    let tamper_tx: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(bond_key.clone(), installed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(bond_key.clone(), StateMutation::Put(tampered)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        installed_store.commit_durable(&context(1), tamper_tx),
        DurableCommitOutcome::Committed
    );
    let error: GenesisError = install_genesis(
        &installed_store,
        &context(1),
        domain(),
        &resolver(),
        &manifest,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::TamperedInstalledRecord("fast-path bond record")
    ));

    let missing_store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    install_genesis(
        &missing_store,
        &context(1),
        domain(),
        &resolver(),
        &manifest,
        10,
    )
    .unwrap();
    let missing_observation: VersionedStateValue = missing_store
        .get_versioned_durable(&context(1), domain(), &bond_key)
        .unwrap();
    let delete_tx: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(bond_key.clone(), missing_observation.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(bond_key, StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        missing_store.commit_durable(&context(1), delete_tx),
        DurableCommitOutcome::Committed
    );
    let error: GenesisError = install_genesis(
        &missing_store,
        &context(1),
        domain(),
        &resolver(),
        &manifest,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::TamperedInstalledRecord("fast-path bond record")
    ));
}

#[test]
fn address_only_genesis_does_not_create_a_bond_row() {
    let (manifest, _, _, _, _) = build_fixture();
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    let bond_key: Vec<u8> =
        fastpath_bond_record_key(&chain(), &ValidatorId::new(sender())).unwrap();
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(1), domain(), &bond_key)
        .unwrap();
    assert_eq!(observed.revision(), StateRevision::INITIAL);
    assert!(observed.value().is_none());
}

/// DR-0135: `Shared`/`Immutable`/`System` owners remain unsupported at
/// genesis exactly as before this decision.
#[test]
fn genesis_rejects_shared_owner_object() {
    let (mut manifest, _, _, _, _) = build_fixture();
    manifest.objects[1].object.owner = Owner::Shared;
    manifest.signature = key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();

    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("genesis object owner must be an Address or protocol custody scope")
    ));
}

#[test]
fn stable_vectors_0x6416_manifest_and_0x6417_marker() {
    let (manifest, _, _, _, _) = build_fixture();
    let manifest_bytes = encode_genesis_manifest(&manifest).unwrap();
    assert_eq!(manifest_bytes.len(), 17210);
    let manifest_sha256 = hex(&Sha256::digest(&manifest_bytes));
    assert_eq!(
        manifest_sha256,
        "84bbd63b21df55e77f595982d6f261068c72079f87872cc04a931789f3bba215"
    );

    let decoded = decode_genesis_manifest(&manifest_bytes).unwrap();
    assert_eq!(decoded, manifest);

    let manifest_digest = genesis_manifest_commitment(&resolver(), &manifest).unwrap();
    let marker = GenesisInstallMarker {
        context: protocol(),
        manifest_digest,
        genesis_authority: manifest.genesis_authority,
        installed_at_checkpoint: 42,
    };
    let marker_bytes = encode_genesis_install_marker(&marker).unwrap();
    assert_eq!(marker_bytes.len(), 182);
    let marker_sha256 = hex(&Sha256::digest(&marker_bytes));
    assert_eq!(
        marker_sha256,
        "1e134d0daf7a42936031a7098bdfab1e82b08d13c279123f8cc20a1e2cfe56a5"
    );

    let decoded_marker = decode_genesis_install_marker(&marker_bytes).unwrap();
    assert_eq!(decoded_marker, marker);
}

#[test]
fn unsigned_manifest_object_tampering_fails_before_install() {
    let (mut manifest, _, _, _, _) = build_fixture();
    manifest.objects[1].object.data[0] ^= 0x01;
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error = install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 1)
        .expect_err("objects not covered by the genesis signature must fail closed");
    assert!(matches!(
        error,
        GenesisError::Invalid("invalid genesis manifest signature")
    ));
}

/// DR-0131: a genesis validator set with two distinct `ValidatorId`s sharing
/// an identical public key must fail closed at install time, exactly like
/// [`validator_set::ValidatorSet::new`] rejects it directly.
#[test]
fn duplicate_validator_public_keys_are_rejected_at_genesis_install() {
    let (mut manifest, _, _, _, _) = build_fixture();
    let shared_key: Vec<u8> = manifest.validator_set.validators[0].public_key.clone();
    manifest
        .validator_set
        .validators
        .push(FastPathValidatorEntry {
            id: ValidatorId::new([0x42; 32]),
            voting_power: 1,
            signature_scheme: SignatureSchemeId::Ed25519,
            public_key: shared_key,
        });
    manifest.signature = key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error = install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 1)
        .expect_err("a shared validator public key must fail closed at genesis");
    assert!(matches!(
        error,
        GenesisError::Invalid("invalid genesis fast-path validator set")
    ));
}

#[test]
fn fresh_install_and_verify_only_restart_in_memory() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, origin, instance_record, def_id, coin_id) = build_fixture();

    // 1. Fresh install.
    let outcome =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    let (marker, digest) = match outcome {
        GenesisInstallOutcome::FreshInstall {
            marker,
            manifest_digest,
        } => (marker, manifest_digest),
        _ => panic!("expected FreshInstall"),
    };
    assert_eq!(marker.manifest_digest, digest);
    assert_eq!(marker.genesis_authority, manifest.genesis_authority);
    assert_eq!(marker.installed_at_checkpoint, 10);

    // Verify all installed records in store.
    let man_key = genesis_manifest_key(&protocol()).unwrap();
    let mark_key = genesis_marker_key(&protocol()).unwrap();
    let pub_key = publication::publication_record_key(&origin).unwrap();
    let inst_key = local_instance_state::instance_record_key(
        protocol().chain_id(),
        &instance_record.creator,
        &instance_record.seed,
    )
    .unwrap();
    let pub_pol_key = publication::publication_policy_key_for_profile(&protocol(), 4).unwrap();
    let exec_pol_key =
        local_instance_state::execution_policy_key_for_profile(&protocol(), 4).unwrap();
    let fee_pol_key = local_instance_state::paid_fee_policy_key(&protocol()).unwrap();
    let economics_policy_key =
        local_instance_state::fastpath_economics_policy_key(&protocol()).unwrap();

    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &man_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert_eq!(
        store
            .get_versioned_durable(&context(1), domain(), &economics_policy_key)
            .unwrap()
            .value(),
        Some(
            encode_fastpath_economics_policy(&manifest.economics_policy)
                .unwrap()
                .as_slice()
        )
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &mark_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &pub_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &inst_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &pub_pol_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &exec_pol_key)
            .unwrap()
            .value()
            .is_some()
    );
    assert!(
        store
            .get_versioned_durable(&context(1), domain(), &fee_pol_key)
            .unwrap()
            .value()
            .is_some()
    );

    // DR-0131: the committed epoch record is created atomically alongside
    // genesis validator-set activation, binding the exact installed
    // checkpoint and validator-set digest.
    let epoch_record_key =
        local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap();
    let epoch_record_bytes = store
        .get_versioned_durable(&context(1), domain(), &epoch_record_key)
        .unwrap()
        .value()
        .unwrap()
        .to_vec();
    let epoch_record =
        local_instance_state::decode_fastpath_epoch_record(&epoch_record_bytes).unwrap();
    assert_eq!(epoch_record.current_epoch, protocol().epoch());
    assert_eq!(epoch_record.previous_epoch, None);
    assert_eq!(epoch_record.activated_at_checkpoint, 10);
    let installed_validator_set: validator_set::ValidatorSet = validator_set::ValidatorSet::new(
        protocol().epoch(),
        manifest
            .validator_set
            .validators
            .iter()
            .map(|validator| validator_set::ValidatorInfo {
                id: validator.id,
                voting_power: validator.voting_power,
                signature_scheme: validator.signature_scheme,
                public_key: validator.public_key.clone(),
            })
            .collect(),
    )
    .unwrap();
    assert_eq!(
        epoch_record.current_validator_set_digest,
        installed_validator_set.digest(&resolver()).unwrap()
    );

    for obj_id in [def_id, coin_id] {
        let auth_key = local_instance_state::object_authority_key(obj_id);
        assert!(
            store
                .get_versioned_durable(&context(1), domain(), &auth_key)
                .unwrap()
                .value()
                .is_some()
        );
        assert!(matches!(
            store
                .get_object_head(&context(1), domain(), obj_id)
                .unwrap(),
            DurableObjectHead::Current { .. }
        ));
        let ver = store
            .get_object_version(&context(1), domain(), obj_id, DurableObjectVersion::FIRST)
            .unwrap();
        assert!(ver.is_some());
    }

    // 2. Restart verify-only.
    let restart_outcome =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    match restart_outcome {
        GenesisInstallOutcome::VerifiedExisting {
            marker: remk,
            manifest_digest: redig,
        } => {
            assert_eq!(remk, marker);
            assert_eq!(redig, digest);
        }
        _ => panic!("expected VerifiedExisting"),
    }
}

#[test]
fn mutable_balance_changes_tolerated_while_version_1_provenance_exact_and_supply_reissue_prevented()
{
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, _, _, _, coin_id) = build_fixture();

    // 1. Fresh install.
    install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();

    // 2. Simulate subsequent mutation (e.g. transfer/split, balance reduced to 500_000, version advanced to 2).
    let mutated_coin_data = encode_call_value(
        &public_standard_asset::coin_body_layout(),
        &CallValue::U64(500_000),
    )
    .unwrap();
    let mutated_coin = Object {
        id: coin_id,
        version: 2,
        owner: Owner::Address(Address::new(sender())),
        type_hash: manifest.objects[1].object.type_hash,
        schema_version: public_standard_asset::SCHEMA_VERSION,
        data: mutated_coin_data,
    };
    let canonical_bytes = encode_object(&mutated_coin).unwrap();
    let digest = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
        .unwrap();
    let version_two_record = DurableObjectVersionRecord::from_inline_object(
        mutated_coin.clone(),
        digest,
        DurableObjectProvenance::new(chain(), ProtocolVersion::new(3)),
        20,
    )
    .unwrap();

    let head_read = DurableObjectHeadRead::new(
        coin_id,
        store
            .get_object_head(&context(1), domain(), coin_id)
            .unwrap(),
    );
    let update_mutation = DurableObjectMutationEntry::new(
        coin_id,
        DurableObjectMutation::Update {
            version: version_two_record,
            owner_projection: DurableObjectOwnerProjection::from_owner(mutated_coin.owner.clone())
                .unwrap(),
            routing_projection: DurableObjectRoutingProjection::default(),
        },
    );
    let object_changes = DurableObjectChanges::new(vec![head_read], vec![update_mutation]).unwrap();

    let durable_id = DurableRequestId::new([9; 32]).unwrap();
    let receipt = DurableRequestReceipt::new(durable_id, digest, vec![1, 2, 3]).unwrap();
    let tx =
        DurableInvocationTransaction::new(domain(), None, object_changes, receipt, None).unwrap();
    assert_eq!(
        store.commit_invocation(&context(1), tx),
        DurableCommitOutcome::Committed
    );

    // Verify current head is at version 2.
    let head = store
        .get_object_head(&context(1), domain(), coin_id)
        .unwrap();
    match head {
        DurableObjectHead::Current { object_version, .. } => assert_eq!(object_version.get(), 2),
        _ => panic!("expected Current head at version 2"),
    }

    // 3. Restart: verify-only path MUST succeed because version-1 provenance is exact.
    let restart_outcome =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    assert!(matches!(
        restart_outcome,
        GenesisInstallOutcome::VerifiedExisting { .. }
    ));

    // 4. Supply reissue prevented: head is STILL version 2, NOT overwritten or reset to version 1.
    let head_after = store
        .get_object_head(&context(1), domain(), coin_id)
        .unwrap();
    match head_after {
        DurableObjectHead::Current { object_version, .. } => assert_eq!(object_version.get(), 2),
        _ => panic!("expected Current head at version 2 after restart"),
    }
}

#[test]
fn partial_prior_state_fails_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, origin, _, _, coin_id) = build_fixture();

    // Partial case 1: publication record exists without marker.
    let pub_key = publication::publication_record_key(&origin).unwrap();
    let obs = store
        .get_versioned_durable(&context(1), domain(), &pub_key)
        .unwrap();
    let tx = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(pub_key.clone(), obs.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(pub_key, StateMutation::Put(vec![1, 2])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), tx),
        DurableCommitOutcome::Committed
    );

    let err =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        err,
        GenesisError::PartialPriorState("publication")
    ));

    // Partial case 2: object head exists without marker.
    let store2 = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let canonical_bytes = encode_object(&manifest.objects[1].object).unwrap();
    let digest = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
        .unwrap();
    let version = DurableObjectVersionRecord::from_inline_object(
        manifest.objects[1].object.clone(),
        digest,
        DurableObjectProvenance::new(chain(), ProtocolVersion::new(3)),
        10,
    )
    .unwrap();
    let object_changes = DurableObjectChanges::new(
        vec![DurableObjectHeadRead::new(
            coin_id,
            DurableObjectHead::Absent,
        )],
        vec![DurableObjectMutationEntry::new(
            coin_id,
            DurableObjectMutation::Create {
                version,
                owner_projection: DurableObjectOwnerProjection::from_owner(
                    manifest.objects[1].object.owner.clone(),
                )
                .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        )],
    )
    .unwrap();
    let durable_id = DurableRequestId::new([8; 32]).unwrap();
    let receipt = DurableRequestReceipt::new(durable_id, digest, vec![1]).unwrap();
    let tx =
        DurableInvocationTransaction::new(domain(), None, object_changes, receipt, None).unwrap();
    assert_eq!(
        store2.commit_invocation(&context(1), tx),
        DurableCommitOutcome::Committed
    );

    let err2 =
        install_genesis(&store2, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        err2,
        GenesisError::PartialPriorState("object head")
    ));
}

#[test]
fn tombstoned_marker_fails_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, _, _, _, _) = build_fixture();

    let mark_key = genesis_marker_key(&protocol()).unwrap();
    // Put then delete marker.
    let obs0 = store
        .get_versioned_durable(&context(1), domain(), &mark_key)
        .unwrap();
    let tx1 = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(mark_key.clone(), obs0.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(mark_key.clone(), StateMutation::Put(vec![1])).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), tx1),
        DurableCommitOutcome::Committed
    );

    let obs = store
        .get_versioned_durable(&context(1), domain(), &mark_key)
        .unwrap();
    let tx2 = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(mark_key.clone(), obs.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(mark_key, StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), tx2),
        DurableCommitOutcome::Committed
    );

    let err =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(err, GenesisError::TombstonedMarker));
}

#[test]
fn missing_or_tampered_records_fail_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (manifest, origin, _, _, _) = build_fixture();

    install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();

    // 1. Missing record on restart: delete publication record.
    let pub_key = publication::publication_record_key(&origin).unwrap();
    let obs = store
        .get_versioned_durable(&context(1), domain(), &pub_key)
        .unwrap();
    let tx = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(pub_key.clone(), obs.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(pub_key.clone(), StateMutation::Delete).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(1), tx),
        DurableCommitOutcome::Committed
    );

    let err =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        err,
        GenesisError::TamperedInstalledRecord("publication record")
    ));

    // 2. Tampered marker manifest digest.
    let store2 = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    install_genesis(&store2, &context(1), domain(), &resolver(), &manifest, 10).unwrap();

    let mark_key = genesis_marker_key(&protocol()).unwrap();
    let bad_marker = GenesisInstallMarker {
        context: protocol(),
        manifest_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xff; 32]),
        genesis_authority: manifest.genesis_authority,
        installed_at_checkpoint: 10,
    };
    let obs2 = store2
        .get_versioned_durable(&context(1), domain(), &mark_key)
        .unwrap();
    let tx2 = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(mark_key.clone(), obs2.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                mark_key,
                StateMutation::Put(encode_genesis_install_marker(&bad_marker).unwrap()),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store2.commit_durable(&context(1), tx2),
        DurableCommitOutcome::Committed
    );

    let err2 =
        install_genesis(&store2, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(err2, GenesisError::ManifestCommitmentMismatch));

    // 3. The signed static FastVote validator set is part of the exact
    // installed genesis image. A restart must reject any byte-level drift
    // instead of silently accepting a different consensus authority.
    let store3: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    install_genesis(&store3, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    let validator_set_key: Vec<u8> =
        local_instance_state::fastpath_validator_set_key(&protocol()).unwrap();
    let validator_set_observation: VersionedStateValue = store3
        .get_versioned_durable(&context(1), domain(), &validator_set_key)
        .unwrap();
    let mut tampered_validator_set: Vec<u8> = validator_set_observation
        .value()
        .expect("genesis validator set")
        .to_vec();
    let last: &mut u8 = tampered_validator_set
        .last_mut()
        .expect("non-empty validator-set record");
    *last ^= 0x01;
    let tamper_transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(
                validator_set_key.clone(),
                validator_set_observation.revision(),
            )
            .unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                validator_set_key,
                StateMutation::Put(tampered_validator_set),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store3.commit_durable(&context(1), tamper_transaction),
        DurableCommitOutcome::Committed
    );

    let err3 =
        install_genesis(&store3, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        err3,
        GenesisError::TamperedInstalledRecord("fast-path validator set")
    ));

    // 4. The separately persisted economics policy is verified byte-for-byte
    // on restart and cannot be repaired from the still-valid manifest row.
    let store4: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    install_genesis(&store4, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
    let economics_key: Vec<u8> =
        local_instance_state::fastpath_economics_policy_key(&protocol()).unwrap();
    let economics_observation: VersionedStateValue = store4
        .get_versioned_durable(&context(1), domain(), &economics_key)
        .unwrap();
    let mut tampered_economics: Vec<u8> = economics_observation
        .value()
        .expect("genesis economics policy")
        .to_vec();
    *tampered_economics.last_mut().expect("non-empty policy") ^= 0x01;
    let tamper_economics: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(economics_key.clone(), economics_observation.revision())
                .unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(economics_key, StateMutation::Put(tampered_economics)).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store4.commit_durable(&context(1), tamper_economics),
        DurableCommitOutcome::Committed
    );
    let err4: GenesisError =
        install_genesis(&store4, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        err4,
        GenesisError::TamperedInstalledRecord("fast-path economics policy")
    ));
}

#[test]
fn fencing_rejects_stale_writer() {
    // Store fenced at generation 2.
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(2).unwrap());
    let (manifest, _, _, _, _) = build_fixture();

    // Invocation with generation 1 (stale).
    let err =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(
        err,
        GenesisError::DurableRead(DurableReadError::WriterFenced { .. })
            | GenesisError::CommitRejected(DurableCommitRejection::WriterFenced { .. })
    ));
}

#[test]
fn fee_abi_admission_mismatch_fails_closed() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let (mut manifest, _, _, _, _) = build_fixture();

    // Tamper reserve entrypoint so fee interface admission fails.
    manifest.fee_policy.reserve_entrypoint = "unknown_reserve".into();
    manifest.signature = key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();

    let err =
        install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
    assert!(matches!(err, GenesisError::FeeInterfaceAdmission(_)));
}

#[test]
fn signed_economics_policy_fails_closed_on_fee_bond_and_abi_mismatch() {
    let (mut fee_disabled, _, _, _, _) = build_fixture();
    fee_disabled.economics_policy.resources[0].fee_escrow = false;
    resign_manifest(&mut fee_disabled);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &fee_disabled,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("fee resource does not match the signed economics policy")
    ));

    let mut below_minimum: GenesisManifest = manifest_with_custody(ObjectId::new([0x61; 32]));
    below_minimum.economics_policy.resources[0]
        .bond
        .as_mut()
        .unwrap()
        .min_bond = Amount::new(2_000_000);
    resign_manifest(&mut below_minimum);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &below_minimum,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("bond violates the signed economics policy")
    ));

    let (mut unknown_entrypoint, _, _, _, _) = build_fixture();
    unknown_entrypoint.economics_policy.resources[0].split_entrypoint = "unknown_split".to_owned();
    resign_manifest(&mut unknown_entrypoint);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &unknown_entrypoint,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Invalid("economics resource entrypoint is not in the authenticated ABI")
    ));

    let (mut unknown_constructor, _, _, _, _) = build_fixture();
    let mut unused_resource: FastPathEconomicsResourcePolicy =
        unknown_constructor.economics_policy.resources[0].clone();
    let unused_value: [u8; 32] = [0xFF; 32];
    unused_resource.resource_id = BondResourceId::new(7, unused_value).unwrap();
    unused_resource.ty = abi::package_types::ScopedTypeTag::new(
        unused_resource.ty.origin().clone(),
        u16::MAX,
        vec![abi::package_types::ScopedTypeArg::Opaque {
            domain: 7,
            value: unused_value,
        }],
    )
    .unwrap();
    unused_resource.bond = None;
    unused_resource.fee_escrow = true;
    unknown_constructor
        .economics_policy
        .resources
        .push(unused_resource);
    unknown_constructor
        .economics_policy
        .resources
        .sort_by_key(|resource: &FastPathEconomicsResourcePolicy| resource.resource_id);
    resign_manifest(&mut unknown_constructor);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &unknown_constructor,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Body(BodyError::Binding(BindingError::UnknownConstructor))
    ));

    let (mut wrong_schema, _, _, _, _) = build_fixture();
    wrong_schema.economics_policy.resources[0].schema += 1;
    resign_manifest(&mut wrong_schema);
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let error: GenesisError = install_genesis(
        &store,
        &context(1),
        domain(),
        &resolver(),
        &wrong_schema,
        10,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        GenesisError::Body(BodyError::Binding(BindingError::SchemaMismatch))
    ));
}

#[test]
fn file_backed_sqlite_fresh_install_restart_mutation_and_fencing() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("genesis-durable-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("state.sqlite");
    let namespace = SqliteNamespace::new(chain(), ValidatorId::new([4; 32]), domain());

    let (mut manifest, _, _, _, coin_id) = build_fixture();
    let custody_id: ObjectId = ObjectId::new([0x32; 32]);
    manifest
        .objects
        .push(custody_object_entry(&manifest, custody_id, chain()));
    manifest.signature = key()
        .sign(&genesis_manifest_signing_frame(&manifest).unwrap())
        .into();
    let bond_key: Vec<u8> =
        fastpath_bond_record_key(&chain(), &ValidatorId::new(sender())).unwrap();
    let fresh_bond_bytes: Vec<u8>;

    // 1. Fresh install on file-backed SQLite with generation 1.
    {
        let store = SqliteDurableStore::open(
            &db_path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let outcome =
            install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
        assert!(matches!(
            outcome,
            GenesisInstallOutcome::FreshInstall { .. }
        ));
        assert!(matches!(
            store
                .get_object_head(&context(1), domain(), custody_id)
                .unwrap(),
            DurableObjectHead::Current { .. }
        ));
        fresh_bond_bytes = store
            .get_versioned_durable(&context(1), domain(), &bond_key)
            .unwrap()
            .value()
            .expect("fresh SQLite bond record")
            .to_vec();
        let bond: FastPathBondRecord = decode_fastpath_bond_record(&fresh_bond_bytes).unwrap();
        assert_eq!(bond.validator_id, ValidatorId::new(sender()));
        assert_eq!(bond.custody_object.id, custody_id);
        assert_eq!(bond.amount, 1_000_000);
    }

    // 2. Reopen and verify-only restart.
    {
        let store = SqliteDurableStore::open(
            &db_path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let restart_outcome =
            install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
        assert!(matches!(
            restart_outcome,
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));
        assert!(matches!(
            store
                .get_object_head(&context(1), domain(), custody_id)
                .unwrap(),
            DurableObjectHead::Current { .. }
        ));
        let reopened_bond_bytes: Vec<u8> = store
            .get_versioned_durable(&context(1), domain(), &bond_key)
            .unwrap()
            .value()
            .expect("reopened SQLite bond record")
            .to_vec();
        assert_eq!(reopened_bond_bytes, fresh_bond_bytes);
    }

    // 3. Mutate coin object to version 2 on SQLite.
    {
        let store = SqliteDurableStore::open(
            &db_path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let mutated_coin_data = encode_call_value(
            &public_standard_asset::coin_body_layout(),
            &CallValue::U64(250_000),
        )
        .unwrap();
        let mutated_coin = Object {
            id: coin_id,
            version: 2,
            owner: Owner::Address(Address::new(sender())),
            type_hash: manifest.objects[1].object.type_hash,
            schema_version: public_standard_asset::SCHEMA_VERSION,
            data: mutated_coin_data,
        };
        let canonical_bytes = encode_object(&mutated_coin).unwrap();
        let digest = resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, &canonical_bytes)
            .unwrap();
        let version_two_record = DurableObjectVersionRecord::from_inline_object(
            mutated_coin.clone(),
            digest,
            DurableObjectProvenance::new(chain(), ProtocolVersion::new(3)),
            25,
        )
        .unwrap();

        let head_read = DurableObjectHeadRead::new(
            coin_id,
            store
                .get_object_head(&context(1), domain(), coin_id)
                .unwrap(),
        );
        let update_mutation = DurableObjectMutationEntry::new(
            coin_id,
            DurableObjectMutation::Update {
                version: version_two_record,
                owner_projection: DurableObjectOwnerProjection::from_owner(
                    mutated_coin.owner.clone(),
                )
                .unwrap(),
                routing_projection: DurableObjectRoutingProjection::default(),
            },
        );
        let object_changes =
            DurableObjectChanges::new(vec![head_read], vec![update_mutation]).unwrap();

        let durable_id = DurableRequestId::new([7; 32]).unwrap();
        let receipt = DurableRequestReceipt::new(durable_id, digest, vec![1, 2]).unwrap();
        let tx = DurableInvocationTransaction::new(domain(), None, object_changes, receipt, None)
            .unwrap();
        assert_eq!(
            store.commit_invocation(&context(1), tx),
            DurableCommitOutcome::Committed
        );
    }

    // 4. Reopen and verify restart still succeeds and head is STILL version 2 (supply reissue prevented).
    {
        let store = SqliteDurableStore::open(
            &db_path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        let restart_outcome =
            install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap();
        assert!(matches!(
            restart_outcome,
            GenesisInstallOutcome::VerifiedExisting { .. }
        ));

        let head = store
            .get_object_head(&context(1), domain(), coin_id)
            .unwrap();
        match head {
            DurableObjectHead::Current { object_version, .. } => {
                assert_eq!(object_version.get(), 2)
            }
            _ => panic!("expected Current head at version 2 on SQLite"),
        }
    }

    // 5. Advance writer fence to generation 2: attempt install with generation 1 (stale) fails with fencing.
    {
        let store =
            SqliteDurableStore::open(&db_path, namespace, WriterFenceGeneration::new(1).unwrap())
                .unwrap();
        store
            .advance_writer_fence(
                WriterFenceGeneration::new(1).unwrap(),
                WriterFenceGeneration::new(2).unwrap(),
            )
            .unwrap();
        let err =
            install_genesis(&store, &context(1), domain(), &resolver(), &manifest, 10).unwrap_err();
        assert!(matches!(
            err,
            GenesisError::DurableRead(DurableReadError::WriterFenced { .. })
                | GenesisError::CommitRejected(DurableCommitRejection::WriterFenced { .. })
        ));
    }
}
