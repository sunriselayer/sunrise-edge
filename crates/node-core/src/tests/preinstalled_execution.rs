#[test]
fn strict_profile_rejects_inadmissible_destination_and_treasury_owners() {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let sender: Address = dev_sender_address(&dev_signing_key(0x41));
    let mut universal_owner_bytes: [u8; 32] = [0; 32];
    universal_owner_bytes[0] = 1;
    universal_owner_bytes[31] = 0x80;
    let universal_owner: Address = Address::new(universal_owner_bytes);
    let (source_ref, _source_head) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x42; 32]),
        Owner::Address(sender),
        0x30,
    );
    let destination_id: ObjectId = ObjectId::new([0x43; 32]);
    let (destination_ref, _destination_head) = preload_inline_object(
        &store,
        "sunrise-test",
        destination_id,
        Owner::Address(universal_owner),
        0x31,
    );
    let dispatch = AuthenticatedObjectDispatch {
        authority: sender,
        owner_address_policy: Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
        accesses: vec![
            AuthenticatedObjectAccess {
                object_ref: source_ref,
                mode: AccessMode::Write,
            },
            AuthenticatedObjectAccess {
                object_ref: destination_ref,
                mode: AccessMode::Write,
            },
        ],
    };
    let policy: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        Digest32::new(HashAlgorithmId::Sha2_256, [0x32; 32]),
        0x31,
    )
    .unwrap();
    let envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::new(b"test".to_vec(), vec![policy]).unwrap();
    let authorization = ResolvedPreinstalledAuthorization {
        entrypoint: "run",
        envelope: &envelope,
    };
    for treasury_object_id in [None, Some(destination_id)] {
        assert_eq!(
            load_and_authorize_objects(
                &store,
                &MemoryBlobStore::default(),
                &durable_context(),
                domain(0x44),
                &ChainId::new("sunrise-test").unwrap(),
                &dispatch,
                Some(&authorization),
                treasury_object_id,
            ),
            Err(NodeCoreError::InadmissibleObjectOwnerAddress {
                object_id: destination_id,
                source: Ed25519OwnerAddressError::NonCanonicalPoint,
            })
        );
    }
}

#[test]
fn typed_entrypoint_rejects_mismatch_before_wasm_execution() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let sender: Address = Address::new([0x31; 32]);
    let object_id: ObjectId = ObjectId::new([0x32; 32]);
    let mut object: Object =
        owner_transition_object(&hash_resolver, Epoch::new(7), object_id, sender, vec![0x33]);
    object.type_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xFF; 32]);
    let module_id: ModuleId = ModuleId::new([0x34; 32]);
    // Invalid WASM bytes make the ordering observable: reaching the
    // engine would return an execution error instead of this ABI error.
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        vec![0xFF],
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    let transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref: sample_object_ref(0x32),
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(Address::new([0x35; 32])),
    );
    let registered: &SystemModule = registry.get(module_id, 1).unwrap();
    let fee_policy: CommittedFeePolicy = zero_fee_policy();
    let machine = PreinstalledWasmMachine {
        transaction: &transaction,
        resolver: &hash_resolver,
        registered_module: Some(registered),
        catalog: &catalog,
        engine: &WasmExecutionEngine,
        fee_policy: &fee_policy,
        fee_composition: None,
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    let state = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object,
            mode: AccessMode::Write,
        }],
    };

    assert!(matches!(
        machine.transition(&state, &submit_event_for_protocol(protocol_version, 0x36)),
        Err(NodeCoreError::TypedAbi(
            abi::AbiError::TypeIdentityMismatch { .. }
        ))
    ));
}

#[test]
fn owner_transition_v3_rejects_before_wasm_execution() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(3);
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let sender: Address = Address::new([0x37; 32]);
    let object: Object = owner_transition_object(
        &hash_resolver,
        Epoch::new(7),
        ObjectId::new([0x38; 32]),
        sender,
        vec![0x39],
    );
    let module_id: ModuleId = ModuleId::new([0x3A; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        vec![0xFF],
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    let transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref: sample_object_ref(0x38),
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(Address::new([0x3B; 32])),
    );
    let registered: &SystemModule = registry.get(module_id, 1).unwrap();
    let fee_policy: CommittedFeePolicy = zero_fee_policy();
    let machine = PreinstalledWasmMachine {
        transaction: &transaction,
        resolver: &hash_resolver,
        registered_module: Some(registered),
        catalog: &catalog,
        engine: &WasmExecutionEngine,
        fee_policy: &fee_policy,
        fee_composition: None,
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    let state = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object,
            mode: AccessMode::Write,
        }],
    };

    assert_eq!(
        machine
            .transition(&state, &submit_event_for_protocol(protocol_version, 0x3C))
            .unwrap_err(),
        NodeCoreError::OwnerTransitionProtocolVersionTooLow {
            actual: protocol_version,
            minimum: ProtocolVersion::new(4),
        }
    );
}

#[test]
fn owner_transition_rejects_module_effect_for_transferred_object() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let sender: Address = Address::new([0x3D; 32]);
    let object_id: ObjectId = ObjectId::new([0x3E; 32]);
    let object: Object =
        owner_transition_object(&hash_resolver, Epoch::new(7), object_id, sender, vec![0x3F]);
    let module_id: ModuleId = ModuleId::new([0x40; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    let transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref: sample_object_ref(0x3E),
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(Address::new([0x41; 32])),
    );
    let registered: &SystemModule = registry.get(module_id, 1).unwrap();
    let fee_policy: CommittedFeePolicy = zero_fee_policy();
    let machine = PreinstalledWasmMachine {
        transaction: &transaction,
        resolver: &hash_resolver,
        registered_module: Some(registered),
        catalog: &catalog,
        engine: &WasmExecutionEngine,
        fee_policy: &fee_policy,
        fee_composition: None,
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    let state = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object,
            mode: AccessMode::Write,
        }],
    };

    assert_eq!(
        machine
            .transition(&state, &submit_event_for_protocol(protocol_version, 0x42))
            .unwrap_err(),
        NodeCoreError::OwnerTransitionObjectEffectForbidden { object_id }
    );
}

#[test]
fn owner_transition_rejects_fee_payer_and_treasury_aliases() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let sender: Address = Address::new([0x43; 32]);
    let object_id: ObjectId = ObjectId::new([0x44; 32]);
    let object: Object =
        owner_transition_object(&hash_resolver, Epoch::new(7), object_id, sender, vec![0x45]);
    let module_id: ModuleId = ModuleId::new([0x46; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    let object_ref: ObjectRef = ObjectRef {
        id: object_id,
        version: object.version,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x47; 32]),
    };
    let base_transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref: object_ref.clone(),
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(Address::new([0x48; 32])),
    );
    let state = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object,
            mode: AccessMode::Write,
        }],
    };
    let effects = ExecutionEffects {
        tx_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x49; 32]),
        status: ExecutionStatus::Success,
        object_effects: Vec::new(),
        events: Vec::new(),
        gas_used: 0,
    };
    let registered: &SystemModule = registry.get(module_id, 1).unwrap();
    let catalog_entry: &PreinstalledModuleCatalogEntry = catalog.get(module_id, 1).unwrap();
    let fee_policy: CommittedFeePolicy = zero_fee_policy();

    let mut payer_transaction: Transaction = base_transaction.clone();
    payer_transaction.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(1),
        fee_object: object_ref,
    });
    let payer_machine = PreinstalledWasmMachine {
        transaction: &payer_transaction,
        resolver: &hash_resolver,
        registered_module: Some(registered),
        catalog: &catalog,
        engine: &WasmExecutionEngine,
        fee_policy: &fee_policy,
        fee_composition: None,
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    assert_eq!(
        payer_machine
            .synthesize_owner_transition(catalog_entry, &state, &effects)
            .err(),
        Some(NodeCoreError::OwnerTransitionFeeObjectAlias { object_id })
    );

    let composer: RecordingFeeComposer = RecordingFeeComposer::new();
    let treasury_machine = PreinstalledWasmMachine {
        transaction: &base_transaction,
        resolver: &hash_resolver,
        registered_module: Some(registered),
        catalog: &catalog,
        engine: &WasmExecutionEngine,
        fee_policy: &fee_policy,
        fee_composition: Some(PreinstalledFeeComposition::new(object_id, &composer)),
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    assert_eq!(
        treasury_machine
            .synthesize_owner_transition(catalog_entry, &state, &effects)
            .err(),
        Some(NodeCoreError::OwnerTransitionFeeObjectAlias { object_id })
    );
}

#[test]
fn owner_transition_v4_receipt_and_committed_mutation_match_exactly() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let epoch: Epoch = Epoch::new(7);
    let object_domain: AtomicityDomainId = domain(0x4A);
    let node_config: NodeConfig = NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        b"node/state".to_vec(),
    )
    .unwrap();
    let mut protocol_config: ProtocolConfig = active_protocol_config(0x4A);
    protocol_config.protocol_version = protocol_version;
    let signing_key: SigningKey = dev_signing_key(0x4A);
    let sender: Address = dev_sender_address(&signing_key);
    let recipient: Address = dev_sender_address(&dev_signing_key(0x4B));
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let module_id: ModuleId = ModuleId::new([0x4C; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        256,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    protocol_config.system_modules = registry;

    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context: DurableOperationContext = durable_context();
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();
    let object_id: ObjectId = ObjectId::new([0x4D; 32]);
    let original: Object =
        owner_transition_object(&hash_resolver, epoch, object_id, sender, vec![0x4E, 0x4F]);
    let object_ref: ObjectRef = commit_memory_inline_object_with_protocol_version(
        &store,
        &context,
        object_domain,
        original.clone(),
        "sunrise-test",
        protocol_version,
        9,
        0x50,
    );
    let transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(recipient),
    );
    let request_id: RequestId = request(0x51);
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request_id,
        &signing_key,
        epoch,
        transaction,
        &node_config,
        &protocol_config,
    );

    let resolved: ResolvedNodeOutput =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &WasmExecutionEngine,
            submission,
            10,
            None,
        )
        .unwrap();
    let response: &NodeResponse = &resolved.output().responses()[0];
    assert_eq!(response.status(), NodeResponseStatus::Accepted);
    let receipt_effects: ExecutionEffects =
        execution::decode_execution_effects(response.payload().unwrap()).unwrap();
    assert_eq!(receipt_effects.object_effects.len(), 1);
    let ObjectEffect::Mutated {
        previous_version,
        new_object,
    } = &receipt_effects.object_effects[0]
    else {
        panic!("owner transition receipt did not contain one mutation");
    };
    assert_eq!(*previous_version, 1);
    assert_eq!(new_object.id, object_id);
    assert_eq!(new_object.version, 2);
    assert_eq!(new_object.owner, Owner::Address(recipient));
    assert_eq!(new_object.data, original.data);
    assert_eq!(new_object.type_hash, original.type_hash);
    assert_eq!(new_object.schema_version, original.schema_version);

    let committed: DurableObjectVersionRecord = store
        .get_object_version(
            &context,
            object_domain,
            object_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(committed_object(&committed, &blob_store), *new_object);

    let persisted_receipt: ReceiptQueryResult =
        query_request_receipt(&store, &context, object_domain, request_id).unwrap();
    let ReceiptQueryResult::Present { record, .. } = persisted_receipt else {
        panic!("accepted owner transition receipt was not persisted");
    };
    assert_eq!(record.responses()[0].payload(), response.payload());
}

/// Proves the index-space invariant documented on
/// [`PreinstalledOwnerTransitionPolicy`] and DR-0106: with a signed
/// manifest of *three* declared accesses (transferred object, a distinct
/// fee payer, and the fee treasury as the final entry) but the treasury
/// hidden from engine visibility, `transferred_access_index = 0` still
/// resolves to the intended object rather than silently drifting once a
/// third manifest entry is introduced.
#[test]
fn owner_transition_index_unaffected_by_hidden_final_treasury() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let epoch: Epoch = Epoch::new(7);
    let object_domain: AtomicityDomainId = domain(0x53);
    let node_config: NodeConfig = NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        b"node/state".to_vec(),
    )
    .unwrap();
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x53);
    protocol_config.protocol_version = protocol_version;
    let signing_key: SigningKey = dev_signing_key(0x53);
    let sender: Address = dev_sender_address(&signing_key);
    let recipient: Address = dev_sender_address(&dev_signing_key(0x54));
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);

    // Two Write params, matching the two engine-visible resolved objects
    // once the treasury is hidden: index 0 is the transferred object,
    // index 1 is the distinct fee payer.
    let constructor: ConstructorDeclaration = ConstructorDeclaration {
        id: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
        body_type_id: OWNER_TRANSITION_BODY_TYPE_ID,
        body_version: 1,
        schema_version: 1,
        arity: TypeArity::Fixed,
        projection: Vec::new(),
    };
    let signature: EntrypointSignature = EntrypointSignature::new(
        "run".to_string(),
        vec![
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
                schema_version: 1,
            },
            ParamDeclaration {
                mode: AccessMode::Write,
                constructor: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
                schema_version: 1,
            },
        ],
    )
    .unwrap();
    let typed: PreinstalledTypedEntrypointPolicy =
        PreinstalledTypedEntrypointPolicy::new(vec![constructor], signature).unwrap();
    let owner: PreinstalledOwnerTransitionPolicy = PreinstalledOwnerTransitionPolicy::new(
        "run".to_string(),
        0,
        OWNER_TRANSITION_ARGS_TYPE_ID,
        1,
        1,
    )
    .unwrap();
    let envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::with_typed_policies(
            b"owner-transition-hidden-treasury-test".to_vec(),
            Vec::new(),
            vec![typed],
            vec![owner],
        )
        .unwrap();

    let module_id: ModuleId = ModuleId::new([0x55; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        256,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        envelope,
    );
    protocol_config.system_modules = registry;

    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context: DurableOperationContext = durable_context();
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();

    let object_id: ObjectId = ObjectId::new([0x56; 32]);
    let original: Object =
        owner_transition_object(&hash_resolver, epoch, object_id, sender, vec![0x57, 0x58]);
    let object_ref: ObjectRef = commit_memory_inline_object_with_protocol_version(
        &store,
        &context,
        object_domain,
        original.clone(),
        "sunrise-test",
        protocol_version,
        9,
        0x59,
    );

    let payer_id: ObjectId = ObjectId::new([0x5A; 32]);
    let payer_object: Object =
        owner_transition_object(&hash_resolver, epoch, payer_id, sender, vec![0x5B]);
    let payer_ref: ObjectRef = commit_memory_inline_object_with_protocol_version(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        protocol_version,
        9,
        0x5C,
    );

    let treasury_owner: Address = Address::new([0x5D; 32]);
    let treasury_id: ObjectId = ObjectId::new([0x5E; 32]);
    let mut treasury_object: Object =
        test_object(treasury_id, 1, Owner::Address(treasury_owner), 0x5E);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object_with_protocol_version(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        protocol_version,
        9,
        0x5F,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: object_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        0,
        manifest,
        module_ref,
        owner_transition_args(recipient),
    );
    transaction.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });

    let request_id: RequestId = request(0x60);
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request_id,
        &signing_key,
        epoch,
        transaction,
        &node_config,
        &protocol_config,
    );

    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);
    let resolved: ResolvedNodeOutput =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &WasmExecutionEngine,
            submission,
            10,
            Some(fee_composition),
        )
        .unwrap();

    let response: &NodeResponse = &resolved.output().responses()[0];
    assert_eq!(response.status(), NodeResponseStatus::Accepted);
    let receipt_effects: ExecutionEffects =
        execution::decode_execution_effects(response.payload().unwrap()).unwrap();
    // The owner-transition target (transferred index 0) is the only
    // application effect: it is unaffected by the fee payer/treasury
    // entries appended after it in the signed manifest.
    assert_eq!(receipt_effects.object_effects.len(), 1);
    let ObjectEffect::Mutated { new_object, .. } = &receipt_effects.object_effects[0] else {
        panic!("owner transition receipt did not contain one mutation");
    };
    assert_eq!(new_object.id, object_id);
    assert_eq!(new_object.owner, Owner::Address(recipient));
    assert_eq!(new_object.data, original.data);

    // The distinct fee payer (engine-visible typed parameter 1) and the
    // hidden treasury were still separately debited/credited: the
    // hidden-from-engine treasury access did not simply vanish.
    assert!(
        store
            .get_object_version(
                &context,
                object_domain,
                payer_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .is_some(),
        "fee payer must have been separately debited"
    );
    let committed_treasury: DurableObjectVersionRecord = store
        .get_object_version(
            &context,
            object_domain,
            treasury_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&committed_treasury, &blob_store).data,
        vec![0x00, 0xF1]
    );
}

#[test]
fn owner_transition_inadmissible_recipient_commits_nothing() {
    let protocol_version: ProtocolVersion = ProtocolVersion::new(4);
    let epoch: Epoch = Epoch::new(7);
    let object_domain: AtomicityDomainId = domain(0x52);
    let node_config: NodeConfig = NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        b"node/state".to_vec(),
    )
    .unwrap();
    let mut protocol_config: ProtocolConfig = active_protocol_config(0x52);
    protocol_config.protocol_version = protocol_version;
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    let signing_key: SigningKey = dev_signing_key(0x52);
    let sender: Address = dev_sender_address(&signing_key);
    let mut recipient_bytes: [u8; 32] = [0; 32];
    recipient_bytes[0] = 1;
    recipient_bytes[31] = 0x80;
    let inadmissible_recipient: Address = Address::new(recipient_bytes);
    let hash_resolver: HashSuiteResolver = resolver_for_protocol("sunrise-test", protocol_version);
    let module_id: ModuleId = ModuleId::new([0x53; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        256,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        owner_transition_envelope(),
    );
    protocol_config.system_modules = registry;

    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let context: DurableOperationContext = durable_context();
    let object_id: ObjectId = ObjectId::new([0x54; 32]);
    let object: Object =
        owner_transition_object(&hash_resolver, epoch, object_id, sender, vec![0x55]);
    let object_ref: ObjectRef = commit_memory_inline_object_with_protocol_version(
        &store,
        &context,
        object_domain,
        object,
        "sunrise-test",
        protocol_version,
        9,
        0x56,
    );
    let transaction: Transaction = preinstalled_transaction_with_protocol_version(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        epoch,
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        }]),
        module_ref,
        owner_transition_args(inadmissible_recipient),
    );
    let submission: AuthenticatedSubmitTransaction =
        authenticated_profile_2_submission_from_transaction(
            "sunrise-test",
            request(0x57),
            &signing_key,
            epoch,
            transaction,
            &node_config,
            &protocol_config,
        );

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &WasmExecutionEngine,
            submission,
            10,
            None,
        )
        .unwrap_err();
    assert_eq!(
        error,
        NodeCoreError::InadmissibleObjectOutputOwnerAddress {
            object_id,
            source: Ed25519OwnerAddressError::NonCanonicalPoint,
        }
    );
    assert!(
        store
            .get_object_version(
                &context,
                object_domain,
                object_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        query_request_receipt(&store, &context, object_domain, request(0x57)).unwrap(),
        ReceiptQueryResult::Absent {
            request_id: request(0x57)
        }
    );
}

#[test]
fn preinstalled_wasm_owned_write_commits_object_nonce_and_receipt() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xFD);
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    let signing_key: SigningKey = dev_signing_key(0xDA);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xFD);
    let module_id = ModuleId::new([0x70; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0x95; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0x95),
        "sunrise-test",
        9,
        0x3A,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction =
        authenticated_profile_2_submission_from_transaction(
            "sunrise-test",
            request(0xF0),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
    let engine = WasmExecutionEngine;
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();

    assert_eq!(resolved.output().responses().len(), 1);
    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    assert!(resolved.output().responses()[0].payload().is_some());
    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
    let write_v2: DurableObjectVersionRecord = store
        .get_object_version(
            &context,
            object_domain,
            write_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    let committed_write: Object = committed_object(&write_v2, &blob_store);
    assert_eq!(committed_write.owner, Owner::Address(sender));
    assert_eq!(committed_write.data, vec![0xCA, 0xFE]);
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce: VersionedStateValue = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record: SenderNonceRecord =
        SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

/// DR-0131 criterion 4: the preinstalled-WASM `SubmitTransaction` entrypoint
/// rejects a request bound to a non-current epoch at the shared durable
/// boundary, before durable module/object work or mutation. The precise
/// `EpochMismatch`, unchanged object version, and absent receipt pin that
/// entrypoint-level contract without adding a test-only execution engine to
/// the concrete preinstalled-WASM API.
#[test]
fn preinstalled_wasm_rejects_a_wrong_current_epoch_before_any_execution_or_mutation() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xF3);
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    let signing_key: SigningKey = dev_signing_key(0xE9);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xF3);
    let module_id = ModuleId::new([0x73; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0x98; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0x98),
        "sunrise-test",
        9,
        0x3D,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction =
        authenticated_profile_2_submission_from_transaction(
            "sunrise-test",
            request(0xF3),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &protocol_config,
        );
    // Overrides `commit_memory_inline_object`'s own installed epoch record
    // (Epoch::new(7)), simulating a Slice-2 transition this DR does not
    // implement.
    commit_fastpath_epoch_record(
        &store,
        &context,
        object_domain,
        "sunrise-test",
        Epoch::new(8),
    );
    let engine = WasmExecutionEngine;
    let blob_store: MemoryBlobStore = MemoryBlobStore::default();

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();
    assert_eq!(
        error,
        NodeCoreError::EpochMismatch {
            expected: Epoch::new(8),
            actual: Epoch::new(7),
        }
    );
    assert!(
        store
            .get_object_version(
                &context,
                object_domain,
                write_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        query_request_receipt(&store, &context, object_domain, request(0xF3)).unwrap(),
        ReceiptQueryResult::Absent {
            request_id: request(0xF3)
        }
    );
}

#[test]
fn preinstalled_wasm_committed_policy_allows_exact_cross_owner_destination_write() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xD1);
    let signing_key: SigningKey = dev_signing_key(0xD1);
    let sender: Address = dev_sender_address(&signing_key);
    let recipient: Address = Address::new([0xD2; 32]);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xD1);
    let module_id: ModuleId = ModuleId::new([0xD3; 32]);
    let destination_byte: u8 = 0x21;
    let policy: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        Digest32::new(
            HashAlgorithmId::Sha2_256,
            [destination_byte.wrapping_add(1); 32],
        ),
        u32::from(destination_byte),
    )
    .unwrap();
    let envelope: PreinstalledModuleSemanticsEnvelope = PreinstalledModuleSemanticsEnvelope::new(
        b"two-object-transfer-test".to_vec(),
        vec![policy],
    )
    .unwrap();
    let (registry, catalog, module_ref) = preinstalled_module_fixture_with_envelope(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_two_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
        envelope,
    );
    protocol_config.system_modules = registry;

    let source_id: ObjectId = ObjectId::new([0xD4; 32]);
    let destination_id: ObjectId = ObjectId::new([0xD5; 32]);
    let source_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(source_id, 1, Owner::Address(sender), 0x20),
        "sunrise-test",
        9,
        0xD4,
    );
    let destination_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(
            destination_id,
            1,
            Owner::Address(recipient),
            destination_byte,
        ),
        "sunrise-test",
        9,
        0xD5,
    );
    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: source_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: destination_ref,
            mode: AccessMode::Write,
        },
    ]);
    let transaction: Transaction = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xD6),
        &signing_key,
        Epoch::new(7),
        transaction,
        &node_config,
        &protocol_config,
    );

    let blob_store: MemoryBlobStore = MemoryBlobStore::default();
    let resolved: ResolvedNodeOutput =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &blob_store,
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &WasmExecutionEngine,
            submission,
            10,
            None,
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    for (object_id, expected_owner) in [(source_id, sender), (destination_id, recipient)] {
        let record: DurableObjectVersionRecord = store
            .get_object_version(
                &context,
                object_domain,
                object_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .unwrap();
        let object: Object = committed_object(&record, &blob_store);
        assert_eq!(object.owner, Owner::Address(expected_owner));
        assert_eq!(object.data, vec![0xCA, 0xFE]);
    }
}

#[test]
fn preinstalled_cross_owner_policy_rejects_wrong_position_entrypoint_mode_type_and_schema() {
    let expected_type: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x32; 32]);
    let exact_policy = || {
        PreinstalledObjectAccessPolicy::new(
            1,
            "run".to_string(),
            AccessMode::Write,
            expected_type,
            0x31,
        )
        .unwrap()
    };

    assert!(
        load_cross_owner_destination_with_policy(
            Some(exact_policy()),
            "run",
            AccessMode::Write,
            Owner::Address(Address::new([0x99; 32])),
            true,
        )
        .is_ok()
    );

    let wrong_position: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        2,
        "run".to_string(),
        AccessMode::Write,
        expected_type,
        0x31,
    )
    .unwrap();
    let wrong_type: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        Digest32::new(HashAlgorithmId::Sha2_256, [0xFF; 32]),
        0x31,
    )
    .unwrap();
    let wrong_schema: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        expected_type,
        0x32,
    )
    .unwrap();
    let cases: Vec<(Option<PreinstalledObjectAccessPolicy>, &str, AccessMode)> = vec![
        (None, "run", AccessMode::Write),
        (Some(wrong_position), "run", AccessMode::Write),
        (Some(exact_policy()), "other", AccessMode::Write),
        (Some(exact_policy()), "run", AccessMode::Consume),
        (Some(wrong_type), "run", AccessMode::Write),
        (Some(wrong_schema), "run", AccessMode::Write),
    ];
    for (policy, entrypoint, mode) in cases {
        assert!(matches!(
            load_cross_owner_destination_with_policy(
                policy,
                entrypoint,
                mode,
                Owner::Address(Address::new([0x99; 32])),
                true,
            ),
            Err(NodeCoreError::ObjectOwnerMismatch { .. })
        ));
    }
}

#[test]
fn preinstalled_cross_owner_policy_never_authorizes_non_address_owner_kinds() {
    let policy: PreinstalledObjectAccessPolicy = PreinstalledObjectAccessPolicy::new(
        1,
        "run".to_string(),
        AccessMode::Write,
        Digest32::new(HashAlgorithmId::Sha2_256, [0x32; 32]),
        0x31,
    )
    .unwrap();
    for owner in [Owner::Shared, Owner::System, Owner::Immutable] {
        assert!(matches!(
            load_cross_owner_destination_with_policy(
                Some(policy.clone()),
                "run",
                AccessMode::Write,
                owner,
                true,
            ),
            Err(NodeCoreError::ObjectOwnerKindUnsupported { .. })
        ));
    }

    assert!(matches!(
        load_cross_owner_destination_with_policy(
            Some(policy),
            "run",
            AccessMode::Write,
            Owner::Address(Address::new([0x99; 32])),
            false,
        ),
        Err(NodeCoreError::ObjectOwnerMismatch { .. })
    ));
}

#[test]
fn preinstalled_wasm_exact_replay_does_not_reexecute_or_reapply() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xFE);
    let signing_key: SigningKey = dev_signing_key(0xDB);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xFE);
    let module_id = ModuleId::new([0x71; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0x96; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0x96),
        "sunrise-test",
        9,
        0x3B,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xF1),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let replay_submission: AuthenticatedSubmitTransaction = submission.clone();
    let engine = WasmExecutionEngine;

    let first =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();
    // An empty catalog and a different composition-trusted checkpoint on
    // replay prove that the persisted receipt short-circuits before module
    // resolution, object load, checkpoint validation, or execution.
    let empty_catalog: PreinstalledModuleCatalog =
        PreinstalledModuleCatalog::new(Vec::new()).unwrap();
    let replay =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &empty_catalog,
            &engine,
            replay_submission,
            999,
            None,
        )
        .unwrap();

    assert_eq!(first, replay);
    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
    assert!(
        store
            .get_object_version(
                &context,
                object_domain,
                write_id,
                DurableObjectVersion::new(3).unwrap(),
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn preinstalled_wasm_rejects_unknown_inactive_and_not_yet_active_module_before_commit() {
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xFF);
    let signing_key: SigningKey = dev_signing_key(0xDC);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x72; 32]);
    let engine = WasmExecutionEngine;

    // Unknown: empty registry, nonempty catalog.
    let (_, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let empty_registry = SystemModuleRegistry::new();
    let run_case = |registry: &SystemModuleRegistry,
                    catalog: &PreinstalledModuleCatalog,
                    module_ref: ObjectRef,
                    request_byte: u8|
     -> (NodeCoreError, usize) {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let (object_ref, _) = preload_inline_object(
            &store,
            "sunrise-test",
            ObjectId::new([request_byte; 32]),
            Owner::Address(sender),
            request_byte,
        );
        let manifest = manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission = authenticated_submission_from_transaction(
            "sunrise-test",
            request(request_byte),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &{
                let mut committed_config: ProtocolConfig = protocol_config.clone();
                committed_config.system_modules = registry.clone();
                committed_config
            },
        );
        let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
&MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();
        (error, store.commits.lock().unwrap().len())
    };

    let (error, commits) = run_case(&empty_registry, &catalog, module_ref.clone(), 0xA0);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleUnknown {
            module_id,
            version: 1
        }
    );
    assert_eq!(commits, 0);

    // Pending (not yet activated / not Active): registry has the module,
    // but its status is Pending.
    let (pending_registry, _, pending_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        2,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Pending,
    );
    let pending_entry = PreinstalledModuleCatalogEntry::new(
        module_id,
        2,
        preinstalled_write_wasm_bytes(),
        preinstalled_manifest(module_id, 64),
        PreinstalledModuleSemanticsEnvelope::opaque_only(b"test-semantics-v1".to_vec()).unwrap(),
    )
    .unwrap();
    let pending_catalog = PreinstalledModuleCatalog::new(vec![pending_entry]).unwrap();
    let (error, commits) = run_case(&pending_registry, &pending_catalog, pending_ref, 0xA1);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleInactive {
            module_id,
            version: 2
        }
    );
    assert_eq!(commits, 0);

    // Active but not yet activated at the transaction's epoch (7).
    let (future_registry, future_catalog, future_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        3,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(8),
        system_modules::ModuleStatus::Active,
    );
    let (error, commits) = run_case(&future_registry, &future_catalog, future_ref, 0xA2);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleNotYetActive {
            module_id,
            version: 3,
            activation_epoch: Epoch::new(8),
            current_epoch: Epoch::new(7),
        }
    );
    assert_eq!(commits, 0);
}

#[test]
fn preinstalled_wasm_rejects_reference_digest_code_manifest_and_semantics_mismatch_before_commit() {
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xF6);
    let signing_key: SigningKey = dev_signing_key(0xDD);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let engine = WasmExecutionEngine;

    let run_case = |registry: SystemModuleRegistry,
                    catalog: PreinstalledModuleCatalog,
                    module_ref: ObjectRef,
                    request_byte: u8|
     -> (NodeCoreError, usize) {
        let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let (object_ref, _) = preload_inline_object(
            &store,
            "sunrise-test",
            ObjectId::new([request_byte; 32]),
            Owner::Address(sender),
            request_byte,
        );
        let manifest = manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]);
        let tx = preinstalled_transaction(
            sender,
            ChainId::new("sunrise-test").unwrap(),
            Epoch::new(7),
            0,
            manifest,
            module_ref,
            vec![1, 2],
        );
        let submission = authenticated_submission_from_transaction(
            "sunrise-test",
            request(request_byte),
            &signing_key,
            Epoch::new(7),
            tx,
            &node_config,
            &{
                let mut committed_config: ProtocolConfig = protocol_config.clone();
                committed_config.system_modules = registry.clone();
                committed_config
            },
        );
        let error = handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
&MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();
        (error, store.commits.lock().unwrap().len())
    };

    // Declared `module_ref.digest` disagrees with the registry commitment.
    let module_id_a = ModuleId::new([0x73; 32]);
    let (registry_a, catalog_a, ref_a) = preinstalled_module_fixture(
        &hash_resolver,
        module_id_a,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let mut tampered_ref = ref_a.clone();
    tampered_ref.digest = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    let (error, commits) = run_case(registry_a, catalog_a, tampered_ref, 0xB0);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleReferenceDigestMismatch {
            module_id: module_id_a,
            version: 1
        }
    );
    assert_eq!(commits, 0);

    // Not cataloged: registry commits it, but no catalog entry exists.
    let module_id_b = ModuleId::new([0x74; 32]);
    let (registry_b, _catalog_b, ref_b) = preinstalled_module_fixture(
        &hash_resolver,
        module_id_b,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let empty_catalog = PreinstalledModuleCatalog::new(vec![]).unwrap();
    let (error, commits) = run_case(registry_b, empty_catalog, ref_b, 0xB1);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleNotCataloged {
            module_id: module_id_b,
            version: 1
        }
    );
    assert_eq!(commits, 0);

    // Registry code hash disagrees with the catalog's actual WASM bytes.
    let module_id_c = ModuleId::new([0x75; 32]);
    let (mut registry_c, catalog_c, mut ref_c) = preinstalled_module_fixture(
        &hash_resolver,
        module_id_c,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let mut tampered_module = registry_c.get(module_id_c, 1).unwrap().clone();
    tampered_module.canonical_code_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    registry_c = SystemModuleRegistry::new();
    registry_c.add_module(tampered_module.clone()).unwrap();
    ref_c.digest = tampered_module.canonical_code_hash;
    let (error, commits) = run_case(registry_c, catalog_c, ref_c, 0xB2);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleCodeHashMismatch {
            module_id: module_id_c,
            version: 1
        }
    );
    assert_eq!(commits, 0);

    // Registry manifest hash disagrees with the catalog's actual manifest.
    let module_id_d = ModuleId::new([0x76; 32]);
    let (mut registry_d, catalog_d, ref_d) = preinstalled_module_fixture(
        &hash_resolver,
        module_id_d,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let mut tampered_manifest_module = registry_d.get(module_id_d, 1).unwrap().clone();
    tampered_manifest_module.manifest_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    registry_d = SystemModuleRegistry::new();
    registry_d.add_module(tampered_manifest_module).unwrap();
    let (error, commits) = run_case(registry_d, catalog_d, ref_d, 0xB3);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleManifestHashMismatch {
            module_id: module_id_d,
            version: 1
        }
    );
    assert_eq!(commits, 0);

    // Registry semantics hash disagrees with the catalog entry.
    let module_id_e = ModuleId::new([0x77; 32]);
    let (mut registry_e, catalog_e, ref_e) = preinstalled_module_fixture(
        &hash_resolver,
        module_id_e,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    let mut tampered_semantics_module = registry_e.get(module_id_e, 1).unwrap().clone();
    tampered_semantics_module.semantics_hash = Digest32::new(HashAlgorithmId::Sha2_256, [0xEE; 32]);
    registry_e = SystemModuleRegistry::new();
    registry_e.add_module(tampered_semantics_module).unwrap();
    let (error, commits) = run_case(registry_e, catalog_e, ref_e, 0xB4);
    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleSemanticsHashMismatch {
            module_id: module_id_e,
            version: 1
        }
    );
    assert_eq!(commits, 0);
}

#[test]
fn preinstalled_wasm_rejects_oversized_args_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xF8);
    let signing_key: SigningKey = dev_signing_key(0xDE);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x78; 32]);
    // max_input_size = 1, but args below are 2 bytes.
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        1,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (object_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x98; 32]),
        Owner::Address(sender),
        0x98,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xB5),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleArgsTooLarge {
            module_id,
            version: 1,
            actual: 2,
            maximum: 1,
        }
    );
    assert_eq!(store.commits.lock().unwrap().len(), 0);
}

#[test]
fn preinstalled_wasm_trapped_execution_commits_deterministic_rejected_receipt_without_object_mutation()
 {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xF9);
    let signing_key: SigningKey = dev_signing_key(0xDF);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xF9);
    let module_id = ModuleId::new([0x79; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_trap_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0x99; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0x99),
        "sunrise-test",
        9,
        0x3C,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let expected_tx_hash: Digest32 = hash_transaction(&tx, &hash_resolver).unwrap();
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xB6),
        &signing_key,
        Epoch::new(7),
        tx.clone(),
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();

    assert_eq!(resolved.output().responses().len(), 1);
    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Rejected
    );
    let payload: &[u8] = resolved.output().responses()[0].payload().unwrap();

    // The contract's own abort message must never reach the persisted
    // payload, and neither must engine-internal (`wasmi`) text: every
    // trap is normalized to one fixed, engine-independent reason before
    // encoding (see `preinstalled_wasm::normalize_trapped_preinstalled_execution`).
    let payload_text = String::from_utf8_lossy(payload);
    assert!(!payload_text.contains("contract-secret-abort-marker"));
    assert!(!payload_text.contains("wasmi"));

    // The encoded payload is stable: it is exactly the canonical
    // encoding of the normalized closed failure (fixed reason, full
    // `gas_limit` charge, empty effects/events), independent of exactly
    // where inside the contract execution trapped.
    let expected_effects = execution::ExecutionEffects {
        tx_hash: expected_tx_hash,
        status: ExecutionStatus::Failure {
            reason: "preinstalled module execution trapped".to_string(),
        },
        object_effects: Vec::new(),
        events: Vec::new(),
        gas_used: tx.gas_limit,
    };
    let expected_payload = encode_execution_effects(&expected_effects).unwrap();
    assert_eq!(payload, expected_payload.as_slice());

    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(1));
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce: VersionedStateValue = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record: SenderNonceRecord =
        SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

#[test]
fn preinstalled_wasm_zero_object_access_is_rejected_before_domain_resolution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE0);
    let signing_key: SigningKey = dev_signing_key(0xE0);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x7A; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    // No access-manifest entries at all: this MVP path requires at least
    // one authenticated object.
    let manifest = manifest_with(Vec::new());
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC0),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::PreinstalledModuleZeroObjectAccess);
    assert_eq!(store.commits.lock().unwrap().len(), 0);
}

#[test]
fn preinstalled_wasm_consume_commits_tombstone_end_to_end() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE2);
    let signing_key: SigningKey = dev_signing_key(0xE2);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xE2);
    let module_id = ModuleId::new([0x7C; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_consume_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let consume_id: ObjectId = ObjectId::new([0x9B; 32]);
    let consume_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(consume_id, 1, Owner::Address(sender), 0x9B),
        "sunrise-test",
        9,
        0x3E,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: consume_ref,
        mode: AccessMode::Consume,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC1),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let head: DurableObjectHead = store
        .get_object_head(&context, object_domain, consume_id)
        .unwrap();
    assert!(matches!(head, DurableObjectHead::Tombstoned { .. }));
}

#[test]
fn preinstalled_wasm_create_effect_is_fail_closed() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE3);
    let signing_key: SigningKey = dev_signing_key(0xE3);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x7D; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_create_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (object_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xC2; 32]),
        Owner::Address(sender),
        0xC2,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC2),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::ObjectCreationUnsupported { .. }
    ));
    assert_eq!(store.commits.lock().unwrap().len(), 0);
}

#[test]
fn strict_preinstalled_output_owner_rejects_before_atomic_commit() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xA7);
    protocol_config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    let signing_key: SigningKey = dev_signing_key(0xA7);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id: ModuleId = ModuleId::new([0xA8; 32]);
    let (registry, catalog, module_ref): (
        SystemModuleRegistry,
        PreinstalledModuleCatalog,
        ObjectRef,
    ) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_create_with_inadmissible_owner_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let input_id: ObjectId = ObjectId::new([0xA9; 32]);
    let (object_ref, original_head): (ObjectRef, DurableObjectHead) = preload_inline_object(
        &store,
        "sunrise-test",
        input_id,
        Owner::Address(sender),
        0xA9,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let transaction: Transaction = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    let request_id: RequestId = request(0xAA);
    let submission: AuthenticatedSubmitTransaction =
        authenticated_profile_2_submission_from_transaction(
            "sunrise-test",
            request_id,
            &signing_key,
            Epoch::new(7),
            transaction,
            &node_config,
            &protocol_config,
        );
    let context: DurableOperationContext = durable_context();

    let error: NodeCoreError =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &WasmExecutionEngine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert!(
        matches!(
            error,
            NodeCoreError::InadmissibleObjectOutputOwnerAddress {
                source: Ed25519OwnerAddressError::NonCanonicalPoint,
                ..
            }
        ),
        "unexpected error: {error:?}"
    );
    // No invocation reached the atomic store, so nonce, receipt, and
    // outbox remain absent together rather than partially committing.
    assert!(store.commits.lock().unwrap().is_empty());
    assert!(store.receipt.lock().unwrap().is_none());
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let nonce: VersionedStateValue = store
        .get_versioned_durable(&context, domain(0xA7), nonce_key.as_slice())
        .unwrap();
    assert!(nonce.value().is_none());
    let current_head: DurableObjectHead = store
        .get_object_head(&context, domain(0xA7), input_id)
        .unwrap();
    assert_eq!(current_head, original_head);
    assert!(
        store
            .get_object_version(
                &context,
                domain(0xA7),
                input_id,
                DurableObjectVersion::new(2).unwrap(),
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn preinstalled_wasm_missing_entrypoint_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE4);
    let signing_key: SigningKey = dev_signing_key(0xE4);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x7E; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (object_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xC3; 32]),
        Owner::Address(sender),
        0xC3,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Read,
    }]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.entrypoint = "does-not-exist".to_string();
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC4),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::Execution(ExecutionError::MissingEntrypoint(_))
    ));
    assert_eq!(store.commits.lock().unwrap().len(), 0);
}

#[test]
fn preinstalled_wasm_gas_limit_exact_ceiling_succeeds_and_over_ceiling_is_rejected() {
    // Over the ceiling: rejected before the engine ever runs, no commit.
    let node_config: NodeConfig = config("sunrise-test");
    let mut over_protocol_config: ProtocolConfig = active_protocol_config(0xE5);
    let signing_key: SigningKey = dev_signing_key(0xE5);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let over_module_id = ModuleId::new([0x7F; 32]);
    let (over_registry, over_catalog, over_module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        over_module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    over_protocol_config.system_modules = over_registry;
    let over_store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (over_object_ref, _) = preload_inline_object(
        &over_store,
        "sunrise-test",
        ObjectId::new([0xC5; 32]),
        Owner::Address(sender),
        0xC5,
    );
    let over_manifest = manifest_with(vec![AccessEntry {
        object_ref: over_object_ref,
        mode: AccessMode::Read,
    }]);
    let mut over_tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        over_manifest,
        over_module_ref,
        vec![1, 2],
    );
    over_tx.gas_limit = MAX_PREINSTALLED_MODULE_GAS_LIMIT + 1;
    let over_submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC6),
        &signing_key,
        Epoch::new(7),
        over_tx,
        &node_config,
        &over_protocol_config,
    );
    let engine = WasmExecutionEngine;

    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &over_store,
            &durable_context(),
            &hash_resolver,
            &over_catalog,
            &engine,
            over_submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::PreinstalledModuleGasLimitExceedsCeiling {
            requested: MAX_PREINSTALLED_MODULE_GAS_LIMIT + 1,
            maximum: MAX_PREINSTALLED_MODULE_GAS_LIMIT,
        }
    );
    assert_eq!(over_store.commits.lock().unwrap().len(), 0);

    // Exactly at the ceiling: accepted and committed end-to-end.
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE6);
    let context: DurableOperationContext = durable_context();
    let object_domain: AtomicityDomainId = domain(0xE6);
    let module_id = ModuleId::new([0x80; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0xC7; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0xC7),
        "sunrise-test",
        9,
        0x3F,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.gas_limit = MAX_PREINSTALLED_MODULE_GAS_LIMIT;
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC7),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
}

#[test]
fn preinstalled_wasm_successful_noop_on_declared_write_is_fail_closed_non_commit() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE7);
    let signing_key: SigningKey = dev_signing_key(0xE7);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x81; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_noop_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (object_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xC8; 32]),
        Owner::Address(sender),
        0xC8,
    );
    let write_object_id = object_ref.id;
    let manifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Write,
    }]);
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC8),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    // The contract runs to completion without trapping (a genuine
    // `ExecutionStatus::Success`) but never calls `write_object_data`, so
    // it produces no effect for the declared `Write` access. This must
    // still fail closed instead of silently committing as a no-op.
    let error =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectEffectMismatch {
            object_id: write_object_id,
            reason: "write access requires exactly one mutated effect",
        }
    );
    assert_eq!(store.commits.lock().unwrap().len(), 0);
}

#[test]
fn preinstalled_wasm_resolves_end_to_end_across_hash_suite_rotation() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = NodeConfig::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(15),
        b"node/state".to_vec(),
    )
    .unwrap();
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xE8);
    let signing_key: SigningKey = dev_signing_key(0xE8);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver_with_rotation("sunrise-test", Epoch::new(10));
    let object_domain: AtomicityDomainId = domain(0xE8);
    let module_id = ModuleId::new([0x82; 32]);
    // Committed while the SHA2-256 genesis suite is active (epoch 0, see
    // `preinstalled_module_fixture`).
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;
    let write_id: ObjectId = ObjectId::new([0xC9; 32]);
    let write_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(write_id, 1, Owner::Address(sender), 0xC9),
        "sunrise-test",
        9,
        0x40,
    );
    commit_fastpath_epoch_record(
        &store,
        &context,
        object_domain,
        "sunrise-test",
        Epoch::new(15),
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: write_ref,
        mode: AccessMode::Write,
    }]);
    // Epoch 15 is well after the resolver's SHA3-256 rotation at epoch
    // 10, even though the module was committed under the SHA2-256
    // genesis suite; resolution must still succeed (see
    // `hashing::verify_digest`).
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(15),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xC9),
        &signing_key,
        Epoch::new(15),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;

    let resolved =
        handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &hash_resolver,
            &catalog,
            &engine,
            submission,
            9,
            None,
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let write_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, write_id)
        .unwrap();
    assert_eq!(write_head.object_version(), DurableObjectVersion::new(2));
}

#[test]
fn memory_store_authenticated_owned_consume_commits_tombstone_with_nonce() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xFB);
    let signing_key: SigningKey = dev_signing_key(0xCB);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xFB);
    let object_id: ObjectId = ObjectId::new([0x85; 32]);
    let object_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(object_id, 1, Owner::Address(sender), 0x85),
        "sunrise-test",
        5,
        0x37,
    );
    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref,
        mode: AccessMode::Consume,
    }]);
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xE9),
        &signing_key,
        Epoch::new(7),
        0,
        manifest,
        &node_config,
        &protocol_config,
    );
    let machine: OwnedObjectEffectMachine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Consume)],
        replacement_data: vec![0],
        calls: AtomicUsize::new(0),
    };
    commit_fastpath_epoch_record(
        &store,
        &context,
        object_domain,
        "sunrise-test",
        Epoch::new(7),
    );

    handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &hash_resolver,
        submission,
        6,
        &machine,
    )
    .unwrap();

    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let head: DurableObjectHead = store
        .get_object_head(&context, object_domain, object_id)
        .unwrap();
    assert!(matches!(head, DurableObjectHead::Tombstoned { .. }));
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let persisted_nonce: VersionedStateValue = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record: SenderNonceRecord =
        SenderNonceRecord::decode(persisted_nonce.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}

#[test]
fn authenticated_owned_write_requires_exact_effect_before_commit() {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xFC);
    let signing_key: SigningKey = dev_signing_key(0xCC);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id: ObjectId = ObjectId::new([0x86; 32]);
    let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0x86,
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xEA),
        &signing_key,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        }]),
        &node_config,
        &protocol_config,
    );
    let machine: IdempotentMachine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(7));

    let error: NodeCoreError =
        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &MemoryBlobStore::default(),
            &store,
            &durable_context(),
            &resolver("sunrise-test"),
            submission,
            2,
            &machine,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectEffectMismatch {
            object_id,
            reason: "write access requires exactly one mutated effect",
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    assert!(store.commits.lock().unwrap().is_empty());
    assert!(store.receipt.lock().unwrap().is_none());
}

#[test]
fn authenticated_read_only_object_rejects_machine_effect_before_commit() {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xFC);
    let signing_key: SigningKey = dev_signing_key(0xCE);
    let sender: Address = dev_sender_address(&signing_key);
    let object_id: ObjectId = ObjectId::new([0xA1; 32]);
    let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
        &store,
        "sunrise-test",
        object_id,
        Owner::Address(sender),
        0xA1,
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xEC),
        &signing_key,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Read,
        }]),
        &node_config,
        &protocol_config,
    );

    let error: NodeCoreError = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &ReadObjectEffectMachine,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectEffectMismatch {
            object_id,
            reason: "read access produced a mutation effect",
        }
    );
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn authenticated_owned_modes_reject_immutable_object_before_transition() {
    for (mode, request_byte) in [(AccessMode::Write, 0xED_u8), (AccessMode::Consume, 0xEE_u8)] {
        let store: ScriptedDurableStore =
            ScriptedDurableStore::new(DurableCommitOutcome::Committed);
        let node_config: NodeConfig = config("sunrise-test");
        let protocol_config: ProtocolConfig = active_protocol_config(0xFC);
        let signing_key: SigningKey = dev_signing_key(0xCF);
        let object_id: ObjectId = ObjectId::new([request_byte; 32]);
        let (object_ref, _): (ObjectRef, DurableObjectHead) = preload_inline_object(
            &store,
            "sunrise-test",
            object_id,
            Owner::Immutable,
            request_byte,
        );
        let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
            "sunrise-test",
            request(request_byte),
            &signing_key,
            Epoch::new(7),
            0,
            manifest_with(vec![AccessEntry { object_ref, mode }]),
            &node_config,
            &protocol_config,
        );
        let machine: IdempotentMachine = IdempotentMachine {
            calls: AtomicUsize::new(0),
        };
        preload_fastpath_epoch_record(&store, "sunrise-test", Epoch::new(7));

        let error: NodeCoreError =
            handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
                &MemoryBlobStore::default(),
                &store,
                &durable_context(),
                &resolver("sunrise-test"),
                submission,
                2,
                &machine,
            )
            .unwrap_err();

        assert_eq!(
            error,
            NodeCoreError::ObjectOwnerKindUnsupported { object_id }
        );
        assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
        assert!(store.commits.lock().unwrap().is_empty());
    }
}

#[test]
fn authenticated_owned_write_checkpoint_regression_commits_nothing() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xF9);
    let signing_key: SigningKey = dev_signing_key(0xCD);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let object_domain: AtomicityDomainId = domain(0xF9);
    let object_id: ObjectId = ObjectId::new([0x87; 32]);
    let object_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(object_id, 1, Owner::Address(sender), 0x87),
        "sunrise-test",
        18,
        0x3A,
    );
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xEF),
        &signing_key,
        Epoch::new(7),
        0,
        manifest_with(vec![AccessEntry {
            object_ref,
            mode: AccessMode::Write,
        }]),
        &node_config,
        &protocol_config,
    );
    let machine: OwnedObjectEffectMachine = OwnedObjectEffectMachine {
        expected_inputs: vec![(object_id, AccessMode::Write)],
        replacement_data: vec![0xA7],
        calls: AtomicUsize::new(0),
    };
    commit_fastpath_epoch_record(
        &store,
        &context,
        object_domain,
        "sunrise-test",
        Epoch::new(7),
    );

    let error: NodeCoreError =
        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &resolver("sunrise-test"),
            submission,
            17,
            &machine,
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectCreatedCheckpointRegression {
            object_id,
            previous_created_checkpoint: 18,
            attempted_created_checkpoint: 17,
        }
    );
    assert_eq!(machine.calls.load(Ordering::SeqCst), 1);
    let head: DurableObjectHead = store
        .get_object_head(&context, object_domain, object_id)
        .unwrap();
    assert_eq!(head.object_version(), DurableObjectVersion::new(1));
    let nonce_key: Vec<u8> =
        sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    assert!(
        store
            .get_versioned_durable(&context, object_domain, &nonce_key)
            .unwrap()
            .value()
            .is_none()
    );
}

#[test]
fn generic_durable_handler_rejects_object_effects_without_dispatch() {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let object_id: ObjectId = ObjectId::new([0xA1; 32]);

    let error: NodeCoreError = handle_resolved_durable_idempotent_event(
        &store,
        &durable_context(),
        &placement(0xFD, 7),
        &config("sunrise-test"),
        &resolver("sunrise-test"),
        event("sunrise-test", request(0xEB)),
        &UndeclaredObjectEffectMachine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::UndeclaredObjectEffect { object_id });
    assert!(store.commits.lock().unwrap().is_empty());
}

/// One machine implementation used only to inject a genuine, deterministic
/// TOCTOU race into a single-threaded owned-object Write test:
/// `transition()` runs strictly after `load_and_authorize_objects` has
/// captured its object-head snapshot and strictly before the outer
/// invocation commits. It commits a competing update, then returns its own
/// conflicting update effect against the stale verified input.
struct StaleHeadRaceMachine<'a> {
    store: &'a MemoryDurableStateStore,
    context: DurableOperationContext,
    racing_invocation: Mutex<Option<DurableInvocationTransaction>>,
    calls: AtomicUsize,
}

impl TransactionalNodeStateMachine for StaleHeadRaceMachine<'_> {
    fn access_plan(&self, _event: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"state/stale-head-race".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }

    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let racing_invocation = self
            .racing_invocation
            .lock()
            .unwrap()
            .take()
            .expect("the racing invocation commits exactly once");
        assert_eq!(
            self.store
                .commit_invocation(&self.context, racing_invocation),
            DurableCommitOutcome::Committed
        );
        let [input]: &[ResolvedObject] = state.resolved_objects() else {
            panic!("expected one authenticated Write object");
        };
        assert_eq!(input.mode, AccessMode::Write);
        let mut new_object: Object = input.object.clone();
        new_object.version = new_object.version.checked_add(1).unwrap();
        new_object.data = vec![0x84];
        TransactionalNodeTransition::with_object_effects(
            Vec::new(),
            vec![ObjectEffect::Mutated {
                previous_version: input.object.version,
                new_object,
            }],
            NodeOutput::new(
                vec![NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Accepted,
                    None,
                )?],
                Vec::new(),
            )?,
        )
    }
}

#[test]
fn memory_store_stale_head_race_yields_object_conflict_without_consuming_nonce_then_retries() {
    let store = MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config = config("sunrise-test");
    let protocol_config = active_protocol_config(0xF8);
    let signing_key = dev_signing_key(0xC8);
    let sender: Address = dev_sender_address(&signing_key);
    let context = durable_context();
    let resolver = resolver("sunrise-test");
    let object_domain = domain(0xF8);
    let object_id = ObjectId::new([0x82; 32]);

    let object_v1 = test_object(object_id, 1, Owner::Address(sender), 0x82);
    let (record_v1, digest_v1) = hashed_object_version(object_v1, "sunrise-test", 1);
    let owner_projection =
        DurableObjectOwnerProjection::from_owner(Owner::Address(sender)).unwrap();
    let create_mutation = runtime::DurableObjectMutation::Create {
        version: record_v1,
        owner_projection: owner_projection.clone(),
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    let create_changes = DurableObjectChanges::new(
        vec![runtime::DurableObjectHeadRead::new(
            object_id,
            DurableObjectHead::Absent,
        )],
        vec![runtime::DurableObjectMutationEntry::new(
            object_id,
            create_mutation,
        )],
    )
    .unwrap();
    let create_receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x24; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x25; 32]),
        vec![0x26],
    )
    .unwrap();
    let create_invocation = DurableInvocationTransaction::new(
        object_domain,
        None,
        create_changes,
        create_receipt,
        None,
    )
    .unwrap();
    assert_eq!(
        store.commit_invocation(&context, create_invocation),
        DurableCommitOutcome::Committed
    );
    let head_v1 = store
        .get_object_head(&context, object_domain, object_id)
        .unwrap();

    let object_v2 = test_object(object_id, 2, Owner::Address(sender), 0x83);
    let (record_v2, digest_v2) = hashed_object_version(object_v2, "sunrise-test", 2);
    let racing_mutation = runtime::DurableObjectMutation::Update {
        version: record_v2,
        owner_projection,
        routing_projection: DurableObjectRoutingProjection::default(),
    };
    let racing_changes = DurableObjectChanges::new(
        vec![runtime::DurableObjectHeadRead::new(object_id, head_v1)],
        vec![runtime::DurableObjectMutationEntry::new(
            object_id,
            racing_mutation,
        )],
    )
    .unwrap();
    let racing_receipt = DurableRequestReceipt::new(
        DurableRequestId::new([0x27; 32]).unwrap(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x28; 32]),
        vec![0x29],
    )
    .unwrap();
    let racing_invocation = DurableInvocationTransaction::new(
        object_domain,
        None,
        racing_changes,
        racing_receipt,
        None,
    )
    .unwrap();

    let racing_machine = StaleHeadRaceMachine {
        store: &store,
        context,
        racing_invocation: Mutex::new(Some(racing_invocation)),
        calls: AtomicUsize::new(0),
    };
    let stale_manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 1,
            digest: digest_v1,
        },
        mode: AccessMode::Write,
    }]);
    let stale_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xE6),
        &signing_key,
        Epoch::new(7),
        0,
        stale_manifest,
        &node_config,
        &protocol_config,
    );

    commit_fastpath_epoch_record(
        &store,
        &context,
        object_domain,
        "sunrise-test",
        Epoch::new(7),
    );
    let race_error =
        handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
            &MemoryBlobStore::default(),
            &store,
            &context,
            &resolver,
            stale_submission,
            2,
            &racing_machine,
        )
        .unwrap_err();
    assert_eq!(race_error, NodeCoreError::ObjectConflict { object_id });
    assert_eq!(racing_machine.calls.load(Ordering::SeqCst), 1);

    // The outer commit was rejected atomically, so the racing write's own
    // (state-free) invocation is the only thing that committed: the
    // sender-nonce key was never written and the same nonce is still
    // expected next.
    let nonce_key = sender_nonce_key_for("sunrise-test", *sender.as_bytes(), Epoch::new(7));
    let nonce_after_conflict = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    assert!(nonce_after_conflict.value().is_none());

    let head_v2 = store
        .get_object_head(&context, object_domain, object_id)
        .unwrap();
    assert_eq!(head_v2.object_version(), DurableObjectVersion::new(2));

    let retry_manifest = manifest_with(vec![AccessEntry {
        object_ref: ObjectRef {
            id: object_id,
            version: 2,
            digest: digest_v2,
        },
        mode: AccessMode::Read,
    }]);
    let retry_submission = authenticated_submission_with_manifest(
        "sunrise-test",
        request(0xE7),
        &signing_key,
        Epoch::new(7),
        0,
        retry_manifest,
        &node_config,
        &protocol_config,
    );
    let retry_machine = IdempotentMachine {
        calls: AtomicUsize::new(0),
    };
    let resolved = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &context,
        &resolver,
        retry_submission,
        &retry_machine,
    )
    .unwrap();
    assert_eq!(retry_machine.calls.load(Ordering::SeqCst), 1);
    assert_eq!(resolved.output().responses().len(), 1);

    let nonce_after_retry = store
        .get_versioned_durable(&context, object_domain, &nonce_key)
        .unwrap();
    let nonce_record = SenderNonceRecord::decode(nonce_after_retry.value().unwrap()).unwrap();
    assert_eq!(nonce_record.next_nonce, 1);
}
