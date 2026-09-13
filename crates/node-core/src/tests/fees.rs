// ── S3 fee lifecycle ─────────────────────────────────────────────────

fn fee_asset_id() -> standard_assets::AssetId {
    standard_assets::AssetId::new([0xF3; 32])
}

fn fee_gas_schedule() -> fees::GasSchedule {
    fees::GasSchedule {
        base_fee: 1,
        execution_price: 1,
        read_price: 0,
        write_price: 0,
        storage_price: 0,
        system_module_price: 0,
    }
}

fn fee_asset_registry() -> fees::FeeAssetRegistry {
    let mut registry = fees::FeeAssetRegistry::new();
    registry
        .add_asset(fees::FeeAsset {
            asset_id: fee_asset_id(),
            fee_units_per_asset_unit: 1,
            enabled: true,
        })
        .unwrap();
    registry
}

/// Committed protocol configuration with a non-zero fee schedule and one
/// enabled fee asset, otherwise identical to [`active_protocol_config`].
fn fee_active_protocol_config(byte: u8) -> ProtocolConfig {
    let mut protocol_config = active_protocol_config(byte);
    protocol_config.gas_schedule = fee_gas_schedule();
    protocol_config.fee_assets = fee_asset_registry();
    protocol_config
}

/// Deterministically appends a fixed debit/credit tag to each body and
/// records the exact settled amount it was asked to charge, so tests can
/// assert both the merged bytes and the amount without needing real
/// balance semantics.
#[derive(Debug)]
struct RecordingFeeComposer {
    charged_amount: Mutex<Option<u64>>,
}

impl RecordingFeeComposer {
    fn new() -> Self {
        Self {
            charged_amount: Mutex::new(None),
        }
    }
}

impl FeeEffectComposer for RecordingFeeComposer {
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        *self.charged_amount.lock().unwrap() = Some(request.amount.get());
        let mut payer_body = request.payer_body.to_vec();
        payer_body.push(0xF0);
        let mut treasury_body = request.treasury_body.to_vec();
        treasury_body.push(0xF1);
        Ok(FeeChargeBodies {
            payer_body,
            treasury_body,
        })
    }
}

/// Returns both bodies unchanged, deterministically triggering
/// [`NodeCoreError::FeeCompositionNoOp`] whenever a non-zero amount is
/// charged.
#[derive(Debug)]
struct EchoFeeComposer;

impl FeeEffectComposer for EchoFeeComposer {
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        Ok(FeeChargeBodies {
            payer_body: request.payer_body.to_vec(),
            treasury_body: request.treasury_body.to_vec(),
        })
    }
}

/// Changes only the payer body, leaving the treasury body byte-identical
/// to its effective input — deterministically triggering
/// [`NodeCoreError::FeeCompositionNoOp`]: a non-zero charge must move
/// value on both sides, not just debit the payer.
#[derive(Debug)]
struct PayerOnlyChangeFeeComposer;

impl FeeEffectComposer for PayerOnlyChangeFeeComposer {
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        let mut payer_body = request.payer_body.to_vec();
        payer_body.push(0xF2);
        Ok(FeeChargeBodies {
            payer_body,
            treasury_body: request.treasury_body.to_vec(),
        })
    }
}

/// Changes only the treasury body, leaving the payer body byte-identical
/// to its effective input — deterministically triggering
/// [`NodeCoreError::FeeCompositionNoOp`]: a non-zero charge must move
/// value on both sides, not just credit the treasury.
#[derive(Debug)]
struct TreasuryOnlyChangeFeeComposer;

impl FeeEffectComposer for TreasuryOnlyChangeFeeComposer {
    fn compose_fee_charge(
        &self,
        request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        let mut treasury_body = request.treasury_body.to_vec();
        treasury_body.push(0xF3);
        Ok(FeeChargeBodies {
            payer_body: request.payer_body.to_vec(),
            treasury_body,
        })
    }
}

/// Always rejects with a fixed, caller-chosen error.
#[derive(Debug)]
struct RejectingFeeComposer(FeeCompositionError);

impl FeeEffectComposer for RejectingFeeComposer {
    fn compose_fee_charge(
        &self,
        _request: &FeeChargeRequest<'_>,
    ) -> Result<FeeChargeBodies, FeeCompositionError> {
        Err(self.0.clone())
    }
}

#[test]
fn preinstalled_wasm_fee_charges_actual_gas_used_not_gas_limit() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xD0);
    let signing_key: SigningKey = dev_signing_key(0xD0);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xD0);
    let module_id = ModuleId::new([0xD0; 32]);
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

    let payer_id: ObjectId = ObjectId::new([0xD1; 32]);
    let mut payer_object = test_object(payer_id, 1, Owner::Address(sender), 0xD1);
    payer_object.data = vec![0x10];
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        9,
        0xD2,
    );
    let treasury_owner: Address = Address::new([0xD3; 32]);
    let treasury_id: ObjectId = ObjectId::new([0xD4; 32]);
    let mut treasury_object = test_object(treasury_id, 1, Owner::Address(treasury_owner), 0xD4);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        9,
        0xD5,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xD6),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);
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
            Some(fee_composition),
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let payload = resolved.output().responses()[0].payload().unwrap();
    let effects = execution::decode_execution_effects(payload).unwrap();
    assert!(effects.gas_used < 1_000_000);

    let charged = composer.charged_amount.lock().unwrap().unwrap();
    assert_eq!(charged, 1 + effects.gas_used);

    let payer_v2 = store
        .get_object_version(
            &context,
            object_domain,
            payer_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&payer_v2, &blob_store).data,
        vec![0x10, 0xF0]
    );
    let treasury_v2 = store
        .get_object_version(
            &context,
            object_domain,
            treasury_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&treasury_v2, &blob_store).data,
        vec![0x00, 0xF1]
    );
}

#[test]
fn preinstalled_wasm_fee_merges_into_application_mutated_payer_object() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xD7);
    let signing_key: SigningKey = dev_signing_key(0xD7);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xD7);
    let module_id = ModuleId::new([0xD7; 32]);
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

    let payer_id: ObjectId = ObjectId::new([0xD8; 32]);
    let mut payer_object = test_object(payer_id, 1, Owner::Address(sender), 0xD8);
    payer_object.data = vec![0x10];
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        9,
        0xD9,
    );
    let treasury_owner: Address = Address::new([0xDA; 32]);
    let treasury_id: ObjectId = ObjectId::new([0xDB; 32]);
    let mut treasury_object = test_object(treasury_id, 1, Owner::Address(treasury_owner), 0xDB);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        9,
        0xDC,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xDD),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);
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
            Some(fee_composition),
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );

    // Exactly one Mutated effect for the payer: version bumps by one,
    // not two, even though both the application and the fee charge
    // touched it (requirement 6).
    let payer_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, payer_id)
        .unwrap();
    assert_eq!(payer_head.object_version(), DurableObjectVersion::new(2));
    let payer_v2 = store
        .get_object_version(
            &context,
            object_domain,
            payer_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&payer_v2, &blob_store).data,
        vec![0xCA, 0xFE, 0xF0]
    );
    let treasury_v2 = store
        .get_object_version(
            &context,
            object_domain,
            treasury_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&treasury_v2, &blob_store).data,
        vec![0x00, 0xF1]
    );
}

#[test]
fn preinstalled_wasm_trapped_call_still_charges_fee_and_credits_treasury() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xDE);
    let signing_key: SigningKey = dev_signing_key(0xDE);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xDE);
    let module_id = ModuleId::new([0xDE; 32]);
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

    let payer_id: ObjectId = ObjectId::new([0xDF; 32]);
    let mut payer_object = test_object(payer_id, 1, Owner::Address(sender), 0xDF);
    payer_object.data = vec![0x10];
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        9,
        0xE1,
    );
    let treasury_owner: Address = Address::new([0xE2; 32]);
    let treasury_id: ObjectId = ObjectId::new([0xE3; 32]);
    let mut treasury_object = test_object(treasury_id, 1, Owner::Address(treasury_owner), 0xE3);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        9,
        0xE4,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xE5),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);
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
            Some(fee_composition),
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Rejected
    );
    let payload = resolved.output().responses()[0].payload().unwrap();
    let effects = execution::decode_execution_effects(payload).unwrap();
    assert!(effects.object_effects.is_empty());
    assert_eq!(effects.gas_used, 1_000_000);

    let charged = composer.charged_amount.lock().unwrap().unwrap();
    assert_eq!(charged, 1 + 1_000_000);

    // The application never ran (trap), so the committed payer body is
    // exactly its loaded data with only the fee tag appended.
    let payer_v2 = store
        .get_object_version(
            &context,
            object_domain,
            payer_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&payer_v2, &blob_store).data,
        vec![0x10, 0xF0]
    );
    let treasury_v2 = store
        .get_object_version(
            &context,
            object_domain,
            treasury_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&treasury_v2, &blob_store).data,
        vec![0x00, 0xF1]
    );
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
fn preinstalled_wasm_trap_with_zero_schedule_and_fee_composition_present_commits_no_mutation() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0xFB);
    let signing_key: SigningKey = dev_signing_key(0xFB);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xFB);
    let module_id = ModuleId::new([0xFB; 32]);
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
    let payer_id: ObjectId = ObjectId::new([0xFC; 32]);
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        test_object(payer_id, 1, Owner::Address(sender), 0xFC),
        "sunrise-test",
        9,
        0xFD,
    );
    let treasury_id: ObjectId = ObjectId::new([0xFE; 32]);

    let manifest: AccessManifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref,
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
        request(0xFF),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap();

    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Rejected
    );
    let payer_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, payer_id)
        .unwrap();
    assert_eq!(payer_head.object_version(), DurableObjectVersion::new(1));
}

#[test]
fn preinstalled_wasm_fee_treasury_is_hidden_from_engine_object_count() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x60);
    let signing_key: SigningKey = dev_signing_key(0x60);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0x60);
    let module_id = ModuleId::new([0x60; 32]);
    let (registry, catalog, module_ref) = preinstalled_module_fixture(
        &hash_resolver,
        module_id,
        1,
        preinstalled_write_two_wasm_bytes(),
        64,
        Epoch::new(0),
        system_modules::ModuleStatus::Active,
    );
    protocol_config.system_modules = registry;

    let payer_id: ObjectId = ObjectId::new([0x61; 32]);
    let mut payer_object = test_object(payer_id, 1, Owner::Address(sender), 0x61);
    payer_object.data = vec![0x00, 0x00];
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        9,
        0x62,
    );
    let treasury_owner: Address = Address::new([0x63; 32]);
    let treasury_id: ObjectId = ObjectId::new([0x64; 32]);
    let mut treasury_object = test_object(treasury_id, 1, Owner::Address(treasury_owner), 0x64);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        9,
        0x65,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x66),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);
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
            Some(fee_composition),
        )
        .unwrap();

    // The module attempts to write declared indices 0 and 1, but with
    // the treasury excluded from engine inputs the engine holds exactly
    // one object; the out-of-range write to index 1 silently no-ops (see
    // `execution::wasm_engine::write_object_data`), so only the payer
    // carries the application's write, fee-tagged on top.
    assert_eq!(
        resolved.output().responses()[0].status(),
        NodeResponseStatus::Accepted
    );
    let payer_v2 = store
        .get_object_version(
            &context,
            object_domain,
            payer_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&payer_v2, &blob_store).data,
        vec![0xCA, 0xFE, 0xF0]
    );
    let treasury_v2 = store
        .get_object_version(
            &context,
            object_domain,
            treasury_id,
            DurableObjectVersion::new(2).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        committed_object(&treasury_v2, &blob_store).data,
        vec![0x00, 0xF1]
    );
}

#[test]
fn generic_read_only_entrypoint_rejects_fee_payment() {
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xE6);
    let signing_key: SigningKey = dev_signing_key(0xE6);
    let sender: Address = dev_sender_address(&signing_key);
    let mut tx = unsigned_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(1),
        fee_object: sample_object_ref(0xE7),
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xE7),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let machine = OwnedObjectEffectMachine {
        expected_inputs: Vec::new(),
        replacement_data: vec![0],
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::FeePaymentUnsupportedOnPath);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn generic_owned_effects_entrypoint_rejects_fee_payment() {
    let node_config: NodeConfig = config("sunrise-test");
    let protocol_config: ProtocolConfig = active_protocol_config(0xE8);
    let signing_key: SigningKey = dev_signing_key(0xE8);
    let sender: Address = dev_sender_address(&signing_key);
    let mut tx = unsigned_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(1),
        fee_object: sample_object_ref(0xE9),
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xEA),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let machine = OwnedObjectEffectMachine {
        expected_inputs: Vec::new(),
        replacement_data: vec![0],
        calls: AtomicUsize::new(0),
    };

    let error = handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &MemoryBlobStore::default(),
        &store,
        &durable_context(),
        &resolver("sunrise-test"),
        submission,
        9,
        &machine,
    )
    .unwrap_err();

    assert_eq!(error, NodeCoreError::FeePaymentUnsupportedOnPath);
    assert_eq!(machine.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn preinstalled_wasm_nonzero_schedule_requires_fee_payment() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xEB);
    let signing_key: SigningKey = dev_signing_key(0xEB);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0xEB; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xEC; 32]),
        Owner::Address(sender),
        0xEC,
    );
    let treasury_owner = Address::new([0xED; 32]);
    let treasury_id = ObjectId::new([0xEE; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0xEE,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
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
        request(0xEF),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeePaymentRequired);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A declared `fee_payment` must never be silently ignored just because
/// the committed schedule's worst-case fee at `gas_limit` happens to be
/// zero: node-core has no way to charge it and must fail closed instead
/// of admitting the transaction as though it were fee-free.
#[test]
fn preinstalled_wasm_fee_payment_declared_against_zero_worst_case_fee_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    // Deliberately not `fee_active_protocol_config`: the default,
    // genesis-derived `gas_schedule` prices every unit at zero, so the
    // committed worst-case fee at any `gas_limit` is zero.
    let mut protocol_config: ProtocolConfig = active_protocol_config(0x64);
    let signing_key: SigningKey = dev_signing_key(0x64);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x64; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x65; 32]),
        Owner::Address(sender),
        0x65,
    );
    let treasury_id = ObjectId::new([0x66; 32]);
    // No treasury access is declared: only the `fee_payment` itself is
    // misdeclared here.
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref.clone(),
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
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x67),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeePaymentNotRequired);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// No fee-charging composition is wired for this deployment (`None`
/// passed to the handler), yet the transaction declares a
/// `fee_payment`. It must never be silently ignored — that would admit
/// the transaction as fee-free while dropping the sender's declared
/// payment.
#[test]
fn preinstalled_wasm_fee_payment_declared_with_no_fee_composition_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = active_protocol_config(0x68);
    let signing_key: SigningKey = dev_signing_key(0x68);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x68; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x69; 32]),
        Owner::Address(sender),
        0x69,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref.clone(),
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
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x6A),
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

    assert_eq!(error, NodeCoreError::FeePaymentUnsupportedOnPath);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// No fee-charging composition is wired, and the transaction declares no
/// `fee_payment` either, but the committed schedule's worst-case fee at
/// `gas_limit` is non-zero. Historical fee-free behavior must not
/// silently apply here: with a committed non-zero price and nothing to
/// charge it against, the deployment is misconfigured and must fail
/// closed rather than let the transaction execute for free.
#[test]
fn preinstalled_wasm_nonzero_schedule_with_no_fee_composition_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x6B);
    let signing_key: SigningKey = dev_signing_key(0x6B);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x6B; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x6C; 32]),
        Owner::Address(sender),
        0x6C,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref,
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
        request(0x6D),
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

    assert_eq!(error, NodeCoreError::FeeCompositionUnavailable);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A committed schedule that prices a category this path never measures
/// (`read_price`, `write_price`, `storage_price`, or
/// `system_module_price`) must fail closed before the engine ever runs,
/// rather than let `fees::calculate_fee` silently multiply that price by
/// the always-zero usage this path reports and drop it from the total.
#[test]
fn preinstalled_wasm_schedule_pricing_an_unmeasured_category_is_rejected_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x91);
    protocol_config.gas_schedule.storage_price = 1;
    let signing_key: SigningKey = dev_signing_key(0x91);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x91; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x92; 32]),
        Owner::Address(sender),
        0x92,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref,
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
        request(0x93),
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
        NodeCoreError::UnsupportedGasScheduleShape(GasScheduleShapeFault::UnmeasuredCategoryPriced)
    );
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A committed schedule with a zero `base_fee` but a non-zero
/// `execution_price` lets a legitimate zero-`gas_used` success settle a
/// zero fee even though worst-case admission at `gas_limit` already
/// required a treasury `Write`. This must fail closed before the engine
/// ever runs rather than depend on whichever `gas_used` a specific
/// invocation happens to report.
#[test]
fn preinstalled_wasm_zero_base_fee_with_nonzero_execution_price_is_rejected_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x94);
    protocol_config.gas_schedule.base_fee = 0;
    let signing_key: SigningKey = dev_signing_key(0x94);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x94; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x95; 32]),
        Owner::Address(sender),
        0x95,
    );
    let manifest = manifest_with(vec![AccessEntry {
        object_ref: payer_ref,
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
        request(0x96),
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
        NodeCoreError::UnsupportedGasScheduleShape(
            GasScheduleShapeFault::ZeroBaseFeeWithExecutionPrice
        )
    );
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_fee_object_not_declared_write_is_rejected_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x6C);
    let signing_key: SigningKey = dev_signing_key(0x6C);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x6C; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x6D; 32]),
        Owner::Address(sender),
        0x6D,
    );
    let treasury_owner = Address::new([0x6E; 32]);
    let treasury_id = ObjectId::new([0x6F; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x6F,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        // Not declared anywhere in the manifest.
        fee_object: sample_object_ref(0x70),
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x71),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeObjectNotDeclaredWrite);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_fee_object_not_owned_by_sender_is_rejected_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x72);
    let signing_key: SigningKey = dev_signing_key(0x72);
    let sender: Address = dev_sender_address(&signing_key);
    let recipient: Address = Address::new([0x73; 32]);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x72; 32]);
    let destination_byte: u8 = 0x22;
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
    let envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::new(b"fee-owner-test".to_vec(), vec![policy]).unwrap();
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

    let store = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let (source_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x74; 32]),
        Owner::Address(sender),
        0x21,
    );
    let (destination_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x75; 32]),
        Owner::Address(recipient),
        destination_byte,
    );
    let treasury_owner = Address::new([0x76; 32]);
    let treasury_id = ObjectId::new([0x77; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x77,
    );

    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: source_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: destination_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        // Authorized for cross-owner Write by the committed policy, but
        // never owned by the sender: the fee lifecycle requires more
        // than mere authorization.
        fee_object: destination_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x78),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeObjectNotOwnedBySender);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_fee_object_equal_to_treasury_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x79);
    let signing_key: SigningKey = dev_signing_key(0x79);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x79; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x7A; 32]),
        Owner::Address(sender),
        0x7A,
    );
    let treasury_owner = Address::new([0x7B; 32]);
    let treasury_id = ObjectId::new([0x7C; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x7C,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref.clone(),
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: treasury_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x7D),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeObjectIsTreasury);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_treasury_declared_at_non_final_index_is_misdeclared() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x7E);
    let signing_key: SigningKey = dev_signing_key(0x7E);
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
    // A sender-owned stand-in for the treasury id, so object loading
    // succeeds under the ordinary same-owner rule: this test isolates
    // manifest-structure validation from ownership authorization.
    let treasury_id = ObjectId::new([0x7F; 32]);
    let (treasury_stand_in_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(sender),
        0x7F,
    );
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x80; 32]),
        Owner::Address(sender),
        0x80,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: treasury_stand_in_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x81),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeTreasuryAccessMisdeclared);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_sender_substituted_object_as_treasury_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x82);
    let signing_key: SigningKey = dev_signing_key(0x82);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x82; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x83; 32]),
        Owner::Address(sender),
        0x83,
    );
    // Sender's own object, declared final -- an attempt to redirect the
    // fee credit to an address the sender controls. The real trusted
    // treasury id (below) never appears in this manifest at all.
    let (substituted_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x84; 32]),
        Owner::Address(sender),
        0x84,
    );
    let treasury_id = ObjectId::new([0x85; 32]);
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: substituted_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x86),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeTreasuryAccessMisdeclared);
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_max_fee_below_worst_case_is_rejected_before_execution() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x87);
    let signing_key: SigningKey = dev_signing_key(0x87);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x87; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x88; 32]),
        Owner::Address(sender),
        0x88,
    );
    let treasury_owner = Address::new([0x89; 32]);
    let treasury_id = ObjectId::new([0x8A; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x8A,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        vec![1, 2],
    );
    // gas_limit is 1_000_000 (see `preinstalled_transaction`), so the
    // worst-case fee is 1 + 1_000_000 = 1_000_001; `max_fee` of 1 can
    // never cover it.
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(1),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x8B),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        NodeCoreError::FeePaymentRejected(fees::FeeError::MaxFeeExceeded { .. })
    ));
    // The engine never ran: no commit was ever attempted.
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_fee_composer_insufficient_balance_rejects_whole_request() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x8C);
    let signing_key: SigningKey = dev_signing_key(0x8C);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x8C; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x8D; 32]),
        Owner::Address(sender),
        0x8D,
    );
    let treasury_owner = Address::new([0x8E; 32]);
    let treasury_id = ObjectId::new([0x8F; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x8F,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x90),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = RejectingFeeComposer(FeeCompositionError::InsufficientBalance);
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::FeeCompositionFailed(FeeCompositionError::InsufficientBalance)
    );
    // No commit at all: no nonce burn, no receipt, no object mutation.
    assert!(store.commits.lock().unwrap().is_empty());
}

#[test]
fn preinstalled_wasm_fee_composer_no_op_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0x91);
    let signing_key: SigningKey = dev_signing_key(0x91);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0x91; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x92; 32]),
        Owner::Address(sender),
        0x92,
    );
    let treasury_owner = Address::new([0x93; 32]);
    let treasury_id = ObjectId::new([0x94; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0x94,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0x95),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = EchoFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeCompositionNoOp);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A composer that debits the payer but leaves the treasury body
/// byte-identical is not a valid non-zero settlement: value must move on
/// both sides, never just off the payer.
#[test]
fn preinstalled_wasm_fee_composer_payer_only_change_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xA0);
    let signing_key: SigningKey = dev_signing_key(0xA0);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0xA0; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xA1; 32]),
        Owner::Address(sender),
        0xA1,
    );
    let treasury_owner = Address::new([0xA2; 32]);
    let treasury_id = ObjectId::new([0xA3; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0xA3,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xA4),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = PayerOnlyChangeFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeCompositionNoOp);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// A composer that credits the treasury but leaves the payer body
/// byte-identical is not a valid non-zero settlement: value must move on
/// both sides, never just onto the treasury.
#[test]
fn preinstalled_wasm_fee_composer_treasury_only_change_is_rejected() {
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xA5);
    let signing_key: SigningKey = dev_signing_key(0xA5);
    let sender: Address = dev_sender_address(&signing_key);
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let module_id = ModuleId::new([0xA5; 32]);
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
    let (payer_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0xA6; 32]),
        Owner::Address(sender),
        0xA6,
    );
    let treasury_owner = Address::new([0xA7; 32]);
    let treasury_id = ObjectId::new([0xA8; 32]);
    let (treasury_ref, _) = preload_inline_object(
        &store,
        "sunrise-test",
        treasury_id,
        Owner::Address(treasury_owner),
        0xA8,
    );
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xA9),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let engine = WasmExecutionEngine;
    let composer = TreasuryOnlyChangeFeeComposer;
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap_err();

    assert_eq!(error, NodeCoreError::FeeCompositionNoOp);
    assert!(store.commits.lock().unwrap().is_empty());
}

/// Owned fixture state for the `charge_fee` adversarial tests below.
/// `charge_fee` never reads `self.transaction`, `self.resolver`,
/// `self.catalog`, `self.engine`, or `self.fee_policy`, so their exact
/// contents are immaterial; only `payer`, `treasury`, and `fee_payment`
/// matter to the assertions.
fn charge_fee_test_state() -> (
    Transaction,
    HashSuiteResolver,
    PreinstalledModuleCatalog,
    WasmExecutionEngine,
    CommittedFeePolicy,
    Object,
    Object,
    fees::FeePayment,
) {
    let signing_key = dev_signing_key(0xB0);
    let sender = dev_sender_address(&signing_key);
    let resolver = resolver("sunrise-test");
    let catalog = PreinstalledModuleCatalog::new(Vec::new()).unwrap();
    let engine = WasmExecutionEngine;
    let fee_policy = CommittedFeePolicy {
        gas_schedule: fee_gas_schedule(),
        fee_assets: fee_asset_registry(),
    };
    let payer = test_object(ObjectId::new([0xB1; 32]), 1, Owner::Address(sender), 0xB1);
    let treasury_owner = Address::new([0xB2; 32]);
    let treasury = test_object(
        ObjectId::new([0xB3; 32]),
        1,
        Owner::Address(treasury_owner),
        0xB3,
    );
    let fee_object_ref = ObjectRef {
        id: payer.id,
        version: payer.version,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xB4; 32]),
    };
    let fee_payment = fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: fee_object_ref.clone(),
    };
    let manifest = manifest_with(vec![
        AccessEntry {
            object_ref: fee_object_ref,
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: ObjectRef {
                id: treasury.id,
                version: treasury.version,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xB5; 32]),
            },
            mode: AccessMode::Write,
        },
    ]);
    let module_ref = ObjectRef {
        id: ObjectId::new([0xB6; 32]),
        version: 1,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xB7; 32]),
    };
    let tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    (
        tx,
        resolver,
        catalog,
        engine,
        fee_policy,
        payer,
        treasury,
        fee_payment,
    )
}

/// `charge_fee` finds at most one application effect naming the fee
/// object; two effects for the same id must be rejected as a duplicate,
/// never silently coalesced into one merged mutation. This scenario is
/// unreachable through the real WASM engine (the fee object is always a
/// single declared `Write` access, so the engine can produce at most one
/// effect for it), so `charge_fee` is exercised directly.
#[test]
fn preinstalled_wasm_charge_fee_rejects_duplicate_payer_effect() {
    let (tx, resolver, catalog, engine, fee_policy, payer, treasury, fee_payment) =
        charge_fee_test_state();
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury.id, &composer);
    let machine = PreinstalledWasmMachine {
        transaction: &tx,
        resolver: &resolver,
        registered_module: None,
        catalog: &catalog,
        engine: &engine,
        fee_policy: &fee_policy,
        fee_composition: Some(fee_composition),
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    machine.treasury_object.set(treasury.clone()).unwrap();
    let snapshot = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object: payer.clone(),
            mode: AccessMode::Write,
        }],
    };
    let mut payer_next = payer.clone();
    payer_next.version = payer.version + 1;
    payer_next.data = vec![0x01];
    let duplicate_effect = ObjectEffect::Mutated {
        previous_version: payer.version,
        new_object: payer_next,
    };

    let error = machine
        .charge_fee(
            &snapshot,
            &fee_payment,
            payer.id,
            treasury.id,
            fees::Amount::new(5),
            vec![duplicate_effect.clone(), duplicate_effect],
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::DuplicateObjectEffect {
            object_id: payer.id
        }
    );
}

/// A `Created` application effect for the fee object id is exactly what
/// `translate_authenticated_object_effects` would reject for a declared
/// `Write` access; `charge_fee` must reject it too rather than treating
/// it as "no existing effect" and silently overwriting it with a fresh
/// mutation.
#[test]
fn preinstalled_wasm_charge_fee_rejects_created_payer_effect() {
    let (tx, resolver, catalog, engine, fee_policy, payer, treasury, fee_payment) =
        charge_fee_test_state();
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury.id, &composer);
    let machine = PreinstalledWasmMachine {
        transaction: &tx,
        resolver: &resolver,
        registered_module: None,
        catalog: &catalog,
        engine: &engine,
        fee_policy: &fee_policy,
        fee_composition: Some(fee_composition),
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    machine.treasury_object.set(treasury.clone()).unwrap();
    let snapshot = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object: payer.clone(),
            mode: AccessMode::Write,
        }],
    };
    let created = test_object(payer.id, 1, payer.owner.clone(), 0xB9);

    let error = machine
        .charge_fee(
            &snapshot,
            &fee_payment,
            payer.id,
            treasury.id,
            fees::Amount::new(5),
            vec![ObjectEffect::Created(created)],
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectCreationUnsupported {
            object_id: payer.id
        }
    );
}

/// A `Deleted` application effect for the fee object id disagrees with
/// its required `Write` access exactly like
/// `translate_authenticated_object_effects` would reject it;
/// `charge_fee` must reject it too instead of masking it by filtering
/// every same-id effect out during merge and inserting a fresh mutation.
#[test]
fn preinstalled_wasm_charge_fee_rejects_deleted_payer_effect() {
    let (tx, resolver, catalog, engine, fee_policy, payer, treasury, fee_payment) =
        charge_fee_test_state();
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury.id, &composer);
    let machine = PreinstalledWasmMachine {
        transaction: &tx,
        resolver: &resolver,
        registered_module: None,
        catalog: &catalog,
        engine: &engine,
        fee_policy: &fee_policy,
        fee_composition: Some(fee_composition),
        resolved_module: std::cell::OnceCell::new(),
        treasury_object: std::cell::OnceCell::new(),
    };
    machine.treasury_object.set(treasury.clone()).unwrap();
    let snapshot = NodeStateSnapshot {
        values: BTreeMap::new(),
        resolved_objects: vec![ResolvedObject {
            object: payer.clone(),
            mode: AccessMode::Write,
        }],
    };

    let error = machine
        .charge_fee(
            &snapshot,
            &fee_payment,
            payer.id,
            treasury.id,
            fees::Amount::new(5),
            vec![ObjectEffect::Deleted {
                id: payer.id,
                version: payer.version,
            }],
        )
        .unwrap_err();

    assert_eq!(
        error,
        NodeCoreError::ObjectEffectMismatch {
            object_id: payer.id,
            reason: "fee object write access requires exactly one mutated effect",
        }
    );
}

#[test]
fn preinstalled_wasm_fee_paying_exact_replay_does_not_recharge() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    store.set_time(100);
    let node_config: NodeConfig = config("sunrise-test");
    let mut protocol_config: ProtocolConfig = fee_active_protocol_config(0xF4);
    let signing_key: SigningKey = dev_signing_key(0xF4);
    let sender: Address = dev_sender_address(&signing_key);
    let context: DurableOperationContext = durable_context();
    let hash_resolver: HashSuiteResolver = resolver("sunrise-test");
    let object_domain: AtomicityDomainId = domain(0xF4);
    let module_id = ModuleId::new([0xF4; 32]);
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

    let payer_id: ObjectId = ObjectId::new([0xF5; 32]);
    let mut payer_object = test_object(payer_id, 1, Owner::Address(sender), 0xF5);
    payer_object.data = vec![0x10];
    let payer_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        payer_object,
        "sunrise-test",
        9,
        0xF6,
    );
    let treasury_owner: Address = Address::new([0xF7; 32]);
    let treasury_id: ObjectId = ObjectId::new([0xF8; 32]);
    let mut treasury_object = test_object(treasury_id, 1, Owner::Address(treasury_owner), 0xF8);
    treasury_object.data = vec![0x00];
    let treasury_ref: ObjectRef = commit_memory_inline_object(
        &store,
        &context,
        object_domain,
        treasury_object,
        "sunrise-test",
        9,
        0xF9,
    );

    let manifest: AccessManifest = manifest_with(vec![
        AccessEntry {
            object_ref: payer_ref.clone(),
            mode: AccessMode::Write,
        },
        AccessEntry {
            object_ref: treasury_ref,
            mode: AccessMode::Write,
        },
    ]);
    let mut tx = preinstalled_transaction(
        sender,
        ChainId::new("sunrise-test").unwrap(),
        Epoch::new(7),
        0,
        manifest,
        module_ref,
        Vec::new(),
    );
    tx.fee_payment = Some(fees::FeePayment {
        asset_id: fee_asset_id(),
        max_fee: fees::Amount::new(2_000_000),
        fee_object: payer_ref,
    });
    let submission: AuthenticatedSubmitTransaction = authenticated_submission_from_transaction(
        "sunrise-test",
        request(0xFA),
        &signing_key,
        Epoch::new(7),
        tx,
        &node_config,
        &protocol_config,
    );
    let replay_submission: AuthenticatedSubmitTransaction = submission.clone();
    let engine = WasmExecutionEngine;
    let composer = RecordingFeeComposer::new();
    let fee_composition = PreinstalledFeeComposition::new(treasury_id, &composer);

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
            Some(fee_composition),
        )
        .unwrap();

    // An empty catalog and no fee composition at all on replay prove
    // that the persisted receipt short-circuits before module
    // resolution, fee admission, or execution -- the fee is not
    // reapplied.
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
    let payer_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, payer_id)
        .unwrap();
    assert_eq!(payer_head.object_version(), DurableObjectVersion::new(2));
    let treasury_head: DurableObjectHead = store
        .get_object_head(&context, object_domain, treasury_id)
        .unwrap();
    assert_eq!(treasury_head.object_version(), DurableObjectVersion::new(2));
}
