// ── preinstalled WASM composition (Developer MVP step 3) ────────────────

/// A contract that overwrites `object[0]`'s data with a fixed byte,
/// exactly like `execution::wasm_engine`'s own `write_object_contract`
/// test fixture.
fn preinstalled_write_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "get_object_count"   (func $get_object_count   (result i32)))
            (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
            (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
            (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
            (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
            (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
            (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
            (import "env" "get_args_len"       (func $get_args_len       (result i32)))
            (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
            (import "env" "abort"              (func $abort              (param i32 i32)))
            (memory 1)
            (export "memory" (memory 0))
            (data (i32.const 0) "\CA\FE")
            (func (export "run")
              (drop (call $write_object_data (i32.const 0) (i32.const 0) (i32.const 2)))))"#,
    )
    .unwrap()
}

/// A contract that overwrites both declared objects. It is intentionally
/// metadata-blind: node-core must authorize the non-sender destination
/// from the committed semantics policy before execution.
fn preinstalled_write_two_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "get_object_count"   (func $get_object_count   (result i32)))
            (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
            (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
            (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
            (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
            (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
            (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
            (import "env" "get_args_len"       (func $get_args_len       (result i32)))
            (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
            (import "env" "abort"              (func $abort              (param i32 i32)))
            (memory 1)
            (export "memory" (memory 0))
            (data (i32.const 0) "\CA\FE")
            (func (export "run")
              (drop (call $write_object_data (i32.const 0) (i32.const 0) (i32.const 2)))
              (drop (call $write_object_data (i32.const 1) (i32.const 0) (i32.const 2)))))"#,
    )
    .unwrap()
}

/// A contract that always traps via `abort`.
fn preinstalled_trap_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "get_object_count"   (func $get_object_count   (result i32)))
            (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
            (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
            (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
            (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
            (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
            (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
            (import "env" "get_args_len"       (func $get_args_len       (result i32)))
            (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
            (import "env" "abort"              (func $abort              (param i32 i32)))
            (memory 1)
            (export "memory" (memory 0))
            (data (i32.const 0) "contract-secret-abort-marker")
            (func (export "run")
              (call $abort (i32.const 0) (i32.const 28))))"#,
    )
    .unwrap()
}

/// A contract that succeeds without touching any resolved object, even
/// though the transaction may declare `Write`/`Consume` access.
fn preinstalled_noop_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (memory 1)
            (export "memory" (memory 0))
            (func (export "run")))"#,
    )
    .unwrap()
}

/// A contract that consumes `object[0]`.
fn preinstalled_consume_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "get_object_count"   (func $get_object_count   (result i32)))
            (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
            (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
            (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
            (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
            (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
            (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
            (import "env" "get_args_len"       (func $get_args_len       (result i32)))
            (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
            (import "env" "abort"              (func $abort              (param i32 i32)))
            (memory 1)
            (export "memory" (memory 0))
            (func (export "run")
              (drop (call $consume_object (i32.const 0)))))"#,
    )
    .unwrap()
}

/// A contract that calls `create_object` once, matching
/// `execution::wasm_engine`'s own `create_object` test fixture layout
/// (34-byte type hash at offset 0, one data byte at offset 34).
fn preinstalled_create_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "get_object_count"   (func $get_object_count   (result i32)))
            (import "env" "get_object_data_len"(func $get_object_data_len(param i32)(result i32)))
            (import "env" "read_object_data"   (func $read_object_data   (param i32 i32 i32 i32)(result i32)))
            (import "env" "write_object_data"  (func $write_object_data  (param i32 i32 i32)(result i32)))
            (import "env" "consume_object"     (func $consume_object     (param i32)(result i32)))
            (import "env" "create_object"      (func $create_object      (param i32 i32 i32 i32 i32 i32)(result i32)))
            (import "env" "emit_event"         (func $emit_event         (param i32 i32 i32 i32)(result i32)))
            (import "env" "get_args_len"       (func $get_args_len       (result i32)))
            (import "env" "read_args"          (func $read_args          (param i32 i32 i32)(result i32)))
            (import "env" "abort"              (func $abort              (param i32 i32)))
            (memory 1)
            (export "memory" (memory 0))
            (data (i32.const 0) "\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\FF")
            (func (export "run")
              (drop (call $create_object (i32.const 34) (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 0) (i32.const 0)))))"#,
    )
    .unwrap()
}

/// A contract that creates an Address-owned object using the historical
/// universal ZIP-215 non-canonical identity encoding. Profile 1 admits
/// these owner bytes, while profile 2 must reject them before durable
/// commit. The separate Create prohibition remains in force either way.
fn preinstalled_create_with_inadmissible_owner_wasm_bytes() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "create_object" (func $create_object (param i32 i32 i32 i32 i32 i32)(result i32)))
            (memory 1)
            (export "memory" (memory 0))
            (data (i32.const 0) "\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\FF")
            (data (i32.const 35) "\01")
            (data (i32.const 66) "\80")
            (func (export "run")
              (drop (call $create_object (i32.const 34) (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 3) (i32.const 35)))))"#,
    )
    .unwrap()
}

fn preinstalled_manifest(
    module_id: ModuleId,
    max_input_size: u64,
) -> system_modules::SystemModuleManifest {
    system_modules::SystemModuleManifest {
        module_id,
        input_schema: system_modules::TypeSchema {
            descriptor: "counter.input.v1".to_string(),
            schema_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x11; 32]),
        },
        output_schema: system_modules::TypeSchema {
            descriptor: "counter.output.v1".to_string(),
            schema_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
        },
        max_input_size,
        gas_model: system_modules::GasModel {
            base_cost: 1,
            per_input_byte_cost: 1,
        },
        zk_hint: None,
    }
}

/// Builds a committed [`SystemModuleRegistry`] entry and a matching
/// [`PreinstalledModuleCatalog`] entry whose commitments agree, plus the
/// `ObjectRef` an authenticated transaction must declare as `module_ref`
/// to reference it (see [`preinstalled_wasm::resolve_preinstalled_module`]
/// for the exact mapping).
fn preinstalled_module_fixture(
    resolver: &HashSuiteResolver,
    module_id: ModuleId,
    version: u64,
    wasm_bytes: Vec<u8>,
    max_input_size: u64,
    activation_epoch: Epoch,
    status: system_modules::ModuleStatus,
) -> (SystemModuleRegistry, PreinstalledModuleCatalog, ObjectRef) {
    let envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::opaque_only(b"test-semantics-v1".to_vec()).unwrap();
    preinstalled_module_fixture_with_envelope(
        resolver,
        module_id,
        version,
        wasm_bytes,
        max_input_size,
        activation_epoch,
        status,
        envelope,
    )
}

#[allow(clippy::too_many_arguments)]
fn preinstalled_module_fixture_with_envelope(
    resolver: &HashSuiteResolver,
    module_id: ModuleId,
    version: u64,
    wasm_bytes: Vec<u8>,
    max_input_size: u64,
    activation_epoch: Epoch,
    status: system_modules::ModuleStatus,
    envelope: PreinstalledModuleSemanticsEnvelope,
) -> (SystemModuleRegistry, PreinstalledModuleCatalog, ObjectRef) {
    let manifest = preinstalled_manifest(module_id, max_input_size);
    let code_hash = resolver
        .hash_for_purpose(Epoch::new(0), HashPurpose::ContractCode, &wasm_bytes)
        .unwrap();
    let manifest_bytes = system_modules::encode_system_module_manifest(&manifest).unwrap();
    let manifest_hash = resolver
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::SystemModuleManifest,
            &manifest_bytes,
        )
        .unwrap();
    let semantics_bytes: Vec<u8> = encode_preinstalled_semantics_envelope(&envelope).unwrap();
    let semantics_hash: Digest32 = resolver
        .hash_for_purpose(
            Epoch::new(0),
            HashPurpose::SystemModuleManifest,
            &semantics_bytes,
        )
        .unwrap();
    let module = system_modules::SystemModule {
        module_id,
        version,
        canonical_code_hash: code_hash,
        semantics_hash,
        manifest_hash,
        activation_epoch,
        status,
    };
    let mut registry = SystemModuleRegistry::new();
    registry.add_module(module).unwrap();
    let entry =
        PreinstalledModuleCatalogEntry::new(module_id, version, wasm_bytes, manifest, envelope)
            .unwrap();
    let catalog = PreinstalledModuleCatalog::new(vec![entry]).unwrap();
    let module_ref = ObjectRef {
        id: ObjectId::new(*module_id.as_bytes()),
        version,
        digest: code_hash,
    };
    (registry, catalog, module_ref)
}

fn preinstalled_transaction(
    sender: Address,
    chain: ChainId,
    epoch: Epoch,
    nonce: u64,
    access_manifest: AccessManifest,
    module_ref: ObjectRef,
    args: Vec<u8>,
) -> Transaction {
    preinstalled_transaction_with_protocol_version(
        sender,
        chain,
        ProtocolVersion::new(3),
        epoch,
        nonce,
        access_manifest,
        module_ref,
        args,
    )
}

#[allow(clippy::too_many_arguments)]
fn preinstalled_transaction_with_protocol_version(
    sender: Address,
    chain: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    nonce: u64,
    access_manifest: AccessManifest,
    module_ref: ObjectRef,
    args: Vec<u8>,
) -> Transaction {
    Transaction {
        chain_id: chain,
        protocol_version,
        epoch,
        sender,
        nonce,
        access_manifest,
        module_ref,
        entrypoint: "run".to_string(),
        args,
        gas_limit: 1_000_000,
        fee_payment: None,
        signature: Vec::new(),
    }
}

const OWNER_TRANSITION_CONSTRUCTOR_ID: u16 = 0x7A01;
const OWNER_TRANSITION_BODY_TYPE_ID: u16 = 0x7A01;
const OWNER_TRANSITION_ARGS_TYPE_ID: u16 = 0x7A02;

fn owner_transition_envelope() -> PreinstalledModuleSemanticsEnvelope {
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
        vec![ParamDeclaration {
            mode: AccessMode::Write,
            constructor: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
            schema_version: 1,
        }],
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
    PreinstalledModuleSemanticsEnvelope::with_typed_policies(
        b"owner-transition-test".to_vec(),
        Vec::new(),
        vec![typed],
        vec![owner],
    )
    .unwrap()
}

fn owner_transition_args(recipient: Address) -> Vec<u8> {
    let mut args: CanonicalStruct = CanonicalStruct::new(OWNER_TRANSITION_ARGS_TYPE_ID, 1);
    args.field_bytes(1, recipient.as_bytes().to_vec()).unwrap();
    args.finish().unwrap()
}

fn owner_transition_object(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    id: ObjectId,
    owner: Address,
    data: Vec<u8>,
) -> Object {
    let type_hash: Digest32 = abi::derive_type_id(
        resolver,
        epoch,
        &TypeTag {
            constructor: ConstructorId::new(OWNER_TRANSITION_CONSTRUCTOR_ID),
            type_arg: None,
        },
    )
    .unwrap();
    let mut body: CanonicalStruct = CanonicalStruct::new(OWNER_TRANSITION_BODY_TYPE_ID, 1);
    body.field_bytes(1, data).unwrap();
    Object {
        id,
        version: 1,
        owner: Owner::Address(owner),
        type_hash,
        schema_version: 1,
        data: body.finish().unwrap(),
    }
}

fn zero_fee_policy() -> CommittedFeePolicy {
    let config: ProtocolConfig = ProtocolConfig::genesis();
    CommittedFeePolicy {
        gas_schedule: config.gas_schedule,
        fee_assets: config.fee_assets,
    }
}

fn submit_event_for_protocol(protocol_version: ProtocolVersion, request_byte: u8) -> NodeEvent {
    NodeEvent::new(
        ChainId::new("sunrise-test").unwrap(),
        protocol_version,
        Epoch::new(7),
        request(request_byte),
        NodeEventKind::SubmitTransaction,
        canonical(TEST_PAYLOAD_TYPE_ID, 9),
    )
    .unwrap()
}

fn load_cross_owner_destination_with_policy(
    policy: Option<PreinstalledObjectAccessPolicy>,
    entrypoint: &str,
    destination_mode: AccessMode,
    destination_owner: Owner,
    source_is_sender: bool,
) -> Result<LoadedAuthenticatedObjects, NodeCoreError> {
    let store: ScriptedDurableStore = ScriptedDurableStore::new(DurableCommitOutcome::Committed);
    let sender: Address = Address::new([0x41; 32]);
    let (source_ref, _source_head) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x42; 32]),
        Owner::Address(if source_is_sender {
            sender
        } else {
            Address::new([0x98; 32])
        }),
        0x30,
    );
    let (destination_ref, _destination_head) = preload_inline_object(
        &store,
        "sunrise-test",
        ObjectId::new([0x43; 32]),
        destination_owner,
        0x31,
    );
    let dispatch = AuthenticatedObjectDispatch {
        authority: sender,
        owner_address_policy: Ed25519OwnerAddressPolicy::LegacyZip215,
        accesses: vec![
            AuthenticatedObjectAccess {
                object_ref: source_ref,
                mode: AccessMode::Write,
            },
            AuthenticatedObjectAccess {
                object_ref: destination_ref,
                mode: destination_mode,
            },
        ],
    };
    let policies: Vec<PreinstalledObjectAccessPolicy> = policy.into_iter().collect();
    let envelope: PreinstalledModuleSemanticsEnvelope =
        PreinstalledModuleSemanticsEnvelope::new(b"test".to_vec(), policies).unwrap();
    let authorization = ResolvedPreinstalledAuthorization {
        entrypoint,
        envelope: &envelope,
    };
    load_and_authorize_objects(
        &store,
        &MemoryBlobStore::default(),
        &durable_context(),
        domain(0x44),
        &ChainId::new("sunrise-test").unwrap(),
        &dispatch,
        Some(&authorization),
        None,
    )
}
