//! Constants independently reconstructed by scripts/local-execution-vectors.mjs.
use abi::call_values::{CallAbi, CallValue, ValueLayout, encode_call_value};
use abi::executable_abi::{ExecutableAbi, decode_executable_abi, encode_executable_abi};
use abi::package_types::{PackageOrigin, ScopedTypeTag};
use abi::public_abi::{ConstructorDeclaration, EntrypointDeclaration, PackageAbi};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::{CallIntent, encode_instance_target};
use execution::local_execution::*;
use execution::publication::{PublicationContext, UnverifiedDependencyRef};
use execution::{ExecutionEffects, ExecutionStatus};
use hashing::HashSuiteResolver;
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn vector(bytes: &[u8], length: usize, expected: &str) {
    assert_eq!(bytes.len(), length);
    assert_eq!(hex(&Sha256::digest(bytes)), expected);
}

#[test]
fn independently_reconstructed_execution_wires_and_signature() {
    let chain: ChainId = ChainId::new("local-vector").unwrap();
    let context: PublicationContext =
        PublicationContext::new(chain.clone(), ProtocolVersion::new(3), Epoch::new(0)).unwrap();
    let resolver: HashSuiteResolver = HashSuiteResolver::new(
        chain.clone(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    let key: SigningKey = SigningKey::from([7; 32]);
    let sender: [u8; 32] = VerificationKey::from(&key).into();
    let origin: PackageOrigin = PackageOrigin::unverified(chain, sender, [10; 32]).unwrap();
    let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        origin.clone(),
        1,
        context.clone(),
        Digest32::new(HashAlgorithmId::Sha2_256, [0x66; 32]),
    )
    .unwrap();
    let metadata: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: vec![ConstructorDeclaration {
                    local_id: 1,
                    schema: 1,
                    arguments: vec![],
                }],
                entrypoints: vec![EntrypointDeclaration {
                    name: "run".into(),
                    type_parameters: vec![],
                    objects: vec![],
                }],
            },
            arguments: vec![ValueLayout::Tuple(vec![])],
            bodies: vec![ValueLayout::U64],
        },
        initializer: Some("run".into()),
        transferable_constructors: vec![1],
        results: vec![vec![]],
    };
    let encoded: Vec<u8> = encode_executable_abi(&metadata).unwrap();
    vector(
        &encoded,
        478,
        "b6e038faaae51d2e955f7c769de0124d48371e0fa3e1858b567fd0add917ae54",
    );
    assert_eq!(decode_executable_abi(&encoded).unwrap(), metadata);
    vector(
        &encode_local_execution_semantics().unwrap(),
        150,
        "153a5fd1ce1d960598cd98cbeb64990cc6df8d8415f6e74ae5289ce916019002",
    );
    let policy: LocalExecutionPolicy = LocalExecutionPolicy::new(context.clone());
    vector(
        &policy.encode().unwrap(),
        386,
        "b644dbfe79db0cb61c9b183ab5b3ad23e72861651418c43df804a33f74e51586",
    );
    assert_eq!(
        LocalExecutionPolicy::decode(&policy.encode().unwrap()).unwrap(),
        policy
    );
    let record: InstanceRecord = InstanceRecord {
        context: context.clone(),
        creator: sender,
        seed: [2; 32],
        code: code.clone(),
        revision: 1,
        initializer: "run".into(),
    };
    vector(
        &encode_instance_record(&record).unwrap(),
        435,
        "87aa76edf3ccb09490d69fcb0fddd781a67944b940f8c4b80c15b8d38e49e252",
    );
    assert_eq!(
        decode_instance_record(&encode_instance_record(&record).unwrap()).unwrap(),
        record
    );
    let target = instance_target(&resolver, &record).unwrap();
    vector(
        &encode_instance_target(&target).unwrap(),
        162,
        "5a9d72a4556636cfd27e21818f9f4b8fc212fbfa256f9849731c47df6ebbff8b",
    );
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        authorizations: Vec::new(),
        mode: LocalExecutionMode::Instantiate,
        policy_digest: policy.digest(&resolver).unwrap(),
        call: CallIntent {
            context: context.clone(),
            request_id: [3; 32],
            sender,
            nonce: 4,
            code: code.clone(),
            instance: target.clone(),
            entrypoint: "run".into(),
            type_arguments: vec![],
            access: abi::AccessManifest { entries: vec![] },
            arguments: encode_call_value(&ValueLayout::Tuple(vec![]), &CallValue::Tuple(vec![]))
                .unwrap(),
            gas_limit: 100_000,
        },
    };
    vector(
        &encode_local_execution_intent(&intent).unwrap(),
        801,
        "d7e705bbbf4610fa6bd82a702555d6b856e0d120a6c3ccaa56aac0b4a1d5a5c0",
    );
    let signing: Vec<u8> = local_execution_signing_frame(&context, &intent).unwrap();
    vector(
        &signing,
        893,
        "7bc8b9511c3819631f94b8d287e7401dfcaf5e7bf330284e2f1fffcc02268723",
    );
    let signed: SignedLocalExecutionIntent = SignedLocalExecutionIntent {
        intent,
        signature: key.sign(&signing).into(),
    };
    assert_eq!(
        hex(&signed.signature),
        "137d1b45ca14f261f4a19e36e480b224a6cd59898a40edb5104775557816bb68104f69caffd2cb3f2d188b99c640414436cee07f0258a051aacf84bbcdd1e603"
    );
    let bytes: Vec<u8> = encode_signed_local_execution(&signed).unwrap();
    vector(
        &bytes,
        887,
        "e7df11bf8073a1309b16ee152777cb3b3289f4789a54019702dfd401eafd3bd0",
    );
    authenticate_local_execution(&resolver, &policy, &bytes).unwrap();
    let event: Digest32 = local_execution_event_digest(&resolver, &signed).unwrap();
    assert_eq!(
        hex(&event.bytes()),
        "10306f955b32e62bcf94585df4456c67d210873436633828064f650d194e6c71"
    );
    let id = derive_local_created_object_id(
        &resolver,
        &context,
        &record.context,
        &target,
        &code,
        event,
        0,
    )
    .unwrap();
    assert_eq!(
        hex(id.as_bytes()),
        "db57cdc4d9903664392b6118ae2c3f418fd239691f5286b4101950e4e622656e"
    );
    let authority: ObjectAuthority = ObjectAuthority {
        object_id: id,
        instance_context: context.clone(),
        instance: target,
        code,
        ty: ScopedTypeTag::new(origin, 1, vec![]).unwrap(),
    };
    vector(
        &encode_object_authority(&authority).unwrap(),
        692,
        "af7bbd49be81eb7195de8cf2b925e48f044b785004eb02505d9c3b400b1dce90",
    );
    assert_eq!(
        decode_object_authority(&encode_object_authority(&authority).unwrap()).unwrap(),
        authority
    );
    let mut result: LocalExecutionResult = LocalExecutionResult {
        request_id: [3; 32],
        instance: record,
        mode: LocalExecutionMode::Instantiate,
        effects: ExecutionEffects {
            tx_hash: event,
            status: ExecutionStatus::Success,
            object_effects: vec![],
            events: vec![],
            gas_used: 42,
        },
    };
    vector(
        &encode_local_execution_result(&result).unwrap(),
        648,
        "43277aaa01fab2d97cc1ce20ea7d491d20def0516bea3c51c8cdb99a1326add6",
    );
    validate_local_execution_result(&resolver, &resolver, &signed, &result).unwrap();
    result.effects.status = ExecutionStatus::Failure {
        reason: LOCAL_EXECUTION_TRAP_REASON.into(),
    };
    let rejected: Vec<u8> = encode_local_execution_result(&result).unwrap();
    vector(
        &rejected,
        676,
        "5e2664f3824ac57fbcca7368f77f1f3ad35ad48ac546fee59a7e7c3f31c30388",
    );
    assert_eq!(decode_local_execution_result(&rejected).unwrap(), result);
    validate_local_execution_result(&resolver, &resolver, &signed, &result).unwrap();

    type Decoder = fn(&[u8]) -> bool;
    let decoders: Vec<(&str, Vec<u8>, Decoder)> = vec![
        ("executable ABI", encoded, |b| {
            decode_executable_abi(b).is_ok()
        }),
        ("policy", policy.encode().unwrap(), |b| {
            LocalExecutionPolicy::decode(b).is_ok()
        }),
        (
            "record",
            encode_instance_record(&result.instance).unwrap(),
            |b| decode_instance_record(b).is_ok(),
        ),
        (
            "intent",
            encode_local_execution_intent(&signed.intent).unwrap(),
            |b| decode_local_execution_intent(b).is_ok(),
        ),
        ("signed", bytes, |b| {
            decode_signed_local_execution(b).is_ok()
        }),
        (
            "authority",
            encode_object_authority(&authority).unwrap(),
            |b| decode_object_authority(b).is_ok(),
        ),
        ("result", rejected, |b| {
            decode_local_execution_result(b).is_ok()
        }),
    ];
    for (name, original, decode) in decoders {
        assert!(decode(&original), "{name}");
        let mut trailing: Vec<u8> = original.clone();
        trailing.push(0);
        assert!(!decode(&trailing), "trailing {name}");
        let mut unknown_version: Vec<u8> = original.clone();
        unknown_version[6..8].copy_from_slice(&99u16.to_le_bytes());
        assert!(!decode(&unknown_version), "version {name}");
        let mut unknown_field: Vec<u8> = original.clone();
        let count: u16 = u16::from_le_bytes([original[8], original[9]]);
        unknown_field[8..10].copy_from_slice(&count.checked_add(1).unwrap().to_le_bytes());
        unknown_field.extend_from_slice(&u16::MAX.to_le_bytes());
        unknown_field.extend_from_slice(&0u32.to_le_bytes());
        assert!(!decode(&unknown_field), "field {name}");
    }
}

/// Pins the exact wire bytes introduced by DR-0124: the profile-four
/// semantics descriptor, the profile-four execution policy, and a
/// version-two executable ABI wrapper carrying one declared result slot.
/// Any change to these lengths or digests is a wire change and must be
/// deliberate; the profile-two and profile-three vectors above are
/// unaffected by construction, since none of them encode a `results` field.
#[test]
fn generic_object_result_semantics_policy_and_abi_wires_are_stable() {
    use abi::public_abi::{ObjectMode, ObjectResultDeclaration, TypePattern};

    let chain: ChainId = ChainId::new("local-vector").unwrap();
    let context: PublicationContext =
        PublicationContext::new(chain.clone(), ProtocolVersion::new(3), Epoch::new(0)).unwrap();
    let key: SigningKey = SigningKey::from([7; 32]);
    let sender: [u8; 32] = VerificationKey::from(&key).into();
    let origin: PackageOrigin = PackageOrigin::unverified(chain, sender, [10; 32]).unwrap();

    let semantics: Vec<u8> = encode_generic_object_result_semantics().unwrap();
    vector(
        &semantics,
        202,
        "01ff9f7b2bff859423cf7dbf82e2c4b8c73ec145c484f188b403afb302da039d",
    );

    let policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context);
    let encoded_policy: Vec<u8> = policy.encode().unwrap();
    vector(
        &encoded_policy,
        522,
        "e834e8b5a28257d9e8db72cd6ffaa7c09f02b058d46274cacdbbda009b589aa7",
    );
    assert_eq!(
        LocalExecutionPolicy::decode(&encoded_policy).unwrap(),
        policy
    );

    let metadata: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: vec![ConstructorDeclaration {
                    local_id: 1,
                    schema: 1,
                    arguments: vec![],
                }],
                entrypoints: vec![EntrypointDeclaration {
                    name: "run".into(),
                    type_parameters: vec![],
                    objects: vec![],
                }],
            },
            arguments: vec![ValueLayout::Tuple(vec![])],
            bodies: vec![ValueLayout::U64],
        },
        initializer: Some("run".into()),
        transferable_constructors: vec![1],
        results: vec![vec![ObjectResultDeclaration {
            mode: ObjectMode::Consume,
            schema: 1,
            ty: TypePattern {
                origin,
                constructor: 1,
                arguments: vec![],
            },
            optional: false,
        }]],
    };
    let encoded_abi: Vec<u8> = encode_executable_abi(&metadata).unwrap();
    vector(
        &encoded_abi,
        734,
        "486216472e343b05a9ee8158a4f1e629ae8f31f7d76d20b4c72e205e74a004f2",
    );
    assert_eq!(decode_executable_abi(&encoded_abi).unwrap(), metadata);
}
