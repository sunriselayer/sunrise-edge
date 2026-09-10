use abi::call_values::{CallAbi, CallValue, ValueLayout, encode_call_value};
use abi::executable_abi::{ExecutableAbi, decode_executable_abi, encode_executable_abi};
use abi::package_types::{PackageOrigin, ScopedTypeTag};
use abi::public_abi::{ConstructorDeclaration, EntrypointDeclaration, PackageAbi};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::{
    CallIntent, SignedCallIntent, authenticate_call_intent, encode_signed_call_intent,
};
use execution::local_execution::*;
use execution::publication::*;
use execution::{
    ExecutionEffects, ExecutionStatus, validate_contract_wasm, validate_contract_wasm_profile,
};
use hashing::HashSuiteResolver;
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("instance-test").unwrap(),
        ProtocolVersion::new(7),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("instance-test").unwrap(),
        ProtocolVersion::new(7),
        Epoch::new(0),
    )
    .unwrap()
}
fn key() -> SigningKey {
    SigningKey::from([7; 32])
}
fn metadata(seed: u8, initializer: Option<&str>) -> ExecutableAbi {
    let origin: PackageOrigin = PackageOrigin::unverified(
        context().chain_id().clone(),
        VerificationKey::from(&key()).into(),
        [seed; 32],
    )
    .unwrap();
    ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin,
                constructors: vec![ConstructorDeclaration {
                    local_id: 1,
                    schema: 1,
                    arguments: vec![],
                }],
                entrypoints: ["init", "run"]
                    .iter()
                    .map(|name| EntrypointDeclaration {
                        name: (*name).into(),
                        type_parameters: vec![],
                        objects: vec![],
                    })
                    .collect(),
            },
            arguments: vec![ValueLayout::Tuple(vec![]), ValueLayout::Tuple(vec![])],
            bodies: vec![ValueLayout::U64],
        },
        initializer: initializer.map(str::to_owned),
        transferable_constructors: vec![1],
        results: vec![vec![], vec![]],
    }
}
fn publication(
    seed: u8,
    initializer: Option<&str>,
    dependencies: Vec<UnverifiedDependencyRef>,
) -> AuthenticatedPublicationCandidate {
    let meta: ExecutableAbi = metadata(seed, initializer);
    let artifact:CodeArtifact=CodeArtifact::new(ArtifactParts{context:context(),origin:meta.call.objects.origin.clone(),revision:1,wasm_profile:2,semantics:local_execution_semantics(&resolver(),&context()).unwrap(),wasm:wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"init\")) (func (export \"run\")))").unwrap(),unverified_abi:encode_executable_abi(&meta).unwrap(),exports:vec!["init".into(),"run".into()],unverified_dependencies:dependencies}).unwrap();
    let digest: Digest32 = artifact_commitment(&resolver(), &context(), &artifact).unwrap();
    let frame: Vec<u8> =
        publication_submission_signing_frame(&resolver(), &context(), &artifact, 0, [seed; 32])
            .unwrap();
    let submission: PublicationSubmission = PublicationSubmission::new(
        [seed; 32],
        PublicationRequest::new(artifact, 0, digest, key().sign(&frame).into()),
    )
    .unwrap();
    authenticate_publication_submission(
        &resolver(),
        &context(),
        &local_execution_semantics(&resolver(), &context()).unwrap(),
        submission,
    )
    .unwrap()
}
fn reference(candidate: &AuthenticatedPublicationCandidate) -> UnverifiedDependencyRef {
    let artifact: &CodeArtifact = candidate.artifact();
    UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        1,
        artifact.context().clone(),
        *candidate.digest(),
    )
    .unwrap()
}
fn fixture() -> (
    VerifiedPublicationInterface,
    InstanceRecord,
    SignedLocalExecutionIntent,
) {
    let candidate: AuthenticatedPublicationCandidate = publication(1, Some("init"), vec![]);
    let record: InstanceRecord = InstanceRecord {
        context: context(),
        creator: VerificationKey::from(&key()).into(),
        seed: [2; 32],
        code: reference(&candidate),
        revision: 1,
        initializer: "init".into(),
    };
    let call: CallIntent = CallIntent {
        context: context(),
        request_id: [3; 32],
        sender: record.creator,
        nonce: 0,
        code: record.code.clone(),
        instance: instance_target(&resolver(), &record).unwrap(),
        entrypoint: "init".into(),
        type_arguments: vec![],
        access: abi::AccessManifest { entries: vec![] },
        arguments: encode_call_value(&ValueLayout::Tuple(vec![]), &CallValue::Tuple(vec![]))
            .unwrap(),
        gas_limit: 10000,
    };
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        authorizations: Vec::new(),
        mode: LocalExecutionMode::Instantiate,
        policy_digest: LocalExecutionPolicy::new(context())
            .digest(&resolver())
            .unwrap(),
        call,
    };
    let signed: SignedLocalExecutionIntent = sign(intent);
    (
        verify_publication_interface(candidate, vec![]).unwrap(),
        record,
        signed,
    )
}
fn sign(intent: LocalExecutionIntent) -> SignedLocalExecutionIntent {
    let signature: [u8; 64] = key()
        .sign(&local_execution_signing_frame(&context(), &intent).unwrap())
        .into();
    SignedLocalExecutionIntent { intent, signature }
}

#[test]
fn typed_profile_whitelists_only_sunrise_and_exact_signatures() {
    let typed:Vec<u8>=wat::parse_str("(module (import \"sunrise\" \"get_caller\" (func (param i32) (result i32))) (memory (export \"memory\") 1 2) (func (export \"run\")))").unwrap();
    assert!(validate_contract_wasm(&typed, &["run"]).is_err());
    assert_eq!(
        validate_contract_wasm_profile(&typed, &["run"], 2)
            .unwrap()
            .profile_version(),
        2
    );
    let legacy:Vec<u8>=wat::parse_str("(module (import \"env\" \"get_object_count\" (func (result i32))) (memory (export \"memory\") 1 2) (func (export \"run\")))").unwrap();
    assert!(validate_contract_wasm(&legacy, &["run"]).is_ok());
    assert!(validate_contract_wasm_profile(&legacy, &["run"], 2).is_err());
    let wrong:Vec<u8>=wat::parse_str("(module (import \"sunrise\" \"create_object\" (func (param i32 i32 i32 i32 i32 i32) (result i32))) (memory (export \"memory\") 1 2) (func (export \"run\")))").unwrap();
    assert!(validate_contract_wasm_profile(&wrong, &["run"], 2).is_err());
    assert!(validate_contract_wasm_profile(&typed, &["run"], 3).is_ok());
    assert_eq!(
        validate_contract_wasm_profile(&typed, &["run"], 4)
            .unwrap()
            .profile_version(),
        4
    );
    assert!(validate_contract_wasm_profile(&typed, &["run"], 5).is_err());
}

#[test]
fn executable_wrapper_rejects_invalid_roles_permissions_and_historical_bytes() {
    let valid: ExecutableAbi = metadata(1, Some("init"));
    let bytes: Vec<u8> = encode_executable_abi(&valid).unwrap();
    assert_eq!(decode_executable_abi(&bytes).unwrap(), valid);
    assert!(
        decode_executable_abi(&abi::call_values::encode_call_abi(&valid.call).unwrap()).is_err()
    );
    let mut wrong: ExecutableAbi = valid.clone();
    wrong.initializer = Some("missing".into());
    assert!(encode_executable_abi(&wrong).is_err());
    wrong = valid.clone();
    wrong.transferable_constructors = vec![1, 1];
    assert!(encode_executable_abi(&wrong).is_err());
    wrong = valid.clone();
    wrong.transferable_constructors = vec![2];
    assert!(encode_executable_abi(&wrong).is_err());
    wrong = valid.clone();
    wrong.call.objects.entrypoints[0].type_parameters =
        vec![abi::public_abi::ArgumentKind::Nominal];
    assert!(encode_executable_abi(&wrong).is_err());
    assert!(encode_executable_abi(&metadata(1, None)).is_ok());
    let mut trailing: Vec<u8> = bytes;
    trailing.push(0);
    assert!(decode_executable_abi(&trailing).is_err());
}

#[test]
fn execution_domain_policy_and_creator_are_signed_before_admission() {
    let (interface, _record, signed) = fixture();
    let policy: LocalExecutionPolicy = LocalExecutionPolicy::new(context());
    let bytes: Vec<u8> = encode_signed_local_execution(&signed).unwrap();
    let authenticated = authenticate_local_execution(&resolver(), &policy, &bytes).unwrap();
    assert!(bind_local_execution(&authenticated, &interface).is_ok());
    assert_eq!(decode_signed_local_execution(&bytes).unwrap(), signed);
    let old: SignedCallIntent = SignedCallIntent {
        intent: signed.intent.call.clone(),
        signature: signed.signature,
    };
    assert!(
        authenticate_call_intent(&context(), &encode_signed_call_intent(&old).unwrap()).is_err()
    );
    let mut changed: SignedLocalExecutionIntent = signed.clone();
    changed.intent.call.request_id = [4; 32];
    assert!(
        authenticate_local_execution(
            &resolver(),
            &policy,
            &encode_signed_local_execution(&changed).unwrap()
        )
        .is_err()
    );
    changed = signed.clone();
    changed.intent.policy_digest = Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]);
    assert!(
        authenticate_local_execution(
            &resolver(),
            &policy,
            &encode_signed_local_execution(&changed).unwrap()
        )
        .is_err()
    );
    changed = signed.clone();
    changed.intent.call.instance.creator = VerificationKey::from(&SigningKey::from([8; 32])).into();
    assert!(encode_signed_local_execution(&changed).is_err());
    let mut ordinary: LocalExecutionIntent = signed.intent;
    ordinary.mode = LocalExecutionMode::Call;
    let ordinary: SignedLocalExecutionIntent = sign(ordinary);
    let authenticated = authenticate_local_execution(
        &resolver(),
        &policy,
        &encode_signed_local_execution(&ordinary).unwrap(),
    )
    .unwrap();
    assert!(bind_local_execution(&authenticated, &interface).is_err());
    assert_eq!(
        LocalExecutionPolicy::decode(&policy.encode().unwrap()).unwrap(),
        policy
    );
}

#[test]
fn library_views_share_immutable_wasm_and_retain_defining_metadata() {
    let library = publication(1, None, vec![]);
    let origin = library.artifact().origin().clone();
    let root = publication(2, Some("init"), vec![reference(&library)]);
    let interface = verify_publication_interface(root, vec![library]).unwrap();
    let view = interface.for_origin(&origin).unwrap();
    assert!(std::ptr::eq(
        view.candidate().request().expect("legacy candidate"),
        interface.dependencies()[0]
            .request()
            .expect("legacy candidate")
    ));
    assert_eq!(view.executable_abi(&origin).unwrap().initializer, None);
    let ty: ScopedTypeTag = ScopedTypeTag::new(origin, 1, vec![]).unwrap();
    let body: Vec<u8> = encode_call_value(&ValueLayout::U64, &CallValue::U64(7)).unwrap();
    assert!(validate_nominal_body(&view, &ty, 1, &body).is_ok());
    assert!(validate_nominal_body(&view, &ty, 2, &body).is_err());
}

#[test]
fn instance_sidecar_creation_and_result_selectors_roundtrip_and_bind() {
    let (_interface, record, signed) = fixture();
    let target = instance_target(&resolver(), &record).unwrap();
    let event = local_execution_event_digest(&resolver(), &signed).unwrap();
    assert_eq!(
        decode_instance_record(&encode_instance_record(&record).unwrap()).unwrap(),
        record
    );
    let id = derive_local_created_object_id(
        &resolver(),
        &context(),
        &record.context,
        &target,
        &record.code,
        event,
        0,
    )
    .unwrap();
    let next = derive_local_created_object_id(
        &resolver(),
        &context(),
        &record.context,
        &target,
        &record.code,
        event,
        1,
    )
    .unwrap();
    assert_ne!(id, next);
    assert!(
        derive_local_created_object_id(
            &resolver(),
            &context(),
            &record.context,
            &target,
            &record.code,
            event,
            MAX_LOCAL_CREATED_OBJECTS
        )
        .is_err()
    );
    let authority: ObjectAuthority = ObjectAuthority {
        object_id: id,
        instance_context: record.context.clone(),
        instance: target,
        code: record.code.clone(),
        ty: ScopedTypeTag::new(record.code.origin().clone(), 1, vec![]).unwrap(),
    };
    assert_eq!(
        decode_object_authority(&encode_object_authority(&authority).unwrap()).unwrap(),
        authority
    );
    let result: LocalExecutionResult = LocalExecutionResult {
        request_id: signed.intent.call.request_id,
        instance: record,
        mode: signed.intent.mode,
        effects: ExecutionEffects {
            tx_hash: event,
            status: ExecutionStatus::Success,
            object_effects: vec![],
            events: vec![],
            gas_used: 3,
        },
    };
    assert_eq!(
        decode_local_execution_result(&encode_local_execution_result(&result).unwrap()).unwrap(),
        result
    );
    validate_local_execution_result(&resolver(), &resolver(), &signed, &result).unwrap();
    let mut wrong: LocalExecutionResult = result.clone();
    wrong.request_id = [8; 32];
    assert!(validate_local_execution_result(&resolver(), &resolver(), &signed, &wrong).is_err());
    wrong = result;
    wrong.effects.status = ExecutionStatus::Failure {
        reason: "raw vm implementation message".into(),
    };
    assert!(encode_local_execution_result(&wrong).is_err());
    wrong.effects.status = ExecutionStatus::Failure {
        reason: LOCAL_EXECUTION_TRAP_REASON.into(),
    };
    assert!(encode_local_execution_result(&wrong).is_ok());
}
