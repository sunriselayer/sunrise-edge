use abi::package_types::PackageOrigin;
use abi::{AccessEntry, AccessManifest};
use canonical_encoding::{CanonicalStruct, decode_canonical_frame};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::{CallIntent, InstanceTarget};
use execution::call_authorization::*;
use execution::local_execution::*;
use execution::publication::{PublicationContext, UnverifiedDependencyRef};
use hashing::HashSuiteResolver;
use objects::{AccessMode, ObjectId, ObjectRef};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};

fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("authorization-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap()
}
fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        context().chain_id().clone(),
        context().protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn key() -> SigningKey {
    SigningKey::from([7; 32])
}
fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}
fn target(seed: u8) -> ExecutionTarget {
    let sender: [u8; 32] = VerificationKey::from(&key()).into();
    ExecutionTarget {
        instance: InstanceTarget {
            creator: sender,
            seed: [seed; 32],
            revision: 1,
            record_digest: digest(seed),
        },
        code: UnverifiedDependencyRef::new(
            PackageOrigin::unverified(context().chain_id().clone(), sender, [10; 32]).unwrap(),
            1,
            context(),
            digest(66),
        )
        .unwrap(),
    }
}
fn authorization() -> CallAuthorization {
    CallAuthorization {
        caller: target(1),
        callee: target(2),
        entrypoint: "run".into(),
        type_arguments: vec![],
        objects: vec![AuthorizedObject {
            object_id: ObjectId::new([44; 32]),
            mode: AccessMode::Read,
        }],
    }
}
fn intent(general: bool) -> LocalExecutionIntent {
    let root = target(1);
    let policy = if general {
        LocalExecutionPolicy::general(context())
    } else {
        LocalExecutionPolicy::new(context())
    };
    LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&resolver()).unwrap(),
        authorizations: vec![],
        call: CallIntent {
            context: context(),
            request_id: [5; 32],
            sender: VerificationKey::from(&key()).into(),
            nonce: 0,
            code: root.code,
            instance: root.instance,
            entrypoint: "run".into(),
            type_arguments: vec![],
            access: AccessManifest {
                entries: vec![AccessEntry {
                    object_ref: ObjectRef {
                        id: ObjectId::new([44; 32]),
                        version: 1,
                        digest: digest(45),
                    },
                    mode: AccessMode::Read,
                }],
            },
            arguments: vec![],
            gas_limit: 1000,
        },
    }
}
fn signed(intent: LocalExecutionIntent) -> SignedLocalExecutionIntent {
    let signature = key()
        .sign(&local_execution_signing_frame(&context(), &intent).unwrap())
        .into();
    SignedLocalExecutionIntent { intent, signature }
}
#[test]
fn ordered_authorization_roundtrips_and_has_no_implicit_arguments() {
    let authorization = authorization();
    let bytes = encode_call_authorizations(std::slice::from_ref(&authorization)).unwrap();
    assert_eq!(
        decode_call_authorizations(&bytes).unwrap(),
        vec![authorization.clone()]
    );
    assert_eq!(
        decode_execution_target(&encode_execution_target(&authorization.callee).unwrap()).unwrap(),
        authorization.callee
    );
    assert_eq!(
        decode_authorized_object(&encode_authorized_object(&authorization.objects[0]).unwrap())
            .unwrap(),
        authorization.objects[0]
    );
    assert_eq!(
        decode_call_authorizations(&encode_call_authorizations(&[]).unwrap()).unwrap(),
        vec![]
    );
}
#[test]
fn malformed_versions_fields_lengths_counts_and_duplicate_selectors_reject() {
    let bytes = encode_call_authorizations(&[authorization()]).unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_call_authorizations(&trailing).is_err());
    let mut version = bytes.clone();
    version[6] = 2;
    assert!(decode_call_authorizations(&version).is_err());
    let mut count = CanonicalStruct::new(0x640F, 1);
    count.field_u32(1, 17).unwrap();
    assert!(decode_call_authorizations(&count.finish().unwrap()).is_err());
    let mut extra = CanonicalStruct::new(0x640F, 1);
    extra.field_u32(1, 0).unwrap();
    extra.field_u32(2, 0).unwrap();
    assert!(decode_call_authorizations(&extra.finish().unwrap()).is_err());
    assert!(decode_call_authorizations(&vec![0; MAX_CALL_AUTHORIZATION_BYTES + 1]).is_err());
    let mut duplicate = authorization();
    duplicate.objects.push(duplicate.objects[0].clone());
    assert!(encode_call_authorizations(&[duplicate]).is_err());
    assert!(encode_call_authorizations(&vec![authorization(); 17]).is_err());
    let mut many = authorization();
    many.objects = vec![many.objects[0].clone(); 33];
    assert!(encode_call_authorizations(&[many]).is_err());
}
#[test]
fn root_manifest_ceiling_and_exact_targets_are_checked_before_signing() {
    let mut value = intent(true);
    value.authorizations = vec![authorization()];
    assert!(encode_local_execution_intent(&value).is_ok());
    value.authorizations[0].objects[0].mode = AccessMode::Write;
    assert!(encode_local_execution_intent(&value).is_err());
    value.authorizations[0] = authorization();
    value.authorizations[0].objects[0].object_id = ObjectId::new([99; 32]);
    assert!(encode_local_execution_intent(&value).is_err());
    value.authorizations[0] = authorization();
    value.authorizations[0].callee.instance.seed = [1; 32];
    assert!(encode_local_execution_intent(&value).is_err());
    value.authorizations[0] = authorization();
    value.authorizations[0].callee.code =
        UnverifiedDependencyRef::new(target(1).code.origin().clone(), 1, context(), digest(99))
            .unwrap();
    assert!(encode_local_execution_intent(&value).is_err());
    value.authorizations = (2..=9)
        .map(|seed| CallAuthorization {
            callee: target(seed),
            ..authorization()
        })
        .collect();
    assert!(encode_local_execution_intent(&value).is_err());
}
#[test]
fn v1_and_v2_signatures_cannot_acquire_or_drop_authorizations() {
    let old = signed(intent(false));
    let old_bytes = encode_signed_local_execution(&old).unwrap();
    assert_eq!(decode_canonical_frame(&old_bytes).unwrap().version(), 1);
    assert!(
        authenticate_local_execution(
            &resolver(),
            &LocalExecutionPolicy::new(context()),
            &old_bytes
        )
        .is_ok()
    );
    let mut new = intent(true);
    new.authorizations = vec![authorization()];
    let new = signed(new);
    let new_bytes = encode_signed_local_execution(&new).unwrap();
    assert_eq!(decode_canonical_frame(&new_bytes).unwrap().version(), 2);
    assert!(
        authenticate_local_execution(
            &resolver(),
            &LocalExecutionPolicy::general(context()),
            &new_bytes
        )
        .is_ok()
    );
    assert!(
        authenticate_local_execution(
            &resolver(),
            &LocalExecutionPolicy::new(context()),
            &new_bytes
        )
        .is_err()
    );
    let mut removed = new.clone();
    removed.intent.authorizations.clear();
    assert!(
        authenticate_local_execution(
            &resolver(),
            &LocalExecutionPolicy::general(context()),
            &encode_signed_local_execution(&removed).unwrap()
        )
        .is_err()
    );
    let mut modified = new.clone();
    modified.intent.authorizations[0].entrypoint = "other".into();
    assert!(
        authenticate_local_execution(
            &resolver(),
            &LocalExecutionPolicy::general(context()),
            &encode_signed_local_execution(&modified).unwrap()
        )
        .is_err()
    );
    let mut outer = new_bytes.clone();
    outer[6] = 1;
    assert!(decode_signed_local_execution(&outer).is_err());
    let empty_general = signed(intent(true));
    let bytes = encode_signed_local_execution(&empty_general).unwrap();
    assert_eq!(decode_canonical_frame(&bytes).unwrap().version(), 1);
    assert!(
        authenticate_local_execution(
            &resolver(),
            &LocalExecutionPolicy::general(context()),
            &bytes
        )
        .is_ok()
    );
}
#[test]
fn policy_activation_is_explicit_and_old_limits_never_default() {
    let old = LocalExecutionPolicy::new(context());
    let new = LocalExecutionPolicy::general(context());
    assert_eq!(old.profile(), 2);
    assert_eq!(new.profile(), 3);
    assert_ne!(
        old.digest(&resolver()).unwrap(),
        new.digest(&resolver()).unwrap()
    );
    for policy in [&old, &new] {
        assert_eq!(
            LocalExecutionPolicy::decode(&policy.encode().unwrap()).unwrap(),
            *policy
        );
    }
    let mut bytes = new.encode().unwrap();
    bytes[2] = 1;
    assert!(LocalExecutionPolicy::decode(&bytes).is_err());
    assert_ne!(
        general_execution_semantics(&resolver(), &context()).unwrap(),
        local_execution_semantics(&resolver(), &context()).unwrap()
    );
}
#[test]
fn general_host_import_has_an_exact_profile_and_signature() {
    let wasm=wat::parse_str("(module (import \"sunrise\" \"call_contract\" (func (param i32 i32 i32 i32 i32) (result i32))) (memory (export \"memory\") 1 2) (func (export \"run\")))").unwrap();
    assert!(execution::validate_contract_wasm_profile(&wasm, &["run"], 3).is_ok());
    assert!(execution::validate_contract_wasm_profile(&wasm, &["run"], 2).is_err());
    assert!(execution::validate_contract_wasm_profile(&wasm, &["run"], 1).is_err());
    let wrong=wat::parse_str("(module (import \"sunrise\" \"call_contract\" (func (param i32 i32 i32 i32) (result i32))) (memory (export \"memory\") 1 2) (func (export \"run\")))").unwrap();
    assert!(execution::validate_contract_wasm_profile(&wrong, &["run"], 3).is_err());
}

fn publication(
    profile: u32,
    seed: u8,
    dependencies: Vec<UnverifiedDependencyRef>,
) -> execution::publication::AuthenticatedPublicationCandidate {
    use execution::publication::*;
    let origin = PackageOrigin::unverified(
        context().chain_id().clone(),
        VerificationKey::from(&key()).into(),
        [seed; 32],
    )
    .unwrap();
    let abi = abi::call_values::CallAbi {
        objects: abi::public_abi::PackageAbi {
            origin: origin.clone(),
            constructors: vec![],
            entrypoints: vec![abi::public_abi::EntrypointDeclaration {
                name: "run".into(),
                type_parameters: vec![],
                objects: vec![],
            }],
        },
        arguments: vec![abi::call_values::ValueLayout::Tuple(vec![])],
        bodies: vec![],
    };
    let bytes = if profile == 1 {
        abi::call_values::encode_call_abi(&abi).unwrap()
    } else {
        abi::executable_abi::encode_executable_abi(&abi::executable_abi::ExecutableAbi {
            call: abi,
            initializer: None,
            transferable_constructors: vec![],
            results: vec![vec![]],
        })
        .unwrap()
    };
    let semantics = match profile {
        3 => general_execution_semantics(&resolver(), &context()).unwrap(),
        2 => local_execution_semantics(&resolver(), &context()).unwrap(),
        _ => digest(99),
    };
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin,
        revision: 1,
        wasm_profile: profile,
        semantics,
        wasm: wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"run\")))")
            .unwrap(),
        unverified_abi: bytes,
        exports: vec!["run".into()],
        unverified_dependencies: dependencies,
    })
    .unwrap();
    let commitment = artifact_commitment(&resolver(), &context(), &artifact).unwrap();
    let frame =
        publication_submission_signing_frame(&resolver(), &context(), &artifact, 0, [seed; 32])
            .unwrap();
    authenticate_publication_submission(
        &resolver(),
        &context(),
        &semantics,
        PublicationSubmission::new(
            [seed; 32],
            PublicationRequest::new(artifact, 0, commitment, key().sign(&frame).into()),
        )
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn profile_three_closures_accept_two_and_three_but_not_nonexecuting_artifacts() {
    use execution::publication::*;
    for (root_profile, child_profile, accepted) in
        [(3, 2, true), (3, 3, true), (3, 1, false), (2, 3, false)]
    {
        let child = publication(child_profile, 20, vec![]);
        let artifact = child.request().artifact();
        let reference = UnverifiedDependencyRef::new(
            artifact.origin().clone(),
            1,
            context(),
            *child.request().artifact_digest(),
        )
        .unwrap();
        let root = publication(root_profile, 21, vec![reference]);
        assert_eq!(
            verify_publication_interface(root, vec![child]).is_ok(),
            accepted
        );
    }
}
#[test]
fn general_runtime_rejects_missing_scopes() {
    let signed = signed(intent(true));
    let policy = LocalExecutionPolicy::general(context());
    let resolver = resolver();
    let authenticated = authenticate_local_execution(
        &resolver,
        &policy,
        &encode_signed_local_execution(&signed).unwrap(),
    )
    .unwrap();
    let request = LocalExecutionRequest {
        scopes: &[],
        intent: &authenticated,
        resolver: &resolver,
        policy: &policy,
        event_digest: local_execution_event_digest(&resolver, &signed).unwrap(),
        inputs: &[],
    };
    assert!(matches!(
        execution::LocalWasmExecutionEngine::new().execute(request),
        Err(LocalExecutionError::Invalid("missing root scope"))
    ));
}
