use abi::package_types::PackageOrigin;
use abi::package_types::ScopedTypeArg;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::call_authorization::*;
use execution::local_execution::*;
use execution::publication::*;
use execution::{ExecutionStatus, LocalWasmExecutionEngine, ObjectEffect, ResolvedObject};
use hashing::HashSuiteResolver;
use objects::{AccessMode, ObjectRef};
use protocol_types::{ChainId, Epoch, HashPurpose, HashSuite, HashSuiteSchedule, ProtocolVersion};
use public_standard_asset::*;
fn key() -> SigningKey {
    SigningKey::from([7; 32])
}
fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("general-vm").unwrap(),
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
fn origin(seed: u8) -> PackageOrigin {
    PackageOrigin::unverified(context().chain_id().clone(), sender(), [seed; 32]).unwrap()
}
fn reference(candidate: &AuthenticatedPublicationCandidate) -> UnverifiedDependencyRef {
    let artifact = candidate.request().artifact();
    UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        1,
        context(),
        *candidate.request().artifact_digest(),
    )
    .unwrap()
}
fn publish() -> AuthenticatedPublicationCandidate {
    let package: StandardAssetPackage = build_package(&origin(1)).unwrap();
    let semantics = generic_object_result_semantics(&resolver(), &context()).unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: origin(1),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: vec![],
    })
    .unwrap();
    let digest = artifact_commitment(&resolver(), &context(), &artifact).unwrap();
    let frame =
        publication_submission_signing_frame(&resolver(), &context(), &artifact, 0, [1; 32])
            .unwrap();
    authenticate_publication_submission(
        &resolver(),
        &context(),
        &semantics,
        PublicationSubmission::new(
            [1; 32],
            PublicationRequest::new(artifact, 0, digest, key().sign(&frame).into()),
        )
        .unwrap(),
    )
    .unwrap()
}
fn scope(
    candidate: AuthenticatedPublicationCandidate,
    dependencies: Vec<AuthenticatedPublicationCandidate>,
    seed: u8,
    initializer: &str,
) -> ResolvedExecutionScope {
    let instance = InstanceRecord {
        context: context(),
        creator: sender(),
        seed: [seed; 32],
        code: reference(&candidate),
        revision: 1,
        initializer: initializer.into(),
    };
    ResolvedExecutionScope {
        target: instance_target(&resolver(), &instance).unwrap(),
        instance,
        interface: verify_publication_interface(candidate, dependencies).unwrap(),
    }
}
fn run(
    scopes: Vec<ResolvedExecutionScope>,
    entry: &str,
    args: Vec<u8>,
    inputs: &[ScopedResolvedObject],
    authorizations: Vec<CallAuthorization>,
    gas: u64,
    type_arguments: Vec<ScopedTypeArg>,
) -> Result<LocalExecutionOutcome, LocalExecutionError> {
    let resolver = resolver();
    let policy = LocalExecutionPolicy::generic_object_results(context());
    let root = &scopes[0];
    let access = abi::AccessManifest {
        entries: inputs
            .iter()
            .map(|input| abi::AccessEntry {
                mode: input.resolved.mode,
                object_ref: ObjectRef {
                    id: input.resolved.object.id,
                    version: input.resolved.object.version,
                    digest: resolver
                        .hash_for_purpose(
                            Epoch::new(0),
                            HashPurpose::Object,
                            &objects::encode_object(&input.resolved.object).unwrap(),
                        )
                        .unwrap(),
                },
            })
            .collect(),
    };
    let call = CallIntent {
        context: context(),
        request_id: [5; 32],
        sender: sender(),
        nonce: 0,
        code: root.instance.code.clone(),
        instance: root.target.clone(),
        entrypoint: entry.into(),
        type_arguments,
        access,
        arguments: args,
        gas_limit: gas,
    };
    let intent = LocalExecutionIntent {
        mode: if entry == root.instance.initializer {
            LocalExecutionMode::Instantiate
        } else {
            LocalExecutionMode::Call
        },
        policy_digest: policy.digest(&resolver).unwrap(),
        call,
        authorizations,
    };
    let signature = key()
        .sign(&local_execution_signing_frame(&context(), &intent)?)
        .into();
    let signed = SignedLocalExecutionIntent { intent, signature };
    let authenticated =
        authenticate_local_execution(&resolver, &policy, &encode_signed_local_execution(&signed)?)?;
    LocalWasmExecutionEngine::new().execute(LocalExecutionRequest {
        scopes: &scopes,
        intent: &authenticated,
        resolver: &resolver,
        policy: &policy,
        event_digest: local_execution_event_digest(&resolver, &signed)?,
        inputs,
    })
}
fn created(
    outcome: &LocalExecutionOutcome,
    index: usize,
    mode: AccessMode,
) -> ScopedResolvedObject {
    let object = outcome
        .effects
        .object_effects
        .iter()
        .filter_map(|effect| match effect {
            ObjectEffect::Created(object) => Some(object),
            _ => None,
        })
        .nth(index)
        .unwrap()
        .clone();
    let authority = outcome
        .created_authorities
        .iter()
        .find(|created| created.authority.object_id == object.id)
        .unwrap()
        .authority
        .clone();
    ScopedResolvedObject {
        resolved: ResolvedObject { object, mode },
        authority,
    }
}
fn mutated(outcome: &LocalExecutionOutcome, prior: &ScopedResolvedObject) -> ScopedResolvedObject {
    let mut next: ScopedResolvedObject = prior.clone();
    next.resolved.object = outcome
        .effects
        .object_effects
        .iter()
        .find_map(|effect| match effect {
            ObjectEffect::Mutated { new_object, .. }
                if new_object.id == prior.resolved.object.id =>
            {
                Some(new_object.clone())
            }
            _ => None,
        })
        .unwrap();
    next
}
fn call(
    root: &ResolvedExecutionScope,
    name: &str,
    args: Vec<u8>,
    inputs: &[ScopedResolvedObject],
    asset: Option<objects::ObjectId>,
) -> LocalExecutionOutcome {
    let types: Vec<ScopedTypeArg> = asset
        .map(|id| vec![asset_type_argument(&id)])
        .unwrap_or_default();
    run(
        vec![root.clone()],
        name,
        args,
        inputs,
        vec![],
        MAX_LOCAL_EXECUTION_GAS,
        types,
    )
    .unwrap()
}
#[track_caller]
fn success(outcome: &LocalExecutionOutcome) {
    assert_eq!(outcome.effects.status, ExecutionStatus::Success);
}
#[test]
fn guest_asset_lifecycle_and_reservation_conserve_supply() {
    let root: ResolvedExecutionScope = scope(publish(), vec![], 3, "init");
    let init: LocalExecutionOutcome = call(&root, "init", no_arguments().unwrap(), &[], None);
    success(&init);
    let definition: ScopedResolvedObject = created(&init, 0, AccessMode::Read);
    let asset: objects::ObjectId = definition.resolved.object.id;
    let cap: ScopedResolvedObject = created(&init, 1, AccessMode::Write);
    assert_eq!(treasury_supply(&cap.resolved.object.data).unwrap(), 0);
    let mint: LocalExecutionOutcome = call(
        &root,
        "mint",
        mint_arguments(100, &sender()).unwrap(),
        &[cap.clone()],
        Some(asset),
    );
    success(&mint);
    let cap: ScopedResolvedObject = mutated(&mint, &cap);
    assert_eq!(treasury_supply(&cap.resolved.object.data).unwrap(), 100);
    let coin: ScopedResolvedObject = created(&mint, 0, AccessMode::Write);
    assert_eq!(coin_amount(&coin.resolved.object.data).unwrap(), 100);
    let invocation = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"invocation")
        .unwrap();
    let policy = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"policy")
        .unwrap();
    let reserve: LocalExecutionOutcome = call(
        &root,
        "reserve",
        reserve_arguments(40, &invocation, &policy, &sender(), &sender()).unwrap(),
        &[coin.clone()],
        Some(asset),
    );
    success(&reserve);
    let remainder: ScopedResolvedObject = mutated(&reserve, &coin);
    assert_eq!(coin_amount(&remainder.resolved.object.data).unwrap(), 60);
    let reservation: ScopedResolvedObject = created(&reserve, 0, AccessMode::Consume);
    assert_eq!(
        reservation_body(&reservation.resolved.object.data)
            .unwrap()
            .reserved,
        40
    );
    let settled: LocalExecutionOutcome = call(
        &root,
        "settle",
        settle_arguments(15, &invocation, &policy).unwrap(),
        &[reservation],
        Some(asset),
    );
    success(&settled);
    let fee: ScopedResolvedObject = created(&settled, 0, AccessMode::Read);
    let refund: ScopedResolvedObject = created(&settled, 1, AccessMode::Read);
    assert_eq!(coin_amount(&fee.resolved.object.data).unwrap(), 15);
    assert_eq!(coin_amount(&refund.resolved.object.data).unwrap(), 25);
}
