
/// The only in-crate [`PaidContractEngine`] implementation. Using the trait
/// here is what proves the boundary is injectable rather than a concrete
/// unit struct, and that `execute_paid` does not collide with the zero-fee
/// `LocalContractEngine::execute` on the same type.
fn paid_engine() -> impl PaidContractEngine {
    LocalWasmExecutionEngine::new()
}
fn key() -> SigningKey {
    SigningKey::from([7; 32])
}

/// Signs and authenticates one [`PaidIntent`] exactly as a sender would.
/// Every test below goes through this: no test ever fabricates an
/// `AuthenticatedPaidIntent` or a signature.
fn authenticate(intent: PaidIntent) -> AuthenticatedPaidIntent {
    let frame = paid_intent_signing_frame(&context(), &intent).unwrap();
    let signature: [u8; 64] = key().sign(&frame).into();
    let signed = SignedPaidIntent { intent, signature };
    let bytes = encode_signed_paid_intent(&signed).unwrap();
    authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap()
}

/// The complete canonical `ObjectRef` of one resolved object, including its
/// content digest.
fn object_ref_of(object: &Object) -> objects::ObjectRef {
    objects::ObjectRef {
        id: object.id,
        version: object.version,
        digest: resolver()
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::Object,
                &objects::encode_object(object).unwrap(),
            )
            .unwrap(),
    }
}
fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
fn treasury() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([9; 32])).into()
}
fn refund_account() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([11; 32])).into()
}
fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("paid-execution-engine-test").unwrap(),
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
fn origin(seed: u8) -> abi::package_types::PackageOrigin {
    abi::package_types::PackageOrigin::unverified(
        context().chain_id().clone(),
        sender(),
        [seed; 32],
    )
    .unwrap()
}

fn publish_asset(seed: u8) -> AuthenticatedPublicationCandidate {
    let package: StandardAssetPackage = build_package(&origin(seed)).unwrap();
    let semantics = generic_object_result_semantics(&resolver(), &context()).unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: origin(seed),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: package.wasm,
        unverified_abi: package.encoded_abi,
        exports: package.exports,
        unverified_dependencies: vec![],
    })
    .unwrap();
    let commitment = artifact_commitment(&resolver(), &context(), &artifact).unwrap();
    let frame =
        publication_submission_signing_frame(&resolver(), &context(), &artifact, 0, [1; 32])
            .unwrap();
    authenticate_publication_submission(
        &resolver(),
        &context(),
        &semantics,
        PublicationSubmission::new(
            [1; 32],
            PublicationRequest::new(artifact, 0, commitment, key().sign(&frame).into()),
        )
        .unwrap(),
    )
    .unwrap()
}

fn dependency_ref(candidate: &AuthenticatedPublicationCandidate) -> UnverifiedDependencyRef {
    let artifact = candidate.artifact();
    UnverifiedDependencyRef::new(artifact.origin().clone(), 1, context(), *candidate.digest())
        .unwrap()
}

fn asset_scope(seed: u8, instance_seed: u8) -> ResolvedExecutionScope {
    let candidate = publish_asset(seed);
    let code = dependency_ref(&candidate);
    let instance = InstanceRecord {
        context: context(),
        creator: sender(),
        seed: [instance_seed; 32],
        code,
        revision: 1,
        initializer: "init".into(),
    };
    ResolvedExecutionScope {
        target: instance_target(&resolver(), &instance).unwrap(),
        instance,
        interface: verify_publication_interface(candidate, vec![]).unwrap(),
    }
}

/// One ordinary authenticated zero-fee root call, exactly as the production
/// `execute` path does, used only to seed real objects (init/mint).
fn call(
    scopes: &[ResolvedExecutionScope],
    entry: &str,
    arguments: Vec<u8>,
    inputs: &[ScopedResolvedObject],
    types: Vec<abi::package_types::ScopedTypeArg>,
) -> LocalExecutionOutcome {
    let resolver: HashSuiteResolver = resolver();
    let policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let root: &ResolvedExecutionScope = &scopes[0];
    let access = abi::AccessManifest {
        entries: inputs
            .iter()
            .map(|input| abi::AccessEntry {
                mode: input.resolved.mode,
                object_ref: objects::ObjectRef {
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
        type_arguments: types,
        access,
        arguments,
        gas_limit: MAX_LOCAL_EXECUTION_GAS,
    };
    let intent = LocalExecutionIntent {
        mode: if entry == root.instance.initializer {
            LocalExecutionMode::Instantiate
        } else {
            LocalExecutionMode::Call
        },
        policy_digest: policy.digest(&resolver).unwrap(),
        call,
        authorizations: vec![],
    };
    let signature = key()
        .sign(&local_execution_signing_frame(&context(), &intent).unwrap())
        .into();
    let signed = SignedLocalExecutionIntent { intent, signature };
    let encoded = encode_signed_local_execution(&signed).unwrap();
    let authenticated = authenticate_local_execution(&resolver, &policy, &encoded).unwrap();
    LocalWasmExecutionEngine::new()
        .execute(LocalExecutionRequest {
            scopes,
            intent: &authenticated,
            resolver: &resolver,
            policy: &policy,
            event_digest: local_execution_event_digest(&resolver, &signed).unwrap(),
            inputs,
        })
        .unwrap()
}

fn created(
    outcome: &LocalExecutionOutcome,
    index: usize,
    mode: AccessMode,
) -> ScopedResolvedObject {
    let object: Object = outcome
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
        resolved: execution::ResolvedObject { object, mode },
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

struct Asset {
    scope: ResolvedExecutionScope,
    id: ObjectId,
    coin: ScopedResolvedObject,
}

fn asset(seed: u8, instance_seed: u8, amount: u64) -> Asset {
    let scope: ResolvedExecutionScope = asset_scope(seed, instance_seed);
    let scopes: Vec<ResolvedExecutionScope> = vec![scope.clone()];
    let init = call(
        &scopes,
        "init",
        public_standard_asset::no_arguments().unwrap(),
        &[],
        vec![],
    );
    assert_eq!(init.effects.status, ExecutionStatus::Success);
    let definition = created(&init, 0, AccessMode::Read);
    let id: ObjectId = definition.resolved.object.id;
    let cap = created(&init, 1, AccessMode::Write);
    let mint = call(
        &scopes,
        "mint",
        public_standard_asset::mint_arguments(amount, &sender()).unwrap(),
        std::slice::from_ref(&cap),
        vec![public_standard_asset::asset_type_argument(&id)],
    );
    assert_eq!(mint.effects.status, ExecutionStatus::Success);
    let coin = created(&mint, 0, AccessMode::Write);
    Asset { scope, id, coin }
}

fn fee_policy(asset: &Asset) -> PaidFeePolicy {
    let origin: abi::package_types::PackageOrigin = asset.scope.instance.code.origin().clone();
    PaidFeePolicy {
        context: context(),
        base_policy_digest: LocalExecutionPolicy::generic_object_results(context())
            .digest(&resolver())
            .unwrap(),
        instance: asset.scope.target.clone(),
        code: asset.scope.instance.code.clone(),
        reserve_entrypoint: "reserve".into(),
        reserve_all_entrypoint: "reserve_all".into(),
        settle_entrypoint: "settle".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        asset_type: public_standard_asset::coin_type_tag(&origin, &asset.id).unwrap(),
        reservation_type: public_standard_asset::reservation_type_tag(&origin, &asset.id).unwrap(),
        schema: public_standard_asset::SCHEMA_VERSION,
        fee_recipient: treasury(),
        gas_schedule: GasSchedule {
            base_fee: 100,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        conversion_divisor: 1_000,
        reserve_allowance: 200_000,
        settle_allowance: 200_000,
        calls: 8,
        handles: 16,
        creations: 4,
        events: 16,
        memory_bytes: 8 * 1024 * 1024,
        output_bytes: 1024 * 1024,
        publish_artifact_byte_price: 1,
        publish_closure_node_price: 1,
    }
}

/// Builds and runs one real authenticated paid `transfer` Call, exactly as
/// production admission would after its own object/policy/nonce checks.
/// Shared by the positive Call test and the result-codec regression tests
/// below, so those regressions exercise a genuine charged wire result
/// rather than a hand-assembled one.
fn run_transfer_call(asset: &Asset, request_id: [u8; 32], nonce: u64) -> PaidExecutionOutcome {
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(asset);
    let policy_digest = paid_fee_policy_digest(&resolver(), &policy).unwrap();

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let source_ref = objects::ObjectRef {
        id: coin_source.resolved.object.id,
        version: coin_source.resolved.object.version,
        digest: resolver()
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::Object,
                &objects::encode_object(&coin_source.resolved.object).unwrap(),
            )
            .unwrap(),
    };

    let application = CallIntent {
        context: context(),
        request_id,
        sender: sender(),
        nonce,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: source_ref.clone(),
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };

    let intent = PaidIntent {
        context: context(),
        request_id,
        sender: sender(),
        nonce,
        fee_policy_digest: policy_digest,
        consent: FeeSourceConsent {
            source: source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    };
    let frame = paid_intent_signing_frame(&context(), &intent).unwrap();
    let signature: [u8; 64] = key().sign(&frame).into();
    let signed = SignedPaidIntent { intent, signature };
    let bytes = encode_signed_paid_intent(&signed).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();

    let request = PaidExecutionRequest {
        authenticated: &authenticated,
        resolver: &resolver(),
        base_policy: &base_policy,
        fee_policy: &policy,
        scopes: &scopes,
        source: coin_source.clone(),
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: std::slice::from_ref(&coin_source),
        },
    };

    let outcome: PaidExecutionOutcome = paid_engine()
        .execute_paid(request)
        .expect("paid transfer call");
    // Every real charged receipt this file produces is also checked by the
    // independent verifier, so the positive path exercises both.
    verify_paid_execution_result(
        &outcome,
        &authenticated,
        &resolver(),
        &base_policy,
        &policy,
        &asset.scope.instance,
        &[],
    )
    .expect("independent verification");
    outcome
}

