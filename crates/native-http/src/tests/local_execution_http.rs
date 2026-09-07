use super::*;
use abi::{
    call_values::{CallAbi, CallValue, ValueLayout, encode_call_abi, encode_call_value},
    executable_abi::{ExecutableAbi, encode_executable_abi},
    package_types::PackageOrigin,
    public_abi::{EntrypointDeclaration, PackageAbi},
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::local_execution::*;
use execution::publication::*;
use node_core::publication::{
    LocalPublicationPolicy, local_executable_publication_semantics,
    local_publication_profile_semantics, publication_policy_key_for_profile,
};
use runtime::{
    AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
    DurableDomainStateStore, StateMutation, StateMutationEntry, StateReadAssertion, StateRevision,
};

fn context() -> PublicationContext {
    PublicationContext::new(
        config().chain_id().clone(),
        config().protocol_version(),
        config().epoch(),
    )
    .unwrap()
}
fn policies() -> (
    LocalPublicationPolicy,
    LocalPublicationPolicy,
    LocalExecutionPolicy,
) {
    let resolver = resolver();
    let context = context();
    (
        LocalPublicationPolicy::new(
            context.clone(),
            local_publication_profile_semantics(&resolver, &context).unwrap(),
        ),
        LocalPublicationPolicy::executable(
            context.clone(),
            local_executable_publication_semantics(&resolver, &context).unwrap(),
        ),
        LocalExecutionPolicy::new(context),
    )
}
fn local_app(enabled: bool) -> Router {
    let domain = AtomicityDomainId::new([0x89; 32]).unwrap();
    let store = Arc::new(MemoryDurableStateStore::new(
        WriterFenceGeneration::new(3).unwrap(),
    ));
    let (legacy, executable, policy) = policies();
    let operation = DurableOperationContext::new(
        WriterFenceGeneration::new(3).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([7; 16]).unwrap(),
    );
    let entries = vec![
        (
            publication_policy_key_for_profile(legacy.context(), 1).unwrap(),
            legacy.encode().unwrap(),
        ),
        (
            publication_policy_key_for_profile(executable.context(), 2).unwrap(),
            executable.encode().unwrap(),
        ),
        (
            node_core::local_instance_state::execution_policy_key(policy.context()).unwrap(),
            policy.encode().unwrap(),
        ),
    ];
    let reads = entries
        .iter()
        .map(|(key, _)| StateReadAssertion::new(key.clone(), StateRevision::INITIAL).unwrap())
        .collect();
    let writes = entries
        .into_iter()
        .map(|(key, value)| StateMutationEntry::new(key, StateMutation::Put(value)).unwrap())
        .collect();
    assert!(matches!(
        store.commit_durable(
            &operation,
            AtomicStateTransaction::new(
                domain,
                AtomicStateReadSet::new(reads).unwrap(),
                AtomicStateMutationSet::new(writes).unwrap()
            )
            .unwrap()
        ),
        DurableCommitOutcome::Committed
    ));
    let mut composition = PreinstalledWasmComposition::new(
        Arc::new(PreinstalledModuleCatalog::new(vec![]).unwrap()),
        WasmExecutionEngine,
        1,
    );
    if enabled {
        composition = composition
            .with_local_publication(legacy)
            .with_local_execution(LocalExecutionComposition::new(executable, policy));
    }
    preinstalled_wasm_structured_durable_router(
        StructuredDurableNativeComponents::new(
            store,
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        composition,
        active_protocol_config(domain),
        structured_request_authority(),
        config(),
        resolver(),
        Arc::new(IncrementMachine::new(config().state_key())),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap()
}
fn publication(profile: u32, nonce: u64) -> PublicationSubmission {
    let key = SigningKey::from([7; 32]);
    let publisher: [u8; 32] = VerificationKey::from(&key).into();
    let origin =
        PackageOrigin::unverified(config().chain_id().clone(), publisher, [profile as u8; 32])
            .unwrap();
    let abi = CallAbi {
        objects: PackageAbi {
            origin: origin.clone(),
            constructors: vec![],
            entrypoints: vec![EntrypointDeclaration {
                name: "init".to_owned(),
                type_parameters: vec![],
                objects: vec![],
            }],
        },
        arguments: vec![ValueLayout::U64],
        bodies: vec![],
    };
    let abi = if profile == 2 {
        encode_executable_abi(&ExecutableAbi {
            call: abi,
            initializer: Some("init".to_owned()),
            transferable_constructors: vec![],
        })
        .unwrap()
    } else {
        encode_call_abi(&abi).unwrap()
    };
    let semantics = if profile == 2 {
        local_executable_publication_semantics(&resolver(), &context()).unwrap()
    } else {
        local_publication_profile_semantics(&resolver(), &context()).unwrap()
    };
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin,
        revision: 1,
        wasm_profile: profile,
        semantics,
        wasm: wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"init\")))")
            .unwrap(),
        unverified_abi: abi,
        exports: vec!["init".to_owned()],
        unverified_dependencies: vec![],
    })
    .unwrap();
    let digest = artifact_commitment(&resolver(), &context(), &artifact).unwrap();
    let frame = publication_submission_signing_frame(
        &resolver(),
        &context(),
        &artifact,
        nonce,
        [profile as u8; 32],
    )
    .unwrap();
    PublicationSubmission::new(
        [profile as u8; 32],
        PublicationRequest::new(artifact, nonce, digest, key.sign(&frame).into()),
    )
    .unwrap()
}
async fn post(app: &Router, path: &str, body: Vec<u8>) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, NODE_EVENT_MEDIA_TYPE)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn explicit_local_http_retains_profile_one_and_executes_profile_two() {
    let app = local_app(true);
    let legacy = publication(1, 0);
    let executable = publication(2, 1);
    for submission in [&legacy, &executable] {
        let response = post(
            &app,
            publication::PUBLICATION_PATH,
            encode_publication_submission(submission).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let output =
            HttpNodeResult::decode(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(output.responses()[0].status(), NodeResponseStatus::Accepted);
    }
    let key = SigningKey::from([7; 32]);
    let code = UnverifiedDependencyRef::new(
        executable.request().artifact().origin().clone(),
        1,
        context(),
        *executable.request().artifact_digest(),
    )
    .unwrap();
    let instance = InstanceRecord {
        context: context(),
        creator: VerificationKey::from(&key).into(),
        seed: [5; 32],
        code: code.clone(),
        revision: 1,
        initializer: "init".to_owned(),
    };
    let call = execution::call::CallIntent {
        context: context(),
        request_id: [3; 32],
        sender: instance.creator,
        nonce: 2,
        code,
        instance: instance_target(&resolver(), &instance).unwrap(),
        entrypoint: "init".to_owned(),
        type_arguments: vec![],
        access: AccessManifest::new(),
        arguments: encode_call_value(&ValueLayout::U64, &CallValue::U64(0)).unwrap(),
        gas_limit: 10000,
    };
    let intent = LocalExecutionIntent {
        authorizations: Vec::new(),
        mode: LocalExecutionMode::Instantiate,
        policy_digest: policies().2.digest(&resolver()).unwrap(),
        call,
    };
    let signature = key
        .sign(&local_execution_signing_frame(&context(), &intent).unwrap())
        .into();
    let signed = SignedLocalExecutionIntent { intent, signature };
    let response = post(
        &app,
        local_execution::EXECUTION_PATH,
        encode_signed_local_execution(&signed).unwrap(),
    )
    .await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let result = HttpNodeResult::decode(&bytes).unwrap();
    assert_eq!(result.responses()[0].status(), NodeResponseStatus::Accepted);
    let decoded = decode_local_execution_result(result.responses()[0].payload().unwrap()).unwrap();
    validate_local_execution_result(&resolver(), &resolver(), &signed, &decoded).unwrap();
    let path = format!(
        "/v1/contracts/instances/{}/{}",
        hex(&instance.creator),
        hex(&instance.seed)
    );
    let response = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        decode_instance_record(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap(),
        instance
    );
    assert_eq!(
        post(&app, local_execution::EXECUTION_PATH, vec![1])
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut changed = signed;
    changed.intent.call.context = PublicationContext::new(
        config().chain_id().clone(),
        config().protocol_version(),
        Epoch::new(8),
    )
    .unwrap();
    assert_eq!(
        post(
            &app,
            local_execution::EXECUTION_PATH,
            encode_signed_local_execution(&changed).unwrap()
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn local_execution_routes_default_closed_and_selectors_are_strict() {
    let app = local_app(false);
    assert_eq!(
        post(&app, local_execution::EXECUTION_PATH, vec![])
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let path = format!(
        "/v1/contracts/instances/{}/{}",
        hex(&[7; 32]),
        hex(&[5; 32])
    );
    assert_eq!(
        app.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        local_app(true)
            .oneshot(
                Request::builder()
                    .uri("/v1/contracts/instances/bad/bad")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn execution_pre_parser_enforces_exact_opted_in_body_bound() {
    let maximum = MAX_LOCAL_EXECUTION_INTENT_BYTES;
    for (enabled, length, expected) in [
        (false, maximum + 1, "404"),
        (true, maximum, "404"),
        (true, maximum + 1, "413"),
    ] {
        let policy = test_serve_policy(4, 2000, 2000, 3000).with_local_execution(enabled);
        let (address, shutdown, server) = start_serve_test(policy).await;
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let headers = format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n",
            local_execution::EXECUTION_PATH,
            NODE_EVENT_MEDIA_TYPE
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        let _write = stream.write_all(&vec![0; length]).await;
        let bytes = read_to_connection_end(&mut stream).await.unwrap();
        assert!(String::from_utf8_lossy(&bytes).starts_with(&format!("HTTP/1.1 {expected}")));
        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}

#[test]
fn execution_composition_rejects_wrong_context_without_storage() {
    let store = Arc::new(ScriptedIndexedStore::new(vec![], vec![]));
    let context = PublicationContext::new(
        config().chain_id().clone(),
        config().protocol_version(),
        Epoch::new(8),
    )
    .unwrap();
    let publication = LocalPublicationPolicy::executable(
        context.clone(),
        local_executable_publication_semantics(&resolver(), &context).unwrap(),
    );
    let composition = PreinstalledWasmComposition::new(
        Arc::new(PreinstalledModuleCatalog::new(vec![]).unwrap()),
        WasmExecutionEngine,
        1,
    )
    .with_local_execution(LocalExecutionComposition::new(
        publication,
        LocalExecutionPolicy::new(context),
    ));
    let result = preinstalled_wasm_structured_durable_router(
        StructuredDurableNativeComponents::new(
            Arc::clone(&store),
            Arc::new(MemoryBlobStore::default()),
            Arc::new(MemoryTransport::default()),
            Arc::new(ManualClock::new(10000)),
            Arc::new(SequenceIndexedIdentities::default()),
        ),
        composition,
        active_protocol_config(AtomicityDomainId::new([0x89; 32]).unwrap()),
        structured_request_authority(),
        config(),
        resolver(),
        Arc::new(IncrementMachine::new(config().state_key())),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    );
    assert!(matches!(
        result,
        Err(StructuredDurableRouterError::PublicationContextAuthorityMismatch)
    ));
    assert_eq!(store.storage_calls.load(Ordering::SeqCst), 0);
}
