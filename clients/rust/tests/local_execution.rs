use abi::{
    call_values::{CallAbi, CallValue, ValueLayout, encode_call_value},
    executable_abi::{ExecutableAbi, encode_executable_abi},
    public_abi::{EntrypointDeclaration, PackageAbi},
};
use std::cell::RefCell;
use std::collections::VecDeque;
use sunrise_edge_client::{call::CallIntent, local_execution::*, publication::*, *};

fn expected() -> ExpectedProtocolContext {
    ExpectedProtocolContext::new(
        ChainId::new("local-client-test").unwrap(),
        ProtocolVersion::new(1),
        Epoch::new(0),
        HashSuiteId::new(1),
        2,
        1,
        2,
        AtomicityDomainId::new([1; 32]).unwrap(),
    )
    .unwrap()
}
fn fixture() -> (
    HashSuiteResolver,
    LocalSigner,
    VerifiedPublicationInterface,
    InstanceRecord,
    CallIntent,
) {
    fixture_profile(2, 4)
}
fn fixture_profile(
    profile: u32,
    seed: u8,
) -> (
    HashSuiteResolver,
    LocalSigner,
    VerifiedPublicationInterface,
    InstanceRecord,
    CallIntent,
) {
    fixture_dependencies(profile, seed, vec![])
}
fn fixture_dependencies(
    profile: u32,
    seed: u8,
    dependencies: Vec<AuthenticatedPublicationCandidate>,
) -> (
    HashSuiteResolver,
    LocalSigner,
    VerifiedPublicationInterface,
    InstanceRecord,
    CallIntent,
) {
    let expected = expected();
    let resolver = local_publication_resolver(&expected).unwrap();
    let signer = LocalSigner::from_seed([7; 32]);
    let context = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .unwrap();
    let origin = PackageOrigin::unverified(
        expected.chain_id().clone(),
        *signer.address().as_bytes(),
        [seed; 32],
    )
    .unwrap();
    let metadata = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: vec![],
                entrypoints: ["init", "run"]
                    .iter()
                    .map(|name| EntrypointDeclaration {
                        name: (*name).to_owned(),
                        type_parameters: vec![],
                        objects: vec![],
                    })
                    .collect(),
            },
            arguments: vec![ValueLayout::U64; 2],
            bodies: vec![],
        },
        initializer: Some("init".to_owned()),
        transferable_constructors: vec![],
        results: vec![Vec::new(); 2],
    };
    let semantics = if profile == 3 {
        general_execution_semantics(&resolver, &context).unwrap()
    } else {
        local_execution_semantics(&resolver, &context).unwrap()
    };
    let references: Vec<UnverifiedDependencyRef> = dependencies
        .iter()
        .map(|candidate| {
            let artifact = candidate.artifact();
            UnverifiedDependencyRef::new(
                artifact.origin().clone(),
                artifact.revision(),
                artifact.context().clone(),
                *candidate.digest(),
            )
            .unwrap()
        })
        .collect();
    let artifact = CodeArtifact::new(ArtifactParts { context: context.clone(), origin, revision: 1, wasm_profile: profile, semantics, wasm: wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"init\")) (func (export \"run\")))").unwrap(), unverified_abi: encode_executable_abi(&metadata).unwrap(), exports: vec!["init".to_owned(), "run".to_owned()], unverified_dependencies: references }).unwrap();
    let submission = build_signed_publication(
        &signer,
        &resolver,
        &expected,
        artifact,
        0,
        RequestId::new([1; 32]).unwrap(),
    )
    .unwrap();
    let code = UnverifiedDependencyRef::new(
        submission.request().artifact().origin().clone(),
        1,
        context.clone(),
        *submission.request().artifact_digest(),
    )
    .unwrap();
    let candidate =
        authenticate_publication_submission(&resolver, &context, &semantics, submission).unwrap();
    let interface = verify_publication_interface(candidate, dependencies).unwrap();
    let instance = InstanceRecord {
        context: context.clone(),
        creator: *signer.address().as_bytes(),
        seed: [seed; 32],
        code: code.clone(),
        revision: 1,
        initializer: "init".to_owned(),
    };
    let call = CallIntent {
        context,
        request_id: [3; 32],
        sender: *signer.address().as_bytes(),
        nonce: 1,
        code,
        instance: instance_target(&resolver, &instance).unwrap(),
        entrypoint: "init".to_owned(),
        type_arguments: vec![],
        access: AccessManifest::new(),
        arguments: encode_call_value(&ValueLayout::U64, &CallValue::U64(7)).unwrap(),
        gas_limit: 10000,
    };
    (resolver, signer, interface, instance, call)
}

struct Fake(RefCell<VecDeque<WireResponse>>);

#[test]
fn scope_loader_shares_code_and_stops_before_the_34th_publication_fetch() {
    use call_authorization::{CallAuthorization, ExecutionTarget};
    for overlapping in [true, false] {
        let mut fixtures = Vec::new();
        for scope in 0_u8..5 {
            let dependencies: Vec<AuthenticatedPublicationCandidate> = (0_u8..6)
                .map(|node| {
                    fixture_profile(3, 20 + scope * 6 + node)
                        .2
                        .candidate()
                        .clone()
                })
                .collect();
            fixtures.push(fixture_dependencies(3, scope + 1, dependencies));
        }
        let (resolver, _, root_interface, root, call) = fixtures.remove(0);
        let expected = expected();
        let context = HttpContextQueryResult::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
            expected.hash_suite_id(),
            2,
            1,
            2,
            expected.domain(),
            vec![1],
        )
        .unwrap();
        let mut responses: VecDeque<WireResponse> = VecDeque::new();
        let mut authorizations: Vec<CallAuthorization> = Vec::new();
        let mut unique_nodes: usize = 7;
        for (_, _, interface, mut instance, _) in fixtures {
            if overlapping {
                instance.code = root.code.clone();
            }
            authorizations.push(CallAuthorization {
                caller: ExecutionTarget {
                    instance: call.instance.clone(),
                    code: call.code.clone(),
                },
                callee: ExecutionTarget {
                    instance: instance_target(&resolver, &instance).unwrap(),
                    code: instance.code.clone(),
                },
                entrypoint: "run".to_owned(),
                type_arguments: vec![],
                objects: vec![],
            });
            responses.push_back(response(context.encode().unwrap(), QUERY_RESULT_MEDIA_TYPE));
            responses.push_back(response(
                encode_instance_record(&instance).unwrap(),
                QUERY_RESULT_MEDIA_TYPE,
            ));
            if !overlapping {
                for candidate in std::iter::once(interface.candidate())
                    .chain(interface.dependencies().iter().rev())
                {
                    if unique_nodes == call_authorization::MAX_EXECUTION_CODE_NODES {
                        break;
                    }
                    let submission =
                        PublicationSubmission::new([1; 32], candidate.request().unwrap().clone())
                            .unwrap();
                    responses
                        .push_back(response(context.encode().unwrap(), QUERY_RESULT_MEDIA_TYPE));
                    responses.push_back(response(
                        encode_publication_submission(&submission).unwrap(),
                        QUERY_RESULT_MEDIA_TYPE,
                    ));
                    unique_nodes += 1;
                }
            }
        }
        // Exact response count: any extra publication/context query panics in Fake.
        let client = Client::new(Fake(RefCell::new(responses)));
        let result = client.query_execution_scopes(
            &call,
            &authorizations,
            root,
            root_interface,
            &resolver,
            &expected,
            &LocalExecutionPolicy::general(call.context.clone()),
        );
        if overlapping {
            assert_eq!(result.unwrap().len(), 5);
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("publication closure nodes")
            );
        }
        assert!(client.transport().0.borrow().is_empty());
    }
}

#[test]
fn scope_query_rejects_replacement_record_before_loading_code() {
    use call_authorization::{CallAuthorization, ExecutionTarget};
    let (resolver, _, interface, instance, call) = fixture_profile(3, 4);
    let (_, _, _, child, _) = fixture_profile(3, 5);
    let expected = expected();
    let context = HttpContextQueryResult::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
        expected.hash_suite_id(),
        2,
        1,
        2,
        expected.domain(),
        vec![1],
    )
    .unwrap();
    let mut pin = instance_target(&resolver, &child).unwrap();
    pin.record_digest = Digest32::new(HashAlgorithmId::Sha2_256, [99; 32]);
    let authorization = CallAuthorization {
        caller: ExecutionTarget {
            instance: call.instance.clone(),
            code: call.code.clone(),
        },
        callee: ExecutionTarget {
            instance: pin,
            code: child.code.clone(),
        },
        entrypoint: "run".to_owned(),
        type_arguments: vec![],
        objects: vec![],
    };
    // No publication response is supplied: fetching code before pin comparison
    // would exhaust the strict mock and panic.
    let client = Client::new(Fake(RefCell::new(VecDeque::from([
        response(context.encode().unwrap(), QUERY_RESULT_MEDIA_TYPE),
        response(
            encode_instance_record(&child).unwrap(),
            QUERY_RESULT_MEDIA_TYPE,
        ),
    ]))));
    assert!(
        client
            .query_execution_scopes(
                &call,
                &[authorization],
                instance,
                interface,
                &resolver,
                &expected,
                &LocalExecutionPolicy::general(call.context.clone())
            )
            .is_err()
    );
}

#[test]
fn general_signing_uses_shared_exact_scope_checks() {
    use call_authorization::{CallAuthorization, ExecutionTarget};
    let (resolver, signer, interface, instance, mut call) = fixture_profile(3, 4);
    let (_, _, child_interface, child, _) = fixture_profile(3, 5);
    call.entrypoint = "run".to_owned();
    let policy: LocalExecutionPolicy = LocalExecutionPolicy::general(call.context.clone());
    let scopes: Vec<ResolvedExecutionScope> = vec![
        ResolvedExecutionScope {
            target: call.instance.clone(),
            instance,
            interface,
        },
        ResolvedExecutionScope {
            target: instance_target(&resolver, &child).unwrap(),
            instance: child.clone(),
            interface: child_interface,
        },
    ];
    let authorization: CallAuthorization = CallAuthorization {
        caller: ExecutionTarget {
            instance: call.instance.clone(),
            code: call.code.clone(),
        },
        callee: ExecutionTarget {
            instance: scopes[1].target.clone(),
            code: child.code.clone(),
        },
        entrypoint: "run".to_owned(),
        type_arguments: vec![],
        objects: vec![],
    };
    let signed = build_signed_general_execution(
        &signer,
        &resolver,
        &expected(),
        &policy,
        LocalExecutionMode::Call,
        call.clone(),
        vec![authorization.clone()],
        &scopes,
    )
    .unwrap();
    let bytes: Vec<u8> = encode_signed_local_execution(&signed).unwrap();
    authenticate_local_execution(&resolver, &policy, &bytes).unwrap();
    assert_eq!(decode_signed_local_execution(&bytes).unwrap(), signed);
    for case in 0..6 {
        let mut changed_scopes = scopes.clone();
        let mut changed_authorization = authorization.clone();
        let mut changed_policy = policy.clone();
        match case {
            0 => changed_scopes[1].target.revision += 1,
            1 => changed_authorization.callee.code = call.code.clone(),
            2 => changed_authorization.entrypoint = "init".to_owned(),
            3 => {
                changed_scopes.pop();
            }
            4 => changed_policy = LocalExecutionPolicy::new(call.context.clone()),
            5 => {
                changed_scopes[1].instance.context = PublicationContext::new(
                    expected().chain_id().clone(),
                    expected().protocol_version(),
                    Epoch::new(1),
                )
                .unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            build_signed_general_execution(
                &signer,
                &resolver,
                &expected(),
                &changed_policy,
                LocalExecutionMode::Call,
                call.clone(),
                vec![changed_authorization],
                &changed_scopes
            )
            .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn profile_three_query_requires_explicit_trusted_policy() {
    let (resolver, _, interface, instance, call) = fixture_profile(3, 4);
    let expected = expected();
    let context = HttpContextQueryResult::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
        expected.hash_suite_id(),
        2,
        1,
        2,
        expected.domain(),
        vec![1],
    )
    .unwrap();
    let submission =
        PublicationSubmission::new([1; 32], interface.candidate().request().unwrap().clone())
            .unwrap();
    for general in [false, true] {
        let client = Client::new(Fake(RefCell::new(VecDeque::from([
            response(context.encode().unwrap(), QUERY_RESULT_MEDIA_TYPE),
            response(
                encode_publication_submission(&submission).unwrap(),
                QUERY_RESULT_MEDIA_TYPE,
            ),
        ]))));
        let policy = if general {
            LocalExecutionPolicy::general(call.context.clone())
        } else {
            LocalExecutionPolicy::new(call.context.clone())
        };
        assert_eq!(
            client
                .query_executable_interface_for_policy(
                    &instance.code,
                    &resolver,
                    &expected,
                    &policy
                )
                .is_ok(),
            general
        );
    }
}
impl Transport for Fake {
    fn send(&self, _: &WireRequest) -> Result<WireResponse, TransportError> {
        Ok(self.0.borrow_mut().pop_front().unwrap())
    }
}
fn response(body: Vec<u8>, media: &str) -> WireResponse {
    WireResponse {
        status: 200,
        content_type: Some(media.to_owned()),
        body,
    }
}

#[test]
fn signs_exact_policy_and_rejects_changed_target_context_and_initializer() {
    let (resolver, signer, interface, instance, call) = fixture();
    let signed = build_signed_local_execution(
        &signer,
        &resolver,
        &expected(),
        LocalExecutionMode::Instantiate,
        call.clone(),
        &instance,
        &interface,
    )
    .unwrap();
    let policy = LocalExecutionPolicy::new(call.context.clone());
    authenticate_local_execution(
        &resolver,
        &policy,
        &encode_signed_local_execution(&signed).unwrap(),
    )
    .unwrap();
    let mut mutated = signed.clone();
    mutated.intent.call.request_id = [9; 32];
    assert!(
        authenticate_local_execution(
            &resolver,
            &policy,
            &encode_signed_local_execution(&mutated).unwrap()
        )
        .is_err()
    );
    let mut other = call.clone();
    other.instance.seed = [9; 32];
    assert!(
        build_signed_local_execution(
            &signer,
            &resolver,
            &expected(),
            LocalExecutionMode::Instantiate,
            other,
            &instance,
            &interface
        )
        .is_err()
    );
    let mut other = call.clone();
    other.context = PublicationContext::new(
        call.context.chain_id().clone(),
        call.context.protocol_version(),
        Epoch::new(1),
    )
    .unwrap();
    assert!(
        build_signed_local_execution(
            &signer,
            &resolver,
            &expected(),
            LocalExecutionMode::Instantiate,
            other,
            &instance,
            &interface
        )
        .is_err()
    );
    assert!(
        build_signed_local_execution(
            &signer,
            &resolver,
            &expected(),
            LocalExecutionMode::Call,
            call,
            &instance,
            &interface
        )
        .is_err()
    );
}

#[test]
fn execution_acknowledgement_requires_matching_status_target_and_request() {
    let (resolver, signer, interface, instance, call) = fixture();
    let signed = build_signed_local_execution(
        &signer,
        &resolver,
        &expected(),
        LocalExecutionMode::Instantiate,
        call,
        &instance,
        &interface,
    )
    .unwrap();
    let result = LocalExecutionResult {
        request_id: signed.intent.call.request_id,
        instance,
        mode: LocalExecutionMode::Instantiate,
        effects: ExecutionEffects {
            tx_hash: local_execution_event_digest(&resolver, &signed).unwrap(),
            status: ExecutionStatus::Success,
            object_effects: vec![],
            events: vec![],
            gas_used: 10,
        },
    };
    for case in 0..5 {
        let mut changed = result.clone();
        let status = if case == 1 {
            NodeResponseStatus::Rejected
        } else {
            NodeResponseStatus::Accepted
        };
        if case == 2 {
            changed.instance.seed = [8; 32];
        }
        if case == 3 {
            changed.request_id = [8; 32];
        }
        if case == 4 {
            changed.effects.tx_hash = Digest32::new(HashAlgorithmId::Sha2_256, [8; 32]);
        }
        let id = RequestId::new(signed.intent.call.request_id).unwrap();
        let output = HttpNodeResult::new(
            id,
            vec![
                NodeResponse::new(
                    id,
                    status,
                    Some(encode_local_execution_result(&changed).unwrap()),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let client = Client::new(Fake(RefCell::new(VecDeque::from([response(
            output.encode().unwrap(),
            NODE_RESULT_MEDIA_TYPE,
        )]))));
        let received = client.submit_local_execution(&signed, &resolver, &resolver);
        if case == 0 {
            assert_eq!(received.unwrap(), result);
        } else {
            assert!(received.is_err());
        }
    }
}

#[test]
fn instance_query_rejects_wrong_selector() {
    let (resolver, _, _, instance, _) = fixture();
    let expected = expected();
    let context = HttpContextQueryResult::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
        expected.hash_suite_id(),
        2,
        1,
        2,
        expected.domain(),
        vec![1],
    )
    .unwrap();
    let client = Client::new(Fake(RefCell::new(VecDeque::from([
        response(context.encode().unwrap(), QUERY_RESULT_MEDIA_TYPE),
        response(
            encode_instance_record(&instance).unwrap(),
            QUERY_RESULT_MEDIA_TYPE,
        ),
    ]))));
    assert!(
        client
            .query_instance(instance.creator, [9; 32], &resolver, &expected)
            .is_err()
    );
}

#[test]
fn executable_interface_rejects_valid_publication_for_a_different_commitment() {
    let (resolver, _, interface, instance, _) = fixture();
    let expected = expected();
    let context = HttpContextQueryResult::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
        expected.hash_suite_id(),
        2,
        1,
        2,
        expected.domain(),
        vec![1],
    )
    .unwrap();
    let submission =
        PublicationSubmission::new([1; 32], interface.candidate().request().unwrap().clone())
            .unwrap();
    for changed in [false, true] {
        let reference = if changed {
            UnverifiedDependencyRef::new(
                instance.code.origin().clone(),
                1,
                instance.context.clone(),
                Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]),
            )
            .unwrap()
        } else {
            instance.code.clone()
        };
        let client = Client::new(Fake(RefCell::new(VecDeque::from([
            response(context.encode().unwrap(), QUERY_RESULT_MEDIA_TYPE),
            response(
                encode_publication_submission(&submission).unwrap(),
                QUERY_RESULT_MEDIA_TYPE,
            ),
        ]))));
        let result = client.query_executable_interface(&reference, &resolver, &expected);
        assert_eq!(result.is_ok(), !changed);
    }
}

#[test]
fn normalized_rejected_result_is_returned_without_becoming_success() {
    let (resolver, signer, interface, instance, call) = fixture();
    let signed = build_signed_local_execution(
        &signer,
        &resolver,
        &expected(),
        LocalExecutionMode::Instantiate,
        call,
        &instance,
        &interface,
    )
    .unwrap();
    let result = LocalExecutionResult {
        request_id: signed.intent.call.request_id,
        instance,
        mode: LocalExecutionMode::Instantiate,
        effects: ExecutionEffects {
            tx_hash: local_execution_event_digest(&resolver, &signed).unwrap(),
            status: ExecutionStatus::Failure {
                reason: LOCAL_EXECUTION_TRAP_REASON.to_owned(),
            },
            object_effects: vec![],
            events: vec![],
            gas_used: 20,
        },
    };
    let id = RequestId::new(result.request_id).unwrap();
    let output = HttpNodeResult::new(
        id,
        vec![
            NodeResponse::new(
                id,
                NodeResponseStatus::Rejected,
                Some(encode_local_execution_result(&result).unwrap()),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let client = Client::new(Fake(RefCell::new(VecDeque::from([response(
        output.encode().unwrap(),
        NODE_RESULT_MEDIA_TYPE,
    )]))));
    assert_eq!(
        client
            .submit_local_execution(&signed, &resolver, &resolver)
            .unwrap(),
        result
    );
}
