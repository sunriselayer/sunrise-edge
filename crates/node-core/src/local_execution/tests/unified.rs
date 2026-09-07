//! Storage-only tests: a deliberately untrusted engine proposes cross-scope effects.
use super::*;
use execution::call_authorization::{AuthorizedObject, CallAuthorization, ExecutionTarget};

fn general_policy() -> LocalExecutionPolicy {
    LocalExecutionPolicy::general(protocol())
}
fn publish_code(
    store: &MemoryDurableStateStore,
    seed: u8,
    nonce: u64,
    dependency: Option<&UnverifiedDependencyRef>,
) -> UnverifiedDependencyRef {
    let origin: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), sender(), [seed; 32]).unwrap();
    let foreign: PackageOrigin =
        dependency.map_or_else(|| origin.clone(), |reference| reference.origin().clone());
    let object_param = |origin: PackageOrigin| ObjectParameter {
        mode: ObjectMode::Write,
        schema: 1,
        ty: TypePattern {
            origin,
            constructor: 1,
            arguments: vec![],
        },
    };
    let meta: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: vec![ConstructorDeclaration {
                    local_id: 1,
                    schema: 1,
                    arguments: vec![],
                }],
                entrypoints: vec![
                    EntrypointDeclaration {
                        name: "forward".into(),
                        type_parameters: vec![],
                        objects: vec![object_param(origin.clone()), object_param(foreign)],
                    },
                    EntrypointDeclaration {
                        name: "init".into(),
                        type_parameters: vec![],
                        objects: vec![],
                    },
                    EntrypointDeclaration {
                        name: "write".into(),
                        type_parameters: vec![],
                        objects: vec![object_param(origin.clone())],
                    },
                ],
            },
            arguments: vec![ValueLayout::Tuple(vec![]); 3],
            bodies: vec![ValueLayout::U64],
        },
        initializer: Some("init".into()),
        transferable_constructors: vec![1],
    };
    let semantics: Digest32 = general_execution_semantics(&resolver(), &protocol()).unwrap();
    let artifact:CodeArtifact=CodeArtifact::new(ArtifactParts{context:protocol(),origin:origin.clone(),revision:1,wasm_profile:3,semantics,wasm:wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"forward\")) (func (export \"init\")) (func (export \"write\")))").unwrap(),unverified_abi:encode_executable_abi(&meta).unwrap(),exports:vec!["forward".into(),"init".into(),"write".into()],unverified_dependencies:dependency.into_iter().cloned().collect()}).unwrap();
    let digest: Digest32 = artifact_commitment(&resolver(), &protocol(), &artifact).unwrap();
    let frame: Vec<u8> = publication_submission_signing_frame(
        &resolver(),
        &protocol(),
        &artifact,
        nonce,
        [seed; 32],
    )
    .unwrap();
    let submission: PublicationSubmission = PublicationSubmission::new(
        [seed; 32],
        PublicationRequest::new(artifact, nonce, digest, key().sign(&frame).into()),
    )
    .unwrap();
    publication::handle_local_publication(
        store,
        &context(),
        domain(),
        &resolver(),
        &publication::LocalPublicationPolicy::general(protocol(), semantics),
        submission,
    )
    .unwrap();
    UnverifiedDependencyRef::new(origin, 1, protocol(), digest).unwrap()
}
fn general_sign(
    instance: &InstanceRecord,
    nonce: u64,
    id: u8,
    name: &str,
    entries: Vec<AccessEntry>,
    authorizations: Vec<CallAuthorization>,
) -> Vec<u8> {
    let mut signed: SignedLocalExecutionIntent =
        decode_signed_local_execution(&sign(instance, nonce, id, name, entries)).unwrap();
    signed.intent.policy_digest = general_policy().digest(&resolver()).unwrap();
    signed.intent.authorizations = authorizations;
    resign(signed.intent)
}
fn general_run(
    store: &MemoryDurableStateStore,
    bytes: &[u8],
    engine: &impl LocalContractEngine,
) -> AdmissionResult<NodeOutput> {
    handle_local_execution(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &general_policy(),
        engine,
        bytes,
        10,
    )
}
fn initial(code: UnverifiedDependencyRef, seed: u8) -> InstanceRecord {
    InstanceRecord {
        context: protocol(),
        creator: sender(),
        seed: [seed; 32],
        code,
        revision: 1,
        initializer: "init".into(),
    }
}

#[derive(Clone, Copy)]
enum Proposal {
    Init,
    Success,
    Trap,
    ForgedScope,
    ForgedOrdinal,
    ForgedBody,
}
struct ProposingEngine {
    proposal: Proposal,
    calls: Cell<u32>,
}
impl ProposingEngine {
    fn new(proposal: Proposal) -> Self {
        Self {
            proposal,
            calls: Cell::new(0),
        }
    }
}
impl LocalContractEngine for ProposingEngine {
    fn execute(
        &self,
        request: LocalExecutionRequest<'_>,
    ) -> Result<LocalExecutionOutcome, LocalExecutionError> {
        self.calls.set(self.calls.get() + 1);
        let mut effects: ExecutionEffects = ExecutionEffects {
            tx_hash: request.event_digest,
            status: ExecutionStatus::Success,
            object_effects: vec![],
            events: vec![],
            gas_used: 70,
        };
        if matches!(self.proposal, Proposal::Trap) {
            effects.status = ExecutionStatus::Failure {
                reason: LOCAL_EXECUTION_TRAP_REASON.into(),
            };
            return Ok(LocalExecutionOutcome {
                effects,
                created_authorities: vec![],
            });
        }
        for input in request.inputs {
            let mut changed: Object = input.resolved.object.clone();
            changed.version += 1;
            changed.data = encode_call_value(&ValueLayout::U64, &CallValue::U64(99)).unwrap();
            effects.object_effects.push(ObjectEffect::Mutated {
                previous_version: input.resolved.object.version,
                new_object: changed,
            });
        }
        let scope: &ResolvedExecutionScope = if matches!(self.proposal, Proposal::Init) {
            request.root_scope()?
        } else {
            &request.scopes[1]
        };
        let ty: ScopedTypeTag =
            ScopedTypeTag::new(scope.instance.code.origin().clone(), 1, vec![]).unwrap();
        let id: ObjectId = derive_local_created_object_id(
            request.resolver,
            &request.intent.intent().call.context,
            &scope.instance.context,
            &scope.target,
            &scope.instance.code,
            request.event_digest,
            7,
        )?;
        let mut authority: ObjectAuthority = ObjectAuthority {
            object_id: id,
            instance_context: scope.instance.context.clone(),
            instance: scope.target.clone(),
            code: scope.instance.code.clone(),
            ty: ty.clone(),
        };
        if matches!(self.proposal, Proposal::ForgedScope) {
            authority.instance.seed = [98; 32];
        }
        effects.object_effects.push(ObjectEffect::Created(Object {
            id,
            version: 1,
            owner: Owner::Address(Address::new(sender())),
            type_hash: derive_scoped_type_id(request.resolver, protocol().epoch(), &ty).unwrap(),
            schema_version: 1,
            data: if matches!(self.proposal, Proposal::ForgedBody) {
                vec![1]
            } else {
                encode_call_value(&ValueLayout::U64, &CallValue::U64(5)).unwrap()
            },
        }));
        Ok(LocalExecutionOutcome {
            effects,
            created_authorities: vec![CreatedObjectAuthority {
                creation_ordinal: if matches!(self.proposal, Proposal::ForgedOrdinal) {
                    8
                } else {
                    7
                },
                authority,
            }],
        })
    }
}
struct Fixture {
    store: MemoryDurableStateStore,
    root: InstanceRecord,
    child: InstanceRecord,
    root_object: Object,
    child_object: Object,
}
impl Fixture {
    fn new() -> Self {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        let publication_policy: publication::LocalPublicationPolicy =
            publication::LocalPublicationPolicy::general(
                protocol(),
                general_execution_semantics(&resolver(), &protocol()).unwrap(),
            );
        set_state(
            &store,
            publication::publication_policy_key_for_profile(&protocol(), 3).unwrap(),
            StateMutation::Put(publication_policy.encode().unwrap()),
        );
        set_state(
            &store,
            execution_policy_key_for_profile(&protocol(), 3).unwrap(),
            StateMutation::Put(general_policy().encode().unwrap()),
        );
        let child_code: UnverifiedDependencyRef = publish_code(&store, 20, 0, None);
        let root_code: UnverifiedDependencyRef = publish_code(&store, 21, 1, Some(&child_code));
        let root: InstanceRecord = initial(root_code, 30);
        let child: InstanceRecord = initial(child_code, 31);
        let root_object: Object = object(
            &general_run(
                &store,
                &general_sign(&root, 2, 30, "init", vec![], vec![]),
                &ProposingEngine::new(Proposal::Init),
            )
            .unwrap(),
        );
        let child_object: Object = object(
            &general_run(
                &store,
                &general_sign(&child, 3, 31, "init", vec![], vec![]),
                &ProposingEngine::new(Proposal::Init),
            )
            .unwrap(),
        );
        Self {
            store,
            root,
            child,
            root_object,
            child_object,
        }
    }
    fn authorization(&self) -> CallAuthorization {
        CallAuthorization {
            caller: ExecutionTarget {
                instance: instance_target(&resolver(), &self.root).unwrap(),
                code: self.root.code.clone(),
            },
            callee: ExecutionTarget {
                instance: instance_target(&resolver(), &self.child).unwrap(),
                code: self.child.code.clone(),
            },
            entrypoint: "write".into(),
            type_arguments: vec![],
            objects: vec![AuthorizedObject {
                object_id: self.child_object.id,
                mode: AccessMode::Write,
            }],
        }
    }
    fn call(&self, authorizations: Vec<CallAuthorization>) -> Vec<u8> {
        general_sign(
            &self.root,
            4,
            40,
            "forward",
            vec![
                entry(&self.root_object, AccessMode::Write),
                entry(&self.child_object, AccessMode::Write),
            ],
            authorizations,
        )
    }
    fn state(&self) -> (Snapshot, Snapshot) {
        (
            snapshot(&self.store, &context(), &self.root, self.root_object.id),
            snapshot(&self.store, &context(), &self.child, self.child_object.id),
        )
    }
}

#[test]
fn unified_scopes_commit_actual_scope_outputs_and_replay_before_missing_policy() {
    let f: Fixture = Fixture::new();
    let bytes: Vec<u8> = f.call(vec![f.authorization()]);
    let engine: ProposingEngine = ProposingEngine::new(Proposal::Success);
    let output: NodeOutput = general_run(&f.store, &bytes, &engine).unwrap();
    let result: LocalExecutionResult =
        decode_local_execution_result(output.responses()[0].payload().unwrap()).unwrap();
    let created: Object = result
        .effects
        .object_effects
        .iter()
        .find_map(|effect| {
            if let ObjectEffect::Created(object) = effect {
                Some(object.clone())
            } else {
                None
            }
        })
        .unwrap();
    let authority: ObjectAuthority = decode_object_authority(
        f.store
            .get_versioned_durable(&context(), domain(), &object_authority_key(created.id))
            .unwrap()
            .value()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        authority.instance,
        instance_target(&resolver(), &f.child).unwrap()
    );
    assert_eq!(authority.code, f.child.code);
    assert_eq!(nonce(&f.store), 5);
    for id in [f.root_object.id, f.child_object.id] {
        assert_eq!(
            f.store
                .get_object_head(&context(), domain(), id)
                .unwrap()
                .object_version()
                .unwrap()
                .get(),
            2
        );
    }
    set_state(
        &f.store,
        execution_policy_key_for_profile(&protocol(), 3).unwrap(),
        StateMutation::Delete,
    );
    set_state(
        &f.store,
        instance_record_key(protocol().chain_id(), &f.child.creator, &f.child.seed).unwrap(),
        StateMutation::Delete,
    );
    assert_eq!(general_run(&f.store, &bytes, &engine).unwrap(), output);
    assert_eq!(engine.calls.get(), 1);
}
#[test]
fn unauthorized_scope_and_bad_exact_target_reject_before_engine() {
    let f: Fixture = Fixture::new();
    let engine: ProposingEngine = ProposingEngine::new(Proposal::Success);
    let before = f.state();
    assert!(general_run(&f.store, &f.call(vec![]), &engine).is_err());
    let mut bad: CallAuthorization = f.authorization();
    bad.callee.instance.record_digest = Digest32::new(HashAlgorithmId::Sha2_256, [99; 32]);
    assert!(general_run(&f.store, &f.call(vec![bad]), &engine).is_err());
    let mut bad: CallAuthorization = f.authorization();
    bad.callee.code = f.root.code.clone();
    assert!(general_run(&f.store, &f.call(vec![bad]), &engine).is_err());
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(f.state(), before);
    assert_eq!(nonce(&f.store), 4);
}
#[test]
fn forged_child_effects_roll_back_all_scopes() {
    for proposal in [
        Proposal::ForgedScope,
        Proposal::ForgedOrdinal,
        Proposal::ForgedBody,
    ] {
        let f: Fixture = Fixture::new();
        let before = f.state();
        assert!(
            general_run(
                &f.store,
                &f.call(vec![f.authorization()]),
                &ProposingEngine::new(proposal)
            )
            .is_err()
        );
        assert_eq!(f.state(), before);
        assert_eq!(nonce(&f.store), 4);
        assert!(
            f.store
                .get_request_receipt(
                    &context(),
                    domain(),
                    DurableRequestId::new([40; 32]).unwrap()
                )
                .unwrap()
                .is_none()
        );
    }
}
#[test]
fn unified_trap_preserves_all_application_state_and_replays() {
    let f: Fixture = Fixture::new();
    let before = f.state();
    let engine: ProposingEngine = ProposingEngine::new(Proposal::Trap);
    let bytes: Vec<u8> = f.call(vec![f.authorization()]);
    let output: NodeOutput = general_run(&f.store, &bytes, &engine).unwrap();
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Rejected);
    assert_eq!(nonce(&f.store), 5);
    let after = f.state();
    assert_eq!(before.0.head, after.0.head);
    assert_eq!(before.1.head, after.1.head);
    assert_eq!(before.0.versions, after.0.versions);
    assert_eq!(before.1.versions, after.1.versions);
    assert_eq!(&before.0.states[..2], &after.0.states[..2]);
    assert_eq!(&before.1.states[..2], &after.1.states[..2]);
    assert_eq!(general_run(&f.store, &bytes, &engine).unwrap(), output);
    assert_eq!(engine.calls.get(), 1);
}

struct ScopeRace<'a> {
    fixture: &'a Fixture,
}
impl LocalContractEngine for ScopeRace<'_> {
    fn execute(
        &self,
        request: LocalExecutionRequest<'_>,
    ) -> Result<LocalExecutionOutcome, LocalExecutionError> {
        let outcome: LocalExecutionOutcome =
            ProposingEngine::new(Proposal::Success).execute(request)?;
        let record: &InstanceRecord = &self.fixture.child;
        set_state(
            &self.fixture.store,
            instance_record_key(protocol().chain_id(), &record.creator, &record.seed).unwrap(),
            StateMutation::Put(encode_instance_record(record).unwrap()),
        );
        Ok(outcome)
    }
}
#[test]
fn child_instance_cas_race_rejects_entire_proposed_commit() {
    let f: Fixture = Fixture::new();
    let before = f.state();
    let bytes: Vec<u8> = f.call(vec![f.authorization()]);
    assert!(matches!(
        general_run(&f.store, &bytes, &ScopeRace { fixture: &f }),
        Err(LocalExecutionAdmissionError::Node(
            NodeCoreError::StateConflict
        ))
    ));
    let after = f.state();
    assert_eq!(before.0, after.0);
    assert_eq!(before.1.head, after.1.head);
    assert_eq!(before.1.versions, after.1.versions);
    assert_eq!(nonce(&f.store), 4);
    assert!(
        f.store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new([40; 32]).unwrap()
            )
            .unwrap()
            .is_none()
    );
    general_run(&f.store, &bytes, &ProposingEngine::new(Proposal::Success)).unwrap();
}
#[test]
fn profile_three_requires_its_own_policy_and_authorized_abi_rights() {
    let f: Fixture = Fixture::new();
    let engine: ProposingEngine = ProposingEngine::new(Proposal::Success);
    let before = f.state();
    let mut authorization: CallAuthorization = f.authorization();
    authorization.objects[0].mode = AccessMode::Read;
    assert!(general_run(&f.store, &f.call(vec![authorization]), &engine).is_err());
    assert_eq!(f.state(), before);
    set_state(
        &f.store,
        execution_policy_key_for_profile(&protocol(), 3).unwrap(),
        StateMutation::Delete,
    );
    set_state(
        &f.store,
        execution_policy_key(&protocol()).unwrap(),
        StateMutation::Put(policy().encode().unwrap()),
    );
    assert!(matches!(
        general_run(&f.store, &f.call(vec![f.authorization()]), &engine),
        Err(LocalExecutionAdmissionError::Invalid(
            "execution policy absent or different"
        ))
    ));
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(nonce(&f.store), 4);
}
#[test]
fn signed_scope_and_table_counts_are_bounded_before_admission() {
    let f: Fixture = Fixture::new();
    let before = f.state();
    let base: SignedLocalExecutionIntent =
        decode_signed_local_execution(&f.call(vec![f.authorization()])).unwrap();
    let mut too_many: LocalExecutionIntent = base.intent.clone();
    too_many.authorizations = vec![f.authorization(); 17];
    assert!(encode_local_execution_intent(&too_many).is_err());
    let mut scopes: LocalExecutionIntent = base.intent;
    scopes.authorizations = (0..8)
        .map(|index| {
            let mut authorization: CallAuthorization = f.authorization();
            authorization.callee.instance.seed = [100 + index; 32];
            authorization
        })
        .collect();
    assert!(encode_local_execution_intent(&scopes).is_err());
    assert_eq!(f.state(), before);
}
