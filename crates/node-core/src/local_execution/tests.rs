//! Durable local execution regression tests.
mod unified;
use super::*;
use abi::call_values::{CallAbi, CallValue, ValueLayout, encode_call_value};
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::package_types::{PackageOrigin, ScopedTypeTag, derive_scoped_type_id};
use abi::public_abi::{
    ConstructorDeclaration, EntrypointDeclaration, ObjectMode, ObjectParameter, PackageAbi,
    TypePattern,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::publication::{
    ArtifactParts, CodeArtifact, PublicationRequest, PublicationSubmission, artifact_commitment,
    publication_submission_signing_frame,
};
use protocol_types::{HashSuite, HashSuiteSchedule, ValidatorId};
use runtime::{
    DurableDomainStateStore, MemoryBlobStore, MemoryDurableStateStore, StorageCorrelationId,
    StorageDeadline, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::cell::Cell;

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("local-durable").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn protocol() -> PublicationContext {
    PublicationContext::new(
        resolver().chain_id().clone(),
        resolver().protocol_version(),
        Epoch::new(0),
    )
    .unwrap()
}
fn policy() -> LocalExecutionPolicy {
    LocalExecutionPolicy::new(protocol())
}
fn context() -> DurableOperationContext {
    generation(1)
}
fn generation(n: u64) -> DurableOperationContext {
    DurableOperationContext::new(
        WriterFenceGeneration::new(n).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([3; 16]).unwrap(),
    )
}
fn domain() -> AtomicityDomainId {
    AtomicityDomainId::new([8; 32]).unwrap()
}
fn key() -> SigningKey {
    SigningKey::from([7; 32])
}
fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
fn set_state<S: StructuredDurableDomainStateStore>(
    store: &S,
    key: Vec<u8>,
    mutation: StateMutation,
) {
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &key)
        .unwrap();
    let tx: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), tx),
        DurableCommitOutcome::Committed
    );
}
/// DR-0131: every current mutation path fences the singleton
/// `FastPathEpochRecord`; this file never loads a `ValidatorSet`, so any
/// fixed digest satisfies its own fence.
fn ensure_fastpath_epoch_installed<S: StructuredDurableDomainStateStore>(store: &S) {
    set_state(
        store,
        local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap(),
        StateMutation::Put(
            local_instance_state::encode_fastpath_epoch_record(
                &local_instance_state::FastPathEpochRecord {
                    current_epoch: protocol().epoch(),
                    current_validator_set_digest: resolver()
                        .hash_for_purpose(
                            protocol().epoch(),
                            HashPurpose::NodeEvent,
                            b"local-execution-tests-fastpath-epoch-placeholder",
                        )
                        .unwrap(),
                    previous_epoch: None,
                    activated_at_checkpoint: 0,
                },
            )
            .unwrap(),
        ),
    );
}
fn fixture<S: StructuredDurableDomainStateStore>(store: &S) -> InstanceRecord {
    fixture_with_transfer(store, true)
}
fn fixture_with_transfer<S: StructuredDurableDomainStateStore>(
    store: &S,
    transferable: bool,
) -> InstanceRecord {
    ensure_fastpath_epoch_installed(store);
    let origin: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), sender(), [1; 32]).unwrap();
    let names: [(&str, Option<ObjectMode>); 4] = [
        ("consume", Some(ObjectMode::Consume)),
        ("init", None),
        ("read", Some(ObjectMode::Read)),
        ("write", Some(ObjectMode::Write)),
    ];
    let meta: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: vec![ConstructorDeclaration {
                    local_id: 1,
                    schema: 1,
                    arguments: vec![],
                }],
                entrypoints: names
                    .iter()
                    .map(|(name, mode)| EntrypointDeclaration {
                        name: (*name).into(),
                        type_parameters: vec![],
                        objects: mode
                            .map(|mode| {
                                vec![ObjectParameter {
                                    mode,
                                    schema: 1,
                                    ty: TypePattern {
                                        origin: origin.clone(),
                                        constructor: 1,
                                        arguments: vec![],
                                    },
                                }]
                            })
                            .unwrap_or_default(),
                    })
                    .collect(),
            },
            arguments: vec![ValueLayout::Tuple(vec![]); 4],
            bodies: vec![ValueLayout::U64],
        },
        initializer: Some("init".into()),
        transferable_constructors: if transferable { vec![1] } else { vec![] },
        results: vec![Vec::new(); names.len()],
    };
    let semantics: Digest32 = local_execution_semantics(&resolver(), &protocol()).unwrap();
    let publication_policy: publication::LocalPublicationPolicy =
        publication::LocalPublicationPolicy::executable(protocol(), semantics);
    set_state(
        store,
        publication::publication_policy_key_for_profile(&protocol(), 2).unwrap(),
        StateMutation::Put(publication_policy.encode().unwrap()),
    );
    set_state(
        store,
        execution_policy_key(&protocol()).unwrap(),
        StateMutation::Put(policy().encode().unwrap()),
    );
    let artifact:CodeArtifact=CodeArtifact::new(ArtifactParts{context:protocol(),origin,revision:1,wasm_profile:2,semantics,wasm:wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"consume\")) (func (export \"init\")) (func (export \"read\")) (func (export \"write\")))").unwrap(),unverified_abi:encode_executable_abi(&meta).unwrap(),exports:names.iter().map(|(s,_)|(*s).into()).collect(),unverified_dependencies:vec![]}).unwrap();
    let digest: Digest32 = artifact_commitment(&resolver(), &protocol(), &artifact).unwrap();
    let frame: Vec<u8> =
        publication_submission_signing_frame(&resolver(), &protocol(), &artifact, 0, [1; 32])
            .unwrap();
    let reference: UnverifiedDependencyRef =
        UnverifiedDependencyRef::new(artifact.origin().clone(), 1, protocol(), digest).unwrap();
    let submission: PublicationSubmission = PublicationSubmission::new(
        [1; 32],
        PublicationRequest::new(artifact, 0, digest, key().sign(&frame).into()),
    )
    .unwrap();
    publication::handle_local_publication(
        store,
        &context(),
        domain(),
        &resolver(),
        &publication_policy,
        submission,
    )
    .unwrap();
    InstanceRecord {
        context: protocol(),
        creator: sender(),
        seed: [2; 32],
        code: reference,
        revision: 1,
        initializer: "init".into(),
    }
}
fn sign(
    record: &InstanceRecord,
    nonce: u64,
    request: u8,
    name: &str,
    access: Vec<AccessEntry>,
) -> Vec<u8> {
    let call: execution::call::CallIntent = execution::call::CallIntent {
        context: protocol(),
        request_id: [request; 32],
        sender: sender(),
        nonce,
        code: record.code.clone(),
        instance: instance_target(&resolver(), record).unwrap(),
        entrypoint: name.into(),
        type_arguments: vec![],
        access: abi::AccessManifest { entries: access },
        arguments: encode_call_value(&ValueLayout::Tuple(vec![]), &CallValue::Tuple(vec![]))
            .unwrap(),
        gas_limit: 10000,
    };
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        authorizations: Vec::new(),
        mode: if name == "init" {
            LocalExecutionMode::Instantiate
        } else {
            LocalExecutionMode::Call
        },
        policy_digest: policy().digest(&resolver()).unwrap(),
        call,
    };
    resign(intent)
}
fn resign(intent: LocalExecutionIntent) -> Vec<u8> {
    let frame: Vec<u8> = local_execution_signing_frame(&protocol(), &intent).unwrap();
    encode_signed_local_execution(&SignedLocalExecutionIntent {
        intent,
        signature: key().sign(&frame).into(),
    })
    .unwrap()
}
#[derive(Clone, Copy)]
enum Behavior {
    Create,
    Noop,
    Trap,
    Write,
    Delete,
    Transfer,
    WrongId,
    WrongBody,
    WrongVersion,
    WrongAuthority,
    ExtraAuthority,
}
struct Engine {
    behavior: Behavior,
    calls: Cell<u32>,
}
impl Engine {
    fn new(behavior: Behavior) -> Self {
        Self {
            behavior,
            calls: Cell::new(0),
        }
    }
}
impl LocalContractEngine for Engine {
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
            gas_used: 50,
        };
        let mut authorities: Vec<CreatedObjectAuthority> = vec![];
        match self.behavior {
            Behavior::Trap => {
                effects.status = ExecutionStatus::Failure {
                    reason: LOCAL_EXECUTION_TRAP_REASON.into(),
                }
            }
            Behavior::Noop => {}
            Behavior::Write | Behavior::WrongVersion | Behavior::Transfer => {
                let prior: &Object = &request.inputs[0].resolved.object;
                let mut next: Object = prior.clone();
                next.version += 1;
                next.data = encode_call_value(&ValueLayout::U64, &CallValue::U64(9)).unwrap();
                if matches!(self.behavior, Behavior::WrongVersion) {
                    next.version += 1;
                }
                if matches!(self.behavior, Behavior::Transfer) {
                    next.owner = Owner::Address(Address::new(
                        VerificationKey::from(&SigningKey::from([9; 32])).into(),
                    ));
                }
                effects.object_effects.push(ObjectEffect::Mutated {
                    previous_version: prior.version,
                    new_object: next,
                });
            }
            Behavior::Delete => {
                let prior: &Object = &request.inputs[0].resolved.object;
                effects.object_effects.push(ObjectEffect::Deleted {
                    id: prior.id,
                    version: prior.version,
                });
            }
            _ => {
                let code: UnverifiedDependencyRef = request.root_scope()?.instance.code.clone();
                let ty: ScopedTypeTag =
                    ScopedTypeTag::new(code.origin().clone(), 1, vec![]).unwrap();
                let target =
                    instance_target(request.resolver, &request.root_scope()?.instance).unwrap();
                let mut id: ObjectId = derive_local_created_object_id(
                    request.resolver,
                    &request.intent.intent().call.context,
                    &request.root_scope()?.instance.context,
                    &target,
                    &code,
                    request.event_digest,
                    3,
                )
                .unwrap();
                if matches!(self.behavior, Behavior::WrongId) {
                    id = ObjectId::new([99; 32]);
                }
                let mut authority: ObjectAuthority = ObjectAuthority {
                    object_id: id,
                    instance_context: request.root_scope()?.instance.context.clone(),
                    instance: target,
                    code,
                    ty: ty.clone(),
                };
                if matches!(self.behavior, Behavior::WrongAuthority) {
                    authority.instance.seed = [99; 32];
                }
                authorities.push(CreatedObjectAuthority {
                    creation_ordinal: 3,
                    authority,
                });
                if matches!(self.behavior, Behavior::ExtraAuthority) {
                    authorities.push(authorities[0].clone());
                }
                let object: Object = Object {
                    id,
                    version: 1,
                    owner: Owner::Address(Address::new(sender())),
                    type_hash: derive_scoped_type_id(request.resolver, protocol().epoch(), &ty)
                        .unwrap(),
                    schema_version: 1,
                    data: if matches!(self.behavior, Behavior::WrongBody) {
                        vec![0]
                    } else {
                        encode_call_value(&ValueLayout::U64, &CallValue::U64(1)).unwrap()
                    },
                };
                effects.object_effects.push(ObjectEffect::Created(object));
            }
        }
        Ok(LocalExecutionOutcome {
            effects,
            created_authorities: authorities,
        })
    }
}
fn run<S: StructuredDurableDomainStateStore>(
    store: &S,
    bytes: &[u8],
    engine: &Engine,
) -> AdmissionResult<NodeOutput> {
    handle_local_execution(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &policy(),
        engine,
        bytes,
        10,
    )
}
fn nonce<S: StructuredDurableDomainStateStore>(store: &S) -> u64 {
    query_sender_next_nonce(
        store,
        &context(),
        domain(),
        protocol().chain_id().clone(),
        protocol().protocol_version(),
        protocol().epoch(),
        sender(),
    )
    .unwrap()
}
fn object(output: &NodeOutput) -> Object {
    let result: LocalExecutionResult =
        decode_local_execution_result(output.responses()[0].payload().unwrap()).unwrap();
    match &result.effects.object_effects[0] {
        ObjectEffect::Created(o) => o.clone(),
        _ => panic!("expected create"),
    }
}
fn entry(object: &Object, mode: AccessMode) -> AccessEntry {
    AccessEntry {
        object_ref: ObjectRef {
            id: object.id,
            version: object.version,
            digest: resolver()
                .hash_for_purpose(
                    protocol().epoch(),
                    HashPurpose::Object,
                    &objects::encode_object(object).unwrap(),
                )
                .unwrap(),
        },
        mode,
    }
}

#[test]
fn creation_and_mutation_share_nonce_and_immutable_authority() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let engine: Engine = Engine::new(Behavior::Create);
    let init: Vec<u8> = sign(&record, 1, 2, "init", vec![]);
    let output: NodeOutput = run(&store, &init, &engine).unwrap();
    let created: Object = object(&output);
    assert_eq!(nonce(&store), 2);
    assert!(output.outbound_messages().is_empty());
    let sidecar: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &object_authority_key(created.id))
        .unwrap();
    assert!(
        local_instance_state::legacy_absence(&store, &context(), domain(), created.id).is_err()
    );
    assert_eq!(run(&store, &init, &engine).unwrap(), output);
    assert_eq!(engine.calls.get(), 1);
    assert_eq!(
        query_local_instance(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            record.creator,
            record.seed
        )
        .unwrap(),
        Some(record.clone())
    );
    let write: Vec<u8> = sign(
        &record,
        2,
        3,
        "write",
        vec![entry(&created, AccessMode::Write)],
    );
    run(&store, &write, &Engine::new(Behavior::Write)).unwrap();
    assert_eq!(nonce(&store), 3);
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &object_authority_key(created.id))
            .unwrap(),
        sidecar
    );
    assert_eq!(
        store
            .get_object_head(&context(), domain(), created.id)
            .unwrap()
            .object_version()
            .unwrap()
            .get(),
        2
    );
}

/// Same as [`sign`], but for an explicitly chosen signing key/sender,
/// needed to prove a fast-path object-lock rejection independent of any
/// sender/epoch nonce lock (a different sender never shares the locked
/// sender's nonce-lock key, so the nonce-lock cannot be masking the
/// rejection).
fn sign_as(
    signing_key: &SigningKey,
    record: &InstanceRecord,
    nonce: u64,
    request: u8,
    name: &str,
    access: Vec<AccessEntry>,
) -> Vec<u8> {
    let sender: [u8; 32] = VerificationKey::from(signing_key).into();
    let call: execution::call::CallIntent = execution::call::CallIntent {
        context: protocol(),
        request_id: [request; 32],
        sender,
        nonce,
        code: record.code.clone(),
        instance: instance_target(&resolver(), record).unwrap(),
        entrypoint: name.into(),
        type_arguments: vec![],
        access: abi::AccessManifest { entries: access },
        arguments: encode_call_value(&ValueLayout::Tuple(vec![]), &CallValue::Tuple(vec![]))
            .unwrap(),
        gas_limit: 10000,
    };
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        authorizations: Vec::new(),
        mode: if name == "init" {
            LocalExecutionMode::Instantiate
        } else {
            LocalExecutionMode::Call
        },
        policy_digest: policy().digest(&resolver()).unwrap(),
        call,
    };
    let frame: Vec<u8> = local_execution_signing_frame(&protocol(), &intent).unwrap();
    encode_signed_local_execution(&SignedLocalExecutionIntent {
        intent,
        signature: signing_key.sign(&frame).into(),
    })
    .unwrap()
}

/// DR-0131 criterion 8: a previously uncovered direct mutation branch --
/// local execution's owned-object `Write` -- now honors a held
/// `FastPathLockRecord`. The conflicting request is signed by a *different*
/// sender than the one whose fast-path prepare holds the lock, so the
/// sender/epoch nonce-lock (scoped to the locking sender) cannot be masking
/// the object-lock rejection: the second sender's own nonce is never locked
/// at all.
#[test]
fn a_fastpath_object_lock_blocks_local_execution_write_from_a_different_sender() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let engine: Engine = Engine::new(Behavior::Create);
    let init: Vec<u8> = sign(&record, 1, 2, "init", vec![]);
    let created: Object = object(&run(&store, &init, &engine).unwrap());

    // Simulate an in-flight fast-path prepare (owned by `sender()`) holding
    // an exclusive lock on the created object, without invoking the fast
    // path at all: this proves the direct local-execution branch itself now
    // consults the lock, not merely that the fast path writes one.
    let lock_key: Vec<u8> =
        local_instance_state::fastpath_lock_key(protocol().chain_id(), created.id).unwrap();
    let lock: local_instance_state::FastPathLockRecord = local_instance_state::FastPathLockRecord {
        request_id: [0x99; 32],
        object: ObjectRef {
            id: created.id,
            version: created.version,
            digest: resolver()
                .hash_for_purpose(
                    protocol().epoch(),
                    HashPurpose::Object,
                    &objects::encode_object(&created).unwrap(),
                )
                .unwrap(),
        },
        locked_epoch: protocol().epoch(),
    };
    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &lock_key)
        .unwrap();
    let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
        domain(),
        AtomicStateReadSet::new(vec![
            StateReadAssertion::new(lock_key.clone(), observed.revision()).unwrap(),
        ])
        .unwrap(),
        AtomicStateMutationSet::new(vec![
            StateMutationEntry::new(
                lock_key,
                StateMutation::Put(
                    local_instance_state::encode_fastpath_lock_record(&lock).unwrap(),
                ),
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.commit_durable(&context(), transaction),
        DurableCommitOutcome::Committed
    );

    // A genuinely different sender, with its own fresh nonce (0) and no
    // nonce-lock of its own, attempts to write the locked object.
    let other_key: SigningKey = SigningKey::from([0x42; 32]);
    let write: Vec<u8> = sign_as(
        &other_key,
        &record,
        0,
        9,
        "write",
        vec![entry(&created, AccessMode::Write)],
    );
    let result = run(&store, &write, &Engine::new(Behavior::Write));
    assert!(matches!(
        result,
        Err(LocalExecutionAdmissionError::Node(
            NodeCoreError::PersistenceInvariant("object locked by a pending fast-path certificate")
        ))
    ));
    // The object is untouched and the other sender's own nonce never moved.
    assert_eq!(
        store
            .get_object_head(&context(), domain(), created.id)
            .unwrap()
            .object_version()
            .unwrap()
            .get(),
        1
    );
}

/// An explicit later epoch, distinct from the fixture's own fixed
/// `protocol()` (`epoch 0`) -- needed to exercise DR-0132 §3.D's stale
/// (strictly older epoch) object-lock reclamation at local execution's
/// direct `Write` path, which the fixed-epoch fixture above cannot reach
/// (there is no epoch below `0`).
fn next_epoch() -> Epoch {
    Epoch::new(protocol().epoch().get() + 1)
}
fn protocol_at(epoch: Epoch) -> PublicationContext {
    PublicationContext::new(
        resolver().chain_id().clone(),
        resolver().protocol_version(),
        epoch,
    )
    .unwrap()
}
fn policy_at(epoch: Epoch) -> LocalExecutionPolicy {
    LocalExecutionPolicy::new(protocol_at(epoch))
}
/// Rewrites the committed `FastPathEpochRecord` to `next_epoch`, simulating
/// (without a real DR-0132 transition, which this lightweight fixture never
/// runs) a node that has already advanced past the fixture's own genesis
/// epoch -- exactly the state `mutation_fence::fence_current_epoch` and
/// `fence_object_lock` observe after a real `activate`.
fn advance_fastpath_epoch<S: StructuredDurableDomainStateStore>(store: &S, next_epoch: Epoch) {
    set_state(
        store,
        local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap(),
        StateMutation::Put(
            local_instance_state::encode_fastpath_epoch_record(
                &local_instance_state::FastPathEpochRecord {
                    current_epoch: next_epoch,
                    current_validator_set_digest: resolver()
                        .hash_for_purpose(
                            next_epoch,
                            HashPurpose::NodeEvent,
                            b"local-execution-tests-fastpath-epoch-placeholder",
                        )
                        .unwrap(),
                    previous_epoch: Some(protocol().epoch()),
                    activated_at_checkpoint: 0,
                },
            )
            .unwrap(),
        ),
    );
}
/// Identical to [`sign`], but signs against an explicitly given
/// `context`/`policy` instead of the fixture's fixed `protocol()`/`policy()`
/// -- needed to frame a call at a later epoch than the fixture's own
/// genesis-like installation epoch. Always `LocalExecutionMode::Call`: this
/// helper is never used to instantiate.
fn sign_at(
    context: &PublicationContext,
    policy: &LocalExecutionPolicy,
    record: &InstanceRecord,
    nonce: u64,
    request: u8,
    name: &str,
    access: Vec<AccessEntry>,
) -> Vec<u8> {
    let call: execution::call::CallIntent = execution::call::CallIntent {
        context: context.clone(),
        request_id: [request; 32],
        sender: sender(),
        nonce,
        code: record.code.clone(),
        instance: instance_target(&resolver(), record).unwrap(),
        entrypoint: name.into(),
        type_arguments: vec![],
        access: abi::AccessManifest { entries: access },
        arguments: encode_call_value(&ValueLayout::Tuple(vec![]), &CallValue::Tuple(vec![]))
            .unwrap(),
        gas_limit: 10000,
    };
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        authorizations: Vec::new(),
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&resolver()).unwrap(),
        call,
    };
    let frame: Vec<u8> = local_execution_signing_frame(context, &intent).unwrap();
    encode_signed_local_execution(&SignedLocalExecutionIntent {
        intent,
        signature: key().sign(&frame).into(),
    })
    .unwrap()
}
/// Identical to [`run`], but admits against an explicitly given `policy`
/// instead of the fixture's fixed `policy()`.
fn run_at<S: StructuredDurableDomainStateStore>(
    store: &S,
    policy: &LocalExecutionPolicy,
    bytes: &[u8],
    engine: &Engine,
) -> AdmissionResult<NodeOutput> {
    handle_local_execution(
        store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        policy,
        engine,
        bytes,
        10,
    )
}
/// Installs a `FastPathLockRecord` for `object`, stamped `locked_epoch`,
/// exactly like the two tests below need (one stale, one current-at-`e+1`).
fn install_lock<S: StructuredDurableDomainStateStore>(
    store: &S,
    object: &Object,
    locked_epoch: Epoch,
    request_id: [u8; 32],
) -> Vec<u8> {
    let lock_key: Vec<u8> =
        local_instance_state::fastpath_lock_key(protocol().chain_id(), object.id).unwrap();
    let lock: local_instance_state::FastPathLockRecord = local_instance_state::FastPathLockRecord {
        request_id,
        object: ObjectRef {
            id: object.id,
            version: object.version,
            digest: resolver()
                .hash_for_purpose(
                    protocol().epoch(),
                    HashPurpose::Object,
                    &objects::encode_object(object).unwrap(),
                )
                .unwrap(),
        },
        locked_epoch,
    };
    set_state(
        store,
        lock_key.clone(),
        StateMutation::Put(local_instance_state::encode_fastpath_lock_record(&lock).unwrap()),
    );
    lock_key
}

/// DR-0132 §3.D: a fast-path object lock stamped a strictly older epoch than
/// the fenced current epoch is stale -- the transition that would have let
/// its owning certificate reach `apply` again can never happen (DR-0132's
/// fenced-epoch proof) -- so local execution's direct `Write` path reclaims
/// it: the write proceeds and the stale lock is deleted in the same commit,
/// instead of the request failing closed the way the negative control above
/// (a *current*-epoch lock) still does.
#[test]
fn a_stale_fastpath_object_lock_is_reclaimed_by_local_execution_write_at_the_next_epoch() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let engine: Engine = Engine::new(Behavior::Create);
    let init: Vec<u8> = sign(&record, 1, 2, "init", vec![]);
    let created: Object = object(&run(&store, &init, &engine).unwrap());

    // A lock stamped the outgoing epoch -- exactly what a `fast_path::prepare`
    // from before the transition would have left behind, owned by some other,
    // now-irrelevant request.
    let lock_key: Vec<u8> = install_lock(&store, &created, protocol().epoch(), [0x55; 32]);

    let next_epoch: Epoch = next_epoch();
    let next_context: PublicationContext = protocol_at(next_epoch);
    let next_policy: LocalExecutionPolicy = policy_at(next_epoch);
    advance_fastpath_epoch(&store, next_epoch);
    set_state(
        &store,
        execution_policy_key(&next_context).unwrap(),
        StateMutation::Put(next_policy.encode().unwrap()),
    );

    // The nonce domain restarts at the new epoch (DR-0132 consequence): the
    // sender's first nonce at `next_epoch` is `0`, independent of its
    // epoch-0 sequence above.
    let write: Vec<u8> = sign_at(
        &next_context,
        &next_policy,
        &record,
        0,
        3,
        "write",
        vec![entry(&created, AccessMode::Write)],
    );
    run_at(&store, &next_policy, &write, &Engine::new(Behavior::Write)).unwrap();

    let observed: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &lock_key)
        .unwrap();
    assert!(
        observed.value().is_none(),
        "the stale lock must be deleted by the write, not merely bypassed"
    );
    assert_eq!(
        store
            .get_object_head(&context(), domain(), created.id)
            .unwrap()
            .object_version()
            .unwrap()
            .get(),
        2,
        "the write itself must still take effect"
    );
}

/// Negative control adjacent to the test above: a lock stamped the *current*
/// epoch (`next_epoch`, not the outgoing one) still blocks local execution's
/// direct `Write` path, exactly as
/// `a_fastpath_object_lock_blocks_local_execution_write_from_a_different_sender`
/// proves at the fixture's own genesis epoch -- proving reclamation is
/// strictly `locked_epoch < current_epoch`, never merely "locked_epoch !=
/// this request's own epoch".
#[test]
fn a_current_epoch_lock_still_blocks_local_execution_write_at_the_next_epoch() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let engine: Engine = Engine::new(Behavior::Create);
    let init: Vec<u8> = sign(&record, 1, 2, "init", vec![]);
    let created: Object = object(&run(&store, &init, &engine).unwrap());

    let next_epoch: Epoch = next_epoch();
    let next_context: PublicationContext = protocol_at(next_epoch);
    let next_policy: LocalExecutionPolicy = policy_at(next_epoch);
    advance_fastpath_epoch(&store, next_epoch);
    set_state(
        &store,
        execution_policy_key(&next_context).unwrap(),
        StateMutation::Put(next_policy.encode().unwrap()),
    );

    // A lock stamped `next_epoch` itself -- the request's own current
    // epoch, not a stale one.
    install_lock(&store, &created, next_epoch, [0x66; 32]);

    let write: Vec<u8> = sign_at(
        &next_context,
        &next_policy,
        &record,
        0,
        3,
        "write",
        vec![entry(&created, AccessMode::Write)],
    );
    let result = run_at(&store, &next_policy, &write, &Engine::new(Behavior::Write));
    assert!(matches!(
        result,
        Err(LocalExecutionAdmissionError::Node(
            NodeCoreError::PersistenceInvariant("object locked by a pending fast-path certificate")
        ))
    ));
    assert_eq!(
        store
            .get_object_head(&context(), domain(), created.id)
            .unwrap()
            .object_version()
            .unwrap()
            .get(),
        1,
        "the object must be untouched"
    );
}

/// DR-0131 criterion 7: the local-execution-intent event family rejects an
/// externally supplied request id inside the reserved fast-path synthetic
/// namespace, through the one shared validation boundary
/// (`local_instance_state::reject_reserved_request_id`).
#[test]
fn reserved_request_id_prefix_is_rejected_before_any_admission() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let nonce_before: u64 = nonce(&store);
    let mut reserved_id: [u8; 32] = [0u8; 32];
    reserved_id[..local_instance_state::FASTPATH_SYNTHETIC_REQUEST_ID_TAG.len()]
        .copy_from_slice(&local_instance_state::FASTPATH_SYNTHETIC_REQUEST_ID_TAG);
    let call: execution::call::CallIntent = execution::call::CallIntent {
        context: protocol(),
        request_id: reserved_id,
        sender: sender(),
        nonce: nonce_before,
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
        policy_digest: policy().digest(&resolver()).unwrap(),
        call,
    };
    let bytes: Vec<u8> = resign(intent);
    let result = run(&store, &bytes, &Engine::new(Behavior::Create));
    assert!(matches!(
        result,
        Err(LocalExecutionAdmissionError::Invalid(
            "request id reserved for fast-path synthetic receipts"
        ))
    ));
    assert_eq!(nonce(&store), nonce_before);
}

/// DR-0131 criterion 4: local execution rejects a request bound to a
/// non-current epoch before any lock, engine execution, or mutation.
/// `engine.calls` staying at zero proves the fence rejects before the engine
/// boundary is ever entered; the unmoved nonce proves no mutation survives.
#[test]
fn a_wrong_current_epoch_is_rejected_before_any_engine_call_or_nonce_advance() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let nonce_before: u64 = nonce(&store);
    set_state(
        &store,
        local_instance_state::fastpath_epoch_record_key(protocol().chain_id()).unwrap(),
        StateMutation::Put(
            local_instance_state::encode_fastpath_epoch_record(
                &local_instance_state::FastPathEpochRecord {
                    current_epoch: Epoch::new(protocol().epoch().get() + 1),
                    current_validator_set_digest: resolver()
                        .hash_for_purpose(
                            protocol().epoch(),
                            HashPurpose::NodeEvent,
                            b"local-execution-tests-fastpath-epoch-placeholder",
                        )
                        .unwrap(),
                    previous_epoch: None,
                    activated_at_checkpoint: 0,
                },
            )
            .unwrap(),
        ),
    );
    let init: Vec<u8> = sign(&record, nonce_before, 2, "init", vec![]);
    let engine: Engine = Engine::new(Behavior::Create);
    let result = run(&store, &init, &engine);
    assert!(matches!(
        result,
        Err(LocalExecutionAdmissionError::Node(NodeCoreError::EpochMismatch { expected, actual }))
            if expected == Epoch::new(protocol().epoch().get() + 1) && actual == protocol().epoch()
    ));
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(nonce(&store), nonce_before);
}

#[test]
fn forged_engine_outputs_commit_nothing() {
    for behavior in [
        Behavior::WrongId,
        Behavior::WrongBody,
        Behavior::WrongAuthority,
        Behavior::ExtraAuthority,
    ] {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        let record: InstanceRecord = fixture(&store);
        assert!(
            run(
                &store,
                &sign(&record, 1, 2, "init", vec![]),
                &Engine::new(behavior)
            )
            .is_err()
        );
        assert_eq!(nonce(&store), 1);
        assert!(
            query_local_instance(
                &store,
                &context(),
                domain(),
                &resolver(),
                &[],
                protocol().chain_id(),
                record.creator,
                record.seed
            )
            .unwrap()
            .is_none()
        );
    }
}

#[test]
fn trap_consumes_nonce_not_instance_and_replays_without_vm() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let engine: Engine = Engine::new(Behavior::Trap);
    let init: Vec<u8> = sign(&record, 1, 2, "init", vec![]);
    let output: NodeOutput = run(&store, &init, &engine).unwrap();
    assert_eq!(output.responses()[0].status(), NodeResponseStatus::Rejected);
    assert_eq!(nonce(&store), 2);
    assert!(
        query_local_instance(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            record.creator,
            record.seed
        )
        .unwrap()
        .is_none()
    );
    set_state(
        &store,
        execution_policy_key(&protocol()).unwrap(),
        StateMutation::Delete,
    );
    assert_eq!(run(&store, &init, &engine).unwrap(), output);
    assert_eq!(engine.calls.get(), 1);
}

#[test]
fn read_cannot_mutate_or_transfer_and_consume_retains_sidecar() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let created: Object = object(
        &run(
            &store,
            &sign(&record, 1, 2, "init", vec![]),
            &Engine::new(Behavior::Create),
        )
        .unwrap(),
    );
    for (name, mode, behavior) in [
        ("read", AccessMode::Read, Behavior::Write),
        ("read", AccessMode::Read, Behavior::Transfer),
        ("write", AccessMode::Write, Behavior::WrongVersion),
    ] {
        assert!(
            run(
                &store,
                &sign(&record, 2, 3, name, vec![entry(&created, mode)]),
                &Engine::new(behavior)
            )
            .is_err()
        );
        assert_eq!(nonce(&store), 2);
    }
    let sidecar: VersionedStateValue = store
        .get_versioned_durable(&context(), domain(), &object_authority_key(created.id))
        .unwrap();
    run(
        &store,
        &sign(
            &record,
            2,
            3,
            "consume",
            vec![entry(&created, AccessMode::Consume)],
        ),
        &Engine::new(Behavior::Delete),
    )
    .unwrap();
    assert!(matches!(
        store
            .get_object_head(&context(), domain(), created.id)
            .unwrap(),
        DurableObjectHead::Tombstoned { .. }
    ));
    assert_eq!(
        store
            .get_versioned_durable(&context(), domain(), &object_authority_key(created.id))
            .unwrap(),
        sidecar
    );
    assert!(
        run(
            &store,
            &sign(
                &record,
                3,
                4,
                "read",
                vec![entry(&created, AccessMode::Read)]
            ),
            &Engine::new(Behavior::Noop)
        )
        .is_err()
    );
}

#[test]
fn write_transfer_requires_signed_constructor_permission() {
    for transferable in [true, false] {
        let store: MemoryDurableStateStore =
            MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
        let record: InstanceRecord = fixture_with_transfer(&store, transferable);
        let created: Object = object(
            &run(
                &store,
                &sign(&record, 1, 2, "init", vec![]),
                &Engine::new(Behavior::Create),
            )
            .unwrap(),
        );
        let before: Snapshot = snapshot(&store, &context(), &record, created.id);
        let result: AdmissionResult<NodeOutput> = run(
            &store,
            &sign(
                &record,
                2,
                3,
                "write",
                vec![entry(&created, AccessMode::Write)],
            ),
            &Engine::new(Behavior::Transfer),
        );
        if transferable {
            let output: NodeOutput = result.unwrap();
            let receipt: LocalExecutionResult =
                decode_local_execution_result(output.responses()[0].payload().unwrap()).unwrap();
            let ObjectEffect::Mutated { new_object, .. } = &receipt.effects.object_effects[0]
            else {
                panic!("expected transfer");
            };
            assert_ne!(new_object.owner, created.owner);
            assert_eq!(new_object.version, 2);
            assert_eq!(nonce(&store), 3);
            assert_eq!(
                store
                    .get_versioned_durable(&context(), domain(), &object_authority_key(created.id))
                    .unwrap(),
                before.states[1]
            );
        } else {
            assert!(matches!(
                result,
                Err(LocalExecutionAdmissionError::Invalid(
                    "unauthorized transfer"
                ))
            ));
            assert_eq!(snapshot(&store, &context(), &record, created.id), before);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    states: Vec<VersionedStateValue>,
    head: DurableObjectHead,
    versions: Vec<Option<DurableObjectVersionRecord>>,
    receipts: Vec<Option<DurableRequestReceipt>>,
}
fn snapshot<S: StructuredDurableDomainStateStore>(
    store: &S,
    ctx: &DurableOperationContext,
    record: &InstanceRecord,
    id: ObjectId,
) -> Snapshot {
    let keys: Vec<Vec<u8>> = vec![
        instance_record_key(protocol().chain_id(), &record.creator, &record.seed).unwrap(),
        object_authority_key(id),
        PersistenceLayout::new(protocol().chain_id().clone(), protocol().protocol_version())
            .sender_nonce_key(sender(), protocol().epoch()),
        publication::publication_record_key(record.code.origin()).unwrap(),
    ];
    Snapshot {
        states: keys
            .iter()
            .map(|k| store.get_versioned_durable(ctx, domain(), k).unwrap())
            .collect(),
        head: store.get_object_head(ctx, domain(), id).unwrap(),
        versions: (1..=2)
            .map(|v| {
                store
                    .get_object_version(ctx, domain(), id, DurableObjectVersion::new(v).unwrap())
                    .unwrap()
            })
            .collect(),
        receipts: (1..=3)
            .map(|r| {
                store
                    .get_request_receipt(ctx, domain(), DurableRequestId::new([r; 32]).unwrap())
                    .unwrap()
            })
            .collect(),
    }
}

#[test]
fn sqlite_reopen_exact_bytes_nonce_receipts_replay_and_writer_fence() {
    let unique: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path: std::path::PathBuf = std::env::temp_dir().join(format!(
        "local-execution-{}-{unique}.sqlite",
        std::process::id()
    ));
    let namespace: SqliteNamespace = SqliteNamespace::new(
        protocol().chain_id().clone(),
        ValidatorId::new([4; 32]),
        domain(),
    );
    let record: InstanceRecord;
    let init: Vec<u8>;
    let write: Vec<u8>;
    let created: Object;
    let initial_output: NodeOutput;
    let write_output: NodeOutput;
    let expected: Snapshot;
    {
        let store: SqliteDurableStore = SqliteDurableStore::open(
            &path,
            namespace.clone(),
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        record = fixture(&store);
        init = sign(&record, 1, 2, "init", vec![]);
        initial_output = run(&store, &init, &Engine::new(Behavior::Create)).unwrap();
        created = object(&initial_output);
        write = sign(
            &record,
            2,
            3,
            "write",
            vec![entry(&created, AccessMode::Write)],
        );
        write_output = run(&store, &write, &Engine::new(Behavior::Write)).unwrap();
        expected = snapshot(&store, &context(), &record, created.id);
        assert_eq!(
            expected.states[0].value(),
            Some(encode_instance_record(&record).unwrap().as_slice())
        );
        assert!(expected.states[1].value().is_some());
        assert!(expected.versions.iter().all(Option::is_some));
        assert!(expected.receipts.iter().all(Option::is_some));
        assert_eq!(nonce(&store), 3);
        let replay: Engine = Engine::new(Behavior::WrongId);
        assert_eq!(run(&store, &init, &replay).unwrap(), initial_output);
        assert_eq!(run(&store, &write, &replay).unwrap(), write_output);
        assert_eq!(replay.calls.get(), 0);
        let mut reused: SignedLocalExecutionIntent = decode_signed_local_execution(&init).unwrap();
        reused.intent.call.nonce = 3;
        assert!(matches!(
            run(&store, &resign(reused.intent), &replay),
            Err(LocalExecutionAdmissionError::Node(
                NodeCoreError::RequestIdReuse
            ))
        ));
        assert_eq!(snapshot(&store, &context(), &record, created.id), expected);
        store
            .advance_writer_fence(
                WriterFenceGeneration::new(1).unwrap(),
                WriterFenceGeneration::new(2).unwrap(),
            )
            .unwrap();
    }
    {
        let store: SqliteDurableStore =
            SqliteDurableStore::open(&path, namespace, WriterFenceGeneration::new(1).unwrap())
                .unwrap();
        assert_eq!(
            store.writer_fence().unwrap(),
            WriterFenceGeneration::new(2).unwrap()
        );
        let replay: Engine = Engine::new(Behavior::WrongId);
        assert!(run(&store, &init, &replay).is_err());
        for (bytes, expected_output) in [(&init, &initial_output), (&write, &write_output)] {
            let actual: NodeOutput = handle_local_execution(
                &store,
                &MemoryBlobStore::default(),
                &generation(2),
                domain(),
                &resolver(),
                &[],
                &policy(),
                &replay,
                bytes,
                10,
            )
            .unwrap();
            assert_eq!(&actual, expected_output);
        }
        assert_eq!(replay.calls.get(), 0);
        assert_eq!(
            snapshot(&store, &generation(2), &record, created.id),
            expected
        );
        assert_eq!(
            query_local_instance(
                &store,
                &generation(2),
                domain(),
                &resolver(),
                &[],
                protocol().chain_id(),
                record.creator,
                record.seed
            )
            .unwrap(),
            Some(record)
        );
    }
    std::fs::remove_file(path).unwrap();
}

struct RacingEngine<'a> {
    store: &'a MemoryDurableStateStore,
}
impl LocalContractEngine for RacingEngine<'_> {
    fn execute(
        &self,
        request: LocalExecutionRequest<'_>,
    ) -> Result<LocalExecutionOutcome, LocalExecutionError> {
        let result: LocalExecutionOutcome = Engine::new(Behavior::Create).execute(request)?;
        set_state(
            self.store,
            execution_policy_key(&protocol()).unwrap(),
            StateMutation::Put(policy().encode().unwrap()),
        );
        Ok(result)
    }
}
#[test]
fn policy_cas_race_rolls_back_objects_instance_nonce_and_receipt() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let init: Vec<u8> = sign(&record, 1, 2, "init", vec![]);
    let result = handle_local_execution(
        &store,
        &MemoryBlobStore::default(),
        &context(),
        domain(),
        &resolver(),
        &[],
        &policy(),
        &RacingEngine { store: &store },
        &init,
        10,
    );
    assert!(matches!(
        result,
        Err(LocalExecutionAdmissionError::Node(
            NodeCoreError::StateConflict
        ))
    ));
    assert_eq!(nonce(&store), 1);
    assert!(
        store
            .get_request_receipt(
                &context(),
                domain(),
                DurableRequestId::new([2; 32]).unwrap()
            )
            .unwrap()
            .is_none()
    );
    assert!(
        query_local_instance(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            record.creator,
            record.seed
        )
        .unwrap()
        .is_none()
    );
    run(&store, &init, &Engine::new(Behavior::Create)).unwrap();
}

struct LegacyMachine {
    calls: Cell<u32>,
}
impl TransactionalNodeStateMachine for LegacyMachine {
    fn access_plan(&self, _: &NodeEvent) -> Result<NodeStateAccessPlan, NodeCoreError> {
        NodeStateAccessPlan::new(vec![NodeStateAccess::new(
            b"legacy/test".to_vec(),
            NodeStateAccessMode::ReadOnly,
        )?])
    }
    fn transition(
        &self,
        state: &NodeStateSnapshot,
        event: &NodeEvent,
    ) -> Result<TransactionalNodeTransition, NodeCoreError> {
        self.calls.set(self.calls.get() + 1);
        let mut object: Object = state.resolved_objects()[0].object.clone();
        let previous_version: u64 = object.version;
        object.version += 1;
        object.data.clear();
        TransactionalNodeTransition::with_object_effects(
            vec![],
            vec![ObjectEffect::Mutated {
                previous_version,
                new_object: object,
            }],
            NodeOutput::new(
                vec![NodeResponse::new(
                    event.request_id(),
                    NodeResponseStatus::Accepted,
                    None,
                )?],
                vec![],
            )?,
        )
    }
}
#[test]
fn actual_legacy_authenticated_handler_cannot_mutate_public_object() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let created: Object = object(
        &run(
            &store,
            &sign(&record, 1, 2, "init", vec![]),
            &Engine::new(Behavior::Create),
        )
        .unwrap(),
    );
    let before: Snapshot = snapshot(&store, &context(), &record, created.id);
    let mut tx: Transaction = Transaction {
        chain_id: protocol().chain_id().clone(),
        protocol_version: protocol().protocol_version(),
        epoch: protocol().epoch(),
        sender: Address::new(sender()),
        nonce: 2,
        access_manifest: abi::AccessManifest {
            entries: vec![entry(&created, AccessMode::Write)],
        },
        module_ref: entry(&created, AccessMode::Read).object_ref,
        entrypoint: "legacy".into(),
        args: vec![],
        gas_limit: 1000,
        fee_payment: None,
        signature: vec![],
    };
    let signature_domain: crypto::SignatureDomain = crypto::SignatureDomain {
        chain_id: tx.chain_id.clone(),
        protocol_version: tx.protocol_version,
        epoch: tx.epoch,
        message_type: crypto::SignatureMessageType::new("transaction-v1").unwrap(),
        signature_scheme_id: protocol_types::SignatureSchemeId::Ed25519,
    };
    tx.signature = key()
        .sign(
            &crypto::frame_signature_message(
                &signature_domain,
                &execution::encode_transaction_signable(&tx).unwrap(),
            )
            .unwrap(),
        )
        .to_bytes()
        .to_vec();
    let event: NodeEvent = NodeEvent::new(
        tx.chain_id.clone(),
        tx.protocol_version,
        tx.epoch,
        RequestId::new([4; 32]).unwrap(),
        NodeEventKind::SubmitTransaction,
        execution::encode_transaction(&tx).unwrap(),
    )
    .unwrap();
    let config: NodeConfig = NodeConfig::new(
        tx.chain_id.clone(),
        tx.protocol_version,
        tx.epoch,
        b"node/state".to_vec(),
    )
    .unwrap();
    let mut protocol_config: ProtocolConfig = ProtocolConfig::genesis();
    protocol_config.protocol_version = tx.protocol_version;
    protocol_config.domain_placement =
        Some(DomainPlacementManifest::single_domain(1, domain(), Epoch::new(0)).unwrap());
    protocol_config.transaction_auth_profile =
        Some(protocol_config::TransactionAuthProfile::ed25519_address_is_public_key());
    let trusted_context: TrustedTransactionContext<'_> =
        TrustedTransactionContext::new(config.chain_id().clone(), config.epoch(), &protocol_config);
    let authenticated: AuthenticatedSubmitTransaction =
        authenticate_submit_transaction_event(event, &trusted_context).unwrap();
    let engine: LegacyMachine = LegacyMachine {
        calls: Cell::new(0),
    };
    let error = handle_authenticated_resolved_durable_submit_transaction_with_owned_object_effects(
        &MemoryBlobStore::default(),
        &store,
        &context(),
        &resolver(),
        authenticated,
        10,
        &engine,
    )
    .unwrap_err();
    assert!(
        matches!(error, NodeCoreError::ReservedStateAccess(_)),
        "{error:?}"
    );
    assert_eq!(engine.calls.get(), 0);
    assert_eq!(snapshot(&store, &context(), &record, created.id), before);
}

#[test]
fn foreign_instance_checkpoint_regression_and_tombstoned_origin_fail_closed() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let record: InstanceRecord = fixture(&store);
    let created: Object = object(
        &run(
            &store,
            &sign(&record, 1, 2, "init", vec![]),
            &Engine::new(Behavior::Create),
        )
        .unwrap(),
    );
    let write: Vec<u8> = sign(
        &record,
        2,
        3,
        "write",
        vec![entry(&created, AccessMode::Write)],
    );
    assert!(
        handle_local_execution(
            &store,
            &MemoryBlobStore::default(),
            &context(),
            domain(),
            &resolver(),
            &[],
            &policy(),
            &Engine::new(Behavior::Write),
            &write,
            9
        )
        .is_err()
    );
    assert_eq!(nonce(&store), 2);
    let mut other: InstanceRecord = record.clone();
    other.seed = [9; 32];
    run(
        &store,
        &sign(&other, 2, 3, "init", vec![]),
        &Engine::new(Behavior::Noop),
    )
    .unwrap();
    let engine: Engine = Engine::new(Behavior::Noop);
    assert!(
        run(
            &store,
            &sign(
                &other,
                3,
                4,
                "read",
                vec![entry(&created, AccessMode::Read)]
            ),
            &engine
        )
        .is_err()
    );
    assert_eq!(engine.calls.get(), 0);
    let key: Vec<u8> =
        instance_record_key(protocol().chain_id(), &other.creator, &other.seed).unwrap();
    set_state(&store, key, StateMutation::Delete);
    assert!(
        query_local_instance(
            &store,
            &context(),
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            other.creator,
            other.seed
        )
        .is_err()
    );
    assert!(run(&store, &sign(&other, 3, 5, "init", vec![]), &engine).is_err());
    assert_eq!(nonce(&store), 3);
}

fn publish_profile_four_artifact<S: StructuredDurableDomainStateStore>(
    store: &S,
    semantics: Digest32,
) -> UnverifiedDependencyRef {
    ensure_fastpath_epoch_installed(store);
    let origin: PackageOrigin =
        PackageOrigin::unverified(protocol().chain_id().clone(), sender(), [40; 32]).unwrap();
    let meta: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: vec![ConstructorDeclaration {
                    local_id: 1,
                    schema: 1,
                    arguments: vec![],
                }],
                entrypoints: vec![EntrypointDeclaration {
                    name: "init".into(),
                    type_parameters: vec![],
                    objects: vec![],
                }],
            },
            arguments: vec![ValueLayout::Tuple(vec![])],
            bodies: vec![ValueLayout::U64],
        },
        initializer: Some("init".into()),
        transferable_constructors: vec![],
        results: vec![Vec::new()],
    };
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: protocol(),
        origin,
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm: wat::parse_str("(module (memory (export \"memory\") 1 2) (func (export \"init\")))")
            .unwrap(),
        unverified_abi: encode_executable_abi(&meta).unwrap(),
        exports: vec!["init".into()],
        unverified_dependencies: vec![],
    })
    .unwrap();
    let digest: Digest32 = artifact_commitment(&resolver(), &protocol(), &artifact).unwrap();
    let frame: Vec<u8> =
        publication_submission_signing_frame(&resolver(), &protocol(), &artifact, 0, [40; 32])
            .unwrap();
    let reference: UnverifiedDependencyRef =
        UnverifiedDependencyRef::new(artifact.origin().clone(), 1, protocol(), digest).unwrap();
    let submission: PublicationSubmission = PublicationSubmission::new(
        [40; 32],
        PublicationRequest::new(artifact, 0, digest, key().sign(&frame).into()),
    )
    .unwrap();
    let publication_policy: publication::LocalPublicationPolicy =
        publication::LocalPublicationPolicy::object_results(protocol(), semantics);
    set_state(
        store,
        publication::publication_policy_key_for_profile(&protocol(), 4).unwrap(),
        StateMutation::Put(publication_policy.encode().unwrap()),
    );
    publication::handle_local_publication(
        store,
        &context(),
        domain(),
        &resolver(),
        &publication_policy,
        submission,
    )
    .unwrap();
    reference
}

#[test]
fn validate_closure_admits_profile_four_generic_object_result_semantics() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let semantics: Digest32 = generic_object_result_semantics(&resolver(), &protocol()).unwrap();
    let reference: UnverifiedDependencyRef = publish_profile_four_artifact(&store, semantics);
    let loaded: VerifiedDurablePublication = load_verified_publication(
        &store,
        &context(),
        domain(),
        &resolver(),
        &[],
        reference.origin(),
    )
    .unwrap()
    .unwrap();
    validate_closure(&resolver(), &[], &loaded.interface).unwrap();
}

#[test]
fn validate_closure_rejects_profile_four_with_general_semantics() {
    let store: MemoryDurableStateStore =
        MemoryDurableStateStore::new(WriterFenceGeneration::new(1).unwrap());
    let wrong: Digest32 = general_execution_semantics(&resolver(), &protocol()).unwrap();
    let reference: UnverifiedDependencyRef = publish_profile_four_artifact(&store, wrong);
    let loaded: VerifiedDurablePublication = load_verified_publication(
        &store,
        &context(),
        domain(),
        &resolver(),
        &[],
        reference.origin(),
    )
    .unwrap()
    .unwrap();
    assert!(matches!(
        validate_closure(&resolver(), &[], &loaded.interface),
        Err(LocalExecutionAdmissionError::Invalid(
            "non-executable publication semantics"
        ))
    ));
}
