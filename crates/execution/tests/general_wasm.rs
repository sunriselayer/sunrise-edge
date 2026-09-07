#[path = "common/general_inventory.rs"]
mod inventory;
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::package_types::PackageOrigin;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::call_authorization::*;
use execution::local_execution::*;
use execution::publication::*;
use execution::{ExecutionStatus, LocalWasmExecutionEngine, ObjectEffect, ResolvedObject};
use hashing::HashSuiteResolver;
use objects::{AccessMode, ObjectRef};
use protocol_types::{ChainId, Epoch, HashPurpose, HashSuite, HashSuiteSchedule, ProtocolVersion};
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
fn publish(
    mut package: inventory::InventoryPackage,
    dependencies: Vec<UnverifiedDependencyRef>,
) -> AuthenticatedPublicationCandidate {
    package.wasm = wat::parse_str(&package.wat).unwrap();
    let exports = package
        .abi
        .objects
        .entrypoints
        .iter()
        .map(|entry| entry.name.clone())
        .collect();
    let entrypoint_count = package.abi.objects.entrypoints.len();
    let metadata = ExecutableAbi {
        call: package.abi,
        initializer: package.initializer,
        transferable_constructors: package.transferable_constructors,
        results: vec![vec![]; entrypoint_count],
    };
    let semantics = general_execution_semantics(&resolver(), &context()).unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: metadata.call.objects.origin.clone(),
        revision: 1,
        wasm_profile: 3,
        semantics,
        wasm: package.wasm,
        unverified_abi: encode_executable_abi(&metadata).unwrap(),
        exports,
        unverified_dependencies: dependencies,
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
fn replace(package: &mut inventory::InventoryPackage, old: &str, new: &str) {
    assert!(package.wat.contains(old));
    package.wat = package.wat.replacen(old, new, 1);
}
fn data(address: u32, bytes: &[u8]) -> String {
    let escaped: String = bytes.iter().map(|byte| format!("\\{byte:02x}")).collect();
    format!("(data (i32.const {address}) \"{escaped}\")")
}
fn repeat_call(package: &mut inventory::InventoryPackage, count: usize) {
    let prefix = "(call $zero (call $call (i32.const 0)";
    let start = package.wat.find(prefix).unwrap();
    let mut depth = 0i32;
    let mut end = start;
    for (offset, byte) in package.wat.as_bytes()[start..].iter().enumerate() {
        if *byte == b'(' {
            depth += 1;
        } else if *byte == b')' {
            depth -= 1;
        }
        if depth == 0 {
            end = start + offset + 1;
            break;
        }
    }
    let expression = package.wat[start..end].to_owned();
    package
        .wat
        .replace_range(start..end, &expression.repeat(count));
}
struct Fixture {
    root: ResolvedExecutionScope,
    policy: ResolvedExecutionScope,
    policy_code: UnverifiedDependencyRef,
    same: bool,
}
impl Fixture {
    fn new(
        same: bool,
        edit: impl FnOnce(&mut inventory::InventoryPackage),
        edit_policy: impl FnOnce(&mut inventory::InventoryPackage),
    ) -> Self {
        let mut policy = inventory::dispatch_policy(&origin(2));
        if same {
            policy.initializer = None;
        }
        edit_policy(&mut policy);
        let policy = publish(policy, vec![]);
        let policy_code = reference(&policy);
        let mut root = inventory::warehouse(&origin(1), &origin(2), 0);
        if same {
            replace(
                &mut root,
                "(import \"sunrise\" \"get_object_count\"",
                "(import \"sunrise\" \"call_dependency\" (func $dependency (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32))) (import \"sunrise\" \"get_object_count\"",
            );
            let types = abi::package_types::encode_scoped_type_arguments(context().chain_id(), &[])
                .unwrap();
            let args = inventory::scalar_argument(20);
            replace(
                &mut root,
                "(func $require",
                &format!(
                    "{} {} {} (func $require",
                    data(40000, &types),
                    data(41000, b"configure"),
                    data(42000, &args)
                ),
            );
            // Library configure is ordinary only in this same-instance fixture.
            replace(
                &mut root,
                "(call $prepare (i32.const 0))",
                &format!(
                    "(call $prepare (i32.const 0)) (drop (call $dependency (i32.const 0) (i32.const 41000) (i32.const 9) (i32.const 40000) (i32.const {}) (i32.const 512) (i32.const 0) (i32.const 42000) (i32.const {})))",
                    types.len(),
                    args.len()
                ),
            );
        }
        edit(&mut root);
        let root = publish(root, vec![policy_code.clone()]);
        let root = scope(root, vec![policy.clone()], 3, "init");
        let policy = if same {
            root.clone()
        } else {
            scope(policy, vec![], 4, "configure")
        };
        Self {
            root,
            policy,
            policy_code,
            same,
        }
    }
    fn run(
        &self,
        root: &ResolvedExecutionScope,
        entry: &str,
        args: Vec<u8>,
        inputs: &[ScopedResolvedObject],
        auth: Vec<CallAuthorization>,
    ) -> Result<LocalExecutionOutcome, LocalExecutionError> {
        let mut scopes = vec![root.clone()];
        if auth.iter().any(|auth| {
            auth.callee.instance == self.policy.target || auth.caller.instance == self.policy.target
        }) && self.policy.target != root.target
        {
            scopes.push(self.policy.clone());
        }
        run(scopes, entry, args, inputs, auth, MAX_LOCAL_EXECUTION_GAS)
    }
    fn prepare(&self, limit: u64) -> Vec<ScopedResolvedObject> {
        let init = self
            .run(
                &self.root,
                "init",
                inventory::tuple_arguments(&[10, 100]),
                &[],
                vec![],
            )
            .unwrap();
        assert_eq!(init.effects.status, ExecutionStatus::Success);
        let offset = usize::from(self.same);
        let admin = created(&init, offset, AccessMode::Read);
        let reserve = self
            .run(
                &self.root,
                "reserve",
                inventory::tuple_arguments(&[11, 10]),
                &[admin.clone(), created(&init, offset + 1, AccessMode::Write)],
                vec![],
            )
            .unwrap();
        assert_eq!(reserve.effects.status, ExecutionStatus::Success);
        let policy = if self.same {
            created(&init, 0, AccessMode::Write)
        } else {
            let configured = self
                .run(
                    &self.policy,
                    "configure",
                    inventory::scalar_argument(limit),
                    &[],
                    vec![],
                )
                .unwrap();
            created(&configured, 0, AccessMode::Write)
        };
        vec![admin, created(&reserve, 0, AccessMode::Consume), policy]
    }
    fn authorization(&self, inputs: &[ScopedResolvedObject]) -> CallAuthorization {
        CallAuthorization {
            caller: ExecutionTarget {
                instance: self.root.target.clone(),
                code: self.root.instance.code.clone(),
            },
            callee: ExecutionTarget {
                instance: self.policy.target.clone(),
                code: self.policy_code.clone(),
            },
            entrypoint: "approve".into(),
            type_arguments: vec![],
            objects: vec![AuthorizedObject {
                object_id: inputs[2].resolved.object.id,
                mode: AccessMode::Write,
            }],
        }
    }
}
fn run(
    scopes: Vec<ResolvedExecutionScope>,
    entry: &str,
    args: Vec<u8>,
    inputs: &[ScopedResolvedObject],
    authorizations: Vec<CallAuthorization>,
    gas: u64,
) -> Result<LocalExecutionOutcome, LocalExecutionError> {
    let resolver = resolver();
    let policy = LocalExecutionPolicy::general(context());
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
        type_arguments: vec![],
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
fn trap(outcome: LocalExecutionOutcome) {
    assert_eq!(
        outcome.effects.status,
        ExecutionStatus::Failure {
            reason: LOCAL_EXECUTION_TRAP_REASON.into()
        }
    );
    assert!(outcome.effects.object_effects.is_empty());
    assert!(outcome.effects.events.is_empty());
    assert!(outcome.created_authorities.is_empty());
}
#[test]
fn same_and_different_instances_use_one_typed_call_path() {
    for same in [true, false] {
        let fixture = Fixture::new(same, |_| {}, |_| {});
        let inputs = fixture.prepare(20);
        let auth = fixture.authorization(&inputs);
        let outcome = fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth],
            )
            .unwrap();
        assert_eq!(outcome.effects.status, ExecutionStatus::Success);
        assert_eq!(outcome.created_authorities.len(), 2);
        assert_eq!(
            outcome.created_authorities[0].authority.instance,
            fixture.policy.target
        );
        assert_eq!(
            outcome.created_authorities[0].authority.code,
            fixture.policy_code
        );
        assert_eq!(
            outcome.created_authorities[1].authority.instance,
            fixture.root.target
        );
        assert!(outcome.effects.object_effects.iter().any(|effect|matches!(effect,ObjectEffect::Mutated{new_object,..} if new_object.data==inventory::tuple_arguments(&[20,10]))));
        let shipment = created(&outcome, 1, AccessMode::Write);
        let transfer = fixture
            .run(
                &fixture.root,
                "transfer",
                inventory::recipient_argument(sender()),
                &[shipment],
                vec![],
            )
            .unwrap();
        assert_eq!(transfer.effects.status, ExecutionStatus::Success);
    }
}
#[test]
fn nested_late_rejection_rolls_back_every_scope() {
    let fixture = Fixture::new(false, |_| {}, |_| {});
    let inputs = fixture.prepare(5);
    let auth = fixture.authorization(&inputs);
    trap(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth],
            )
            .unwrap(),
    );
}
#[test]
fn wrong_runtime_caller_and_object_scope_trap() {
    let fixture = Fixture::new(false, |_| {}, |_| {});
    let inputs = fixture.prepare(20);
    let mut auth = fixture.authorization(&inputs);
    auth.caller = auth.callee.clone();
    trap(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth],
            )
            .unwrap(),
    );
    let mut auth = fixture.authorization(&inputs);
    auth.callee.instance = fixture.root.target.clone();
    // Keep the foreign admitted scope referenced, while selecting the wrong scope.
    let mut extra = fixture.authorization(&inputs);
    extra.caller = extra.callee.clone();
    trap(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth, extra],
            )
            .unwrap(),
    );
}
#[test]
fn malformed_handle_selector_traps_after_provisional_root_changes() {
    for replacement in ["(i32.const 1)", "(i32.const -1)", "(i32.const 99)"] {
        let fixture = Fixture::new(
            false,
            |package| {
                replace(
                    package,
                    "(i32.store (i32.const 512) (i32.const 2))",
                    &format!("(i32.store (i32.const 512) {replacement})"),
                )
            },
            |_| {},
        );
        let inputs = fixture.prepare(20);
        let auth = fixture.authorization(&inputs);
        trap(
            fixture
                .run(
                    &fixture.root,
                    "fulfil",
                    inventory::tuple_arguments(&[]),
                    &inputs,
                    vec![auth],
                )
                .unwrap(),
        );
    }
}
#[test]
fn reusable_capability_does_not_restore_transferred_rights() {
    let fixture = Fixture::new(
        false,
        |package| repeat_call(package, 2),
        |package| {
            package.transferable_constructors = vec![1];
            replace(
                package,
                ";; Intentionally late:",
                "(drop (call $transfer (i32.const 0) (i32.const 256))) ;; Intentionally late:",
            );
        },
    );
    let inputs = fixture.prepare(20);
    let auth = fixture.authorization(&inputs);
    trap(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth],
            )
            .unwrap(),
    );
}

#[test]
fn repeated_and_skipped_authorizations_are_capabilities_not_batch_steps() {
    let fixture = Fixture::new(false, |package| repeat_call(package, 2), |_| {});
    let inputs = fixture.prepare(20);
    let auth = fixture.authorization(&inputs);
    let outcome = fixture
        .run(
            &fixture.root,
            "fulfil",
            inventory::tuple_arguments(&[]),
            &inputs,
            vec![auth],
        )
        .unwrap();
    assert_eq!(outcome.effects.status, ExecutionStatus::Success);
    assert_eq!(outcome.created_authorities.len(), 3);
    assert!(outcome.effects.object_effects.iter().any(|effect|matches!(effect,ObjectEffect::Mutated{new_object,..} if new_object.data==inventory::tuple_arguments(&[20,20]))));
    let fixture = Fixture::new(true, |_| {}, |_| {});
    let authorization = CallAuthorization {
        caller: ExecutionTarget {
            instance: fixture.root.target.clone(),
            code: fixture.root.instance.code.clone(),
        },
        callee: ExecutionTarget {
            instance: fixture.root.target.clone(),
            code: fixture.policy_code.clone(),
        },
        entrypoint: "configure".into(),
        type_arguments: vec![],
        objects: vec![],
    };
    let outcome = fixture
        .run(
            &fixture.root,
            "init",
            inventory::tuple_arguments(&[10, 100]),
            &[],
            vec![authorization],
        )
        .unwrap();
    assert_eq!(outcome.effects.status, ExecutionStatus::Success);
    assert_eq!(outcome.created_authorities.len(), 3);
}

#[test]
fn active_exact_target_reentry_traps_and_initializers_reject_before_entry() {
    let fixture = Fixture::new(
        false,
        |_| {},
        |package| {
            replace(
                package,
                "(call $prepare (i32.const 1))",
                "(call $prepare (i32.const 1)) (i32.store (i32.const 512) (i32.const 0)) (drop (call $call (i32.const 1) (i32.const 512) (i32.const 1) (i32.const 8192) (global.get $al)))",
            )
        },
    );
    let inputs = fixture.prepare(20);
    let auth = fixture.authorization(&inputs);
    let mut recursive = auth.clone();
    recursive.caller = recursive.callee.clone();
    trap(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth, recursive],
            )
            .unwrap(),
    );
    let fixture = Fixture::new(false, |_| {}, |_| {});
    let inputs = fixture.prepare(20);
    let mut auth = fixture.authorization(&inputs);
    auth.entrypoint = "configure".into();
    auth.objects.clear();
    assert!(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth]
            )
            .is_err()
    );
}

#[test]
fn root_cannot_mutate_forwarded_foreign_state_and_computed_args_are_typed() {
    for operation in [
        "(drop (call $write (i32.const 2) (i32.const 12288) (call $object (i32.const 2))))",
        "(drop (call $call (i32.const 0) (i32.const 512) (i32.const 1) (i32.const 8192) (global.get $al)))",
    ] {
        let fixture = Fixture::new(
            false,
            |package| {
                replace(
                    package,
                    "(i32.store (i32.const 512) (i32.const 2))",
                    &format!("(i32.store (i32.const 512) (i32.const 2)) {operation}"),
                )
            },
            |_| {},
        );
        let inputs = fixture.prepare(20);
        let auth = fixture.authorization(&inputs);
        trap(
            fixture
                .run(
                    &fixture.root,
                    "fulfil",
                    inventory::tuple_arguments(&[]),
                    &inputs,
                    vec![auth],
                )
                .unwrap(),
        );
    }
}

#[test]
fn signed_rights_attenuate_consume_to_write_and_never_escalate_read() {
    let fixture = Fixture::new(
        false,
        |package| {
            package.abi.objects.entrypoints[0].objects[2].mode =
                abi::public_abi::ObjectMode::Consume
        },
        |_| {},
    );
    let mut inputs = fixture.prepare(20);
    inputs[2].resolved.mode = AccessMode::Consume;
    let auth = fixture.authorization(&inputs);
    assert_eq!(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth]
            )
            .unwrap()
            .effects
            .status,
        ExecutionStatus::Success
    );
    let fixture = Fixture::new(false, |_| {}, |_| {});
    let inputs = fixture.prepare(20);
    let mut auth = fixture.authorization(&inputs);
    auth.objects[0].mode = AccessMode::Read;
    assert!(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth]
            )
            .is_err()
    );
}

#[test]
fn reusable_capability_cannot_revive_consumed_aliases() {
    let fixture = Fixture::new(
        false,
        |package| {
            repeat_call(package, 2);
            package.abi.objects.entrypoints[0].objects[2].mode =
                abi::public_abi::ObjectMode::Consume;
        },
        |package| {
            package.abi.objects.entrypoints[0].objects[0].mode =
                abi::public_abi::ObjectMode::Consume;
            replace(
                package,
                ";; Intentionally late:",
                "(drop (call $consume (i32.const 0))) ;; Intentionally late:",
            );
        },
    );
    let mut inputs = fixture.prepare(20);
    inputs[2].resolved.mode = AccessMode::Consume;
    let mut auth = fixture.authorization(&inputs);
    auth.objects[0].mode = AccessMode::Consume;
    trap(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth],
            )
            .unwrap(),
    );
}

#[test]
fn scope_substitution_missing_scope_and_unowned_inputs_fail_closed() {
    let fixture = Fixture::new(false, |_| {}, |_| {});
    let inputs = fixture.prepare(20);
    let auth = fixture.authorization(&inputs);
    assert!(
        run(
            vec![fixture.root.clone()],
            "fulfil",
            inventory::tuple_arguments(&[]),
            &inputs,
            vec![auth.clone()],
            MAX_LOCAL_EXECUTION_GAS
        )
        .is_err()
    );
    let mut altered = fixture.policy.clone();
    altered.target.revision = 2;
    assert!(
        run(
            vec![fixture.root.clone(), altered],
            "fulfil",
            inventory::tuple_arguments(&[]),
            &inputs,
            vec![auth.clone()],
            MAX_LOCAL_EXECUTION_GAS
        )
        .is_err()
    );
    let mut foreign = inputs.clone();
    foreign[2].resolved.object.owner = objects::Owner::Shared;
    assert!(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &foreign,
                vec![auth.clone()]
            )
            .is_err()
    );
    let mut wrong_type = inputs.clone();
    wrong_type[2].resolved.object.schema_version = 2;
    assert!(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &wrong_type,
                vec![auth.clone()]
            )
            .is_err()
    );
    let mut wrong_code = fixture.policy.clone();
    wrong_code.instance.code = fixture.root.instance.code.clone();
    assert!(
        run(
            vec![fixture.root.clone(), wrong_code],
            "fulfil",
            inventory::tuple_arguments(&[]),
            &inputs,
            vec![auth],
            MAX_LOCAL_EXECUTION_GAS
        )
        .is_err()
    );
}

#[test]
fn general_calls_share_call_count_fuel_and_retained_memory() {
    let fixture = Fixture::new(false, |package| repeat_call(package, 64), |_| {});
    let inputs = fixture.prepare(20);
    let auth = fixture.authorization(&inputs);
    trap(
        fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth],
            )
            .unwrap(),
    );
    for calls in [3, 4] {
        let fixture = Fixture::new(
            false,
            |package| repeat_call(package, calls),
            |package| {
                replace(
                    package,
                    "(memory (export \"memory\") 1 2)",
                    "(memory (export \"memory\") 256 256)",
                )
            },
        );
        let inputs = fixture.prepare(20);
        let auth = fixture.authorization(&inputs);
        let outcome = fixture
            .run(
                &fixture.root,
                "fulfil",
                inventory::tuple_arguments(&[]),
                &inputs,
                vec![auth],
            )
            .unwrap();
        if calls == 3 {
            assert_eq!(outcome.effects.status, ExecutionStatus::Success);
        } else {
            trap(outcome);
        }
    }
}

fn empty_package(seed: u8, initializer: bool) -> inventory::InventoryPackage {
    let entries = if initializer {
        vec!["init", "run"]
    } else {
        vec!["run"]
    };
    let wat = format!(
        "(module (memory (export \"memory\") 1 2) {})",
        entries
            .iter()
            .map(|name| format!("(func (export \"{name}\"))"))
            .collect::<String>()
    );
    inventory::InventoryPackage {
        wasm: wat::parse_str(&wat).unwrap(),
        wat,
        abi: abi::call_values::CallAbi {
            objects: abi::public_abi::PackageAbi {
                origin: origin(seed),
                constructors: vec![],
                entrypoints: entries
                    .iter()
                    .map(|name| abi::public_abi::EntrypointDeclaration {
                        name: (*name).into(),
                        type_parameters: vec![],
                        objects: vec![],
                    })
                    .collect(),
            },
            arguments: vec![abi::call_values::ValueLayout::Tuple(vec![]); entries.len()],
            bodies: vec![],
        },
        initializer: initializer.then(|| "init".into()),
        transferable_constructors: vec![],
    }
}

#[test]
fn unique_code_node_bound_is_global_across_scopes_not_per_closure() {
    let fixture = Fixture::new(false, |_| {}, |_| {});
    for leaves in [30u8, 31u8] {
        let children: Vec<AuthenticatedPublicationCandidate> = (40..40 + leaves)
            .map(|seed| publish(empty_package(seed, false), vec![]))
            .collect();
        let parent = publish(
            empty_package(80, true),
            children.iter().map(reference).collect(),
        );
        let selected = scope(parent, children, 81, "init");
        let authorization = CallAuthorization {
            caller: ExecutionTarget {
                instance: fixture.root.target.clone(),
                code: fixture.root.instance.code.clone(),
            },
            callee: ExecutionTarget {
                instance: selected.target.clone(),
                code: selected.instance.code.clone(),
            },
            entrypoint: "run".into(),
            type_arguments: vec![],
            objects: vec![],
        };
        let outcome = run(
            vec![fixture.root.clone(), selected],
            "init",
            inventory::tuple_arguments(&[10, 100]),
            &[],
            vec![authorization],
            MAX_LOCAL_EXECUTION_GAS,
        );
        if leaves == 30 {
            assert_eq!(outcome.unwrap().effects.status, ExecutionStatus::Success);
        } else {
            assert!(matches!(
                outcome,
                Err(LocalExecutionError::Limit("execution code closure"))
            ));
        }
    }
}

#[test]
fn forwarded_object_scope_count_is_globally_bounded() {
    let fixture = Fixture::new(false, |_| {}, |_| {});
    let scopes = vec![fixture.root.clone(); 9];
    assert!(
        run(
            scopes,
            "init",
            inventory::tuple_arguments(&[10, 100]),
            &[],
            vec![],
            MAX_LOCAL_EXECUTION_GAS
        )
        .is_err()
    );
}
