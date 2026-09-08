#[path = "common/inventory.rs"]
mod inventory;
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::package_types::PackageOrigin;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::*;
use execution::publication::*;
use execution::{ExecutionStatus, LocalWasmExecutionEngine, ObjectEffect, ResolvedObject};
use hashing::HashSuiteResolver;
use objects::{AccessMode, ObjectRef};
use protocol_types::{ChainId, Epoch, HashPurpose, HashSuite, HashSuiteSchedule, ProtocolVersion};

fn resolver() -> HashSuiteResolver {
    resolver_version(ProtocolVersion::new(7))
}
fn resolver_version(version: ProtocolVersion) -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("local-vm").unwrap(),
        version,
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap()
}
fn context() -> PublicationContext {
    PublicationContext::new(
        resolver().chain_id().clone(),
        ProtocolVersion::new(7),
        Epoch::new(0),
    )
    .unwrap()
}
fn key() -> SigningKey {
    SigningKey::from([7; 32])
}
fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
fn origin(seed: u8) -> PackageOrigin {
    PackageOrigin::unverified(context().chain_id().clone(), sender(), [seed; 32]).unwrap()
}
fn publish(
    package: inventory::InventoryPackage,
    dependencies: Vec<UnverifiedDependencyRef>,
) -> AuthenticatedPublicationCandidate {
    let entrypoint_count = package.abi.objects.entrypoints.len();
    let metadata: ExecutableAbi = ExecutableAbi {
        call: package.abi,
        initializer: package.initializer,
        transferable_constructors: package.transferable_constructors,
        results: vec![vec![]; entrypoint_count],
    };
    let exports: Vec<String> = metadata
        .call
        .objects
        .entrypoints
        .iter()
        .map(|entry| entry.name.clone())
        .collect();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: metadata.call.objects.origin.clone(),
        revision: 1,
        wasm_profile: 2,
        semantics: local_execution_semantics(&resolver(), &context()).unwrap(),
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
        &local_execution_semantics(&resolver(), &context()).unwrap(),
        PublicationSubmission::new(
            [1; 32],
            PublicationRequest::new(artifact, 0, digest, key().sign(&frame).into()),
        )
        .unwrap(),
    )
    .unwrap()
}
fn reference(candidate: &AuthenticatedPublicationCandidate) -> UnverifiedDependencyRef {
    let artifact = candidate.artifact();
    UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        1,
        artifact.context().clone(),
        *candidate.digest(),
    )
    .unwrap()
}
struct Fixture {
    interface: VerifiedPublicationInterface,
    instance: InstanceRecord,
}
impl Fixture {
    fn new(edit: impl FnOnce(&mut inventory::InventoryPackage)) -> Self {
        Self::with_library(edit, |_| {})
    }
    fn with_library(
        edit: impl FnOnce(&mut inventory::InventoryPackage),
        edit_library: impl FnOnce(&mut inventory::InventoryPackage),
    ) -> Self {
        let mut library = inventory::dispatch_policy(&origin(2));
        edit_library(&mut library);
        library.wasm = wat::parse_str(&library.wat).unwrap();
        let library = publish(library, vec![]);
        let mut package = inventory::warehouse(&origin(1), &origin(2));
        edit(&mut package);
        package.wasm = wat::parse_str(&package.wat).unwrap();
        let root = publish(package, vec![reference(&library)]);
        let instance = InstanceRecord {
            context: context(),
            creator: sender(),
            seed: [3; 32],
            code: reference(&root),
            revision: 1,
            initializer: "init".into(),
        };
        Self {
            interface: verify_publication_interface(root, vec![library]).unwrap(),
            instance,
        }
    }
    fn run(
        &self,
        entry: &str,
        args: Vec<u8>,
        inputs: &[ScopedResolvedObject],
        gas: u64,
    ) -> Result<LocalExecutionOutcome, LocalExecutionError> {
        self.run_at(context(), entry, args, inputs, gas)
    }
    fn run_at(
        &self,
        active: PublicationContext,
        entry: &str,
        args: Vec<u8>,
        inputs: &[ScopedResolvedObject],
        gas: u64,
    ) -> Result<LocalExecutionOutcome, LocalExecutionError> {
        let resolver = resolver_version(active.protocol_version());
        let policy = LocalExecutionPolicy::new(active.clone());
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
            context: active.clone(),
            request_id: [4; 32],
            sender: sender(),
            nonce: 0,
            code: self.instance.code.clone(),
            instance: instance_target(
                &resolver_version(self.instance.context.protocol_version()),
                &self.instance,
            )
            .unwrap(),
            entrypoint: entry.into(),
            type_arguments: vec![],
            access,
            arguments: args,
            gas_limit: gas,
        };
        let intent = LocalExecutionIntent {
            authorizations: Vec::new(),
            mode: if entry == "init" {
                LocalExecutionMode::Instantiate
            } else {
                LocalExecutionMode::Call
            },
            policy_digest: policy.digest(&resolver).unwrap(),
            call,
        };
        let signature = key()
            .sign(&local_execution_signing_frame(&active, &intent).unwrap())
            .into();
        let signed = SignedLocalExecutionIntent { intent, signature };
        let authenticated = authenticate_local_execution(
            &resolver,
            &policy,
            &encode_signed_local_execution(&signed).unwrap(),
        )
        .unwrap();
        let event_digest = local_execution_event_digest(&resolver, &signed).unwrap();
        LocalWasmExecutionEngine::new().execute(LocalExecutionRequest {
            scopes: &[ResolvedExecutionScope {
                instance: self.instance.clone(),
                target: instance_target(
                    &resolver_version(self.instance.context.protocol_version()),
                    &self.instance,
                )
                .unwrap(),
                interface: self.interface.clone(),
            }],
            intent: &authenticated,
            resolver: &resolver,
            policy: &policy,
            event_digest,
            inputs,
        })
    }
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
        .find(|item| item.authority.object_id == object.id)
        .unwrap()
        .authority
        .clone();
    ScopedResolvedObject {
        resolved: ResolvedObject { object, mode },
        authority,
    }
}
fn assert_trap(outcome: LocalExecutionOutcome) {
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

fn replace(package: &mut inventory::InventoryPackage, old: &str, new: &str) {
    assert!(package.wat.contains(old), "fixture hook absent: {old}");
    package.wat = package.wat.replacen(old, new, 1);
}
fn repeat_expression(package: &mut inventory::InventoryPackage, prefix: &str, count: usize) {
    let start: usize = package.wat.find(prefix).unwrap();
    let mut depth: i32 = 0;
    let mut end: usize = start;
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
    let expression: String = package.wat[start..end].to_owned();
    package
        .wat
        .replace_range(start..end, &expression.repeat(count));
}

#[test]
fn invalid_guest_handles_lengths_and_memory_ranges_trap() {
    for operation in [
        "(drop (call $len (i32.const -1)))",
        "(drop (call $len (i32.const 0)))",
        "(drop (call $args (i32.const -1) (i32.const 0) (i32.const 1)))",
        "(drop (call $args (i32.const 0) (i32.const 0) (i32.const -1)))",
        "(drop (call $caller (i32.const 65520)))",
        "(drop (call $instance (i32.const 0) (i32.const 1)))",
    ] {
        let fixture = Fixture::new(|package| {
            replace(
                package,
                "(call $prepare (i32.const 0))",
                &format!("{operation} (call $prepare (i32.const 0))"),
            )
        });
        assert_trap(
            fixture
                .run(
                    "init",
                    inventory::tuple_arguments(&[10, 100, 20]),
                    &[],
                    MAX_LOCAL_EXECUTION_GAS,
                )
                .unwrap(),
        );
    }
}

#[test]
fn consumed_created_objects_leave_ordinal_gaps_and_dynamic_counts() {
    let fixture = Fixture::new(|package| {
        let marker = "(i64.store (call $scalar (i32.const 19456)";
        replace(
            package,
            marker,
            &format!(
                "(call $require (i32.eq (call $count) (i32.const 2))) (drop (call $consume (i32.const 0))) {marker}"
            ),
        );
    });
    let outcome = fixture
        .run(
            "init",
            inventory::tuple_arguments(&[10, 100, 20]),
            &[],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    assert_eq!(outcome.effects.status, ExecutionStatus::Success);
    assert_eq!(
        outcome
            .created_authorities
            .iter()
            .map(|item| item.creation_ordinal)
            .collect::<Vec<u32>>(),
        vec![1, 2]
    );
    for created in &outcome.created_authorities {
        assert_eq!(
            created.authority.object_id,
            derive_local_created_object_id(
                &resolver(),
                &context(),
                &fixture.instance.context,
                &created.authority.instance,
                &created.authority.code,
                outcome.effects.tx_hash,
                created.creation_ordinal
            )
            .unwrap()
        );
    }
}

#[test]
fn use_after_consume_and_read_to_write_escalation_trap() {
    for operation in [
        "(drop (call $consume (i32.const 0))) (drop (call $len (i32.const 0)))",
        "(drop (call $consume (i32.const 0))) (drop (call $consume (i32.const 0)))",
    ] {
        let fixture = Fixture::new(|package| {
            let marker = "(i64.store (call $scalar (i32.const 19456)";
            replace(package, marker, &format!("{operation} {marker}"));
        });
        assert_trap(
            fixture
                .run(
                    "init",
                    inventory::tuple_arguments(&[10, 100, 20]),
                    &[],
                    MAX_LOCAL_EXECUTION_GAS,
                )
                .unwrap(),
        );
    }
    let fixture = Fixture::new(|package| {
        replace(
            package,
            "(call $prepare (i32.const 2))",
            "(call $prepare (i32.const 2)) (drop (call $write (i32.const 0) (i32.const 18432) (i32.const 18)))",
        )
    });
    let init = fixture
        .run(
            "init",
            inventory::tuple_arguments(&[10, 100, 20]),
            &[],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    assert_trap(
        fixture
            .run(
                "reserve",
                inventory::tuple_arguments(&[11, 10]),
                &[
                    created(&init, 0, AccessMode::Read),
                    created(&init, 1, AccessMode::Write),
                ],
                MAX_LOCAL_EXECUTION_GAS,
            )
            .unwrap(),
    );
}

#[test]
fn wrong_nominal_schema_body_and_undeclared_dependency_trap() {
    for (old, new) in [
        (
            "(call $create (i32.const 1024)",
            "(call $create (i32.const 2048)",
        ),
        ("(call $call (i32.const 0)", "(call $call (i32.const 1)"),
    ] {
        let fixture = Fixture::new(|package| replace(package, old, new));
        assert_trap(
            fixture
                .run(
                    "init",
                    inventory::tuple_arguments(&[10, 100, 20]),
                    &[],
                    MAX_LOCAL_EXECUTION_GAS,
                )
                .unwrap(),
        );
    }
}

#[test]
fn child_binding_cannot_escalate_read_to_write() {
    let fixture = Fixture::with_library(
        |_| {},
        |package| {
            package.abi.objects.entrypoints[0].objects[0].mode = abi::public_abi::ObjectMode::Write
        },
    );
    let init = fixture
        .run(
            "init",
            inventory::tuple_arguments(&[10, 100, 20]),
            &[],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    let reserve = fixture
        .run(
            "reserve",
            inventory::tuple_arguments(&[11, 10]),
            &[
                created(&init, 0, AccessMode::Read),
                created(&init, 1, AccessMode::Write),
            ],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    assert_trap(
        fixture
            .run(
                "fulfil",
                inventory::tuple_arguments(&[]),
                &[
                    created(&init, 0, AccessMode::Read),
                    created(&reserve, 0, AccessMode::Consume),
                    created(&init, 2, AccessMode::Read),
                ],
                MAX_LOCAL_EXECUTION_GAS,
            )
            .unwrap(),
    );
}

#[test]
fn aggregate_memory_is_retained_across_fresh_child_instances() {
    let fixture = Fixture::with_library(
        |package| {
            replace(
                package,
                "(memory (export \"memory\") 1 2)",
                "(memory (export \"memory\") 256 256)",
            );
            repeat_expression(
                package,
                "(call $zero (call $call (i32.const 0) (i32.const 700)",
                4,
            );
        },
        |package| {
            replace(
                package,
                "(memory (export \"memory\") 1 2)",
                "(memory (export \"memory\") 256 256)",
            )
        },
    );
    assert_trap(
        fixture
            .run(
                "init",
                inventory::tuple_arguments(&[10, 100, 20]),
                &[],
                MAX_LOCAL_EXECUTION_GAS,
            )
            .unwrap(),
    );
}

#[test]
fn guest_recursion_is_atomic() {
    {
        let operation = "(call $recurse)";
        let fixture = Fixture::new(|package| {
            replace(
                package,
                "(func $require",
                "(func $recurse (call $recurse)) (func $require",
            );
            replace(
                package,
                "(call $prepare (i32.const 0))",
                &format!("{operation} (call $prepare (i32.const 0))"),
            );
        });
        assert_trap(
            fixture
                .run(
                    "init",
                    inventory::tuple_arguments(&[10, 100, 20]),
                    &[],
                    MAX_LOCAL_EXECUTION_GAS,
                )
                .unwrap(),
        );
    }
}

#[test]
fn declared_memory_maximum_preserves_standard_wasm_negative_one() {
    let fixture = Fixture::new(|package| {
        replace(
            package,
            "(call $prepare (i32.const 0))",
            "(call $require (i32.eq (memory.grow (i32.const 3)) (i32.const -1))) (call $prepare (i32.const 0))",
        )
    });
    assert_eq!(
        fixture
            .run(
                "init",
                inventory::tuple_arguments(&[10, 100, 20]),
                &[],
                MAX_LOCAL_EXECUTION_GAS
            )
            .unwrap()
            .effects
            .status,
        ExecutionStatus::Success
    );
}

#[test]
fn historical_epochs_execute_but_historical_protocol_versions_fail_closed() {
    let fixture = Fixture::new(|_| {});
    let init = fixture
        .run(
            "init",
            inventory::tuple_arguments(&[10, 100, 20]),
            &[],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    let inputs = vec![
        created(&init, 0, AccessMode::Read),
        created(&init, 1, AccessMode::Write),
    ];
    let later = PublicationContext::new(
        context().chain_id().clone(),
        ProtocolVersion::new(7),
        Epoch::new(1),
    )
    .unwrap();
    assert_eq!(
        fixture
            .run_at(
                later,
                "reserve",
                inventory::tuple_arguments(&[11, 10]),
                &inputs,
                MAX_LOCAL_EXECUTION_GAS
            )
            .unwrap()
            .effects
            .status,
        ExecutionStatus::Success
    );
    let upgrade = PublicationContext::new(
        context().chain_id().clone(),
        ProtocolVersion::new(8),
        Epoch::new(1),
    )
    .unwrap();
    assert!(matches!(
        fixture.run_at(
            upgrade,
            "reserve",
            inventory::tuple_arguments(&[11, 10]),
            &inputs,
            MAX_LOCAL_EXECUTION_GAS
        ),
        Err(LocalExecutionError::Invalid(
            "execution scope instance authority"
        ))
    ));
}

#[test]
fn transfer_downgrades_even_self_transfer_and_forbids_undeclared_constructor() {
    for (allow_transfer, after) in [
        (false, ""),
        (
            true,
            "(drop (call $write (i32.const 1) (i32.const 16384) (i32.const 66)))",
        ),
        (
            true,
            "(drop (call $transfer (i32.const 1) (i32.const 256)))",
        ),
    ] {
        let fixture = Fixture::new(|package| {
            if allow_transfer {
                package.transferable_constructors = vec![2, 4];
            }
            let marker = "(i64.store (call $scalar (i32.const 19456)";
            replace(
                package,
                marker,
                &format!("(drop (call $transfer (i32.const 1) (i32.const 256))) {after} {marker}"),
            );
        });
        assert_trap(
            fixture
                .run(
                    "init",
                    inventory::tuple_arguments(&[10, 100, 20]),
                    &[],
                    MAX_LOCAL_EXECUTION_GAS,
                )
                .unwrap(),
        );
    }
    let fixture = Fixture::new(|package| {
        package.transferable_constructors = vec![2, 4];
        let marker = "(i64.store (call $scalar (i32.const 19456)";
        replace(
            package,
            marker,
            &format!(
                "(drop (call $transfer (i32.const 1) (i32.const 256))) (drop (call $object (i32.const 1))) {marker}"
            ),
        );
    });
    assert_eq!(
        fixture
            .run(
                "init",
                inventory::tuple_arguments(&[10, 100, 20]),
                &[],
                MAX_LOCAL_EXECUTION_GAS
            )
            .unwrap()
            .effects
            .status,
        ExecutionStatus::Success
    );
}

fn data_segment(address: u32, bytes: &[u8]) -> String {
    let escaped: String = bytes.iter().map(|byte| format!("\\{byte:02x}")).collect();
    format!("(data (i32.const {address}) \"{escaped}\")")
}

#[test]
fn root_cannot_create_or_emit_library_owned_nominal_types() {
    let tag = abi::package_types::encode_scoped_type_tag(
        &abi::package_types::ScopedTypeTag::new(origin(2), 1, vec![]).unwrap(),
    )
    .unwrap();
    let body = inventory::scalar_argument(1);
    for operation in [
        format!(
            "(drop (call $create (i32.const 40000) (i32.const {}) (i32.const 256) (i32.const 41000) (i32.const {})))",
            tag.len(),
            body.len()
        ),
        format!(
            "(drop (call $event (i32.const 40000) (i32.const {}) (i32.const 41000) (i32.const {})))",
            tag.len(),
            body.len()
        ),
    ] {
        let fixture = Fixture::new(|package| {
            replace(
                package,
                "(func $require",
                &format!(
                    "{} {} (func $require",
                    data_segment(40000, &tag),
                    data_segment(41000, &body)
                ),
            );
            replace(
                package,
                "(call $prepare (i32.const 0))",
                &format!("(call $prepare (i32.const 0)) {operation}"),
            );
        });
        assert_trap(
            fixture
                .run(
                    "init",
                    inventory::tuple_arguments(&[10, 100, 20]),
                    &[],
                    MAX_LOCAL_EXECUTION_GAS,
                )
                .unwrap(),
        );
    }
}

#[test]
fn child_fuel_and_call_count_are_global() {
    let fixture = Fixture::with_library(
        |_| {},
        |package| {
            replace(
                package,
                "(call $prepare (i32.const 0))",
                "(loop $forever (br $forever)) (call $prepare (i32.const 0))",
            )
        },
    );
    let outcome = fixture
        .run(
            "init",
            inventory::tuple_arguments(&[10, 100, 20]),
            &[],
            10000,
        )
        .unwrap();
    assert_trap(outcome);
    let fixture = Fixture::new(|package| {
        repeat_expression(
            package,
            "(call $zero (call $call (i32.const 0) (i32.const 700)",
            64,
        )
    });
    assert_trap(
        fixture
            .run(
                "init",
                inventory::tuple_arguments(&[10, 100, 20]),
                &[],
                MAX_LOCAL_EXECUTION_GAS,
            )
            .unwrap(),
    );
}

#[test]
fn creation_count_is_globally_bounded() {
    let fixture = Fixture::new(|package| {
        repeat_expression(package, "(drop (call $create (i32.const 1024)", 129)
    });
    assert_trap(
        fixture
            .run(
                "init",
                inventory::tuple_arguments(&[10, 100, 20]),
                &[],
                MAX_LOCAL_EXECUTION_GAS,
            )
            .unwrap(),
    );
}

#[test]
fn synchronous_library_depth_is_bounded_independently_of_guest_recursion() {
    for library_count in [7u8, 8u8] {
        let mut candidates: Vec<AuthenticatedPublicationCandidate> = Vec::new();
        let mut dependency: Option<UnverifiedDependencyRef> = None;
        for seed in (2..=library_count + 1).rev() {
            let mut package = inventory::dispatch_policy(&origin(seed));
            let dependencies: Vec<UnverifiedDependencyRef> = dependency.iter().cloned().collect();
            if dependency.is_some() {
                let types =
                    abi::package_types::encode_scoped_type_arguments(context().chain_id(), &[])
                        .unwrap();
                replace(
                    &mut package,
                    "(func $require",
                    &format!(
                        "{} {} (func $require",
                        data_segment(40000, &types),
                        data_segment(41000, b"configure")
                    ),
                );
                replace(
                    &mut package,
                    "(call $prepare (i32.const 0))",
                    &format!(
                        "(call $prepare (i32.const 0)) (drop (call $call (i32.const 0) (i32.const 41000) (i32.const 9) (i32.const 40000) (i32.const {}) (i32.const 512) (i32.const 0) (i32.const 8192) (global.get $al)))",
                        types.len()
                    ),
                );
            }
            package.wasm = wat::parse_str(&package.wat).unwrap();
            let candidate = publish(package, dependencies);
            dependency = Some(reference(&candidate));
            candidates.push(candidate);
        }
        let root = publish(
            inventory::warehouse(&origin(1), &origin(2)),
            vec![dependency.unwrap()],
        );
        let instance = InstanceRecord {
            context: context(),
            creator: sender(),
            seed: [3; 32],
            code: reference(&root),
            revision: 1,
            initializer: "init".into(),
        };
        let verified = verify_publication_interface(root, candidates);
        if library_count == 8 {
            assert!(verified.is_err());
            continue;
        }
        let fixture = Fixture {
            interface: verified.unwrap(),
            instance,
        };
        let outcome = fixture
            .run(
                "init",
                inventory::tuple_arguments(&[10, 100, 20]),
                &[],
                MAX_LOCAL_EXECUTION_GAS,
            )
            .unwrap();
        if library_count == 7 {
            assert_eq!(outcome.effects.status, ExecutionStatus::Success);
        } else {
            assert_trap(outcome);
        }
    }
}

#[test]
fn newly_created_other_owner_is_read_only_in_creator_frame() {
    let recipient: [u8; 32] = VerificationKey::from(&SigningKey::from([8; 32])).into();
    for mutate in [false, true] {
        let fixture = Fixture::new(|package| {
            replace(
                package,
                "(func $require",
                &format!("{} (func $require", data_segment(42000, &recipient)),
            );
            let cap_len = inventory::tuple_arguments(&[]).len();
            let old = format!("(i32.const 256) (i32.const 18432) (i32.const {cap_len})");
            replace(
                package,
                &old,
                &format!("(i32.const 42000) (i32.const 18432) (i32.const {cap_len})"),
            );
            let marker = "(i64.store (call $scalar (i32.const 19456)";
            let operation = if mutate {
                format!(
                    "(drop (call $write (i32.const 0) (i32.const 18432) (i32.const {cap_len})))"
                )
            } else {
                "(drop (call $object (i32.const 0)))".into()
            };
            replace(package, marker, &format!("{operation} {marker}"));
        });
        let outcome = fixture
            .run(
                "init",
                inventory::tuple_arguments(&[10, 100, 20]),
                &[],
                MAX_LOCAL_EXECUTION_GAS,
            )
            .unwrap();
        if mutate {
            assert_trap(outcome);
        } else {
            assert_eq!(outcome.effects.status, ExecutionStatus::Success);
        }
    }
}
#[test]
fn inventory_initializer_library_reserve_fulfil_and_transfer() {
    let fixture = Fixture::new(|_| {});
    let initialized = fixture
        .run(
            "init",
            inventory::tuple_arguments(&[10, 100, 20]),
            &[],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    assert_eq!(initialized.effects.status, ExecutionStatus::Success);
    assert_eq!(initialized.created_authorities.len(), 3);
    assert_eq!(
        initialized
            .created_authorities
            .iter()
            .map(|item| item.creation_ordinal)
            .collect::<Vec<u32>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        initialized.created_authorities[2].authority.code.origin(),
        &origin(2)
    );
    let admin = created(&initialized, 0, AccessMode::Read);
    let stock = created(&initialized, 1, AccessMode::Write);
    let policy = created(&initialized, 2, AccessMode::Read);
    let reserved = fixture
        .run(
            "reserve",
            inventory::tuple_arguments(&[11, 10]),
            &[admin.clone(), stock],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    assert_eq!(reserved.effects.status, ExecutionStatus::Success);
    let reservation = created(&reserved, 0, AccessMode::Consume);
    let fulfilled = fixture
        .run(
            "fulfil",
            inventory::tuple_arguments(&[]),
            &[admin, reservation, policy],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    assert_eq!(fulfilled.effects.status, ExecutionStatus::Success);
    assert!(
        fulfilled
            .effects
            .object_effects
            .iter()
            .any(|effect| matches!(effect, ObjectEffect::Deleted { .. }))
    );
    let delivery = created(&fulfilled, 0, AccessMode::Write);
    let recipient: [u8; 32] = VerificationKey::from(&SigningKey::from([8; 32])).into();
    let transferred = fixture
        .run(
            "transfer",
            inventory::recipient_argument(recipient),
            &[delivery],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    assert_eq!(transferred.effects.status, ExecutionStatus::Success);
    assert!(
        matches!(&transferred.effects.object_effects[0],ObjectEffect::Mutated {new_object,..} if new_object.owner == objects::Owner::Address(objects::Address::new(recipient)))
    );
}
#[test]
fn nested_failure_rolls_back_prior_consume_and_creation() {
    let fixture = Fixture::new(|_| {});
    let init = fixture
        .run(
            "init",
            inventory::tuple_arguments(&[10, 100, 5]),
            &[],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    let admin = created(&init, 0, AccessMode::Read);
    let reserve = fixture
        .run(
            "reserve",
            inventory::tuple_arguments(&[11, 10]),
            &[admin.clone(), created(&init, 1, AccessMode::Write)],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    assert_trap(
        fixture
            .run(
                "fulfil",
                inventory::tuple_arguments(&[]),
                &[
                    admin,
                    created(&reserve, 0, AccessMode::Consume),
                    created(&init, 2, AccessMode::Read),
                ],
                MAX_LOCAL_EXECUTION_GAS,
            )
            .unwrap(),
    );
}
#[test]
fn fuel_exhaustion_rolls_back() {
    let fixture = Fixture::new(|_| {});
    assert_trap(
        fixture
            .run("init", inventory::tuple_arguments(&[10, 100, 20]), &[], 50)
            .unwrap(),
    );
}
#[test]
fn read_inputs_still_require_authenticated_sender_and_instance() {
    let fixture = Fixture::new(|_| {});
    let init = fixture
        .run(
            "init",
            inventory::tuple_arguments(&[10, 100, 20]),
            &[],
            MAX_LOCAL_EXECUTION_GAS,
        )
        .unwrap();
    for owner in [
        objects::Owner::Shared,
        objects::Owner::Immutable,
        objects::Owner::System,
        objects::Owner::Address(objects::Address::new(
            VerificationKey::from(&SigningKey::from([8; 32])).into(),
        )),
    ] {
        let mut admin = created(&init, 0, AccessMode::Read);
        admin.resolved.object.owner = owner;
        assert!(
            fixture
                .run(
                    "reserve",
                    inventory::tuple_arguments(&[11, 10]),
                    &[admin, created(&init, 1, AccessMode::Write)],
                    MAX_LOCAL_EXECUTION_GAS
                )
                .is_err()
        );
    }
    let mut admin = created(&init, 0, AccessMode::Read);
    admin.authority.instance.seed = [9; 32];
    assert!(
        fixture
            .run(
                "reserve",
                inventory::tuple_arguments(&[11, 10]),
                &[admin, created(&init, 1, AccessMode::Write)],
                MAX_LOCAL_EXECUTION_GAS
            )
            .is_err()
    );
}
