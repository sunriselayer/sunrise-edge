//! Adversarial VM coverage for DR-0124 generic ordered typed object results.
//!
//! Every case runs real profile-four WASM through the local interpreter under
//! an explicitly selected and signed profile-four [`LocalExecutionPolicy`].
//! The signer binds that policy's digest into the intent, so these runs prove
//! only that the profile-four policy was chosen and authenticated for this
//! call; nothing here proves a durable node-side installation of it. The
//! coordinator root package drives a dependency library that declares ordered
//! result slots, so delivery, absence, revalidation at frame exit, aliasing
//! and buffer bounds are all exercised on the actual host path rather than on
//! a unit harness.

#[path = "common/results_inventory.rs"]
mod inventory;
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::package_types::PackageOrigin;
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::*;
use execution::publication::*;
use execution::{
    ExecutionStatus, GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION, LocalWasmExecutionEngine,
    validate_contract_wasm_profile,
};
use hashing::HashSuiteResolver;
use protocol_types::{ChainId, Epoch, HashSuite, HashSuiteSchedule, ProtocolVersion};

fn key() -> SigningKey {
    SigningKey::from([7; 32])
}
fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("results-vm").unwrap(),
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
    let artifact = candidate.artifact();
    UnverifiedDependencyRef::new(artifact.origin().clone(), 1, context(), *candidate.digest())
        .unwrap()
}

/// Publishes one fixture package at an explicit wasm profile, committing the
/// matching semantics for that profile.
fn publish_at(
    mut package: inventory::ResultsPackage,
    dependencies: Vec<UnverifiedDependencyRef>,
    profile: u32,
) -> Result<AuthenticatedPublicationCandidate, PublicationError> {
    package.wasm = wat::parse_str(&package.wat).unwrap();
    let exports: Vec<String> = package
        .abi
        .objects
        .entrypoints
        .iter()
        .map(|entry| entry.name.clone())
        .collect();
    let metadata = ExecutableAbi {
        call: package.abi,
        initializer: package.initializer,
        transferable_constructors: package.transferable_constructors,
        results: package.results,
    };
    let semantics = if profile == GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION {
        generic_object_result_semantics(&resolver(), &context()).unwrap()
    } else {
        general_execution_semantics(&resolver(), &context()).unwrap()
    };
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: metadata.call.objects.origin.clone(),
        revision: 1,
        wasm_profile: profile,
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
}

fn publish(
    package: inventory::ResultsPackage,
    dependencies: Vec<UnverifiedDependencyRef>,
) -> AuthenticatedPublicationCandidate {
    publish_at(
        package,
        dependencies,
        GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION,
    )
    .unwrap()
}

fn scope(
    candidate: AuthenticatedPublicationCandidate,
    dependencies: Vec<AuthenticatedPublicationCandidate>,
) -> ResolvedExecutionScope {
    let instance = InstanceRecord {
        context: context(),
        creator: sender(),
        seed: [3; 32],
        code: reference(&candidate),
        revision: 1,
        initializer: "init".into(),
    };
    ResolvedExecutionScope {
        target: instance_target(&resolver(), &instance).unwrap(),
        instance,
        interface: verify_publication_interface(candidate, dependencies).unwrap(),
    }
}

/// Root coordinator over the result-declaring dependency library and the
/// two-hop courier, optionally mutating either edited package first.
/// The coordinator's dependency list is strictly ascending by origin, which
/// is exactly the order its positional dependency selectors are derived from.
fn fixture_with(
    edit_resource: impl FnOnce(&mut inventory::ResultsPackage),
    edit_coordinator: impl FnOnce(&mut inventory::ResultsPackage),
) -> ResolvedExecutionScope {
    let mut resource = inventory::resource(&origin(1));
    edit_resource(&mut resource);
    let resource = publish(resource, vec![]);
    let courier = publish(
        inventory::courier(&origin(4), &origin(1)),
        vec![reference(&resource)],
    );
    let mut coordinator = inventory::coordinator(&origin(2), &origin(1), &origin(4));
    edit_coordinator(&mut coordinator);
    let mut dependencies = vec![reference(&resource), reference(&courier)];
    dependencies.sort_by(|left, right| left.origin().cmp(right.origin()));
    let coordinator = publish(coordinator, dependencies);
    scope(coordinator, vec![resource, courier])
}

fn fixture(edit: impl FnOnce(&mut inventory::ResultsPackage)) -> ResolvedExecutionScope {
    fixture_with(|_| {}, edit)
}

/// Replaces one exact statement with a no-op, so a control run differs from
/// its adversarial counterpart by that statement alone.
fn silence(package: &mut inventory::ResultsPackage, statement: &str) {
    assert!(package.wat.contains(statement));
    package.wat = package.wat.replacen(statement, "(nop)", 1);
}

fn run_with(
    policy: &LocalExecutionPolicy,
    root: &ResolvedExecutionScope,
    entry: &str,
    arguments: Vec<u8>,
    authorizations: Vec<execution::call_authorization::CallAuthorization>,
) -> Result<LocalExecutionOutcome, LocalExecutionError> {
    let resolver = resolver();
    let call = CallIntent {
        context: context(),
        request_id: [5; 32],
        sender: sender(),
        nonce: 0,
        code: root.instance.code.clone(),
        instance: root.target.clone(),
        entrypoint: entry.into(),
        type_arguments: vec![],
        access: abi::AccessManifest { entries: vec![] },
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
        authorizations,
    };
    let signature = key()
        .sign(&local_execution_signing_frame(&context(), &intent)?)
        .into();
    let signed = SignedLocalExecutionIntent { intent, signature };
    let authenticated =
        authenticate_local_execution(&resolver, policy, &encode_signed_local_execution(&signed)?)?;
    let scopes = vec![root.clone()];
    execution::execution_scopes::validate_local_execution_scopes(
        &resolver,
        policy,
        authenticated.intent(),
        &scopes,
    )?;
    LocalWasmExecutionEngine::new().execute(LocalExecutionRequest {
        scopes: &scopes,
        intent: &authenticated,
        resolver: &resolver,
        policy,
        event_digest: local_execution_event_digest(&resolver, &signed)?,
        inputs: &[],
    })
}

fn run(root: &ResolvedExecutionScope, entry: &str) -> LocalExecutionOutcome {
    run_with(
        &LocalExecutionPolicy::generic_object_results(context()),
        root,
        entry,
        inventory::tuple0_bytes(),
        vec![],
    )
    .unwrap()
}

/// Signed same-instance authorization from the coordinator to one of the
/// dependency library's entrypoints.
fn authorization(
    root: &ResolvedExecutionScope,
    resource: &UnverifiedDependencyRef,
    entrypoint: &str,
) -> execution::call_authorization::CallAuthorization {
    use execution::call_authorization::{CallAuthorization, ExecutionTarget};
    CallAuthorization {
        caller: ExecutionTarget {
            instance: root.target.clone(),
            code: root.instance.code.clone(),
        },
        callee: ExecutionTarget {
            instance: root.target.clone(),
            code: resource.clone(),
        },
        entrypoint: entrypoint.into(),
        type_arguments: vec![],
        objects: vec![],
    }
}

/// The dependency reference for the result-declaring library inside `root`.
fn resource_code(root: &ResolvedExecutionScope) -> UnverifiedDependencyRef {
    root.interface
        .dependencies()
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
        .find(|reference| reference.origin() == &origin(1))
        .unwrap()
}

fn succeeds(root: &ResolvedExecutionScope, entry: &str) {
    assert_eq!(run(root, entry).effects.status, ExecutionStatus::Success);
}

fn traps(root: &ResolvedExecutionScope, entry: &str) {
    let outcome = run(root, entry);
    assert_eq!(
        outcome.effects.status,
        ExecutionStatus::Failure {
            reason: LOCAL_EXECUTION_TRAP_REASON.into()
        }
    );
    assert!(outcome.effects.object_effects.is_empty());
    assert!(outcome.created_authorities.is_empty());
}

#[test]
fn declared_slots_deliver_handles_absence_sentinels_and_foreign_owned_reads() {
    let root = fixture(|_| {});
    // A plain call_dependency to a result-declaring entrypoint still runs and
    // still validates required slots; the handles are simply dropped.
    succeeds(&root, "call_drop");
    // Returning a Read grant on a foreign-owned object is legitimate: the
    // callee never wrote it, and the receiver gets Read only.
    succeeds(&root, "call_foreign_read");
    // An optional slot left unfilled delivers the fixed-length u32::MAX
    // sentinel in its own position; nothing is compacted.
    succeeds(&root, "call_optional_absent");
}

#[test]
fn frame_exit_revalidates_returned_slots_against_final_live_state() {
    let root = fixture(|_| {});
    // return_object then consume: the slot must not deliver a stale handle.
    traps(&root, "call_consume_trap");
    // return_object then self-transfer: the transfer attenuates the frame's
    // effective right to Read, which no longer covers the declared Consume
    // slot, even though the transfer itself was permitted.
    traps(&root, "call_transfer_trap");
}

#[test]
fn duplicate_slots_receiver_aliases_and_missing_required_slots_fail_closed() {
    let root = fixture(|_| {});
    // The same handle returned into two distinct slots.
    traps(&root, "call_duplicate_trap");
    // A delivered handle the receiver already holds would alias one arena
    // object under two handles in one frame.
    traps(&root, "call_receiver_alias");
    // A non-optional slot the callee never filled.
    traps(&root, "call_required_missing");
}

#[test]
fn undersized_result_buffer_is_rejected_before_any_grant_is_delivered() {
    let root = fixture(|_| {});
    traps(&root, "call_small_buffer");
}

#[test]
fn dependency_defined_grants_relay_without_any_write_authority() {
    // The coordinator returns an object whose defining code is the dependency
    // library, through its own declared slot. Returning a grant is not a
    // write, so this must succeed even though the coordinator could never
    // mutate, consume or transfer that object.
    let root = fixture(|_| {});
    succeeds(&root, "call_relay_dependency_defined");
}

#[test]
fn the_root_frame_enforces_its_own_required_slots() {
    // Same entrypoint, with its single return_object removed: the root has no
    // receiving frame, but a declared required slot must still be filled.
    let root = fixture(|package| {
        let marker = "(call $zero (call $return_object (i32.const 0) (local.get $h))))\n(func (export \"call_required_missing\")";
        assert!(package.wat.contains(marker));
        package.wat = package.wat.replacen(
            marker,
            "(drop (local.get $h)))\n(func (export \"call_required_missing\")",
            1,
        );
    });
    traps(&root, "call_relay_dependency_defined");
}

#[test]
fn profile_three_policies_and_artifacts_reject_the_new_result_abi() {
    // A profile-three policy must not admit profile-four code at all.
    let root = fixture(|_| {});
    assert!(
        run_with(
            &LocalExecutionPolicy::general(context()),
            &root,
            "call_drop",
            inventory::tuple0_bytes(),
            vec![]
        )
        .is_err()
    );
}

/// A package whose module is valid under profile three on its own: no host
/// imports at all, so nothing about its WASM can be what rejects it. Only its
/// declared result slots distinguish it.
fn importless_package(slots: usize) -> inventory::ResultsPackage {
    use abi::call_values::{CallAbi, ValueLayout};
    use abi::public_abi::{
        ConstructorDeclaration, EntrypointDeclaration, ObjectMode, ObjectResultDeclaration,
        PackageAbi, TypePattern,
    };
    let wat = "(module (memory (export \"memory\") 1 2) (func (export \"run\")))".to_owned();
    let package_origin = origin(9);
    inventory::ResultsPackage {
        wasm: wat::parse_str(&wat).unwrap(),
        wat,
        abi: CallAbi {
            objects: PackageAbi {
                origin: package_origin.clone(),
                constructors: vec![ConstructorDeclaration {
                    local_id: 1,
                    schema: 1,
                    arguments: vec![],
                }],
                entrypoints: vec![EntrypointDeclaration {
                    name: "run".into(),
                    type_parameters: vec![],
                    objects: vec![],
                }],
            },
            arguments: vec![ValueLayout::Tuple(vec![])],
            bodies: vec![ValueLayout::Tuple(vec![])],
        },
        initializer: None,
        transferable_constructors: vec![],
        results: vec![vec![
            ObjectResultDeclaration {
                mode: ObjectMode::Read,
                schema: 1,
                ty: TypePattern {
                    origin: package_origin,
                    constructor: 1,
                    arguments: vec![],
                },
                optional: true,
            };
            slots
        ]],
    }
}

#[test]
fn declared_result_slots_are_rejected_on_profile_three_artifacts_in_isolation() {
    // Control: the identical import-free module and ABI, with no declared
    // result slots, publishes and verifies cleanly at profile three. This is
    // what makes the failure below attributable to the declarations alone
    // rather than to an unsupported import or an unrelated shape rule.
    let clean = publish_at(importless_package(0), vec![], 3).unwrap();
    verify_publication_interface(clean, vec![]).unwrap();

    // Version-two executable ABI bytes on a profile-three artifact: the
    // artifact itself is admissible, and only interface verification rejects
    // the declarations, so old-profile code can never gain result slots.
    let smuggled = publish_at(importless_package(1), vec![], 3).unwrap();
    let error = verify_publication_interface(smuggled, vec![]).unwrap_err();
    assert!(
        matches!(
            &error,
            InterfaceError::Abi(abi::call_values::ValueError::Invalid(
                "object result declarations require wasm profile four"
            ))
        ),
        "unexpected rejection: {error:?}"
    );
}

#[test]
fn the_new_host_selectors_are_admissible_only_under_profile_four() {
    let module = wat::parse_str(
        "(module (import \"sunrise\" \"return_object\" (func (param i32 i32) (result i32))) (memory (export \"memory\") 1 2) (func (export \"run\")))",
    )
    .unwrap();
    for profile in [1, 2, 3] {
        assert!(validate_contract_wasm_profile(&module, &["run"], profile).is_err());
    }
    assert_eq!(
        validate_contract_wasm_profile(&module, &["run"], 4)
            .unwrap()
            .profile_version(),
        4
    );
}

#[test]
fn call_contract_with_results_delivers_only_under_a_matching_signed_authorization() {
    let root = fixture(|_| {});
    let resource = resource_code(&root);
    let policy = LocalExecutionPolicy::generic_object_results(context());
    let call = |authorizations| {
        run_with(
            &policy,
            &root,
            "call_contract_results",
            inventory::tuple0_bytes(),
            authorizations,
        )
    };

    // Positive: the signed table names this caller, this callee instance and
    // this entrypoint, so the callee's single declared slot is delivered into
    // the coordinator's own handle namespace.
    let granted = authorization(&root, &resource, "issue_self");
    assert_eq!(
        call(vec![granted.clone()]).unwrap().effects.status,
        ExecutionStatus::Success
    );

    // No table at all: the selector names authorization zero, which does not
    // exist, so nothing is callable by mere possession of the import.
    let outcome = call(vec![]).unwrap();
    assert_eq!(
        outcome.effects.status,
        ExecutionStatus::Failure {
            reason: LOCAL_EXECUTION_TRAP_REASON.into()
        }
    );

    // Wrong runtime caller: the authorization grants the callee, not the
    // coordinator, the right to make this call.
    let mut wrong_caller = granted.clone();
    wrong_caller.caller = wrong_caller.callee.clone();
    assert_eq!(
        call(vec![wrong_caller]).unwrap().effects.status,
        ExecutionStatus::Failure {
            reason: LOCAL_EXECUTION_TRAP_REASON.into()
        }
    );

    // Wrong callee code under the same instance: the signed target selects
    // exact code, never merely an instance. This one is rejected statically
    // by scope validation, before the interpreter ever runs, because the
    // coordinator's own ABI declares no such entrypoint.
    let mut wrong_callee = granted.clone();
    wrong_callee.callee.code = root.instance.code.clone();
    assert!(matches!(
        call(vec![wrong_callee]),
        Err(LocalExecutionError::Invalid("callee ABI binding"))
    ));

    // A different signed entrypoint on the same authorized callee: the table
    // is a capability for one entrypoint, and `issue_skip` leaves its required
    // slot unfilled, so even an authorized call fails closed.
    let other = authorization(&root, &resource, "issue_skip");
    assert_eq!(
        call(vec![other]).unwrap().effects.status,
        ExecutionStatus::Failure {
            reason: LOCAL_EXECUTION_TRAP_REASON.into()
        }
    );
}

#[test]
fn every_delivered_handle_counts_permanently_against_the_cumulative_bound() {
    // Two-hop relay: each batch creates four objects and delivers each of them
    // twice, so a batch costs 4 creations, 2 calls and 12 handles. Twenty-one
    // batches allocate 252 handles with 84 creations and 42 calls; twenty-two
    // would allocate 264 against MAX_LOCAL_OBJECT_HANDLES (256) while still
    // holding 88 creations under MAX_LOCAL_CREATED_OBJECTS (128) and 44 calls
    // under MAX_LOCAL_EXECUTION_CALLS (64). The handle bound is therefore the
    // rule under test, not a creation or call cap reached first.
    assert_eq!(MAX_LOCAL_OBJECT_HANDLES, 256);
    assert_eq!(MAX_LOCAL_CREATED_OBJECTS, 128);
    assert_eq!(MAX_LOCAL_EXECUTION_CALLS, 64);
    let root = fixture(|_| {});
    let policy = LocalExecutionPolicy::generic_object_results(context());
    let stress = |batches: u64| {
        run_with(
            &policy,
            &root,
            "stress",
            inventory::u64_bytes(batches),
            vec![],
        )
        .unwrap()
    };
    let twenty_one = stress(21);
    assert_eq!(twenty_one.effects.status, ExecutionStatus::Success);
    // Exactly four objects per batch really were created, so the creation
    // count at twenty-two batches is 88 and stays under its own cap.
    let created = twenty_one
        .effects
        .object_effects
        .iter()
        .filter(|effect| matches!(effect, execution::ObjectEffect::Created(_)))
        .count();
    assert_eq!(created, 84);
    // And gas is not what runs out: one more batch costs proportionally more
    // than the twenty-one that just succeeded, and still fits the budget.
    let projected = twenty_one.effects.gas_used * 22 / 21;
    assert!(
        projected < MAX_LOCAL_EXECUTION_GAS,
        "projected gas {projected} would exhaust the budget on its own"
    );
    assert_eq!(
        stress(22).effects.status,
        ExecutionStatus::Failure {
            reason: LOCAL_EXECUTION_TRAP_REASON.into()
        }
    );
}

#[test]
fn the_profile_four_policy_commits_distinct_bytes_and_roundtrips() {
    let generic = LocalExecutionPolicy::generic_object_results(context());
    let general = LocalExecutionPolicy::general(context());
    let typed = LocalExecutionPolicy::new(context());
    assert_eq!(generic.profile(), 4);
    let bytes = generic.encode().unwrap();
    assert_ne!(bytes, general.encode().unwrap());
    assert_ne!(bytes, typed.encode().unwrap());
    assert_eq!(LocalExecutionPolicy::decode(&bytes).unwrap(), generic);
    assert_ne!(
        generic.digest(&resolver()).unwrap(),
        general.digest(&resolver()).unwrap()
    );
}

/// Positive controls. Each run below differs from its trapping counterpart
/// above by exactly the one statement or declaration flag under test, so the
/// trap is attributable to that rule and not to unrelated call plumbing.
#[test]
fn every_rejection_above_is_caused_by_the_rule_under_test() {
    // return_then_consume without the consume.
    let root = fixture_with(
        |package| silence(package, "(call $zero (call $consume (local.get $h)))"),
        |_| {},
    );
    succeeds(&root, "call_consume_trap");

    // return_then_transfer without the transfer.
    let root = fixture_with(
        |package| {
            silence(
                package,
                "(call $zero (call $transfer (local.get $h) (i32.const 256)))",
            )
        },
        |_| {},
    );
    succeeds(&root, "call_transfer_trap");

    // dup_slot returning into slot zero only, with slot one made optional.
    let root = fixture_with(
        |package| {
            package.results[0][1].optional = true;
            silence(
                package,
                "(call $zero (call $return_object (i32.const 1) (local.get $h)))",
            );
        },
        |_| {},
    );
    succeeds(&root, "call_duplicate_trap");

    // issue_skip's unfilled slot, declared optional instead of required.
    let root = fixture_with(|package| package.results[5][0].optional = true, |_| {});
    succeeds(&root, "call_required_missing");

    // relay delivering nothing, so the receiver never gets an aliasing handle.
    let root = fixture_with(
        |package| {
            package.results[6][0].optional = true;
            silence(
                package,
                "(call $zero (call $return_object (i32.const 0) (i32.const 0)))",
            );
        },
        |_| {},
    );
    succeeds(&root, "call_receiver_alias");

    // The undersized buffer widened to the declared fixed length.
    let root = fixture(|package| {
        assert!(package.wat.contains("(i32.const 8000) (i32.const 3)"));
        package.wat = package.wat.replacen(
            "(i32.const 8000) (i32.const 3)",
            "(i32.const 8000) (i32.const 16)",
            1,
        );
    });
    succeeds(&root, "call_small_buffer");
}
