//! Publication, instance and plan fixtures for the internal phase tests.
//!
//! These build ordinary authenticated profile-four publication and
//! instantiation scopes and run the real public Standard Asset WASM. No
//! fixture here grants paid admission, and no root state is seeded through
//! a native balance path: every object comes from the guest's own
//! initializer, mint and split executions.
use super::*;
use abi::call_values::CallAbi;
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::package_types::encode_scoped_type_tag;
use abi::public_abi::{ConstructorDeclaration, EntrypointDeclaration, PackageAbi};
use ed25519_zebra::{SigningKey, VerificationKey};
use fees::GasSchedule;
use protocol_types::{ChainId, Epoch, HashPurpose, HashSuite, HashSuiteSchedule, ProtocolVersion};
use public_standard_asset::{StandardAssetPackage, build_package};

pub(super) fn key() -> SigningKey {
    SigningKey::from([7; 32])
}
pub(super) fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
pub(super) fn treasury() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([9; 32])).into()
}
pub(super) fn refund_account() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([11; 32])).into()
}
/// A fixed recipient distinct from any harness fee/refund recipient, so the
/// probe's own `create_then_transfer` output is never ambiguous with a fee
/// or refund coin owned by the same address.
pub(super) fn probe_transfer_target() -> [u8; 32] {
    VerificationKey::from(&SigningKey::from([13; 32])).into()
}
pub(super) fn context() -> publication::PublicationContext {
    publication::PublicationContext::new(
        ChainId::new("phase-coordinator").expect("chain id"),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .expect("context")
}
pub(super) fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        context().chain_id().clone(),
        context().protocol_version(),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .expect("resolver")
}
pub(super) fn origin(seed: u8) -> PackageOrigin {
    PackageOrigin::unverified(context().chain_id().clone(), sender(), [seed; 32]).expect("origin")
}
pub(super) fn digest(label: &[u8]) -> protocol_types::Digest32 {
    resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::Object, label)
        .expect("digest")
}

/// Publishes one module under an ordinary authenticated profile-four
/// publication submission.
pub(super) fn publish_parts(
    seed: u8,
    wasm: Vec<u8>,
    encoded_abi: Vec<u8>,
    exports: Vec<String>,
) -> publication::AuthenticatedPublicationCandidate {
    publish_parts_with_dependencies(seed, wasm, encoded_abi, exports, Vec::new())
}

/// Publishes one module under an ordinary authenticated profile-four
/// publication submission, declaring the exact given unverified dependency
/// edges. No dependency provenance is otherwise trusted beyond the ordinary
/// interface verification the closure already performs.
pub(super) fn publish_parts_with_dependencies(
    seed: u8,
    wasm: Vec<u8>,
    encoded_abi: Vec<u8>,
    exports: Vec<String>,
    unverified_dependencies: Vec<publication::UnverifiedDependencyRef>,
) -> publication::AuthenticatedPublicationCandidate {
    let semantics = generic_object_result_semantics(&resolver(), &context()).expect("semantics");
    let artifact = publication::CodeArtifact::new(publication::ArtifactParts {
        context: context(),
        origin: origin(seed),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm,
        unverified_abi: encoded_abi,
        exports,
        unverified_dependencies,
    })
    .expect("artifact");
    let commitment =
        publication::artifact_commitment(&resolver(), &context(), &artifact).expect("commitment");
    let frame = publication::publication_submission_signing_frame(
        &resolver(),
        &context(),
        &artifact,
        0,
        [1; 32],
    )
    .expect("frame");
    publication::authenticate_publication_submission(
        &resolver(),
        &context(),
        &semantics,
        publication::PublicationSubmission::new(
            [1; 32],
            publication::PublicationRequest::new(
                artifact,
                0,
                commitment,
                key().sign(&frame).into(),
            ),
        )
        .expect("submission"),
    )
    .expect("candidate")
}

/// Publishes the public Standard Asset package.
pub(super) fn publish(seed: u8) -> publication::AuthenticatedPublicationCandidate {
    let package: StandardAssetPackage = build_package(&origin(seed)).expect("package");
    publish_parts(seed, package.wasm, package.encoded_abi, package.exports)
}

/// Builds one instantiated scope for a published candidate.
pub(super) fn scope_for(
    candidate: publication::AuthenticatedPublicationCandidate,
    instance_seed: u8,
    initializer: &str,
) -> ResolvedExecutionScope {
    scope_for_with_dependencies(candidate, Vec::new(), instance_seed, initializer)
}

/// The exact `UnverifiedDependencyRef` a published candidate's own code
/// resolves to, for use as another artifact's declared dependency edge.
pub(super) fn dependency_ref(
    candidate: &publication::AuthenticatedPublicationCandidate,
) -> UnverifiedDependencyRef {
    let artifact = candidate.artifact();
    publication::UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        1,
        context(),
        *candidate.digest(),
    )
    .expect("dependency reference")
}

/// Builds one instantiated scope for a published candidate that itself
/// declares the given already-published dependency candidates.
pub(super) fn scope_for_with_dependencies(
    candidate: publication::AuthenticatedPublicationCandidate,
    dependencies: Vec<publication::AuthenticatedPublicationCandidate>,
    instance_seed: u8,
    initializer: &str,
) -> ResolvedExecutionScope {
    let code = dependency_ref(&candidate);
    let instance = InstanceRecord {
        context: context(),
        creator: sender(),
        seed: [instance_seed; 32],
        code,
        revision: 1,
        initializer: initializer.into(),
    };
    ResolvedExecutionScope {
        target: instance_target(&resolver(), &instance).expect("target"),
        instance,
        interface: publication::verify_publication_interface(candidate, dependencies)
            .expect("interface"),
    }
}

pub(super) fn scope(seed: u8, instance_seed: u8) -> ResolvedExecutionScope {
    scope_for(publish(seed), instance_seed, "init")
}

/// The probe exports, in the strictly ascending order the ABI and the
/// artifact export list both require.
pub(super) const PROBE_ENTRYPOINTS: [&str; 8] = [
    "create_many",
    "create_then_transfer",
    "create_then_trap",
    "emit",
    "emit_then_trap",
    "init",
    "noop",
    "spin",
];

/// A minimal profile-four application payload used only as the
/// *application* phase root in adversarial resource tests. The fee phases
/// always run the real public Standard Asset WASM; this module exists
/// because that package has no input-free entrypoint and no way to create
/// an object and then trap, which the ordinal-gap and exhaustion tests
/// require. It performs no fee work and is never a fee target.
pub(super) fn probe_wat(origin: &PackageOrigin) -> String {
    let tag: Vec<u8> = encode_scoped_type_tag(
        &ScopedTypeTag::new(origin.clone(), 1, Vec::new()).expect("probe tag"),
    )
    .expect("encoded probe tag");
    let body: Vec<u8> = abi::call_values::encode_call_value(&ValueLayout::U64, &CallValue::U64(1))
        .expect("probe body");
    let recipient: [u8; 32] = probe_transfer_target();
    let segment = |address: u32, bytes: &[u8]| -> String {
        let escaped: String = bytes.iter().map(|byte| format!("\\{byte:02x}")).collect();
        format!("(data (i32.const {address}) \"{escaped}\")")
    };
    format!(
        r#"(module
(import "sunrise" "get_caller" (func $caller (param i32) (result i32)))
(import "sunrise" "create_object" (func $create (param i32 i32 i32 i32 i32) (result i32)))
(import "sunrise" "emit_event" (func $emit (param i32 i32 i32 i32) (result i32)))
(import "sunrise" "transfer_object" (func $transfer (param i32 i32) (result i32)))
(import "sunrise" "abort" (func $abort (param i32 i32)))
(memory (export "memory") 1 1)
{tag_data}
{body_data}
{recipient_data}
(func $new (result i32)
 (drop (call $caller (i32.const 4096)))
 (call $create (i32.const 1024) (i32.const {tag_len}) (i32.const 4096)
   (i32.const 2048) (i32.const {body_len})))
(func $event
 (drop (call $emit (i32.const 1024) (i32.const {tag_len})
   (i32.const 2048) (i32.const {body_len}))))
(func (export "create_many") (loop $again (drop (call $new)) (br $again)))
(func (export "create_then_transfer") (drop (call $transfer (call $new) (i32.const 3072))))
(func (export "create_then_trap") (drop (call $new)) (call $abort (i32.const 0) (i32.const 0)))
(func (export "emit") (call $event))
(func (export "emit_then_trap") (call $event) (call $abort (i32.const 0) (i32.const 0)))
(func (export "init"))
(func (export "noop"))
(func (export "spin") (loop $again (br $again)))
)"#,
        tag_data = segment(1024, &tag),
        body_data = segment(2048, &body),
        recipient_data = segment(3072, &recipient),
        tag_len = tag.len(),
        body_len = body.len(),
    )
}

/// The probe's executable ABI: four input-free entrypoints, one local
/// constructor with a `u64` body, and no declared result slots.
pub(super) fn probe_abi(origin: &PackageOrigin) -> ExecutableAbi {
    let entrypoints: Vec<EntrypointDeclaration> = PROBE_ENTRYPOINTS
        .iter()
        .map(|name| EntrypointDeclaration {
            name: (*name).to_owned(),
            type_parameters: Vec::new(),
            objects: Vec::new(),
        })
        .collect();
    let abi: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: vec![ConstructorDeclaration {
                    local_id: 1,
                    schema: 1,
                    arguments: Vec::new(),
                }],
                entrypoints,
            },
            arguments: vec![ValueLayout::Tuple(Vec::new()); PROBE_ENTRYPOINTS.len()],
            bodies: vec![ValueLayout::U64],
        },
        initializer: Some("init".to_owned()),
        transferable_constructors: vec![1],
        results: vec![Vec::new(); PROBE_ENTRYPOINTS.len()],
    };
    abi.validate().expect("probe abi");
    abi
}

/// Publishes and instantiates the probe application module.
pub(super) fn probe_scope(seed: u8, instance_seed: u8) -> ResolvedExecutionScope {
    let origin: PackageOrigin = origin(seed);
    let wasm: Vec<u8> = wat::parse_str(probe_wat(&origin)).expect("probe wasm");
    let abi: ExecutableAbi = probe_abi(&origin);
    let candidate = publish_parts(
        seed,
        wasm,
        encode_executable_abi(&abi).expect("probe abi bytes"),
        PROBE_ENTRYPOINTS
            .iter()
            .map(|name| (*name).into())
            .collect(),
    );
    scope_for(candidate, instance_seed, "init")
}

/// One WASM module's own declared maximum is capped at 256 pages (16 MiB);
/// grow from the initial page up to exactly that per-module ceiling.
const DEPENDENCY_LEAF_MAX_PAGES: usize = 256;
/// Linear-memory growth one leaf dependency call performs: just under
/// 16 MiB, well under any single module's own bound, so repeated calls --
/// not a single module -- are what must cross the cumulative invocation
/// ceiling.
const DEPENDENCY_LEAF_GROWTH_PAGES: usize = DEPENDENCY_LEAF_MAX_PAGES - 1;
pub(super) const DEPENDENCY_LEAF_ENTRYPOINTS: [&str; 1] = ["grow"];

/// A dependency-only leaf module: one input-free, no-import export that
/// grows its own linear memory by exactly `DEPENDENCY_LEAF_GROWTH_BYTES` via
/// a bare `memory.grow`, so the store's global resource limiter -- not a
/// host import -- is what accounts for it.
fn dependency_leaf_wat() -> String {
    format!(
        r#"(module
(memory (export "memory") 1 {max_pages})
(func (export "grow") (drop (memory.grow (i32.const {pages}))))
)"#,
        pages = DEPENDENCY_LEAF_GROWTH_PAGES,
        max_pages = DEPENDENCY_LEAF_MAX_PAGES,
    )
}

fn dependency_leaf_abi(origin: &PackageOrigin) -> ExecutableAbi {
    let entrypoints: Vec<EntrypointDeclaration> = DEPENDENCY_LEAF_ENTRYPOINTS
        .iter()
        .map(|name| EntrypointDeclaration {
            name: (*name).to_owned(),
            type_parameters: Vec::new(),
            objects: Vec::new(),
        })
        .collect();
    let abi: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: Vec::new(),
                entrypoints,
            },
            arguments: vec![ValueLayout::Tuple(Vec::new()); DEPENDENCY_LEAF_ENTRYPOINTS.len()],
            bodies: Vec::new(),
        },
        initializer: None,
        transferable_constructors: Vec::new(),
        results: vec![Vec::new(); DEPENDENCY_LEAF_ENTRYPOINTS.len()],
    };
    abi.validate().expect("dependency leaf abi");
    abi
}

/// Publishes (but does not instantiate as a top-level scope) the leaf
/// dependency module.
pub(super) fn dependency_leaf(seed: u8) -> publication::AuthenticatedPublicationCandidate {
    let origin: PackageOrigin = origin(seed);
    let wasm: Vec<u8> = wat::parse_str(dependency_leaf_wat()).expect("dependency leaf wasm");
    let abi: ExecutableAbi = dependency_leaf_abi(&origin);
    publish_parts(
        seed,
        wasm,
        encode_executable_abi(&abi).expect("dependency leaf abi bytes"),
        DEPENDENCY_LEAF_ENTRYPOINTS
            .iter()
            .map(|name| (*name).into())
            .collect(),
    )
}

pub(super) const MEMORY_SPINNER_ENTRYPOINTS: [&str; 1] = ["spin_dependency"];

/// An application root that repeatedly calls dependency index zero's
/// `grow` export in an unbounded loop, so it stops only when the host
/// denies it (resource exhaustion) or a phase ceiling traps it -- never on
/// its own.
fn memory_spinner_wat() -> String {
    let entry: &[u8] = b"grow";
    let types: Vec<u8> =
        abi::package_types::encode_scoped_type_arguments(context().chain_id(), &[])
            .expect("empty type arguments");
    let args: Vec<u8> = abi::call_values::encode_call_value(
        &ValueLayout::Tuple(Vec::new()),
        &CallValue::Tuple(Vec::new()),
    )
    .expect("empty call arguments");
    let segment = |address: u32, bytes: &[u8]| -> String {
        let escaped: String = bytes.iter().map(|byte| format!("\\{byte:02x}")).collect();
        format!("(data (i32.const {address}) \"{escaped}\")")
    };
    format!(
        r#"(module
(import "sunrise" "call_dependency" (func $call_dep (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
(memory (export "memory") 1 1)
{entry_data}
{types_data}
{args_data}
(func (export "spin_dependency")
  (loop $again
    (drop (call $call_dep
      (i32.const 0)
      (i32.const 4096) (i32.const {entry_len})
      (i32.const 8192) (i32.const {types_len})
      (i32.const 0) (i32.const 0)
      (i32.const 16384) (i32.const {args_len})))
    (br $again)))
)"#,
        entry_data = segment(4096, entry),
        types_data = segment(8192, &types),
        args_data = segment(16384, &args),
        entry_len = entry.len(),
        types_len = types.len(),
        args_len = args.len(),
    )
}

fn memory_spinner_abi(origin: &PackageOrigin) -> ExecutableAbi {
    let entrypoints: Vec<EntrypointDeclaration> = MEMORY_SPINNER_ENTRYPOINTS
        .iter()
        .map(|name| EntrypointDeclaration {
            name: (*name).to_owned(),
            type_parameters: Vec::new(),
            objects: Vec::new(),
        })
        .collect();
    let abi: ExecutableAbi = ExecutableAbi {
        call: CallAbi {
            objects: PackageAbi {
                origin: origin.clone(),
                constructors: Vec::new(),
                entrypoints,
            },
            arguments: vec![ValueLayout::Tuple(Vec::new()); MEMORY_SPINNER_ENTRYPOINTS.len()],
            bodies: Vec::new(),
        },
        initializer: None,
        transferable_constructors: Vec::new(),
        results: vec![Vec::new(); MEMORY_SPINNER_ENTRYPOINTS.len()],
    };
    abi.validate().expect("memory spinner abi");
    abi
}

/// Publishes and instantiates the application root that repeatedly calls
/// the given already-published leaf dependency.
pub(super) fn memory_spinner_scope(
    seed: u8,
    instance_seed: u8,
    leaf: &publication::AuthenticatedPublicationCandidate,
) -> ResolvedExecutionScope {
    let origin: PackageOrigin = origin(seed);
    let wasm: Vec<u8> = wat::parse_str(memory_spinner_wat()).expect("memory spinner wasm");
    let abi: ExecutableAbi = memory_spinner_abi(&origin);
    let candidate = publish_parts_with_dependencies(
        seed,
        wasm,
        encode_executable_abi(&abi).expect("memory spinner abi bytes"),
        MEMORY_SPINNER_ENTRYPOINTS
            .iter()
            .map(|name| (*name).into())
            .collect(),
        vec![dependency_ref(leaf)],
    );
    scope_for_with_dependencies(
        candidate,
        vec![leaf.clone()],
        instance_seed,
        "spin_dependency",
    )
}

/// One input-free application call on the probe instance.
pub(super) fn probe_application(
    scope: usize,
    code: &UnverifiedDependencyRef,
    entry: &str,
) -> ApplicationCall {
    ApplicationCall {
        scope,
        code: code.clone(),
        entrypoint: entry.into(),
        mode: LocalExecutionMode::Call,
        type_arguments: Vec::new(),
        arguments: abi::call_values::encode_call_value(
            &ValueLayout::Tuple(Vec::new()),
            &CallValue::Tuple(Vec::new()),
        )
        .expect("probe arguments"),
        inputs: Vec::new(),
        authorizations: Vec::new(),
    }
}

/// Runs one ordinary authenticated zero-fee root call, exactly as the
/// production `execute` path does, to seed real objects.
pub(super) fn call(
    scopes: &[ResolvedExecutionScope],
    entry: &str,
    arguments: Vec<u8>,
    inputs: &[ScopedResolvedObject],
    types: Vec<ScopedTypeArg>,
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
                            &objects::encode_object(&input.resolved.object).expect("object"),
                        )
                        .expect("object digest"),
                },
            })
            .collect(),
    };
    let call = crate::call::CallIntent {
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
        policy_digest: policy.digest(&resolver).expect("policy digest"),
        call,
        authorizations: vec![],
    };
    let signature = key()
        .sign(&local_execution_signing_frame(&context(), &intent).expect("signing frame"))
        .into();
    let signed = SignedLocalExecutionIntent { intent, signature };
    let encoded = encode_signed_local_execution(&signed).expect("encoded intent");
    let authenticated =
        authenticate_local_execution(&resolver, &policy, &encoded).expect("authenticated");
    LocalWasmExecutionEngine::new()
        .execute(LocalExecutionRequest {
            scopes,
            intent: &authenticated,
            resolver: &resolver,
            policy: &policy,
            event_digest: local_execution_event_digest(&resolver, &signed).expect("event digest"),
            inputs,
        })
        .expect("execution")
}

/// Extracts the n-th created object of an outcome with its host authority.
pub(super) fn created(
    outcome: &LocalExecutionOutcome,
    index: usize,
    mode: objects::AccessMode,
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
        .expect("created object")
        .clone();
    let authority: ObjectAuthority = outcome
        .created_authorities
        .iter()
        .find(|created| created.authority.object_id == object.id)
        .expect("created authority")
        .authority
        .clone();
    ScopedResolvedObject {
        resolved: crate::ResolvedObject { object, mode },
        authority,
    }
}

/// Returns the updated form of a mutated input.
pub(super) fn mutated(
    outcome: &LocalExecutionOutcome,
    prior: &ScopedResolvedObject,
) -> ScopedResolvedObject {
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
        .expect("mutated object");
    next
}

/// One initialized asset instance: its scope, asset identity `A`, and a
/// sender-owned Coin of the requested amount, all produced by real guest
/// executions rather than a native balance backdoor.
pub(super) struct Asset {
    pub scope: ResolvedExecutionScope,
    pub id: ObjectId,
    pub coin: ScopedResolvedObject,
    pub cap: ScopedResolvedObject,
}

pub(super) fn asset(seed: u8, instance_seed: u8, amount: u64) -> Asset {
    let scope: ResolvedExecutionScope = scope(seed, instance_seed);
    let scopes: Vec<ResolvedExecutionScope> = vec![scope.clone()];
    let init: LocalExecutionOutcome = call(
        &scopes,
        "init",
        public_standard_asset::no_arguments().expect("init arguments"),
        &[],
        vec![],
    );
    assert_eq!(init.effects.status, ExecutionStatus::Success);
    let definition: ScopedResolvedObject = created(&init, 0, objects::AccessMode::Read);
    let id: ObjectId = definition.resolved.object.id;
    let cap: ScopedResolvedObject = created(&init, 1, objects::AccessMode::Write);
    let mint: LocalExecutionOutcome = call(
        &scopes,
        "mint",
        public_standard_asset::mint_arguments(amount, &sender()).expect("mint arguments"),
        std::slice::from_ref(&cap),
        vec![public_standard_asset::asset_type_argument(&id)],
    );
    assert_eq!(mint.effects.status, ExecutionStatus::Success);
    let coin: ScopedResolvedObject = created(&mint, 0, objects::AccessMode::Write);
    let cap: ScopedResolvedObject = mutated(&mint, &cap);
    Asset {
        scope,
        id,
        coin,
        cap,
    }
}

/// The committed pricing used by the internal tests: positive base and
/// execution prices, and fixed positive `R`/`S` allowances sized for the
/// pinned exports of this package. These are test calibration values, not
/// an installed fee policy.
pub(super) const RESERVE_ALLOWANCE: u64 = 200_000;
pub(super) const SETTLE_ALLOWANCE: u64 = 200_000;

pub(super) fn pricer() -> ReservationPricer {
    ReservationPricer::new(
        GasSchedule {
            base_fee: 100,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        1_000,
        RESERVE_ALLOWANCE,
        SETTLE_ALLOWANCE,
    )
    .expect("pricer")
}

/// A committed pricing whose settle allowance cannot complete the pinned
/// settlement export. Used to force a settlement failure, and as a pricer
/// that does not reproduce the default admission.
pub(super) fn starved_settle_pricer() -> ReservationPricer {
    ReservationPricer::new(
        GasSchedule {
            base_fee: 100,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        1_000,
        RESERVE_ALLOWANCE,
        1,
    )
    .expect("pricer")
}

/// The reserved amount one admission produces for `limit`.
pub(super) fn reserved_for(pricer: &ReservationPricer, limit: u64) -> u64 {
    pricer
        .admit(limit, Amount::new(u64::MAX))
        .expect("admission")
        .reserved()
        .get()
}

/// Builds the pinned fee target for one asset instance.
pub(super) fn target(asset: &Asset, scope: usize) -> FeeTarget {
    let origin: PackageOrigin = asset.scope.instance.code.origin().clone();
    FeeTarget {
        scope,
        code: asset.scope.instance.code.clone(),
        reserve_entrypoint: "reserve".into(),
        reserve_all_entrypoint: "reserve_all".into(),
        settle_entrypoint: "settle".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        asset_type: public_standard_asset::coin_type_tag(&origin, &asset.id).expect("coin type"),
        reservation_type: public_standard_asset::reservation_type_tag(&origin, &asset.id)
            .expect("reservation type"),
        schema: public_standard_asset::SCHEMA_VERSION,
    }
}

/// One initialized asset plus any additional application scopes, sharing
/// one resolver and one committed profile-four policy.
pub(super) struct Harness {
    pub scopes: Vec<ResolvedExecutionScope>,
    pub resolver: HashSuiteResolver,
    pub policy: LocalExecutionPolicy,
    pub asset: Asset,
}

pub(super) fn harness(
    seed: u8,
    instance_seed: u8,
    amount: u64,
    extra: Vec<ResolvedExecutionScope>,
) -> Harness {
    let asset: Asset = asset(seed, instance_seed, amount);
    let mut scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    scopes.extend(extra);
    Harness {
        scopes,
        resolver: resolver(),
        policy: LocalExecutionPolicy::generic_object_results(context()),
        asset,
    }
}

impl Harness {
    /// Builds one internal phase plan. This is not paid admission: no
    /// signed paid envelope exists, and no zero-fee intent authorizes it.
    pub(super) fn plan<'a>(
        &'a self,
        access: ReservationAccess,
        source: ScopedResolvedObject,
        application: ApplicationCall,
        limit: u64,
        pricer: ReservationPricer,
    ) -> PhasePlan<'a> {
        let admission: Admission = pricer
            .admit(limit, Amount::new(u64::MAX))
            .expect("admission");
        PhasePlan {
            scopes: &self.scopes,
            resolver: &self.resolver,
            policy: &self.policy,
            context: context(),
            sender: sender(),
            event_digest: digest(b"paid-invocation-event"),
            invocation_digest: digest(b"paid-invocation"),
            fee_policy_digest: digest(b"paid-fee-policy"),
            target: target(&self.asset, 0),
            access,
            source,
            application: ApplicationExecution::Wasm(application),
            admission,
            pricer,
            fee_recipient: treasury(),
            refund_recipient: refund_account(),
        }
    }

    /// The fee source, in the access mode the reservation will use.
    pub(super) fn source(&self, access: ReservationAccess) -> ScopedResolvedObject {
        let mut source: ScopedResolvedObject = self.asset.coin.clone();
        source.resolved.mode = access.access();
        source
    }

    /// One application call on the asset instance itself.
    pub(super) fn asset_application(
        &self,
        entry: &str,
        arguments: Vec<u8>,
        inputs: Vec<ScopedResolvedObject>,
    ) -> ApplicationCall {
        ApplicationCall {
            scope: 0,
            code: self.asset.scope.instance.code.clone(),
            entrypoint: entry.into(),
            mode: LocalExecutionMode::Call,
            type_arguments: vec![public_standard_asset::asset_type_argument(&self.asset.id)],
            arguments,
            inputs,
            authorizations: Vec::new(),
        }
    }
}
