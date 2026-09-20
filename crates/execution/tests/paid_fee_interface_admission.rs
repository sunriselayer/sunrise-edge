//! DR-0126 installed fee ABI/role admission tests.
//!
//! `validate_fee_interface_admission` is exercised against the real pinned
//! public Standard Asset publication interface (positive case) and against
//! deliberately mis-shaped custom ABI variants (fail-closed matrix). No
//! WASM export below is ever executed: the validator is purely a
//! declarative ABI/role proof over an authenticated publication interface.
use abi::call_values::{CallAbi, ValueLayout};
use abi::executable_abi::{ExecutableAbi, encode_executable_abi};
use abi::package_types::{PackageOrigin, ScopedTypeTag};
use abi::public_abi::{
    ConstructorDeclaration, EntrypointDeclaration, ObjectMode, ObjectParameter,
    ObjectResultDeclaration, PackageAbi, TypePattern,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::InstanceTarget;
use execution::paid_execution::*;
use execution::publication::*;
use hashing::HashSuiteResolver;
use objects::ObjectId;
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};
use public_standard_asset::{StandardAssetPackage, build_package};

fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("fee-interface-admission-test").unwrap(),
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
fn key() -> SigningKey {
    SigningKey::from([21; 32])
}
fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}
fn origin(seed: u8) -> PackageOrigin {
    PackageOrigin::unverified(context().chain_id().clone(), sender(), [seed; 32]).unwrap()
}
fn asset_id() -> ObjectId {
    ObjectId::new([0x77; 32])
}

fn publish(
    seed: u8,
    wasm: Vec<u8>,
    encoded_abi: Vec<u8>,
    exports: Vec<String>,
) -> AuthenticatedPublicationCandidate {
    let semantics =
        execution::local_execution::generic_object_result_semantics(&resolver(), &context())
            .unwrap();
    let artifact = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: origin(seed),
        revision: 1,
        wasm_profile: 4,
        semantics,
        wasm,
        unverified_abi: encoded_abi,
        exports,
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

fn publish_standard_asset(seed: u8) -> AuthenticatedPublicationCandidate {
    let package: StandardAssetPackage = build_package(&origin(seed)).unwrap();
    publish(seed, package.wasm, package.encoded_abi, package.exports)
}

fn base_fee_policy(origin: &PackageOrigin, code: UnverifiedDependencyRef) -> PaidFeePolicy {
    PaidFeePolicy {
        context: context(),
        base_policy_digest:
            execution::local_execution::LocalExecutionPolicy::generic_object_results(context())
                .digest(&resolver())
                .unwrap(),
        instance: InstanceTarget {
            creator: sender(),
            seed: [9; 32],
            revision: 1,
            record_digest: digest(9),
        },
        code,
        reserve_entrypoint: "reserve".into(),
        reserve_all_entrypoint: "reserve_all".into(),
        settle_entrypoint: "settle".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset_id())],
        asset_type: public_standard_asset::coin_type_tag(origin, &asset_id()).unwrap(),
        reservation_type: public_standard_asset::reservation_type_tag(origin, &asset_id()).unwrap(),
        schema: public_standard_asset::SCHEMA_VERSION,
        fee_recipient: sender(),
        gas_schedule: fees::GasSchedule {
            base_fee: 100,
            execution_price: 1,
            read_price: 0,
            write_price: 0,
            storage_price: 0,
            system_module_price: 0,
        },
        conversion_divisor: 1_000,
        reserve_allowance: MIN_RESERVE_ALLOWANCE,
        settle_allowance: MIN_SETTLE_ALLOWANCE,
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

fn dependency_ref(candidate: &AuthenticatedPublicationCandidate) -> UnverifiedDependencyRef {
    let artifact = candidate.artifact();
    UnverifiedDependencyRef::new(artifact.origin().clone(), 1, context(), *candidate.digest())
        .unwrap()
}

#[test]
fn the_real_pinned_standard_asset_interface_satisfies_the_validator() {
    let candidate = publish_standard_asset(1);
    let code = dependency_ref(&candidate);
    let interface = verify_publication_interface(candidate, vec![]).unwrap();
    let policy = base_fee_policy(&origin(1), code);
    assert!(validate_fee_interface_admission(&interface, &policy).is_ok());
}

// ---- Fail-closed matrix: a deliberately mis-shaped custom fee ABI ----

/// Local-only constructors, distinct from Standard Asset's own numbering,
/// so tests never accidentally reuse the pinned package's real shapes.
const CTOR_COIN: u16 = 1;
const CTOR_RESERVATION: u16 = 2;
const OPAQUE_DOMAIN: u16 = 9;
const SCHEMA: u32 = 1;

fn pattern(origin: &PackageOrigin, constructor: u16) -> TypePattern {
    TypePattern {
        origin: origin.clone(),
        constructor,
        arguments: vec![abi::public_abi::PatternArgument::Parameter(0)],
    }
}
fn object(mode: ObjectMode, origin: &PackageOrigin, constructor: u16) -> ObjectParameter {
    ObjectParameter {
        mode,
        schema: SCHEMA,
        ty: pattern(origin, constructor),
    }
}
fn result(
    mode: ObjectMode,
    origin: &PackageOrigin,
    constructor: u16,
    optional: bool,
) -> ObjectResultDeclaration {
    ObjectResultDeclaration {
        mode,
        schema: SCHEMA,
        ty: pattern(origin, constructor),
        optional,
    }
}
fn entrypoint(name: &str, objects: Vec<ObjectParameter>) -> EntrypointDeclaration {
    EntrypointDeclaration {
        name: name.to_owned(),
        type_parameters: vec![abi::public_abi::ArgumentKind::Opaque(OPAQUE_DOMAIN)],
        objects,
    }
}
fn reserve_tuple_layout() -> ValueLayout {
    let digest32 = || ValueLayout::Bytes {
        min_len: 56,
        max_len: 56,
    };
    let recipient = || ValueLayout::Bytes {
        min_len: 32,
        max_len: 32,
    };
    ValueLayout::Tuple(vec![
        ValueLayout::U64,
        digest32(),
        digest32(),
        recipient(),
        recipient(),
    ])
}
fn settle_tuple_layout() -> ValueLayout {
    let digest32 = || ValueLayout::Bytes {
        min_len: 56,
        max_len: 56,
    };
    ValueLayout::Tuple(vec![ValueLayout::U64, digest32(), digest32()])
}

/// Names, in strictly ascending order (`PackageAbi` requires strictly
/// ascending entrypoint names): `mint`, `reserve`, `reserve_all`, `settle`.
const CUSTOM_ENTRYPOINTS: [&str; 4] = ["mint", "reserve", "reserve_all", "settle"];

fn custom_wat() -> String {
    format!(
        r#"(module
(memory (export "memory") 1 1)
{exports})"#,
        exports = CUSTOM_ENTRYPOINTS
            .iter()
            .map(|name| format!("(func (export \"{name}\"))"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// Builds a custom fee-shaped package whose exact declared shapes can be
/// perturbed per test case, then publishes and verifies its interface.
struct CustomPackage {
    mint: Vec<ObjectParameter>,
    reserve: Vec<ObjectParameter>,
    reserve_results: Vec<ObjectResultDeclaration>,
    reserve_all: Vec<ObjectParameter>,
    reserve_all_results: Vec<ObjectResultDeclaration>,
    settle: Vec<ObjectParameter>,
    settle_results: Vec<ObjectResultDeclaration>,
    transferable: Vec<u16>,
    reserve_argument_layout: ValueLayout,
    settle_argument_layout: ValueLayout,
    /// The ABI's own declared schema for the `Coin`/`Reservation`
    /// constructors. Structural ABI validation requires every object
    /// parameter's declared schema to equal its constructor's declared
    /// schema, so a *policy*-vs-ABI schema mismatch test must move both of
    /// these together, in lockstep with the perturbed object parameter's own
    /// schema, and instead diverge from `custom_policy()`'s fixed `SCHEMA`.
    coin_constructor_schema: u32,
    reservation_constructor_schema: u32,
}

impl CustomPackage {
    fn baseline(origin: &PackageOrigin) -> Self {
        Self {
            mint: vec![],
            reserve: vec![object(ObjectMode::Write, origin, CTOR_COIN)],
            reserve_results: vec![result(ObjectMode::Consume, origin, CTOR_RESERVATION, false)],
            reserve_all: vec![object(ObjectMode::Consume, origin, CTOR_COIN)],
            reserve_all_results: vec![result(ObjectMode::Consume, origin, CTOR_RESERVATION, false)],
            settle: vec![object(ObjectMode::Consume, origin, CTOR_RESERVATION)],
            settle_results: vec![
                result(ObjectMode::Read, origin, CTOR_COIN, false),
                result(ObjectMode::Read, origin, CTOR_COIN, true),
            ],
            transferable: vec![CTOR_COIN],
            reserve_argument_layout: reserve_tuple_layout(),
            settle_argument_layout: settle_tuple_layout(),
            coin_constructor_schema: SCHEMA,
            reservation_constructor_schema: SCHEMA,
        }
    }

    fn publish_and_verify(self, origin: &PackageOrigin, seed: u8) -> VerifiedPublicationInterface {
        let entrypoints = vec![
            entrypoint("mint", self.mint),
            entrypoint("reserve", self.reserve),
            entrypoint("reserve_all", self.reserve_all),
            entrypoint("settle", self.settle),
        ];
        let arguments = vec![
            ValueLayout::Tuple(vec![]),
            self.reserve_argument_layout.clone(),
            self.reserve_argument_layout,
            self.settle_argument_layout,
        ];
        let constructors = vec![
            ConstructorDeclaration {
                local_id: CTOR_COIN,
                schema: self.coin_constructor_schema,
                arguments: vec![abi::public_abi::ArgumentKind::Opaque(OPAQUE_DOMAIN)],
            },
            ConstructorDeclaration {
                local_id: CTOR_RESERVATION,
                schema: self.reservation_constructor_schema,
                arguments: vec![abi::public_abi::ArgumentKind::Opaque(OPAQUE_DOMAIN)],
            },
        ];
        let bodies = vec![ValueLayout::U64, ValueLayout::U64];
        let abi = ExecutableAbi {
            call: CallAbi {
                objects: PackageAbi {
                    origin: origin.clone(),
                    constructors,
                    entrypoints,
                },
                arguments,
                bodies,
            },
            initializer: None,
            transferable_constructors: self.transferable,
            results: vec![
                vec![],
                self.reserve_results,
                self.reserve_all_results,
                self.settle_results,
            ],
        };
        abi.validate()
            .expect("custom abi must be structurally valid");
        let encoded = encode_executable_abi(&abi).unwrap();
        let wasm = wat::parse_str(custom_wat()).unwrap();
        let candidate = publish(
            seed,
            wasm,
            encoded,
            CUSTOM_ENTRYPOINTS.iter().map(|n| (*n).into()).collect(),
        );
        verify_publication_interface(candidate, vec![]).unwrap()
    }
}

/// The custom fixture's own opaque type argument, bound under its own
/// `OPAQUE_DOMAIN`. Deliberately not `public_standard_asset`'s
/// `asset_type_argument`: that helper is bound to Standard Asset's own
/// `ASSET_OPAQUE_DOMAIN`, a different domain than this synthetic fixture
/// declares for its generic type parameter.
fn custom_asset_argument() -> abi::package_types::ScopedTypeArg {
    abi::package_types::ScopedTypeArg::Opaque {
        domain: OPAQUE_DOMAIN,
        value: *asset_id().as_bytes(),
    }
}

fn custom_policy(origin: &PackageOrigin, code: UnverifiedDependencyRef) -> PaidFeePolicy {
    PaidFeePolicy {
        asset_type: ScopedTypeTag::new(origin.clone(), CTOR_COIN, vec![custom_asset_argument()])
            .unwrap(),
        reservation_type: ScopedTypeTag::new(
            origin.clone(),
            CTOR_RESERVATION,
            vec![custom_asset_argument()],
        )
        .unwrap(),
        schema: SCHEMA,
        type_arguments: vec![custom_asset_argument()],
        ..base_fee_policy(origin, code)
    }
}

#[test]
fn the_baseline_custom_shape_satisfies_the_validator() {
    let origin = origin(2);
    let candidate_origin = origin.clone();
    let package = CustomPackage::baseline(&origin);
    // Build a throwaway candidate first only to get its dependency ref
    // cheaply reused for the policy's pinned `code` field.
    let interface = package.publish_and_verify(&candidate_origin, 2);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert!(validate_fee_interface_admission(&interface, &policy).is_ok());
}

/// Asserts rejection with the *exact* expected [`PaidExecutionError::Invalid`]
/// message, not merely `is_err()`: every fail-closed case below must be
/// caused by the specific role/shape check under test, not an unrelated
/// mismatch elsewhere in the validator.
#[track_caller]
fn assert_rejected(
    interface: &VerifiedPublicationInterface,
    policy: &PaidFeePolicy,
    expected: &str,
) {
    match validate_fee_interface_admission(interface, policy) {
        Err(PaidExecutionError::Invalid(message)) => assert_eq!(
            message, expected,
            "wrong rejection reason: got {message:?}, expected {expected:?}"
        ),
        other => panic!("expected Err(PaidExecutionError::Invalid({expected:?})), got {other:?}"),
    }
}

#[test]
fn reserve_object_mode_or_type_mismatch_is_rejected() {
    let origin = origin(3);
    let mut package = CustomPackage::baseline(&origin);
    package.reserve = vec![object(ObjectMode::Consume, &origin, CTOR_COIN)];
    let interface = package.publish_and_verify(&origin, 3);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(&interface, &policy, "reserve-shaped export object role");
}

#[test]
fn reserve_object_arity_zero_or_two_is_rejected() {
    {
        let origin = origin(15);
        let mut package = CustomPackage::baseline(&origin);
        package.reserve = vec![];
        let interface = package.publish_and_verify(&origin, 15);
        let code = dependency_ref(interface.candidate());
        let policy = custom_policy(&origin, code);
        assert_rejected(&interface, &policy, "reserve-shaped export object arity");
    }
    {
        let origin = origin(16);
        let mut package = CustomPackage::baseline(&origin);
        package.reserve = vec![
            object(ObjectMode::Write, &origin, CTOR_COIN),
            object(ObjectMode::Write, &origin, CTOR_COIN),
        ];
        let interface = package.publish_and_verify(&origin, 16);
        let code = dependency_ref(interface.candidate());
        let policy = custom_policy(&origin, code);
        assert_rejected(&interface, &policy, "reserve-shaped export object arity");
    }
}

#[test]
fn reserve_object_schema_mismatch_is_rejected() {
    let origin = origin(17);
    let mut package = CustomPackage::baseline(&origin);
    // The object parameter's schema must equal its own constructor's
    // declared schema (a structural ABI invariant, checked before this
    // validator ever runs). Every declared use of `CTOR_COIN` therefore
    // moves together here, diverging only from `custom_policy()`'s fixed
    // `SCHEMA`, so this isolates the policy-vs-ABI schema check under test.
    package.coin_constructor_schema = SCHEMA + 1;
    package.reserve = vec![ObjectParameter {
        mode: ObjectMode::Write,
        schema: SCHEMA + 1,
        ty: pattern(&origin, CTOR_COIN),
    }];
    package.reserve_all = vec![ObjectParameter {
        mode: ObjectMode::Consume,
        schema: SCHEMA + 1,
        ty: pattern(&origin, CTOR_COIN),
    }];
    package.settle_results = vec![
        ObjectResultDeclaration {
            mode: ObjectMode::Read,
            schema: SCHEMA + 1,
            ty: pattern(&origin, CTOR_COIN),
            optional: false,
        },
        ObjectResultDeclaration {
            mode: ObjectMode::Read,
            schema: SCHEMA + 1,
            ty: pattern(&origin, CTOR_COIN),
            optional: true,
        },
    ];
    let interface = package.publish_and_verify(&origin, 17);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(&interface, &policy, "reserve-shaped export object role");
}

#[test]
fn reserve_object_typed_as_reservation_is_rejected() {
    let origin = origin(18);
    let mut package = CustomPackage::baseline(&origin);
    package.reserve = vec![object(ObjectMode::Write, &origin, CTOR_RESERVATION)];
    let interface = package.publish_and_verify(&origin, 18);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(&interface, &policy, "reserve-shaped export object role");
}

#[test]
fn reserve_missing_or_optional_result_is_rejected() {
    {
        let origin = origin(4);
        let mut package = CustomPackage::baseline(&origin);
        package.reserve_results = vec![];
        let interface = package.publish_and_verify(&origin, 4);
        let code = dependency_ref(interface.candidate());
        let policy = custom_policy(&origin, code);
        assert_rejected(&interface, &policy, "reserve-shaped export result arity");
    }
    {
        let origin = origin(5);
        let mut package = CustomPackage::baseline(&origin);
        package.reserve_results =
            vec![result(ObjectMode::Consume, &origin, CTOR_RESERVATION, true)];
        let interface = package.publish_and_verify(&origin, 5);
        let code = dependency_ref(interface.candidate());
        let policy = custom_policy(&origin, code);
        assert_rejected(&interface, &policy, "reserve-shaped export result role");
    }
}

#[test]
fn reserve_all_object_mode_mismatch_is_rejected() {
    let origin = origin(6);
    let mut package = CustomPackage::baseline(&origin);
    package.reserve_all = vec![object(ObjectMode::Write, &origin, CTOR_COIN)];
    let interface = package.publish_and_verify(&origin, 6);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(&interface, &policy, "reserve-shaped export object role");
}

#[test]
fn reserve_all_object_arity_zero_or_two_is_rejected() {
    {
        let origin = origin(19);
        let mut package = CustomPackage::baseline(&origin);
        package.reserve_all = vec![];
        let interface = package.publish_and_verify(&origin, 19);
        let code = dependency_ref(interface.candidate());
        let policy = custom_policy(&origin, code);
        assert_rejected(&interface, &policy, "reserve-shaped export object arity");
    }
    {
        let origin = origin(20);
        let mut package = CustomPackage::baseline(&origin);
        package.reserve_all = vec![
            object(ObjectMode::Consume, &origin, CTOR_COIN),
            object(ObjectMode::Consume, &origin, CTOR_COIN),
        ];
        let interface = package.publish_and_verify(&origin, 20);
        let code = dependency_ref(interface.candidate());
        let policy = custom_policy(&origin, code);
        assert_rejected(&interface, &policy, "reserve-shaped export object arity");
    }
}

#[test]
fn settle_object_mode_mismatch_is_rejected() {
    let origin = origin(7);
    let mut package = CustomPackage::baseline(&origin);
    package.settle = vec![object(ObjectMode::Write, &origin, CTOR_RESERVATION)];
    let interface = package.publish_and_verify(&origin, 7);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(&interface, &policy, "settle export object role");
}

#[test]
fn settle_object_arity_zero_or_two_is_rejected() {
    {
        let origin = origin(21);
        let mut package = CustomPackage::baseline(&origin);
        package.settle = vec![];
        let interface = package.publish_and_verify(&origin, 21);
        let code = dependency_ref(interface.candidate());
        let policy = custom_policy(&origin, code);
        assert_rejected(&interface, &policy, "settle export object arity");
    }
    {
        let origin = origin(22);
        let mut package = CustomPackage::baseline(&origin);
        package.settle = vec![
            object(ObjectMode::Consume, &origin, CTOR_RESERVATION),
            object(ObjectMode::Consume, &origin, CTOR_RESERVATION),
        ];
        let interface = package.publish_and_verify(&origin, 22);
        let code = dependency_ref(interface.candidate());
        let policy = custom_policy(&origin, code);
        assert_rejected(&interface, &policy, "settle export object arity");
    }
}

#[test]
fn reservation_schema_mismatch_shared_across_reserve_and_settle_is_rejected() {
    let origin = origin(23);
    let mut package = CustomPackage::baseline(&origin);
    // `policy.schema` is one commitment shared by every role (DR-0124), so
    // moving the reservation constructor's declared schema away from it
    // necessarily also desyncs `reserve`/`reserve_all`'s *results* (the only
    // other declared uses of `CTOR_RESERVATION`), which this validator
    // checks first. This still proves a genuine schema mismatch is caught
    // fail-closed, exactly at the first role the validator inspects that
    // references the perturbed constructor.
    package.reservation_constructor_schema = SCHEMA + 1;
    package.reserve_results = vec![ObjectResultDeclaration {
        mode: ObjectMode::Consume,
        schema: SCHEMA + 1,
        ty: pattern(&origin, CTOR_RESERVATION),
        optional: false,
    }];
    package.reserve_all_results = vec![ObjectResultDeclaration {
        mode: ObjectMode::Consume,
        schema: SCHEMA + 1,
        ty: pattern(&origin, CTOR_RESERVATION),
        optional: false,
    }];
    package.settle = vec![ObjectParameter {
        mode: ObjectMode::Consume,
        schema: SCHEMA + 1,
        ty: pattern(&origin, CTOR_RESERVATION),
    }];
    let interface = package.publish_and_verify(&origin, 23);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(&interface, &policy, "reserve-shaped export result role");
}

#[test]
fn settle_wrong_result_slot_count_is_rejected() {
    let origin = origin(8);
    let mut package = CustomPackage::baseline(&origin);
    package.settle_results = vec![result(ObjectMode::Read, &origin, CTOR_COIN, false)];
    let interface = package.publish_and_verify(&origin, 8);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(&interface, &policy, "settle export result arity");
}

#[test]
fn settle_fee_slot_optional_is_rejected() {
    let origin = origin(9);
    let mut package = CustomPackage::baseline(&origin);
    package.settle_results = vec![
        result(ObjectMode::Read, &origin, CTOR_COIN, true),
        result(ObjectMode::Read, &origin, CTOR_COIN, true),
    ];
    let interface = package.publish_and_verify(&origin, 9);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(&interface, &policy, "settle export fee result role");
}

#[test]
fn settle_refund_slot_required_is_rejected() {
    let origin = origin(10);
    let mut package = CustomPackage::baseline(&origin);
    package.settle_results = vec![
        result(ObjectMode::Read, &origin, CTOR_COIN, false),
        result(ObjectMode::Read, &origin, CTOR_COIN, false),
    ];
    let interface = package.publish_and_verify(&origin, 10);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(&interface, &policy, "settle export refund result role");
}

#[test]
fn wrong_argument_layout_on_reserve_or_settle_is_rejected() {
    {
        let origin = origin(11);
        let mut package = CustomPackage::baseline(&origin);
        package.reserve_argument_layout = ValueLayout::Tuple(vec![ValueLayout::U64]);
        let interface = package.publish_and_verify(&origin, 11);
        let code = dependency_ref(interface.candidate());
        let policy = custom_policy(&origin, code);
        assert_rejected(&interface, &policy, "reserve-shaped export argument layout");
    }
    {
        let origin = origin(12);
        let mut package = CustomPackage::baseline(&origin);
        package.settle_argument_layout = ValueLayout::Tuple(vec![ValueLayout::U64]);
        let interface = package.publish_and_verify(&origin, 12);
        let code = dependency_ref(interface.candidate());
        let policy = custom_policy(&origin, code);
        assert_rejected(&interface, &policy, "settle export argument layout");
    }
}

#[test]
fn a_transferable_reservation_constructor_is_rejected() {
    let origin = origin(13);
    let mut package = CustomPackage::baseline(&origin);
    package.transferable = vec![CTOR_COIN, CTOR_RESERVATION];
    let interface = package.publish_and_verify(&origin, 13);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(&interface, &policy, "reservation type is transferable");
}

#[test]
fn another_export_accepting_the_reservation_type_is_rejected() {
    let origin = origin(14);
    let mut package = CustomPackage::baseline(&origin);
    package.mint = vec![object(ObjectMode::Write, &origin, CTOR_RESERVATION)];
    let interface = package.publish_and_verify(&origin, 14);
    let code = dependency_ref(interface.candidate());
    let policy = custom_policy(&origin, code);
    assert_rejected(
        &interface,
        &policy,
        "reservation type accepted by a non-settle export",
    );
}
