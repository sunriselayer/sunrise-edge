//! Real-WASM integration test for `PaidContractEngine` (DR-0124
//! "Authenticated durable integration", 2026-09-08). Runs the actual public
//! Standard Asset WASM through the production store/host/frame validator;
//! no native balance backdoor and no fake authenticated witness.
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::*;
use execution::paid_execution::*;
use execution::publication::*;
use execution::{ExecutionStatus, LocalWasmExecutionEngine, ObjectEffect};

/// The only in-crate [`PaidContractEngine`] implementation. Using the trait
/// here is what proves the boundary is injectable rather than a concrete
/// unit struct, and that `execute_paid` does not collide with the zero-fee
/// `LocalContractEngine::execute` on the same type.
fn paid_engine() -> impl PaidContractEngine {
    LocalWasmExecutionEngine::new()
}
use fees::{Amount, GasSchedule};
use hashing::HashSuiteResolver;
use objects::{AccessMode, Object, ObjectId};
use protocol_types::{ChainId, Epoch, HashPurpose, HashSuite, HashSuiteSchedule, ProtocolVersion};
use public_standard_asset::{StandardAssetPackage, build_package};
/// Locates one decoded field's payload byte range inside its original
/// encoded frame, for targeted corruption in the codec regressions below.
fn field_range(bytes: &[u8], field_id: u16) -> std::ops::Range<usize> {
    let frame = canonical_encoding::decode_canonical_frame(bytes).unwrap();
    let slice = frame.required_field(field_id).unwrap();
    let start = slice.as_ptr() as usize - bytes.as_ptr() as usize;
    start..start + slice.len()
}

#[test]
fn paid_contract_engine_rejects_a_forged_fee_source_digest() {
    // Item 1: the fee source comparison must use the complete canonical
    // `ObjectRef`, including its content digest, not merely id/version.
    let asset: Asset = asset(32, 32, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);
    let policy_digest = paid_fee_policy_digest(&resolver(), &policy).unwrap();

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    // Same id and version as the actually supplied object, but a forged
    // digest: this must never be accepted as a match.
    let forged_source_ref = objects::ObjectRef {
        id: coin_source.resolved.object.id,
        version: coin_source.resolved.object.version,
        digest: resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"forged-object-body")
            .unwrap(),
    };

    let application = CallIntent {
        context: context(),
        request_id: [9; 32],
        sender: sender(),
        nonce: 3,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest { entries: vec![] },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let intent = PaidIntent {
        context: context(),
        request_id: [9; 32],
        sender: sender(),
        nonce: 3,
        fee_policy_digest: policy_digest,
        consent: FeeSourceConsent {
            source: forged_source_ref,
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
        source: coin_source,
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: &[],
        },
    };
    assert!(paid_engine().execute_paid(request).is_err());
}

#[test]
fn paid_contract_engine_runs_a_real_mint_call_that_traps_and_still_settles_the_fee() {
    // Call/apptrap: `mint` writes the TreasuryCap supply and only then
    // fails at the host create boundary because the all-zero recipient is
    // not a decodable owner address, exactly as the coordinator-level
    // fault test exercises, but here through the complete authenticated
    // paid `PaidContractEngine` entry point.
    let asset: Asset = asset(33, 33, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);
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
    let mut cap_input = asset.scope.clone();
    let _ = &mut cap_input;
    let cap = {
        // Re-derive the cap's `ScopedResolvedObject` the same way `asset()`
        // built it: mint against the TreasuryCap created by `init`.
        let init_scopes = vec![asset.scope.clone()];
        let init = call(
            &init_scopes,
            "init",
            public_standard_asset::no_arguments().unwrap(),
            &[],
            vec![],
        );
        created(&init, 1, AccessMode::Write)
    };

    let application = CallIntent {
        context: context(),
        request_id: [10; 32],
        sender: sender(),
        nonce: 4,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "mint".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: objects::ObjectRef {
                    id: cap.resolved.object.id,
                    version: cap.resolved.object.version,
                    digest: resolver()
                        .hash_for_purpose(
                            Epoch::new(0),
                            HashPurpose::Object,
                            &objects::encode_object(&cap.resolved.object).unwrap(),
                        )
                        .unwrap(),
                },
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::mint_arguments(5, &[0u8; 32]).unwrap(),
        gas_limit: 100_000,
    };
    let intent = PaidIntent {
        context: context(),
        request_id: [10; 32],
        sender: sender(),
        nonce: 4,
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
        source: coin_source,
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: std::slice::from_ref(&cap),
        },
    };
    let outcome = paid_engine().execute_paid(request).unwrap();
    assert_eq!(
        outcome.result.status,
        PaidExecutionStatus::ApplicationFailed
    );
    let charged = outcome.result.charged.as_ref().unwrap();
    assert!(charged.actual.get() > 0);
    assert_eq!(outcome.result.effects.events.len(), 0);
    // The charged failure receipt still verifies independently.
    verify_paid_execution_result(&outcome, &authenticated, &resolver(), &base_policy, &policy)
        .expect("independent verification");
}

#[test]
fn the_zero_charge_host_rejected_fallback_receipt_is_bounded_and_verifiable() {
    // The engine pre-validates this exact skeleton before any phase runs, so
    // a deterministic host failure discovered after the VM finished always
    // has a committable receipt inside the complete 16 MiB result bound.
    // Its only variable field is the measured gas, which is a fixed-width
    // `u64`, so its encoded length does not depend on the measurement.
    let asset: Asset = asset(52, 52, 1_000);
    let attempt = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Write,
        [32; 32],
        32,
    );
    let real: PaidExecutionOutcome = attempt.outcome.expect("transfer");
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());

    let fallback = |gas_used: u64| PaidExecutionOutcome {
        result: PaidExecutionResult {
            request_id: real.result.request_id,
            kind: real.result.kind,
            target: real.result.target.clone(),
            status: PaidExecutionStatus::HostRejected,
            effects: execution::ExecutionEffects {
                tx_hash: real.result.effects.tx_hash,
                status: ExecutionStatus::Failure {
                    reason: "local contract trapped".into(),
                },
                object_effects: vec![],
                events: vec![],
                gas_used,
            },
            charged: None,
        },
        created_authorities: vec![],
    };

    let measured: u64 = real.result.effects.gas_used;
    let empty: Vec<u8> = encode_paid_execution_result(&fallback(0).result).unwrap();
    let filled: Vec<u8> = encode_paid_execution_result(&fallback(measured).result).unwrap();
    assert_eq!(empty.len(), filled.len());
    assert!(filled.len() < MAX_PAID_EXECUTION_RESULT_BYTES);
    verify_paid_execution_result(
        &fallback(measured),
        &attempt.authenticated,
        &resolver(),
        &base_policy,
        &attempt.policy,
    )
    .expect("the zero-charge fallback verifies independently");
}

#[test]
fn paid_execution_result_codec_regressions() {
    // Codec validity alone is never sufficient: see
    // `independent_result_verification_rejects_adversarial_receipts` for the
    // checks a party that did not run the invocation must still perform.
    // Exercises `decode_paid_execution_result` fail-closed behavior against
    // Exercises `decode_paid_execution_result` fail-closed behavior against
    // a genuine charged wire result, not a hand-built approximation.
    let asset: Asset = asset(34, 34, 1_000);
    let outcome: PaidExecutionOutcome = run_transfer_call(&asset, [12; 32], 5);
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    let original: Vec<u8> = encode_paid_execution_result(&outcome.result).unwrap();
    assert!(decode_paid_execution_result(&original).is_ok());

    // Unknown trailing field.
    let mut unknown_field: Vec<u8> = original.clone();
    let count: u16 = u16::from_le_bytes([original[8], original[9]]);
    unknown_field[8..10].copy_from_slice(&count.checked_add(1).unwrap().to_le_bytes());
    unknown_field.extend_from_slice(&u16::MAX.to_le_bytes());
    unknown_field.extend_from_slice(&0u32.to_le_bytes());
    assert!(decode_paid_execution_result(&unknown_field).is_err());

    // Missing field 12 (application_gas_units): it is the last canonical
    // field for a charged result, so removing it is exactly its trailing
    // 6-byte header plus 8-byte `u64` payload, with the field count
    // decremented to match.
    let mut missing_twelve: Vec<u8> = original.clone();
    let new_count: u16 = count.checked_sub(1).unwrap();
    missing_twelve[8..10].copy_from_slice(&new_count.to_le_bytes());
    missing_twelve.truncate(missing_twelve.len() - (6 + 8));
    assert!(decode_paid_execution_result(&missing_twelve).is_err());

    // Zero/unknown status code in field 4.
    let mut zero_status: Vec<u8> = original.clone();
    let range = field_range(&original, 4);
    zero_status[range].copy_from_slice(&0u16.to_le_bytes());
    assert!(decode_paid_execution_result(&zero_status).is_err());

    // Non-canonical (unnormalized) failure reason string: forge a
    // `SettlementFailed` zero-charge result and corrupt its trap reason.
    let zero_charge = PaidExecutionResult {
        request_id: [1; 32],
        kind: outcome.result.kind,
        target: outcome.result.target.clone(),
        status: PaidExecutionStatus::SettlementFailed,
        effects: execution::ExecutionEffects {
            tx_hash: outcome.result.effects.tx_hash,
            status: execution::ExecutionStatus::Failure {
                reason: "local contract trapped".into(),
            },
            object_effects: vec![],
            events: vec![],
            gas_used: 1,
        },
        charged: None,
    };
    let zero_charge_bytes = encode_paid_execution_result(&zero_charge).unwrap();
    let mut bad_reason = zero_charge.clone();
    bad_reason.effects.status = execution::ExecutionStatus::Failure {
        reason: "a different message".into(),
    };
    assert!(encode_paid_execution_result(&bad_reason).is_err());
    assert!(decode_paid_execution_result(&zero_charge_bytes).is_ok());
}
fn key() -> SigningKey {
    SigningKey::from([7; 32])
}

/// Lowercase hexadecimal, for the stable wire vector below.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The stable encoded bytes of frame `0x6415/v1` for the fixed receipt built
/// in `paid_execution_result_stable_vector`.
const PAID_EXECUTION_RESULT_VECTOR_0X6415_V1: &str = "534e5245156401000c00010020000000040404040404040404040404040404040404040404040404040404040404040402000200000002000300de010000534e5245046401000600010042000000534e524501630100030001001a000000706169642d657865637574696f6e2d656e67696e652d74657374020004000000030000000300080000000000000000000000020020000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0300200000000303030303030303030303030303030303030303030303030303030303030303040022010000534e524502630100040001007e000000534e524501520100040001001a000000706169642d657865637574696f6e2d656e67696e652d746573740200020000000100030020000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c04002000000001010101010101010101010101010101010101010101010101010101010101010200080000000100000000000000030042000000534e524501630100030001001a000000706169642d657865637574696f6e2d656e67696e652d74657374020004000000030000000300080000000000000000000000040038000000534e52450301010002000100020000000100020020000000dd06cd618c7574f07fa1598daf5a7db4ee41fed5d0473a45720101dc6a0c2c460500080000000100000000000000060004000000696e69740400020000000100050008000000f4010000000000000600080000004001000000000000070008000000b40000000000000008008c000000534e5245044001000300010030000000534e524501400100010001002000000005050505050505050505050505050505050505050505050505050505050505050200080000000100000000000000030038000000534e524503010100020001000200000001000200200000003a509583e0670e464197248f35bea979569653753577c0221f9a4da4ac0b679709008c000000534e5245044001000300010030000000534e524501400100010001002000000006060606060606060606060606060606060606060606060606060606060606060200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000a4de00feed47951df5fece70dbbe22808ed19ab38b2797f4c30e913cf5a001740a0030000000534e524501400100010001002000000007070707070707070707070707070707070707070707070707070707070707070b0091000000534e5245046001000500010038000000534e52450301010002000100020000000100020020000000f23cd8edb53d865af9fded23828d91ae5256a9347bf7756326360e6c132f5530020001000000010400080000009210000000000000050014000000534e524505600100010001000400000000000000060014000000534e5245066001000100010004000000000000000c0008000000e803000000000000";

/// Stable encoding vector for the new `PaidExecutionResult` frame
/// `0x6415/v1`.
///
/// Every input is fixed: the chain context, the signing key behind `sender`,
/// the package origin seed, and digests derived from constant labels under
/// the genesis hash suite. Changing these bytes changes a wire type and is a
/// protocol-critical change, not a test fixup.
#[test]
fn paid_execution_result_stable_vector() {
    let digest = |label: &[u8]| {
        resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, label)
            .unwrap()
    };
    let code =
        UnverifiedDependencyRef::new(origin(1), 1, context(), digest(b"vector-code")).unwrap();
    let record = InstanceRecord {
        context: context(),
        creator: sender(),
        seed: [3; 32],
        code,
        revision: 1,
        initializer: "init".into(),
    };
    let reference = |tag: u8, version: u64| objects::ObjectRef {
        id: ObjectId::new([tag; 32]),
        version,
        digest: digest(&[tag]),
    };
    let result = PaidExecutionResult {
        request_id: [4; 32],
        kind: PaidResultKind::Call,
        target: PaidResultTarget::Instance(record),
        status: PaidExecutionStatus::Success,
        effects: execution::ExecutionEffects {
            tx_hash: digest(b"vector-event"),
            status: ExecutionStatus::Success,
            object_effects: vec![],
            events: vec![],
            gas_used: 4242,
        },
        charged: Some(PaidChargedOutcome {
            reserved: Amount::new(500),
            actual: Amount::new(320),
            refund: Amount::new(180),
            fee_output: reference(5, 1),
            refund_output: Some(reference(6, 1)),
            reservation: ObjectId::new([7; 32]),
            application_gas_units: 1_000,
        }),
    };
    let bytes: Vec<u8> = encode_paid_execution_result(&result).unwrap();
    assert_eq!(hex(&bytes), PAID_EXECUTION_RESULT_VECTOR_0X6415_V1);
    assert_eq!(decode_paid_execution_result(&bytes).unwrap(), result);
}

/// Requires one independent verification failure to carry its exact
/// canonical message, not merely to be an error.
fn assert_message(result: Result<(), PaidExecutionError>, expected: &str) {
    let error: PaidExecutionError = result.expect_err(expected);
    assert_eq!(
        format!("{error}"),
        format!("invalid paid execution wire: {expected}")
    );
}

#[test]
fn independent_result_verification_rejects_adversarial_receipts() {
    // A canonical, self-consistent receipt can still name the wrong request,
    // the wrong invocation, a charge that does not follow from the quote, an
    // output owned by the wrong recipient or a surviving reservation.
    let asset: Asset = asset(50, 50, 1_000);
    let attempt = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Write,
        [30; 32],
        30,
    );
    let outcome: PaidExecutionOutcome = attempt.outcome.expect("transfer");
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let check = |candidate: &PaidExecutionOutcome| {
        verify_paid_execution_result(
            candidate,
            &attempt.authenticated,
            &resolver(),
            &base_policy,
            &attempt.policy,
        )
    };
    check(&outcome).expect("the genuine receipt verifies");
    let charged = outcome.result.charged.clone().expect("charged");
    assert!(charged.refund.get() > 1, "the case below moves one unit");
    let refund_ref = charged.refund_output.clone().expect("refund output");

    // Wrong request identity.
    let mut tampered: PaidExecutionOutcome = outcome.clone();
    tampered.result.request_id = [0xAA; 32];
    assert_message(check(&tampered), "paid result request id");

    // Wrong invocation/event digest.
    let mut tampered = outcome.clone();
    tampered.result.effects.tx_hash = resolver()
        .hash_for_purpose(Epoch::new(0), HashPurpose::NodeEvent, b"forged-event")
        .unwrap();
    assert_message(check(&tampered), "paid result event digest");

    // A charge that still satisfies `actual + refund == reserved` but does
    // not follow from the immutable quote at the reported `A`.
    let mut tampered = outcome.clone();
    {
        let charge = tampered.result.charged.as_mut().unwrap();
        charge.actual = Amount::new(charge.actual.get() + 1);
        charge.refund = Amount::new(charge.refund.get() - 1);
    }
    assert_message(
        check(&tampered),
        "paid result actual does not match the quote",
    );

    // Metered application gas above the signed limit `L`.
    let mut tampered = outcome.clone();
    tampered.result.effects.gas_used = 100_001;
    tampered
        .result
        .charged
        .as_mut()
        .unwrap()
        .application_gas_units = 100_001;
    assert_message(
        check(&tampered),
        "paid result application gas exceeds signed limit",
    );

    // Total measured gas above `L + R + S`.
    let mut tampered = outcome.clone();
    tampered.result.effects.gas_used = 100_000 + 200_000 + 200_000 + 1;
    assert_message(check(&tampered), "paid result gas exceeds total caps");

    // A fee output that is not a surviving created object at all.
    let mut tampered = outcome.clone();
    tampered.result.charged.as_mut().unwrap().fee_output.id = ObjectId::new([0xEE; 32]);
    assert_message(check(&tampered), "paid result fee output not created");

    // Fee and refund outputs swapped: both exist and are distinct, but the
    // fee coin is then owned by the refund recipient, not the pinned fee
    // recipient.
    let mut tampered = outcome.clone();
    {
        let charge = tampered.result.charged.as_mut().unwrap();
        let fee = charge.fee_output.clone();
        charge.fee_output = refund_ref.clone();
        charge.refund_output = Some(fee);
    }
    assert_message(check(&tampered), "paid result fee output authority");

    // A reservation that survived the commit as a created object.
    let mut tampered = outcome.clone();
    tampered.result.charged.as_mut().unwrap().reservation = charged.fee_output.id;
    assert_message(check(&tampered), "paid result reservation survives");

    // Creation authority that does not describe the created effects.
    let mut tampered = outcome.clone();
    tampered.created_authorities.pop();
    assert_message(check(&tampered), "paid result creation authority mismatch");

    // A receipt for a different signed intent: same shape, different sender
    // signature and therefore a different invocation digest and request.
    let other = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Write,
        [31; 32],
        31,
    );
    let error = verify_paid_execution_result(
        &outcome,
        &other.authenticated,
        &resolver(),
        &base_policy,
        &other.policy,
    )
    .expect_err("a receipt for another intent must not verify");
    assert_eq!(
        format!("{error}"),
        "invalid paid execution wire: paid result request id"
    );
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
    verify_paid_execution_result(&outcome, &authenticated, &resolver(), &base_policy, &policy)
        .expect("independent verification");
    outcome
}

#[test]
fn paid_contract_engine_runs_a_real_transfer_call_and_settles_the_fee() {
    let asset: Asset = asset(30, 30, 1_000);
    let outcome: PaidExecutionOutcome = run_transfer_call(&asset, [7; 32], 1);
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    let charged = outcome.result.charged.as_ref().unwrap();
    assert!(charged.actual.get() > 0);
    assert_eq!(
        charged.actual.get() + charged.refund.get(),
        charged.reserved.get()
    );
    assert!(!outcome.created_authorities.is_empty());
    let _ = mutated(
        &LocalExecutionOutcome {
            effects: outcome.result.effects.clone(),
            created_authorities: outcome.created_authorities.clone(),
        },
        &{
            let mut coin_source = asset.coin.clone();
            coin_source.resolved.mode = AccessMode::Write;
            coin_source
        },
    );
}

#[test]
fn paid_contract_engine_runs_a_real_instantiate_and_settles_the_fee() {
    // Instantiate: the application creates a brand new instance of the same
    // published code while the fee source lives in an older instance. Two
    // distinct scopes are therefore required, and the application scope must
    // be the root scope.
    let asset: Asset = asset(40, 40, 1_000);
    let fresh: ResolvedExecutionScope = asset_scope(40, 41);
    let scopes: Vec<ResolvedExecutionScope> = vec![fresh.clone(), asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let source_ref = object_ref_of(&coin_source.resolved.object);

    let application = CallIntent {
        context: context(),
        request_id: [20; 32],
        sender: sender(),
        nonce: 20,
        code: fresh.instance.code.clone(),
        instance: fresh.target.clone(),
        entrypoint: "init".into(),
        type_arguments: vec![],
        access: abi::AccessManifest { entries: vec![] },
        arguments: public_standard_asset::no_arguments().unwrap(),
        gas_limit: 400_000,
    };
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id: [20; 32],
        sender: sender(),
        nonce: 20,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Instantiate(application),
        gas_limit: 400_000,
        authorizations: vec![],
    });

    let outcome = paid_engine()
        .execute_paid(PaidExecutionRequest {
            authenticated: &authenticated,
            resolver: &resolver(),
            base_policy: &base_policy,
            fee_policy: &policy,
            scopes: &scopes,
            source: coin_source,
            application: PaidApplicationScopes::Instantiate { scope: 0 },
        })
        .expect("paid instantiate");
    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    assert_eq!(outcome.result.kind, PaidResultKind::Instantiate);
    assert!(matches!(
        outcome.result.target,
        PaidResultTarget::Instance(_)
    ));
    let charged = outcome.result.charged.as_ref().unwrap();
    assert!(charged.actual.get() > 0);
    // `init` creates the Definition and the TreasuryCap; settlement adds the
    // fee coin and, here, the refund coin.
    assert!(outcome.created_authorities.len() >= 4);
    verify_paid_execution_result(&outcome, &authenticated, &resolver(), &base_policy, &policy)
        .expect("independent verification");
}

/// The exact deterministic Publish application units DR-0124 pins:
/// `artifact_encoded_bytes * byte_price + closure_nodes * node_price`, with
/// the candidate counting as one node and no dependencies here.
fn publish_units(artifact: &CodeArtifact, policy: &PaidFeePolicy) -> u64 {
    encode_code_artifact(artifact).unwrap().len() as u64 * policy.publish_artifact_byte_price
        + policy.publish_closure_node_price
}

/// Builds and runs one real authenticated paid Publish under the supplied
/// signed application limit `L`.
fn run_publish(
    asset: &Asset,
    artifact_seed: u8,
    request_id: [u8; 32],
    nonce: u64,
    gas_limit: u64,
) -> (
    PaidExecutionOutcome,
    AuthenticatedPaidIntent,
    PaidFeePolicy,
    u64,
) {
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(asset);
    let artifact: CodeArtifact = publish_asset(artifact_seed).artifact().clone();
    let units: u64 = publish_units(&artifact, &policy);

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id,
        sender: sender(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: object_ref_of(&coin_source.resolved.object),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Publish(artifact),
        gas_limit,
        authorizations: vec![],
    });
    let outcome = paid_engine()
        .execute_paid(PaidExecutionRequest {
            authenticated: &authenticated,
            resolver: &resolver(),
            base_policy: &base_policy,
            fee_policy: &policy,
            scopes: &scopes,
            source: coin_source,
            application: PaidApplicationScopes::Publish {
                dependencies: vec![],
            },
        })
        .expect("paid publish");
    verify_paid_execution_result(&outcome, &authenticated, &resolver(), &base_policy, &policy)
        .expect("independent verification");
    (outcome, authenticated, policy, units)
}

#[test]
fn paid_contract_engine_charges_a_real_publish_deterministically() {
    let asset: Asset = asset(42, 42, 1_000);
    // Sized above the artifact's own deterministic units so the publication
    // is admitted rather than exhausted.
    let artifact: CodeArtifact = publish_asset(43).artifact().clone();
    let units: u64 = publish_units(&artifact, &fee_policy(&asset));
    let gas_limit: u64 = units + 10_000;
    let (outcome, _, _, measured) = run_publish(&asset, 43, [21; 32], 21, gas_limit);

    assert_eq!(outcome.result.status, PaidExecutionStatus::Success);
    assert_eq!(outcome.result.kind, PaidResultKind::Publish);
    assert!(matches!(
        outcome.result.target,
        PaidResultTarget::Package(_)
    ));
    let charged = outcome.result.charged.as_ref().unwrap();
    // Publish never enters an application WASM frame: `A` is exactly its
    // deterministic metered unit count.
    assert_eq!(charged.application_gas_units, measured);
    assert!(charged.actual.get() > 0);
    assert_eq!(
        charged.actual.get() + charged.refund.get(),
        charged.reserved.get()
    );
}

#[test]
fn paid_publish_exhaustion_charges_the_whole_application_limit() {
    let asset: Asset = asset(44, 44, 1_000);
    let artifact: CodeArtifact = publish_asset(45).artifact().clone();
    let units: u64 = publish_units(&artifact, &fee_policy(&asset));
    // Deliberately below the artifact's deterministic units.
    let gas_limit: u64 = 1_000;
    assert!(units > gas_limit, "the artifact must exceed the limit");
    let (outcome, _, _, _) = run_publish(&asset, 45, [22; 32], 22, gas_limit);

    assert_eq!(
        outcome.result.status,
        PaidExecutionStatus::ApplicationFailed
    );
    let charged = outcome.result.charged.as_ref().unwrap();
    // Exhaustion charges exactly the admitted limit `L`, never more, and
    // settlement still commits the fee.
    assert_eq!(charged.application_gas_units, gas_limit);
    assert!(charged.actual.get() > 0);
    assert!(outcome.result.effects.object_effects.iter().all(|effect| {
        !matches!(effect, ObjectEffect::Created(object) if object.data.len() > 4096)
    }));
}

/// Builds and runs one real authenticated paid `transfer` Call while varying
/// exactly the pieces the adversarial cases below need: the supplied scope
/// set, the signed application access mode on the source, and the signed
/// application `ObjectRef`.
struct TransferAttempt {
    outcome: Result<PaidExecutionOutcome, PaidExecutionError>,
    authenticated: AuthenticatedPaidIntent,
    policy: PaidFeePolicy,
}

fn transfer_attempt(
    asset: &Asset,
    scopes: &[ResolvedExecutionScope],
    application_mode: AccessMode,
    request_id: [u8; 32],
    nonce: u64,
) -> TransferAttempt {
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(asset);
    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let source_ref = object_ref_of(&coin_source.resolved.object);
    let mut application_input = coin_source.clone();
    application_input.resolved.mode = application_mode;

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
                mode: application_mode,
            }],
        },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id,
        sender: sender(),
        nonce,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    });
    let outcome = paid_engine().execute_paid(PaidExecutionRequest {
        authenticated: &authenticated,
        resolver: &resolver(),
        base_policy: &base_policy,
        fee_policy: &policy,
        scopes,
        source: coin_source,
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: std::slice::from_ref(&application_input),
        },
    });
    TransferAttempt {
        outcome,
        authenticated,
        policy,
    }
}

#[test]
fn paid_contract_engine_validates_the_entire_supplied_scope_set() {
    // Comparing a recomputed target at one selector is not complete
    // validation: the whole supplied set must equal the required union of
    // the fee instance plus the application and authorization instances.
    let asset: Asset = asset(46, 46, 1_000);
    let unrelated: ResolvedExecutionScope = asset_scope(46, 47);

    // Baseline: exactly the required set succeeds.
    let ok = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Write,
        [23; 32],
        23,
    )
    .outcome
    .expect("baseline transfer");
    assert_eq!(ok.result.status, PaidExecutionStatus::Success);

    // An extra scope that no signed field requires is rejected, not ignored.
    let extra: Vec<ResolvedExecutionScope> = vec![asset.scope.clone(), unrelated];
    let error = transfer_attempt(&asset, &extra, AccessMode::Write, [24; 32], 24)
        .outcome
        .expect_err("an unneeded scope must be rejected");
    assert!(
        format!("{error}").contains("execution scope instance authority"),
        "{error}"
    );

    // A duplicate of the required scope is rejected.
    let duplicate: Vec<ResolvedExecutionScope> = vec![asset.scope.clone(), asset.scope.clone()];
    let error = transfer_attempt(&asset, &duplicate, AccessMode::Write, [25; 32], 25)
        .outcome
        .expect_err("a duplicate scope must be rejected");
    assert!(
        format!("{error}").contains("execution scope instance authority"),
        "{error}"
    );

    // A scope whose caller-supplied `target` disagrees with the independently
    // derived target of its own record is rejected, even though the selector
    // would still find it.
    let mut forged: ResolvedExecutionScope = asset.scope.clone();
    forged.target.revision += 1;
    let error = transfer_attempt(
        &asset,
        std::slice::from_ref(&forged),
        AccessMode::Write,
        [26; 32],
        26,
    )
    .outcome
    .expect_err("a forged scope target must be rejected");
    assert!(
        format!("{error}").contains("execution scope instance authority"),
        "{error}"
    );
}

#[test]
fn a_write_reservation_never_strengthens_a_signed_read_application_access() {
    // The consent reserves the source with Write, but the application signed
    // Read on that same object. The application keeps exactly its signed
    // Read: it can never satisfy `transfer`'s declared Coin Write parameter
    // by borrowing the reservation's stronger access.
    let asset: Asset = asset(48, 48, 1_000);
    let error = transfer_attempt(
        &asset,
        std::slice::from_ref(&asset.scope),
        AccessMode::Read,
        [27; 32],
        27,
    )
    .outcome
    .expect_err("a signed Read must not be strengthened to Write");
    assert!(
        format!("{error}").contains("access manifest mode"),
        "{error}"
    );
}

#[test]
fn paid_contract_engine_rejects_a_malformed_application_input_reference() {
    // The supplied resolved application input must match its signed
    // `AccessEntry` by the complete canonical `ObjectRef`, including the
    // content digest, not merely by id and version.
    let asset: Asset = asset(49, 49, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let cap = {
        let init = call(
            &scopes,
            "init",
            public_standard_asset::no_arguments().unwrap(),
            &[],
            vec![],
        );
        created(&init, 1, AccessMode::Write)
    };
    // Same id and version as the object actually supplied below, forged digest.
    let forged_entry = objects::ObjectRef {
        id: cap.resolved.object.id,
        version: cap.resolved.object.version,
        digest: resolver()
            .hash_for_purpose(Epoch::new(0), HashPurpose::Object, b"forged-cap-body")
            .unwrap(),
    };

    let application = CallIntent {
        context: context(),
        request_id: [28; 32],
        sender: sender(),
        nonce: 28,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "mint".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest {
            entries: vec![abi::AccessEntry {
                object_ref: forged_entry,
                mode: AccessMode::Write,
            }],
        },
        arguments: public_standard_asset::mint_arguments(5, &refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let authenticated = authenticate(PaidIntent {
        context: context(),
        request_id: [28; 32],
        sender: sender(),
        nonce: 28,
        fee_policy_digest: paid_fee_policy_digest(&resolver(), &policy).unwrap(),
        consent: FeeSourceConsent {
            source: object_ref_of(&coin_source.resolved.object),
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    });
    let error = paid_engine()
        .execute_paid(PaidExecutionRequest {
            authenticated: &authenticated,
            resolver: &resolver(),
            base_policy: &base_policy,
            fee_policy: &policy,
            scopes: &scopes,
            source: coin_source,
            application: PaidApplicationScopes::Call {
                scope: 0,
                inputs: std::slice::from_ref(&cap),
            },
        })
        .expect_err("a forged application input digest must be rejected");
    assert!(
        format!("{error}").contains("application input authority"),
        "{error}"
    );
}

#[test]
fn paid_contract_engine_rejects_a_fee_source_reference_mismatch() {
    let asset: Asset = asset(31, 31, 1_000);
    let scopes: Vec<ResolvedExecutionScope> = vec![asset.scope.clone()];
    let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(context());
    let policy: PaidFeePolicy = fee_policy(&asset);
    let policy_digest = paid_fee_policy_digest(&resolver(), &policy).unwrap();

    let mut wrong_source_ref = objects::ObjectRef {
        id: asset.coin.resolved.object.id,
        version: asset.coin.resolved.object.version,
        digest: resolver()
            .hash_for_purpose(
                Epoch::new(0),
                HashPurpose::Object,
                &objects::encode_object(&asset.coin.resolved.object).unwrap(),
            )
            .unwrap(),
    };
    // A version that does not match the actually supplied resolved source.
    wrong_source_ref.version += 1;

    let application = CallIntent {
        context: context(),
        request_id: [8; 32],
        sender: sender(),
        nonce: 2,
        code: asset.scope.instance.code.clone(),
        instance: asset.scope.target.clone(),
        entrypoint: "transfer".into(),
        type_arguments: vec![public_standard_asset::asset_type_argument(&asset.id)],
        access: abi::AccessManifest { entries: vec![] },
        arguments: public_standard_asset::transfer_arguments(&refund_account()).unwrap(),
        gas_limit: 100_000,
    };
    let mut intent = PaidIntent {
        context: context(),
        request_id: [8; 32],
        sender: sender(),
        nonce: 2,
        fee_policy_digest: policy_digest,
        consent: FeeSourceConsent {
            source: wrong_source_ref,
            access: ReservationAccessKind::Write,
            max_fee: Amount::new(1_000_000),
            refund_recipient: sender(),
        },
        application: PaidApplication::Call(application),
        gas_limit: 100_000,
        authorizations: vec![],
    };
    intent.fee_policy_digest = policy_digest;
    let frame = paid_intent_signing_frame(&context(), &intent).unwrap();
    let signature: [u8; 64] = key().sign(&frame).into();
    let signed = SignedPaidIntent { intent, signature };
    let bytes = encode_signed_paid_intent(&signed).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();

    let mut coin_source = asset.coin.clone();
    coin_source.resolved.mode = AccessMode::Write;
    let request = PaidExecutionRequest {
        authenticated: &authenticated,
        resolver: &resolver(),
        base_policy: &base_policy,
        fee_policy: &policy,
        scopes: &scopes,
        source: coin_source,
        application: PaidApplicationScopes::Call {
            scope: 0,
            inputs: &[],
        },
    };
    assert!(paid_engine().execute_paid(request).is_err());
}
