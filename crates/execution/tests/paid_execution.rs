//! DR-0124 execution-fee consent and policy wire boundary tests.
use abi::package_types::PackageOrigin;
use abi::{AccessEntry, AccessManifest};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::{CallIntent, InstanceTarget};
use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::*;
use execution::publication::{
    ArtifactParts, CodeArtifact, PublicationContext, UnverifiedDependencyRef,
};
use fees::reservation::ReservationError;
use fees::{Amount, GasSchedule};
use hashing::HashSuiteResolver;
use objects::{AccessMode, ObjectId, ObjectRef};
use protocol_types::{
    ChainId, Digest32, Epoch, HashAlgorithmId, HashSuite, HashSuiteSchedule, ProtocolVersion,
};

fn context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("paid-execution-test").unwrap(),
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
    SigningKey::from([7; 32])
}
fn sender() -> [u8; 32] {
    VerificationKey::from(&key()).into()
}
fn digest(byte: u8) -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [byte; 32])
}
fn code() -> UnverifiedDependencyRef {
    UnverifiedDependencyRef::new(
        PackageOrigin::unverified(context().chain_id().clone(), sender(), [10; 32]).unwrap(),
        1,
        context(),
        digest(0x66),
    )
    .unwrap()
}
fn instance(seed: u8) -> InstanceTarget {
    InstanceTarget {
        creator: sender(),
        seed: [seed; 32],
        revision: 1,
        record_digest: digest(seed),
    }
}
fn object_ref(id_byte: u8, version: u64) -> ObjectRef {
    ObjectRef {
        id: ObjectId::new([id_byte; 32]),
        version,
        digest: digest(id_byte),
    }
}
fn consent() -> FeeSourceConsent {
    FeeSourceConsent {
        source: object_ref(0x30, 1),
        access: ReservationAccessKind::Write,
        max_fee: Amount::new(1_000_000),
        refund_recipient: sender(),
    }
}
fn base_call_intent(access: AccessManifest) -> CallIntent {
    CallIntent {
        context: context(),
        request_id: [1; 32],
        sender: sender(),
        nonce: 4,
        code: code(),
        instance: instance(2),
        entrypoint: "run".into(),
        type_arguments: vec![],
        access,
        arguments: vec![],
        gas_limit: 100_000,
    }
}
fn call_application() -> CallIntent {
    base_call_intent(AccessManifest::default())
}
fn instantiate_application() -> CallIntent {
    CallIntent {
        instance: InstanceTarget {
            creator: sender(),
            ..instance(2)
        },
        ..base_call_intent(AccessManifest::default())
    }
}
fn code_artifact() -> CodeArtifact {
    CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: PackageOrigin::unverified(context().chain_id().clone(), sender(), [11; 32])
            .unwrap(),
        revision: 1,
        wasm_profile: 4,
        semantics: digest(0x77),
        wasm: vec![0u8; 8],
        unverified_abi: vec![1u8; 4],
        exports: vec!["run".into()],
        unverified_dependencies: vec![],
    })
    .unwrap()
}
fn base_intent(application: PaidApplication, gas_limit: u64) -> PaidIntent {
    PaidIntent {
        context: context(),
        request_id: [1; 32],
        sender: sender(),
        nonce: 4,
        fee_policy_digest: digest(0),
        consent: consent(),
        application,
        gas_limit,
        authorizations: vec![],
    }
}
fn call_intent() -> PaidIntent {
    base_intent(PaidApplication::Call(call_application()), 100_000)
}
fn instantiate_intent() -> PaidIntent {
    base_intent(
        PaidApplication::Instantiate(instantiate_application()),
        100_000,
    )
}
fn publish_intent() -> PaidIntent {
    let mut intent = base_intent(PaidApplication::Publish(code_artifact()), 100_000);
    intent.consent = FeeSourceConsent {
        access: ReservationAccessKind::Consume,
        ..consent()
    };
    intent
}
fn schedule() -> GasSchedule {
    GasSchedule {
        base_fee: 10,
        execution_price: 1,
        read_price: 0,
        write_price: 0,
        storage_price: 0,
        system_module_price: 0,
    }
}
fn base_policy() -> LocalExecutionPolicy {
    LocalExecutionPolicy::generic_object_results(context())
}
fn fee_policy() -> PaidFeePolicy {
    PaidFeePolicy {
        context: context(),
        base_policy_digest: base_policy().digest(&resolver()).unwrap(),
        instance: instance(9),
        code: UnverifiedDependencyRef::new(
            PackageOrigin::unverified(context().chain_id().clone(), sender(), [20; 32]).unwrap(),
            1,
            context(),
            digest(0x88),
        )
        .unwrap(),
        reserve_entrypoint: "reserve".into(),
        reserve_all_entrypoint: "reserve_all".into(),
        settle_entrypoint: "settle".into(),
        type_arguments: vec![],
        asset_type: abi::package_types::ScopedTypeTag::new(
            PackageOrigin::unverified(context().chain_id().clone(), sender(), [20; 32]).unwrap(),
            2,
            vec![],
        )
        .unwrap(),
        reservation_type: abi::package_types::ScopedTypeTag::new(
            PackageOrigin::unverified(context().chain_id().clone(), sender(), [20; 32]).unwrap(),
            4,
            vec![],
        )
        .unwrap(),
        schema: 1,
        fee_recipient: sender(),
        gas_schedule: schedule(),
        conversion_divisor: 1,
        reserve_allowance: 2,
        settle_allowance: 5,
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
fn signed(mut intent: PaidIntent) -> SignedPaidIntent {
    intent.fee_policy_digest = paid_fee_policy_digest(&resolver(), &fee_policy()).unwrap();
    let frame = paid_intent_signing_frame(&context(), &intent).unwrap();
    let signature: [u8; 64] = key().sign(&frame).into();
    SignedPaidIntent { intent, signature }
}

#[test]
fn consent_application_intent_policy_round_trip() {
    let c = consent();
    assert_eq!(
        decode_fee_source_consent(&encode_fee_source_consent(&c).unwrap()).unwrap(),
        c
    );

    for app in [
        PaidApplication::Call(call_application()),
        PaidApplication::Instantiate(instantiate_application()),
        PaidApplication::Publish(code_artifact()),
    ] {
        let bytes = encode_paid_application(&app).unwrap();
        assert_eq!(decode_paid_application(&bytes).unwrap(), app);
    }

    for intent in [call_intent(), instantiate_intent(), publish_intent()] {
        let bytes = encode_paid_intent(&intent).unwrap();
        assert_eq!(decode_paid_intent(&bytes).unwrap(), intent);
    }

    let policy = fee_policy();
    let bytes = encode_paid_fee_policy(&policy).unwrap();
    assert_eq!(decode_paid_fee_policy(&bytes).unwrap(), policy);
}

#[test]
fn authenticate_and_quote_succeeds_for_all_three_kinds() {
    for intent in [call_intent(), instantiate_intent(), publish_intent()] {
        let s = signed(intent);
        let bytes = encode_signed_paid_intent(&s).unwrap();
        let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();
        let admission =
            quote_paid_intent(&authenticated, &resolver(), &base_policy(), &fee_policy()).unwrap();
        assert!(admission.reserved().get() > 0);
    }
}

#[test]
fn tampering_any_signed_field_invalidates_the_signature() {
    let s = signed(call_intent());
    let bytes = encode_signed_paid_intent(&s).unwrap();

    let mutate = |mutator: &dyn Fn(&mut PaidIntent)| {
        let mut tampered = s.intent.clone();
        mutator(&mut tampered);
        let bytes = encode_signed_paid_intent(&SignedPaidIntent {
            intent: tampered,
            signature: s.signature,
        })
        .unwrap();
        assert!(authenticate_paid_intent(&resolver(), &context(), &bytes).is_err());
    };
    mutate(&|intent| {
        intent.nonce += 1;
        if let PaidApplication::Call(inner) = &mut intent.application {
            inner.nonce += 1;
        }
    });
    mutate(&|intent| {
        intent.request_id[0] ^= 1;
        if let PaidApplication::Call(inner) = &mut intent.application {
            inner.request_id[0] ^= 1;
        }
    });
    mutate(&|intent| {
        intent.gas_limit += 1;
        if let PaidApplication::Call(inner) = &mut intent.application {
            inner.gas_limit += 1;
        }
    });
    mutate(&|intent| intent.fee_policy_digest = digest(9));
    mutate(&|intent| intent.consent.max_fee = Amount::new(intent.consent.max_fee.get() + 1));
    mutate(&|intent| intent.consent.refund_recipient[0] ^= 1);

    assert!(authenticate_paid_intent(&resolver(), &context(), &bytes).is_ok());
}

#[test]
fn header_mismatch_between_envelope_and_nested_call_intent_is_rejected() {
    let mut intent = call_intent();
    if let PaidApplication::Call(inner) = &mut intent.application {
        inner.nonce += 1;
    }
    assert!(encode_paid_intent(&intent).is_err());

    let mut intent = instantiate_intent();
    if let PaidApplication::Instantiate(inner) = &mut intent.application {
        inner.request_id[0] ^= 1;
    }
    assert!(encode_paid_intent(&intent).is_err());
}

#[test]
fn instantiate_requires_creator_sender_and_empty_access_and_type_arguments() {
    let mut intent = instantiate_intent();
    if let PaidApplication::Instantiate(inner) = &mut intent.application {
        inner.instance.creator = [9; 32];
    }
    assert!(encode_paid_intent(&intent).is_err());

    let mut intent = instantiate_intent();
    if let PaidApplication::Instantiate(inner) = &mut intent.application {
        inner.access = AccessManifest {
            entries: vec![AccessEntry {
                object_ref: object_ref(0x50, 1),
                mode: AccessMode::Read,
            }],
        };
    }
    assert!(encode_paid_intent(&intent).is_err());

    let mut intent = instantiate_intent();
    if let PaidApplication::Instantiate(inner) = &mut intent.application {
        inner.type_arguments = vec![abi::package_types::ScopedTypeArg::Opaque {
            domain: 1,
            value: [0; 32],
        }];
    }
    assert!(encode_paid_intent(&intent).is_err());
}

#[test]
fn publish_requires_matching_context_and_publisher() {
    let mut intent = publish_intent();
    let wrong_publisher = CodeArtifact::new(ArtifactParts {
        context: context(),
        origin: PackageOrigin::unverified(context().chain_id().clone(), [9; 32], [11; 32]).unwrap(),
        revision: 1,
        wasm_profile: 4,
        semantics: digest(0x77),
        wasm: vec![0u8; 8],
        unverified_abi: vec![1u8; 4],
        exports: vec!["run".into()],
        unverified_dependencies: vec![],
    })
    .unwrap();
    intent.application = PaidApplication::Publish(wrong_publisher);
    assert!(encode_paid_intent(&intent).is_err());

    let mut intent = publish_intent();
    let other_context = PublicationContext::new(
        ChainId::new("other-chain").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap();
    let wrong_context = CodeArtifact::new(ArtifactParts {
        context: other_context.clone(),
        origin: PackageOrigin::unverified(other_context.chain_id().clone(), sender(), [11; 32])
            .unwrap(),
        revision: 1,
        wasm_profile: 4,
        semantics: digest(0x77),
        wasm: vec![0u8; 8],
        unverified_abi: vec![1u8; 4],
        exports: vec!["run".into()],
        unverified_dependencies: vec![],
    })
    .unwrap();
    intent.application = PaidApplication::Publish(wrong_context);
    assert!(matches!(
        encode_paid_intent(&intent),
        Err(PaidExecutionError::ContextMismatch)
    ));
}

#[test]
fn authorizations_are_valid_only_for_call() {
    use execution::call_authorization::{AuthorizedObject, CallAuthorization, ExecutionTarget};
    let authorization = CallAuthorization {
        caller: ExecutionTarget {
            instance: instance(2),
            code: code(),
        },
        callee: ExecutionTarget {
            instance: instance(2),
            code: code(),
        },
        entrypoint: "run".into(),
        type_arguments: vec![],
        objects: vec![AuthorizedObject {
            object_id: object_ref(0x30, 1).id,
            mode: AccessMode::Read,
        }],
    };
    let mut intent = instantiate_intent();
    intent.authorizations = vec![authorization.clone()];
    assert!(encode_paid_intent(&intent).is_err());

    let mut intent = publish_intent();
    intent.authorizations = vec![authorization];
    assert!(encode_paid_intent(&intent).is_err());
}

#[test]
fn reservation_access_and_application_access_overlap_rules() {
    // Consume: source in application access is always rejected.
    let mut intent = call_intent();
    intent.consent.access = ReservationAccessKind::Consume;
    if let PaidApplication::Call(inner) = &mut intent.application {
        inner.access = AccessManifest {
            entries: vec![AccessEntry {
                object_ref: intent.consent.source.clone(),
                mode: AccessMode::Write,
            }],
        };
    }
    assert!(encode_paid_intent(&intent).is_err());

    // Write with an identical ObjectRef succeeds.
    let mut intent = call_intent();
    if let PaidApplication::Call(inner) = &mut intent.application {
        inner.access = AccessManifest {
            entries: vec![AccessEntry {
                object_ref: intent.consent.source.clone(),
                mode: AccessMode::Consume,
            }],
        };
    }
    assert!(encode_paid_intent(&intent).is_ok());

    // Write with a mismatched version is rejected.
    let mut intent = call_intent();
    if let PaidApplication::Call(inner) = &mut intent.application {
        inner.access = AccessManifest {
            entries: vec![AccessEntry {
                object_ref: object_ref(0x30, 2),
                mode: AccessMode::Write,
            }],
        };
    }
    assert!(encode_paid_intent(&intent).is_err());
}

#[test]
fn source_union_bound_is_enforced() {
    let mut intent = call_intent();
    let entries = (0..32)
        .map(|index| AccessEntry {
            object_ref: object_ref(index as u8, 1),
            mode: AccessMode::Read,
        })
        .collect();
    if let PaidApplication::Call(inner) = &mut intent.application {
        inner.access = AccessManifest { entries };
    }
    // 32 distinct application inputs plus the separately declared source is 33.
    assert!(encode_paid_intent(&intent).is_err());
}

#[test]
fn zero_fee_and_paid_signatures_cannot_cross_authenticate() {
    use execution::local_execution::{
        LocalExecutionIntent, LocalExecutionMode, SignedLocalExecutionIntent,
        authenticate_local_execution, encode_signed_local_execution, local_execution_signing_frame,
    };
    let call = call_application();
    let policy = base_policy();
    let zero_fee_intent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&resolver()).unwrap(),
        call,
        authorizations: vec![],
    };
    let signature: [u8; 64] = key()
        .sign(&local_execution_signing_frame(&context(), &zero_fee_intent).unwrap())
        .into();
    let zero_fee_signed = SignedLocalExecutionIntent {
        intent: zero_fee_intent,
        signature,
    };
    let zero_fee_bytes = encode_signed_local_execution(&zero_fee_signed).unwrap();
    // A zero-fee wire frame is a structurally distinct type and can never
    // authenticate as a paid intent.
    assert!(authenticate_paid_intent(&resolver(), &context(), &zero_fee_bytes).is_err());

    let paid_bytes = encode_signed_paid_intent(&signed(call_intent())).unwrap();
    assert!(authenticate_local_execution(&resolver(), &policy, &paid_bytes).is_err());
}

#[test]
fn invalid_recipients_are_rejected() {
    let mut policy = fee_policy();
    policy.fee_recipient = [0; 32];
    assert!(encode_paid_fee_policy(&policy).is_err());
}

#[test]
fn policy_rejects_zero_schema() {
    let mut policy = fee_policy();
    policy.schema = 0;
    assert!(encode_paid_fee_policy(&policy).is_err());
}

#[test]
fn policy_rejects_equal_asset_and_reservation_types() {
    let mut policy = fee_policy();
    policy.reservation_type = policy.asset_type.clone();
    assert!(encode_paid_fee_policy(&policy).is_err());
}

#[test]
fn policy_rejects_asset_or_reservation_type_not_scoped_to_the_policy_code_origin() {
    let foreign_origin = abi::package_types::PackageOrigin::unverified(
        context().chain_id().clone(),
        sender(),
        [99; 32],
    )
    .unwrap();

    let mut policy = fee_policy();
    policy.asset_type =
        abi::package_types::ScopedTypeTag::new(foreign_origin.clone(), 2, vec![]).unwrap();
    assert!(encode_paid_fee_policy(&policy).is_err());

    let mut policy = fee_policy();
    policy.reservation_type =
        abi::package_types::ScopedTypeTag::new(foreign_origin, 4, vec![]).unwrap();
    assert!(encode_paid_fee_policy(&policy).is_err());
}

#[test]
fn unknown_versions_and_fields_fail_closed_across_all_paid_wire_frames() {
    type Decoder = fn(&[u8]) -> bool;
    let consent_bytes = encode_fee_source_consent(&consent()).unwrap();
    let application_bytes =
        encode_paid_application(&PaidApplication::Call(call_application())).unwrap();
    let intent_bytes = encode_paid_intent(&call_intent()).unwrap();
    let signed_bytes = encode_signed_paid_intent(&signed(call_intent())).unwrap();
    let policy_bytes = encode_paid_fee_policy(&fee_policy()).unwrap();

    let frames: Vec<(&str, Vec<u8>, Decoder)> = vec![
        ("consent", consent_bytes, |b| {
            decode_fee_source_consent(b).is_ok()
        }),
        ("application", application_bytes, |b| {
            decode_paid_application(b).is_ok()
        }),
        ("intent", intent_bytes, |b| decode_paid_intent(b).is_ok()),
        ("signed", signed_bytes, |b| {
            decode_signed_paid_intent(b).is_ok()
        }),
        ("policy", policy_bytes, |b| {
            decode_paid_fee_policy(b).is_ok()
        }),
    ];
    for (name, original, decode) in frames {
        assert!(decode(&original), "{name}");
        let mut unknown_version: Vec<u8> = original.clone();
        unknown_version[6..8].copy_from_slice(&99u16.to_le_bytes());
        assert!(!decode(&unknown_version), "version {name}");
        let mut unknown_field: Vec<u8> = original.clone();
        let count: u16 = u16::from_le_bytes([original[8], original[9]]);
        unknown_field[8..10].copy_from_slice(&count.checked_add(1).unwrap().to_le_bytes());
        unknown_field.extend_from_slice(&u16::MAX.to_le_bytes());
        unknown_field.extend_from_slice(&0u32.to_le_bytes());
        assert!(!decode(&unknown_field), "field {name}");
    }
}

#[test]
fn unknown_application_kind_is_rejected() {
    use canonical_encoding::CanonicalStruct;
    let call_bytes = execution::call::encode_call_intent(&call_application()).unwrap();
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6411, 1);
    frame.field_u16(1, 4).unwrap();
    frame.field_bytes(2, call_bytes).unwrap();
    let bytes: Vec<u8> = frame.finish().unwrap();
    assert!(decode_paid_application(&bytes).is_err());
}

#[test]
fn unknown_reservation_access_discriminant_is_rejected() {
    use canonical_encoding::CanonicalStruct;
    use objects::encode_object_ref;
    let c = consent();
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6410, 1);
    frame
        .field_bytes(1, encode_object_ref(&c.source).unwrap())
        .unwrap();
    frame.field_u16(2, 3).unwrap();
    frame.field_u64(3, c.max_fee.get()).unwrap();
    frame.field_bytes(4, c.refund_recipient.to_vec()).unwrap();
    let bytes: Vec<u8> = frame.finish().unwrap();
    assert!(decode_fee_source_consent(&bytes).is_err());
}

#[test]
fn explicit_empty_authorization_table_field_is_rejected() {
    use canonical_encoding::{CanonicalStruct, encode_digest32};
    use execution::call_authorization::encode_call_authorizations;
    use execution::publication::encode_publication_context;

    let intent = call_intent();
    let context_bytes: Vec<u8> = encode_publication_context(&intent.context).unwrap();
    let consent_bytes: Vec<u8> = encode_fee_source_consent(&intent.consent).unwrap();
    let application_bytes: Vec<u8> = encode_paid_application(&intent.application).unwrap();
    let empty_table: Vec<u8> = encode_call_authorizations(&[]).unwrap();

    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6412, 1);
    frame.field_bytes(1, context_bytes).unwrap();
    frame.field_bytes(2, intent.request_id.to_vec()).unwrap();
    frame.field_bytes(3, intent.sender.to_vec()).unwrap();
    frame.field_u64(4, intent.nonce).unwrap();
    frame
        .field_bytes(5, encode_digest32(&intent.fee_policy_digest).unwrap())
        .unwrap();
    frame.field_bytes(6, consent_bytes).unwrap();
    frame.field_bytes(7, application_bytes).unwrap();
    frame.field_u64(8, intent.gas_limit).unwrap();
    frame.field_bytes(9, empty_table).unwrap();
    let bytes: Vec<u8> = frame.finish().unwrap();

    assert!(decode_paid_intent(&bytes).is_err());
}

#[test]
fn policy_digest_mutation_and_context_wrong_policy_are_rejected() {
    let s = signed(call_intent());
    let bytes = encode_signed_paid_intent(&s).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();

    let mut different_policy = fee_policy();
    different_policy.reserve_allowance = 3;
    assert!(
        quote_paid_intent(
            &authenticated,
            &resolver(),
            &base_policy(),
            &different_policy
        )
        .is_err()
    );

    let wrong_base = LocalExecutionPolicy::general(context());
    assert!(quote_paid_intent(&authenticated, &resolver(), &wrong_base, &fee_policy()).is_err());

    let mut mismatched_context_policy = fee_policy();
    mismatched_context_policy.context = PublicationContext::new(
        ChainId::new("other-chain").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(0),
    )
    .unwrap();
    assert!(
        quote_paid_intent(
            &authenticated,
            &resolver(),
            &base_policy(),
            &mismatched_context_policy
        )
        .is_err()
    );
}

#[test]
fn policy_caps_must_equal_the_fixed_profile() {
    let mut policy = fee_policy();
    policy.calls = 9;
    assert!(encode_paid_fee_policy(&policy).is_err());

    let mut policy = fee_policy();
    policy.memory_bytes += 1;
    assert!(encode_paid_fee_policy(&policy).is_err());
}

#[test]
fn policy_rejects_unsupported_gas_prices_and_nonpositive_publish_prices() {
    let mut policy = fee_policy();
    policy.gas_schedule.read_price = 1;
    assert!(matches!(
        encode_paid_fee_policy(&policy),
        Err(PaidExecutionError::Reservation(
            ReservationError::UnsupportedResourcePrice
        ))
    ));

    let mut policy = fee_policy();
    policy.publish_artifact_byte_price = 0;
    assert!(encode_paid_fee_policy(&policy).is_err());

    let mut policy = fee_policy();
    policy.publish_closure_node_price = 0;
    assert!(encode_paid_fee_policy(&policy).is_err());
}

#[test]
fn zero_actual_fee_schedule_is_rejected() {
    let mut policy = fee_policy();
    policy.gas_schedule.base_fee = 0;
    policy.gas_schedule.execution_price = 0;
    assert!(encode_paid_fee_policy(&policy).is_err());
}

#[test]
fn max_fee_and_total_gas_boundaries_are_enforced() {
    let s = signed(call_intent());
    let bytes = encode_signed_paid_intent(&s).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();
    let admission =
        quote_paid_intent(&authenticated, &resolver(), &base_policy(), &fee_policy()).unwrap();
    assert!(admission.reserved() <= consent().max_fee);

    // A max_fee too small for the computed reservation is rejected.
    let mut too_small = call_intent();
    too_small.consent.max_fee = Amount::new(0);
    let s = signed(too_small);
    let bytes = encode_signed_paid_intent(&s).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();
    assert!(matches!(
        quote_paid_intent(&authenticated, &resolver(), &base_policy(), &fee_policy()),
        Err(PaidExecutionError::Reservation(
            ReservationError::MaxFeeExceeded { .. }
        ))
    ));

    // L + R + S exceeding the DR-0124 bound is rejected.
    let mut too_much_gas = call_intent();
    too_much_gas.gas_limit = 1_000_000;
    if let PaidApplication::Call(inner) = &mut too_much_gas.application {
        inner.gas_limit = 1_000_000;
    }
    let s = signed(too_much_gas);
    let bytes = encode_signed_paid_intent(&s).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();
    assert!(matches!(
        quote_paid_intent(&authenticated, &resolver(), &base_policy(), &fee_policy()),
        Err(PaidExecutionError::Reservation(
            ReservationError::TotalGasLimitExceeded { .. }
        ))
    ));
}

#[test]
fn malformed_and_oversize_bytes_are_rejected_before_allocation() {
    assert!(decode_fee_source_consent(&[0u8; MAX_CONSENT_BYTES + 1]).is_err());
    assert!(decode_paid_intent(&vec![0u8; MAX_PAID_INTENT_BYTES + 1]).is_err());
    assert!(decode_signed_paid_intent(&vec![0u8; MAX_SIGNED_PAID_INTENT_BYTES + 1]).is_err());
    assert!(decode_paid_fee_policy(&vec![0u8; MAX_PAID_FEE_POLICY_BYTES + 1]).is_err());

    let policy = fee_policy();
    let mut bytes = encode_paid_fee_policy(&policy).unwrap();
    let truncated = &bytes[..bytes.len() - 1];
    assert!(decode_paid_fee_policy(truncated).is_err());
    // Flipping the type-identifier header breaks the required type check.
    bytes[4] ^= 0xFF;
    assert!(decode_paid_fee_policy(&bytes).is_err());

    let mut trailing = encode_paid_fee_policy(&policy).unwrap();
    trailing.push(0);
    assert!(decode_paid_fee_policy(&trailing).is_err());
}

#[test]
fn quote_rejects_invalid_signed_refund_recipient_though_authentication_succeeds() {
    let mut intent = call_intent();
    // A signed but non-canonical (non-prime-order) refund recipient: the
    // all-zero key is not a valid Ed25519 public key.
    intent.consent.refund_recipient = [0; 32];
    let s = signed(intent);
    let bytes = encode_signed_paid_intent(&s).unwrap();

    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();
    assert!(matches!(
        quote_paid_intent(&authenticated, &resolver(), &base_policy(), &fee_policy()),
        Err(PaidExecutionError::Owner(_))
    ));
}

#[test]
fn quote_succeeds_for_a_valid_refund_recipient_distinct_from_sender() {
    let other_key = ed25519_zebra::SigningKey::from([9; 32]);
    let other_recipient: [u8; 32] = ed25519_zebra::VerificationKey::from(&other_key).into();

    let mut intent = call_intent();
    intent.consent.refund_recipient = other_recipient;
    let s = signed(intent);
    let bytes = encode_signed_paid_intent(&s).unwrap();

    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();
    let admission =
        quote_paid_intent(&authenticated, &resolver(), &base_policy(), &fee_policy()).unwrap();
    assert!(admission.reserved().get() > 0);
}

#[test]
fn paid_invocation_digest_covers_the_complete_signed_frame() {
    let s = signed(call_intent());
    let base = paid_invocation_digest(&resolver(), &s).unwrap();

    // The signature is included in the hashed bytes.
    let mut tampered_signature = s.clone();
    tampered_signature.signature[0] ^= 1;
    assert_ne!(
        paid_invocation_digest(&resolver(), &tampered_signature).unwrap(),
        base
    );

    // A header field change (nonce, mirrored into the nested call intent so
    // the envelope stays structurally valid) changes the digest.
    let mut tampered_header = s.clone();
    tampered_header.intent.nonce += 1;
    if let PaidApplication::Call(inner) = &mut tampered_header.intent.application {
        inner.nonce += 1;
    }
    assert_ne!(
        paid_invocation_digest(&resolver(), &tampered_header).unwrap(),
        base
    );

    // A payload field change (max_fee) changes the digest.
    let mut tampered_payload = s.clone();
    tampered_payload.intent.consent.max_fee =
        Amount::new(tampered_payload.intent.consent.max_fee.get() + 1);
    assert_ne!(
        paid_invocation_digest(&resolver(), &tampered_payload).unwrap(),
        base
    );

    // A resolver whose chain/protocol-version does not match the signed
    // intent's own context is rejected rather than silently trusted.
    let wrong_resolver = HashSuiteResolver::new(
        ChainId::new("other-chain").unwrap(),
        ProtocolVersion::new(3),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }],
    )
    .unwrap();
    assert!(paid_invocation_digest(&wrong_resolver, &s).is_err());
}

#[test]
fn authenticated_paid_intent_exposes_the_complete_signed_frame() {
    let s = signed(call_intent());
    let bytes = encode_signed_paid_intent(&s).unwrap();
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();
    assert_eq!(authenticated.signed(), &s);
}

#[test]
fn transplanted_signature_across_signature_domains_fails_signature_check_not_decoding() {
    use execution::local_execution::{
        LocalExecutionIntent, LocalExecutionMode, SignedLocalExecutionIntent,
        authenticate_local_execution, decode_signed_local_execution, encode_signed_local_execution,
        local_execution_signing_frame,
    };

    let policy = base_policy();
    let zero_fee_intent = LocalExecutionIntent {
        mode: LocalExecutionMode::Call,
        policy_digest: policy.digest(&resolver()).unwrap(),
        call: call_application(),
        authorizations: vec![],
    };
    let zero_fee_signature: [u8; 64] = key()
        .sign(&local_execution_signing_frame(&context(), &zero_fee_intent).unwrap())
        .into();
    let zero_fee_signed = SignedLocalExecutionIntent {
        intent: zero_fee_intent,
        signature: zero_fee_signature,
    };

    let paid_signed = signed(call_intent());

    // Positive controls: both structurally and cryptographically valid on
    // their own.
    assert!(
        authenticate_local_execution(
            &resolver(),
            &policy,
            &encode_signed_local_execution(&zero_fee_signed).unwrap()
        )
        .is_ok()
    );
    assert!(
        authenticate_paid_intent(
            &resolver(),
            &context(),
            &encode_signed_paid_intent(&paid_signed).unwrap()
        )
        .is_ok()
    );

    // Transplant a genuine zero-fee signature onto an otherwise
    // structurally valid PaidIntent: it decodes fine (same shape, same
    // 64-byte signature field) but must fail signature verification
    // specifically, not a type/decode rejection.
    let paid_with_transplanted_signature = SignedPaidIntent {
        intent: paid_signed.intent.clone(),
        signature: zero_fee_signed.signature,
    };
    let bytes = encode_signed_paid_intent(&paid_with_transplanted_signature).unwrap();
    assert!(decode_signed_paid_intent(&bytes).is_ok());
    assert!(matches!(
        authenticate_paid_intent(&resolver(), &context(), &bytes),
        Err(PaidExecutionError::InvalidSignature)
    ));

    // Inverse: transplant a genuine paid signature onto an otherwise
    // structurally valid zero-fee LocalExecutionIntent.
    let zero_fee_with_transplanted_signature = SignedLocalExecutionIntent {
        intent: zero_fee_signed.intent.clone(),
        signature: paid_signed.signature,
    };
    let bytes = encode_signed_local_execution(&zero_fee_with_transplanted_signature).unwrap();
    assert!(decode_signed_local_execution(&bytes).is_ok());
    let error = authenticate_local_execution(&resolver(), &policy, &bytes).unwrap_err();
    assert!(matches!(
        error,
        execution::local_execution::LocalExecutionError::Invalid("execution signature")
    ));
}

#[test]
fn authentication_succeeds_without_reading_policy_then_changed_policy_quote_fails() {
    let s = signed(call_intent());
    let bytes = encode_signed_paid_intent(&s).unwrap();

    // `authenticate_paid_intent` never takes a fee policy argument: it
    // proves only the signature and context, independent of any policy.
    let authenticated = authenticate_paid_intent(&resolver(), &context(), &bytes).unwrap();

    // The same authenticated intent then fails the separate policy-check
    // step once the trusted expected policy changes.
    let mut changed_policy = fee_policy();
    changed_policy.settle_allowance += 1;
    assert!(
        quote_paid_intent(&authenticated, &resolver(), &base_policy(), &changed_policy).is_err()
    );
    assert!(quote_paid_intent(&authenticated, &resolver(), &base_policy(), &fee_policy()).is_ok());
}

#[test]
fn zero_gas_limit_is_rejected_for_intent_and_nested_call() {
    let mut intent = call_intent();
    intent.gas_limit = 0;
    if let PaidApplication::Call(inner) = &mut intent.application {
        inner.gas_limit = 0;
    }
    assert!(encode_paid_intent(&intent).is_err());
}

#[test]
fn authorization_table_over_the_limit_is_rejected() {
    use execution::call_authorization::{
        CallAuthorization, ExecutionTarget, MAX_CALL_AUTHORIZATIONS,
    };
    let authorization = CallAuthorization {
        caller: ExecutionTarget {
            instance: instance(2),
            code: code(),
        },
        callee: ExecutionTarget {
            instance: instance(2),
            code: code(),
        },
        entrypoint: "run".into(),
        type_arguments: vec![],
        objects: vec![],
    };

    let mut intent = call_intent();
    intent.authorizations = vec![authorization.clone(); MAX_CALL_AUTHORIZATIONS];
    assert!(encode_paid_intent(&intent).is_ok());

    let mut intent = call_intent();
    intent.authorizations = vec![authorization; MAX_CALL_AUTHORIZATIONS + 1];
    assert!(encode_paid_intent(&intent).is_err());
}

#[test]
fn signed_paid_intent_round_trips_and_rejects_trailing_bytes() {
    let s = signed(call_intent());
    let bytes = encode_signed_paid_intent(&s).unwrap();
    assert_eq!(decode_signed_paid_intent(&bytes).unwrap(), s);

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_signed_paid_intent(&trailing).is_err());
}
