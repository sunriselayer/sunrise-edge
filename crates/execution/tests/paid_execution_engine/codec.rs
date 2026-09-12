/// Locates one decoded field's payload byte range inside its original
/// encoded frame, for targeted corruption in the codec regressions below.
fn field_range(bytes: &[u8], field_id: u16) -> std::ops::Range<usize> {
    let frame = canonical_encoding::decode_canonical_frame(bytes).unwrap();
    let slice = frame.required_field(field_id).unwrap();
    let start = slice.as_ptr() as usize - bytes.as_ptr() as usize;
    start..start + slice.len()
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
