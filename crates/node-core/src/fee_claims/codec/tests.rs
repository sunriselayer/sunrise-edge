use super::*;
use objects::ObjectId;
use protocol_types::{ChainId, HashAlgorithmId, ProtocolVersion};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vector_context() -> PublicationContext {
    PublicationContext::new(
        ChainId::new("dr0130-fastpath-vectors").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(9),
    )
    .unwrap()
}

fn vector_resource_id() -> BondResourceId {
    BondResourceId::new(7, [0x79; 32]).unwrap()
}

fn vector_fee_output() -> ObjectRef {
    ObjectRef {
        id: ObjectId::new([0xaa; 32]),
        version: 1,
        digest: Digest32::new(HashAlgorithmId::Sha2_256, [0xbb; 32]),
    }
}

fn zero_share_intent() -> FeeClaimIntent {
    FeeClaimIntent {
        context: vector_context(),
        request_id: [0x91; 32],
        escrow_request_id: [0x92; 32],
        certificate_epoch: Epoch::new(9),
        validator_id: ValidatorId::new([0x93; 32]),
        resource_id: vector_resource_id(),
        expected_generation: 1,
        expected_fee_output: vector_fee_output(),
        expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x81; 32]),
        expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x82; 32]),
        share_amount: 0,
        recipient: Address::new([0x98; 32]),
        operation: FeeClaimOperation::ZeroShare,
    }
}

fn split_intent() -> FeeClaimIntent {
    FeeClaimIntent {
        context: vector_context(),
        request_id: [0xa1; 32],
        escrow_request_id: [0xa2; 32],
        certificate_epoch: Epoch::new(9),
        validator_id: ValidatorId::new([0xa3; 32]),
        resource_id: vector_resource_id(),
        expected_generation: 2,
        expected_fee_output: vector_fee_output(),
        expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x81; 32]),
        expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x82; 32]),
        share_amount: 42,
        recipient: Address::new([0xa8; 32]),
        operation: FeeClaimOperation::Split {
            leg: vec![0x01, 0x02, 0x03],
        },
    }
}

/// Builds a raw `0x6437` frame directly, bypassing [`FeeClaimOperation`]'s
/// own tag/shape invariants, so adversarial tag/field-shape cases can be
/// constructed without going through [`encode_fee_claim_intent`].
fn raw_frame_with_tag_and_extra(
    intent: &FeeClaimIntent,
    tag: u16,
    extra: Option<(u16, Vec<u8>)>,
) -> Vec<u8> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(FEE_CLAIM_INTENT_TYPE, ENCODING_VERSION);
    frame
        .field_bytes(1, encode_publication_context(&intent.context).unwrap())
        .unwrap();
    frame.field_bytes(2, intent.request_id.to_vec()).unwrap();
    frame
        .field_bytes(3, intent.escrow_request_id.to_vec())
        .unwrap();
    frame
        .field_u64(4, intent.certificate_epoch.get())
        .unwrap();
    frame
        .field_bytes(5, intent.validator_id.as_bytes().to_vec())
        .unwrap();
    frame
        .field_bytes(6, encode_bond_resource_id(intent.resource_id).unwrap())
        .unwrap();
    frame.field_u64(7, intent.expected_generation).unwrap();
    frame
        .field_bytes(8, encode_object_ref(&intent.expected_fee_output).unwrap())
        .unwrap();
    frame
        .field_bytes(
            9,
            encode_digest32(&intent.expected_previous_row_digest).unwrap(),
        )
        .unwrap();
    frame
        .field_bytes(
            10,
            encode_digest32(&intent.expected_next_row_digest).unwrap(),
        )
        .unwrap();
    frame.field_u64(11, intent.share_amount).unwrap();
    frame
        .field_bytes(12, intent.recipient.as_bytes().to_vec())
        .unwrap();
    frame.field_u16(13, tag).unwrap();
    if let Some((field_id, bytes)) = extra {
        frame.field_bytes(field_id, bytes).unwrap();
    }
    frame.finish().unwrap()
}

#[test]
fn fee_claim_zero_share_intent_frame_0x6437_round_trips_and_is_stable() {
    let intent = zero_share_intent();
    let bytes = encode_fee_claim_intent(&intent).unwrap();
    assert_eq!(decode_fee_claim_intent(&bytes).unwrap(), intent);
    // Exact bytes, not merely a round trip: cross-checked against the
    // independent JavaScript vector (`feeClaimZeroShareIntent0x6437` in
    // `scripts/fast-path-vectors.mjs`).
    assert_eq!(
        hex(&bytes),
        "534e5245376401000d0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f72730200040000000300000003000800000009000000000000000200200000009191919191919191919191919191919191919191919191919191919191919191030020000000929292929292929292929292929292929292929292929292929292929292929204000800000009000000000000000500200000009393939393939393939393939393939393939393939393939393939393939393060038000000534e524508800100020001000200000007000200200000007979797979797979797979797979797979797979797979797979797979797979070008000000010000000000000008008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb090038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810a0038000000534e5245030101000200010002000000010002002000000082828282828282828282828282828282828282828282828282828282828282820b000800000000000000000000000c002000000098989898989898989898989898989898989898989898989898989898989898980d00020000000100"
    );
}

#[test]
fn fee_claim_split_intent_frame_0x6437_and_signed_0x6438_round_trip_and_are_stable() {
    let intent = split_intent();
    let bytes = encode_fee_claim_intent(&intent).unwrap();
    assert_eq!(decode_fee_claim_intent(&bytes).unwrap(), intent);
    // Exact bytes, not merely a round trip: cross-checked against the
    // independent JavaScript vector (`feeClaimSplitIntent0x6437` in
    // `scripts/fast-path-vectors.mjs`).
    assert_eq!(
        hex(&bytes),
        "534e5245376401000e0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000020020000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1030020000000a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20400080000000900000000000000050020000000a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3060038000000534e524508800100020001000200000007000200200000007979797979797979797979797979797979797979797979797979797979797979070008000000020000000000000008008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb090038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810a0038000000534e5245030101000200010002000000010002002000000082828282828282828282828282828282828282828282828282828282828282820b00080000002a000000000000000c0020000000a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a80d000200000002000e0003000000010203"
    );

    let signed = SignedFeeClaimIntent {
        intent,
        signature: [0x42; 64],
    };
    let signed_bytes = encode_signed_fee_claim_intent(&signed).unwrap();
    assert_eq!(
        decode_signed_fee_claim_intent(&signed_bytes).unwrap(),
        signed
    );
    // Exact bytes, not merely a round trip: cross-checked against the
    // independent JavaScript vector (`signedFeeClaimSplitIntent0x6438` in
    // `scripts/fast-path-vectors.mjs`).
    assert_eq!(
        hex(&signed_bytes),
        "534e524538640100020001006e020000534e5245376401000e0001003f000000534e52450163010003000100170000006472303133302d66617374706174682d766563746f7273020004000000030000000300080000000900000000000000020020000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1030020000000a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a20400080000000900000000000000050020000000a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3060038000000534e524508800100020001000200000007000200200000007979797979797979797979797979797979797979797979797979797979797979070008000000020000000000000008008c000000534e5245044001000300010030000000534e5245014001000100010020000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0200080000000100000000000000030038000000534e52450301010002000100020000000100020020000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb090038000000534e5245030101000200010002000000010002002000000081818181818181818181818181818181818181818181818181818181818181810a0038000000534e5245030101000200010002000000010002002000000082828282828282828282828282828282828282828282828282828282828282820b00080000002a000000000000000c0020000000a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a80d000200000002000e000300000001020302004000000042424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242"
    );

    let mut trailing = signed_bytes.clone();
    trailing.push(0);
    assert!(decode_signed_fee_claim_intent(&trailing).is_err());

    let mut wrong_type = signed_bytes;
    wrong_type[4..6].copy_from_slice(&0x6437u16.to_le_bytes());
    assert!(decode_signed_fee_claim_intent(&wrong_type).is_err());
}

#[test]
fn fee_claim_final_transfer_operation_round_trips() {
    let intent = FeeClaimIntent {
        operation: FeeClaimOperation::FinalTransfer {
            leg: vec![0x0a, 0x0b],
        },
        ..split_intent()
    };
    let bytes = encode_fee_claim_intent(&intent).unwrap();
    assert_eq!(decode_fee_claim_intent(&bytes).unwrap(), intent);
}

#[test]
fn fee_claim_intent_rejects_wrong_type_id() {
    let bytes = encode_fee_claim_intent(&zero_share_intent()).unwrap();
    let mut tampered = bytes.clone();
    tampered[4] ^= 0xFF;
    assert!(matches!(
        decode_fee_claim_intent(&tampered),
        Err(FeeClaimCodecError::Decoding(
            CanonicalDecodingError::UnexpectedTypeId {
                expected: FEE_CLAIM_INTENT_TYPE,
                ..
            }
        ))
    ));
}

#[test]
fn fee_claim_intent_rejects_wrong_version() {
    let bytes = encode_fee_claim_intent(&zero_share_intent()).unwrap();
    let mut tampered = bytes.clone();
    tampered[6] ^= 0xFF;
    assert!(matches!(
        decode_fee_claim_intent(&tampered),
        Err(FeeClaimCodecError::Decoding(
            CanonicalDecodingError::UnexpectedVersion {
                expected: ENCODING_VERSION,
                ..
            }
        ))
    ));
}

#[test]
fn fee_claim_intent_rejects_unknown_operation_tag() {
    let bytes = raw_frame_with_tag_and_extra(&zero_share_intent(), 99, None);
    assert!(matches!(
        decode_fee_claim_intent(&bytes),
        Err(FeeClaimCodecError::Invalid("unknown fee claim operation"))
    ));
}

#[test]
fn fee_claim_intent_rejects_an_extra_field_on_zero_share() {
    let bytes = raw_frame_with_tag_and_extra(&zero_share_intent(), 1, Some((14, vec![0x01])));
    assert!(matches!(
        decode_fee_claim_intent(&bytes),
        Err(FeeClaimCodecError::Decoding(
            CanonicalDecodingError::UnexpectedField(14)
        ))
    ));
}

#[test]
fn fee_claim_intent_rejects_truncated_bytes() {
    let bytes = encode_fee_claim_intent(&zero_share_intent()).unwrap();
    let truncated: &[u8] = &bytes[..bytes.len() - 1];
    assert!(matches!(
        decode_fee_claim_intent(truncated),
        Err(FeeClaimCodecError::Decoding(
            CanonicalDecodingError::Truncated { .. }
        ))
    ));
}

#[test]
fn fee_claim_intent_rejects_a_missing_field() {
    let intent = zero_share_intent();
    let mut frame: CanonicalStruct = CanonicalStruct::new(FEE_CLAIM_INTENT_TYPE, ENCODING_VERSION);
    frame
        .field_bytes(1, encode_publication_context(&intent.context).unwrap())
        .unwrap();
    frame.field_bytes(2, intent.request_id.to_vec()).unwrap();
    // Field 3 (`escrow_request_id`) deliberately omitted.
    frame
        .field_u64(4, intent.certificate_epoch.get())
        .unwrap();
    frame
        .field_bytes(5, intent.validator_id.as_bytes().to_vec())
        .unwrap();
    frame
        .field_bytes(6, encode_bond_resource_id(intent.resource_id).unwrap())
        .unwrap();
    frame.field_u64(7, intent.expected_generation).unwrap();
    frame
        .field_bytes(8, encode_object_ref(&intent.expected_fee_output).unwrap())
        .unwrap();
    frame
        .field_bytes(
            9,
            encode_digest32(&intent.expected_previous_row_digest).unwrap(),
        )
        .unwrap();
    frame
        .field_bytes(
            10,
            encode_digest32(&intent.expected_next_row_digest).unwrap(),
        )
        .unwrap();
    frame.field_u64(11, intent.share_amount).unwrap();
    frame
        .field_bytes(12, intent.recipient.as_bytes().to_vec())
        .unwrap();
    frame.field_u16(13, intent.operation.tag()).unwrap();
    let bytes = frame.finish().unwrap();
    assert!(matches!(
        decode_fee_claim_intent(&bytes),
        Err(FeeClaimCodecError::Decoding(
            CanonicalDecodingError::MissingField(3)
        ))
    ));
}

#[test]
fn fee_claim_operation_rejects_empty_leg_on_encode_and_decode() {
    let empty_leg_intent = FeeClaimIntent {
        operation: FeeClaimOperation::Split { leg: vec![] },
        ..split_intent()
    };
    assert!(matches!(
        encode_fee_claim_intent(&empty_leg_intent),
        Err(FeeClaimCodecError::Invalid(
            "fee claim leg must be nonempty"
        ))
    ));

    let bytes =
        raw_frame_with_tag_and_extra(&zero_share_intent(), OPERATION_TAG_SPLIT, Some((14, vec![])));
    assert!(matches!(
        decode_fee_claim_intent(&bytes),
        Err(FeeClaimCodecError::Invalid(
            "fee claim leg must be nonempty"
        ))
    ));
}

#[test]
fn fee_claim_intent_rejects_bytes_over_the_bound() {
    let oversized = FeeClaimIntent {
        operation: FeeClaimOperation::Split {
            leg: vec![0u8; MAX_FEE_CLAIM_INTENT_BYTES],
        },
        ..split_intent()
    };
    assert!(matches!(
        encode_fee_claim_intent(&oversized),
        Err(FeeClaimCodecError::Invalid("fee claim intent bytes"))
    ));
}

#[test]
fn fee_claim_codec_error_converts_to_node_core_error() {
    let error: NodeCoreError = FeeClaimCodecError::Invalid("boom").into();
    assert!(matches!(error, NodeCoreError::PersistenceInvariant("boom")));

    let decode_error: NodeCoreError = FeeClaimCodecError::Decoding(
        CanonicalDecodingError::UnexpectedField(14),
    )
    .into();
    assert!(matches!(
        decode_error,
        NodeCoreError::CanonicalDecoding(CanonicalDecodingError::UnexpectedField(14))
    ));
}
