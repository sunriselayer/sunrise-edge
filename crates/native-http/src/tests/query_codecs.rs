use super::*;

#[test]
fn http_result_round_trip_is_bounded_and_stable() {
    let id = request_id(0x31);
    let response = NodeResponse::new(
        id,
        NodeResponseStatus::Accepted,
        Some(canonical(TEST_PAYLOAD_TYPE_ID, 4)),
    )
    .unwrap();
    let result = HttpNodeResult::new(id, vec![response]).unwrap();
    let encoded = result.encode().unwrap();

    assert_eq!(HttpNodeResult::decode(&encoded).unwrap(), result);
    assert_eq!(
        hex(&encoded),
        "534e524501e101000300010020000000313131313131313131313131313131313131313131313131\
         31313131313131310200040000000100000003005a00000056000000534e524502e0010003000100\
         20000000313131313131313131313131313131313131313131313131313131313131313102000200\
         00000100030018000000534e524512ef010001000100080000000400000000000000"
            .replace(' ', "")
    );
}

// --- DR-0082 bounded query-result codecs -----------------------------

#[test]
fn context_query_result_round_trip_is_bounded_and_stable() {
    let result = HttpContextQueryResult::new(
        ChainId::new("sunrise-test").unwrap(),
        ProtocolVersion::new(3),
        Epoch::new(7),
        HashSuiteId::new(1),
        1,
        1,
        1,
        AtomicityDomainId::new([0x11; 32]).unwrap(),
        vec![0xAA, 0xBB, 0xCC],
    )
    .unwrap();
    let encoded = result.encode().unwrap();

    assert_eq!(HttpContextQueryResult::decode(&encoded).unwrap(), result);
    let expected_hex = concat!(
        "534e524502e10100090001000c00000073756e726973652d746573740200040000000300000003000800",
        "00000700000000000000040002000000010005000200000001000600020000000100070002000000010008",
        "0020000000111111111111111111111111111111111111111111111111111111111111111109000300000",
        "0aabbcc",
    );
    assert_eq!(hex(&encoded), expected_hex);
}

#[test]
fn context_query_result_rejects_unexpected_field() {
    let mut frame = CanonicalStruct::new(
        CONTEXT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame.field_str(1, "sunrise-test").unwrap();
    frame.field_u32(2, 3).unwrap();
    frame.field_u64(3, 7).unwrap();
    frame.field_u16(4, 1).unwrap();
    frame.field_u16(5, 1).unwrap();
    frame.field_u16(6, 1).unwrap();
    frame.field_u16(7, 1).unwrap();
    frame.field_bytes(8, vec![0x11; 32]).unwrap();
    frame.field_bytes(9, vec![0xAA]).unwrap();
    frame.field_u16(10, 0).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        HttpContextQueryResult::decode(&bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedField(10)
        ))
    ));
}

#[test]
fn context_query_result_rejects_zero_ids_long_chain_id_and_empty_config_bytes() {
    fn build(
        protocol_version: u32,
        hash_suite_id: u16,
        profile: u16,
        scheme: u16,
        binding: u16,
        chain: &str,
        config_bytes: Vec<u8>,
    ) -> Result<HttpContextQueryResult, QueryResultError> {
        HttpContextQueryResult::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(protocol_version),
            Epoch::new(7),
            HashSuiteId::new(hash_suite_id),
            profile,
            scheme,
            binding,
            AtomicityDomainId::new([0x11; 32]).unwrap(),
            config_bytes,
        )
    }

    assert_eq!(
        build(0, 1, 1, 1, 1, "sunrise-test", vec![0xAA]),
        Err(QueryResultError::ZeroProtocolVersion)
    );
    assert_eq!(
        build(3, 0, 1, 1, 1, "sunrise-test", vec![0xAA]),
        Err(QueryResultError::ZeroHashSuiteId)
    );
    assert_eq!(
        build(3, 1, 0, 1, 1, "sunrise-test", vec![0xAA]),
        Err(QueryResultError::ZeroTransactionAuthProfileId)
    );
    assert_eq!(
        build(3, 1, 1, 0, 1, "sunrise-test", vec![0xAA]),
        Err(QueryResultError::ZeroSignatureSchemeId)
    );
    assert_eq!(
        build(3, 1, 1, 1, 0, "sunrise-test", vec![0xAA]),
        Err(QueryResultError::ZeroAddressBindingId)
    );
    let long_chain = "x".repeat(MAX_CHAIN_ID_BYTES + 1);
    assert_eq!(
        build(3, 1, 1, 1, 1, &long_chain, vec![0xAA]),
        Err(QueryResultError::ChainIdTooLong(MAX_CHAIN_ID_BYTES + 1))
    );
    assert_eq!(
        build(3, 1, 1, 1, 1, "sunrise-test", Vec::new()),
        Err(QueryResultError::EmptyProtocolConfigBytes)
    );
    assert!(build(3, 1, 1, 1, 1, "sunrise-test", vec![0xAA]).is_ok());
}

fn sample_inline_object_bytes(object_id: ObjectId, version: u64) -> Vec<u8> {
    let object = Object {
        id: object_id,
        version,
        owner: Owner::Address(Address::new([0x21; 32])),
        type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]),
        schema_version: 1,
        data: vec![0xDD, 0xEE],
    };
    encode_object(&object).unwrap()
}

fn sample_object_query_results() -> Vec<HttpObjectQueryResult> {
    let object_id = ObjectId::new([0x20; 32]);
    vec![
        HttpObjectQueryResult::Absent { object_id },
        HttpObjectQueryResult::Tombstoned {
            object_id,
            head_revision: ObjectHeadRevision::new(2).unwrap(),
            last_object_version: DurableObjectVersion::new(1).unwrap(),
        },
        HttpObjectQueryResult::CurrentInline {
            object_id,
            head_revision: ObjectHeadRevision::new(1).unwrap(),
            object_version: DurableObjectVersion::new(1).unwrap(),
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; 32]),
            creating_chain_id: ChainId::new("sunrise-test").unwrap(),
            creating_protocol_version: ProtocolVersion::new(3),
            canonical_object_bytes: sample_inline_object_bytes(object_id, 1),
        },
        HttpObjectQueryResult::CurrentBlobReference {
            object_id,
            head_revision: ObjectHeadRevision::new(3).unwrap(),
            object_version: DurableObjectVersion::new(2).unwrap(),
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x23; 32]),
            blob_digest: Digest32::new(HashAlgorithmId::Sha3_256, [0x24; 32]),
        },
    ]
}

#[test]
fn object_query_result_round_trips_every_status() {
    for case in sample_object_query_results() {
        let encoded = case.encode().unwrap();
        let decoded = HttpObjectQueryResult::decode(&encoded).unwrap();
        assert_eq!(decoded, case);
        assert_eq!(decoded.object_id(), case.object_id());
    }
}

#[test]
fn unchanged_object_query_statuses_preserve_encoding_v1() {
    let cases: Vec<HttpObjectQueryResult> = sample_object_query_results();
    for index in [0_usize, 1_usize, 3_usize] {
        let encoded: Vec<u8> = cases[index].encode().unwrap();
        assert_eq!(decode_canonical_frame(&encoded).unwrap().version(), 1);
    }
}

#[test]
fn object_query_result_current_inline_v2_matches_pinned_stable_vector() {
    let result = &sample_object_query_results()[2];
    let encoded = result.encode().unwrap();

    let expected_hex = "534e524503e1020009000100020000000300020020000000202020202020202020202020202020202020202020202020202020202020202003000800000001000000000000000400080000000100000000000000050002000000010006002000000022222222222222222222222222222222222222222222222222222222222222220700ec000000534e5245054001000600010030000000534e524501400100010001002000000020202020202020202020202020202020202020202020202020202020202020200200080000000100000000000000030048000000534e52450340010002000100020000000100020030000000534e52450240010001000100200000002121212121212121212121212121212121212121212121212121212121212121040038000000534e52450301010002000100020000000100020020000000999999999999999999999999999999999999999999999999999999999999999905000400000001000000060002000000ddee0a000c00000073756e726973652d746573740b000400000003000000";
    assert_eq!(hex(&encoded), expected_hex);
}

#[test]
fn historical_object_query_v1_vector_decodes_without_digest_context() {
    let historical_hex = "534e524503e1010007000100020000000300020020000000202020202020202020202020202020202020202020202020202020202020202003000800000001000000000000000400080000000100000000000000050002000000010006002000000022222222222222222222222222222222222222222222222222222222222222220700ec000000534e5245054001000600010030000000534e524501400100010001002000000020202020202020202020202020202020202020202020202020202020202020200200080000000100000000000000030048000000534e52450340010002000100020000000100020030000000534e52450240010001000100200000002121212121212121212121212121212121212121212121212121212121212121040038000000534e52450301010002000100020000000100020020000000999999999999999999999999999999999999999999999999999999999999999905000400000001000000060002000000ddee";
    let historical_bytes: Vec<u8> = (0..historical_hex.len())
        .step_by(2)
        .map(|index: usize| u8::from_str_radix(&historical_hex[index..index + 2], 16).unwrap())
        .collect();
    let decoded = HttpObjectQueryResult::decode(&historical_bytes).unwrap();
    assert!(matches!(
        &decoded,
        HttpObjectQueryResult::HistoricalCurrentInline { .. }
    ));
    assert_eq!(decoded.encode().unwrap(), historical_bytes);
}

#[test]
fn object_query_result_binds_the_exact_requested_selector() {
    let a = ObjectId::new([0x30; 32]);
    let b = ObjectId::new([0x31; 32]);
    let result_a = HttpObjectQueryResult::Absent { object_id: a };
    let result_b = HttpObjectQueryResult::Absent { object_id: b };

    assert_eq!(result_a.object_id(), a);
    assert_eq!(result_b.object_id(), b);
    assert_ne!(result_a.encode().unwrap(), result_b.encode().unwrap());
    assert_eq!(
        HttpObjectQueryResult::decode(&result_a.encode().unwrap())
            .unwrap()
            .object_id(),
        a
    );
    assert_ne!(
        HttpObjectQueryResult::decode(&result_a.encode().unwrap())
            .unwrap()
            .object_id(),
        b
    );
}

#[test]
fn object_query_result_rejects_unknown_status_id() {
    let mut frame = CanonicalStruct::new(
        OBJECT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame.field_u16(1, 99).unwrap();
    frame
        .field_bytes(2, ObjectId::new([0x01; 32]).as_bytes().to_vec())
        .unwrap();
    let bytes = frame.finish().unwrap();

    assert_eq!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::UnknownObjectStatus(99))
    );
}

#[test]
fn object_query_result_absent_rejects_a_field_only_valid_for_another_status() {
    let object_id = ObjectId::new([0x32; 32]);
    let mut frame = CanonicalStruct::new(
        OBJECT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame
        .field_u16(1, ObjectQueryStatus::Absent.as_u16())
        .unwrap();
    frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
    frame.field_u64(3, 1).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedField(3)
        ))
    ));
}

#[test]
fn object_query_result_rejects_encoding_v2_for_absent() {
    let object_id = ObjectId::new([0x33; 32]);
    let mut frame = CanonicalStruct::new(OBJECT_QUERY_RESULT_TYPE_ID, 2);
    frame
        .field_u16(1, ObjectQueryStatus::Absent.as_u16())
        .unwrap();
    frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedVersion {
                expected: 1,
                actual: 2,
            }
        ))
    ));
}

#[test]
fn object_query_result_rejects_encoding_v2_for_tombstoned() {
    let object_id = ObjectId::new([0x34; 32]);
    let mut frame = CanonicalStruct::new(OBJECT_QUERY_RESULT_TYPE_ID, 2);
    frame
        .field_u16(1, ObjectQueryStatus::Tombstoned.as_u16())
        .unwrap();
    frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
    frame.field_u64(3, 2).unwrap();
    frame.field_u64(4, 1).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedVersion {
                expected: 1,
                actual: 2,
            }
        ))
    ));
}

#[test]
fn object_query_result_rejects_encoding_v2_for_current_blob_reference() {
    let object_id = ObjectId::new([0x35; 32]);
    let mut frame = CanonicalStruct::new(OBJECT_QUERY_RESULT_TYPE_ID, 2);
    frame
        .field_u16(1, ObjectQueryStatus::CurrentBlobReference.as_u16())
        .unwrap();
    frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
    frame.field_u64(3, 3).unwrap();
    frame.field_u64(4, 2).unwrap();
    frame
        .field_u16(5, HashAlgorithmId::Sha2_256.as_u16())
        .unwrap();
    frame.field_bytes(6, vec![0x23; 32]).unwrap();
    frame
        .field_u16(8, HashAlgorithmId::Sha3_256.as_u16())
        .unwrap();
    frame.field_bytes(9, vec![0x24; 32]).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedVersion {
                expected: 1,
                actual: 2,
            }
        ))
    ));
}

#[test]
fn object_query_result_rejects_mismatched_canonical_type_id() {
    let request_id = request_id(0x01);
    let receipt_bytes = HttpReceiptQueryResult::Absent { request_id }
        .encode()
        .unwrap();

    assert!(matches!(
        HttpObjectQueryResult::decode(&receipt_bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedTypeId { .. }
        ))
    ));
}

fn current_inline_object_frame(
    object_id: ObjectId,
    object_version: u64,
    canonical_object_bytes: Vec<u8>,
) -> Vec<u8> {
    let mut frame = CanonicalStruct::new(
        OBJECT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame
        .field_u16(1, ObjectQueryStatus::CurrentInline.as_u16())
        .unwrap();
    frame.field_bytes(2, object_id.as_bytes().to_vec()).unwrap();
    frame.field_u64(3, 1).unwrap();
    frame.field_u64(4, object_version).unwrap();
    frame
        .field_u16(5, HashAlgorithmId::Sha2_256.as_u16())
        .unwrap();
    frame.field_bytes(6, vec![0x22; 32]).unwrap();
    frame.field_bytes(7, canonical_object_bytes).unwrap();
    frame.finish().unwrap()
}

#[test]
fn object_query_result_current_inline_rejects_oversized_body() {
    let object_id = ObjectId::new([0x25; 32]);
    let bytes = current_inline_object_frame(
        object_id,
        1,
        vec![0_u8; MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1],
    );

    assert_eq!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::ObjectBodyTooLarge {
            actual: MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 1,
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        })
    );
}

#[test]
fn object_query_result_current_inline_rejects_invalid_nested_object_bytes() {
    let object_id = ObjectId::new([0x26; 32]);
    let bytes = current_inline_object_frame(object_id, 1, vec![0xFF, 0x00]);

    assert!(matches!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::InvalidCanonicalObject(_))
    ));
}

#[test]
fn object_query_result_current_inline_rejects_nested_identity_mismatch() {
    let object_id = ObjectId::new([0x27; 32]);
    let other_id = ObjectId::new([0x28; 32]);
    let nested_bytes = sample_inline_object_bytes(other_id, 1);
    let bytes = current_inline_object_frame(object_id, 1, nested_bytes);

    assert_eq!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::ObjectIdentityMismatch {
            expected: object_id,
            actual: other_id,
        })
    );
}

#[test]
fn object_query_result_current_inline_rejects_nested_version_mismatch() {
    let object_id = ObjectId::new([0x29; 32]);
    let nested_bytes = sample_inline_object_bytes(object_id, 2);
    let bytes = current_inline_object_frame(object_id, 1, nested_bytes);

    assert_eq!(
        HttpObjectQueryResult::decode(&bytes),
        Err(QueryResultError::ObjectVersionMismatch {
            expected: 1,
            actual: 2,
        })
    );
}

fn sample_receipt_query_results() -> Vec<HttpReceiptQueryResult> {
    let request_id = request_id(0x50);
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32]);
    let response = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
    let dedup_record_bytes = NodeDedupRecord::new(request_id, event_digest, vec![response])
        .unwrap()
        .encode()
        .unwrap();
    vec![
        HttpReceiptQueryResult::Absent { request_id },
        HttpReceiptQueryResult::Present {
            request_id,
            event_digest,
            dedup_record_bytes,
        },
    ]
}

#[test]
fn receipt_query_result_round_trips_every_status() {
    for case in sample_receipt_query_results() {
        let encoded = case.encode().unwrap();
        let decoded = HttpReceiptQueryResult::decode(&encoded).unwrap();
        assert_eq!(decoded, case);
        assert_eq!(decoded.request_id(), case.request_id());
    }
}

#[test]
fn receipt_query_result_present_matches_pinned_stable_vector() {
    let result = &sample_receipt_query_results()[1];
    let encoded = result.encode().unwrap();

    let expected_hex = "534e524504e10100050001000200000002000200200000005050505050505050505050505050505050505050505050505050505050505050030002000000010004002000000055555555555555555555555555555555555555555555555555555555555555550500aa000000534e524503e0010005000100200000005050505050505050505050505050505050505050505050505050505050505050020002000000010003002000000055555555555555555555555555555555555555555555555555555555555555550400040000000100000005003c00000038000000534e524502e00100020001002000000050505050505050505050505050505050505050505050505050505050505050500200020000000100";
    assert_eq!(hex(&encoded), expected_hex);
}

#[test]
fn receipt_query_result_binds_the_exact_requested_selector() {
    let a = request_id(0x60);
    let b = request_id(0x61);
    let result_a = HttpReceiptQueryResult::Absent { request_id: a };
    let result_b = HttpReceiptQueryResult::Absent { request_id: b };

    assert_eq!(result_a.request_id(), a);
    assert_eq!(result_b.request_id(), b);
    assert_ne!(result_a.encode().unwrap(), result_b.encode().unwrap());
    assert_eq!(
        HttpReceiptQueryResult::decode(&result_a.encode().unwrap())
            .unwrap()
            .request_id(),
        a
    );
}

#[test]
fn receipt_query_result_rejects_unknown_status_id() {
    let mut frame = CanonicalStruct::new(
        RECEIPT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame.field_u16(1, 7).unwrap();
    frame
        .field_bytes(2, request_id(0x01).as_bytes().to_vec())
        .unwrap();
    let bytes = frame.finish().unwrap();

    assert_eq!(
        HttpReceiptQueryResult::decode(&bytes),
        Err(QueryResultError::UnknownReceiptStatus(7))
    );
}

fn present_receipt_frame(
    request_id: RequestId,
    event_digest: Digest32,
    dedup_record_bytes: Vec<u8>,
) -> Vec<u8> {
    let mut frame = CanonicalStruct::new(
        RECEIPT_QUERY_RESULT_TYPE_ID,
        1, /* query-result encoding version, see node_wire */
    );
    frame
        .field_u16(1, ReceiptQueryStatus::Present.as_u16())
        .unwrap();
    frame
        .field_bytes(2, request_id.as_bytes().to_vec())
        .unwrap();
    frame
        .field_u16(3, event_digest.algorithm().as_u16())
        .unwrap();
    frame.field_bytes(4, event_digest.bytes().to_vec()).unwrap();
    frame.field_bytes(5, dedup_record_bytes).unwrap();
    frame.finish().unwrap()
}

// `receipt_query_result_rejects_oversized_body` is not constructible as a
// unit test: `runtime::MAX_DURABLE_RECEIPT_BYTES` currently equals
// `canonical_encoding::MAX_CANONICAL_FRAME_BYTES`, so any field that large
// already fails to canonically frame (`FrameTooLarge`) before this
// decoder's own `ReceiptTooLarge` bound ever runs. The check is kept as
// defense in depth in case the two bounds diverge in the future.

#[test]
fn receipt_query_result_rejects_invalid_nested_dedup_record_bytes() {
    let request_id = request_id(0x53);
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x54; 32]);
    let bytes = present_receipt_frame(request_id, event_digest, vec![0xFF, 0x00]);

    assert!(matches!(
        HttpReceiptQueryResult::decode(&bytes),
        Err(QueryResultError::InvalidDedupRecord(_))
    ));
}

#[test]
fn receipt_query_result_rejects_nested_request_id_mismatch() {
    let request_id_outer = request_id(0x56);
    let request_id_nested = request_id(0x57);
    let event_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x58; 32]);
    let response =
        NodeResponse::new(request_id_nested, NodeResponseStatus::Accepted, None).unwrap();
    let dedup_record_bytes = NodeDedupRecord::new(request_id_nested, event_digest, vec![response])
        .unwrap()
        .encode()
        .unwrap();
    let bytes = present_receipt_frame(request_id_outer, event_digest, dedup_record_bytes);

    assert_eq!(
        HttpReceiptQueryResult::decode(&bytes),
        Err(QueryResultError::RequestIdentityMismatch {
            expected: request_id_outer,
            actual: request_id_nested,
        })
    );
}

#[test]
fn receipt_query_result_rejects_nested_event_digest_mismatch() {
    let request_id = request_id(0x59);
    let event_digest_outer = Digest32::new(HashAlgorithmId::Sha2_256, [0x5A; 32]);
    let event_digest_nested = Digest32::new(HashAlgorithmId::Sha2_256, [0x5B; 32]);
    let response = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
    let dedup_record_bytes = NodeDedupRecord::new(request_id, event_digest_nested, vec![response])
        .unwrap()
        .encode()
        .unwrap();
    let bytes = present_receipt_frame(request_id, event_digest_outer, dedup_record_bytes);

    assert_eq!(
        HttpReceiptQueryResult::decode(&bytes),
        Err(QueryResultError::EventDigestMismatch)
    );
}

#[test]
fn next_nonce_query_result_round_trip_is_bounded_and_stable() {
    let result = HttpNextNonceQueryResult::new(Address::new([0x61; 32]), Epoch::new(7), 42);
    let encoded = result.encode().unwrap();

    assert_eq!(HttpNextNonceQueryResult::decode(&encoded).unwrap(), result);
    let expected_hex = "534e524505e1010003000100200000006161616161616161616161616161616161616161616161616161616161616161020008000000070000000000000003000800000\
02a00000000000000";
    assert_eq!(hex(&encoded), expected_hex);
}

#[test]
fn next_nonce_query_result_binds_the_exact_requested_sender() {
    let a = HttpNextNonceQueryResult::new(Address::new([0x70; 32]), Epoch::new(7), 1);
    let b = HttpNextNonceQueryResult::new(Address::new([0x71; 32]), Epoch::new(7), 1);

    assert_eq!(a.sender(), Address::new([0x70; 32]));
    assert_ne!(a.encode().unwrap(), b.encode().unwrap());
    assert_eq!(
        HttpNextNonceQueryResult::decode(&a.encode().unwrap())
            .unwrap()
            .sender(),
        Address::new([0x70; 32])
    );
}

#[test]
fn next_nonce_query_result_rejects_mismatched_canonical_type_id() {
    let object_bytes = HttpObjectQueryResult::Absent {
        object_id: ObjectId::new([0x01; 32]),
    }
    .encode()
    .unwrap();

    assert!(matches!(
        HttpNextNonceQueryResult::decode(&object_bytes),
        Err(QueryResultError::CanonicalDecoding(
            CanonicalDecodingError::UnexpectedTypeId { .. }
        ))
    ));
}
