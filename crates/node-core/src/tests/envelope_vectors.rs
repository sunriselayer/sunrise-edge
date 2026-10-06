use super::*;

// DR-0201 phase A baseline. These tests freeze `NodeResponse`'s
// omitted-payload encoding and `NodeDedupRecord`'s zero/two-response list
// framing *before* any envelope-ownership migration.
//
// `event_round_trip_has_stable_encoding`,
// `response_round_trip_preserves_optional_payload` and
// `dedup_and_outbox_records_have_stable_canonical_vectors` in
// `core_and_nonce.rs` already pin the one-payload `NodeEvent`/`NodeResponse`
// case and the one-response `NodeDedupRecord` case; this file reuses those
// vectors unchanged and adds the missing zero/two-response and
// list-codec/error-classification baselines.

#[test]
fn node_response_without_payload_has_independent_stable_vector() {
    let response: NodeResponse =
        NodeResponse::new(request(0x31), NodeResponseStatus::Rejected, None).unwrap();
    let encoded: Vec<u8> = response.encode().unwrap();

    assert_eq!(NodeResponse::decode(&encoded).unwrap(), response);
    assert_eq!(
        hex(&encoded),
        concat!(
            "534e524502e00100020001002000000031313131313131313131313131313131",
            "313131313131313131313131313131310200020000000200"
        )
    );
}

#[test]
fn node_response_decode_rejects_unknown_status() {
    let mut frame = CanonicalStruct::new(NODE_RESPONSE_TYPE_ID, ENCODING_VERSION);
    frame.field_bytes(1, [0x32; 32].to_vec()).unwrap();
    frame.field_u16(2, 0x00FF).unwrap();
    let bytes = frame.finish().unwrap();

    assert_eq!(
        NodeResponse::decode(&bytes).unwrap_err(),
        EnvelopeError::UnknownResponseStatus(0x00FF)
    );
}

#[test]
fn node_dedup_record_zero_responses_has_independent_stable_vector() {
    let request_id = request(0x41);
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x42; 32]);
    let dedup = NodeDedupRecord::new(request_id, digest, Vec::new()).unwrap();
    let encoded = dedup.encode().unwrap();

    assert_eq!(NodeDedupRecord::decode(&encoded).unwrap(), dedup);
    assert_eq!(
        hex(&encoded),
        concat!(
            "534e524503e00100050001002000000041414141414141414141414141414141",
            "4141414141414141414141414141414102000200000001000300200000004242",
            "4242424242424242424242424242424242424242424242424242424242420400",
            "0400000000000000050000000000"
        )
    );
}

#[test]
fn node_dedup_record_two_responses_has_independent_stable_vector() {
    let request_id = request(0x51);
    let digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x52; 32]);
    let payload = canonical(TEST_PAYLOAD_TYPE_ID, 11);
    let accepted = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
    let rejected = NodeResponse::new(
        request_id,
        NodeResponseStatus::Rejected,
        Some(payload.clone()),
    )
    .unwrap();
    let dedup =
        NodeDedupRecord::new(request_id, digest, vec![accepted.clone(), rejected.clone()]).unwrap();
    let encoded = dedup.encode().unwrap();

    assert_eq!(NodeDedupRecord::decode(&encoded).unwrap(), dedup);

    assert_eq!(
        hex(&encoded),
        concat!(
            "534e524503e00100050001002000000051515151515151515151515151515151",
            "5151515151515151515151515151515102000200000001000300200000005252",
            "5252525252525252525252525252525252525252525252525252525252520400",
            "040000000200000005009600000038000000534e524502e00100020001002000",
            "0000515151515151515151515151515151515151515151515151515151515151",
            "5151020002000000010056000000534e524502e0010003000100200000005151",
            "5151515151515151515151515151515151515151515151515151515151510200",
            "020000000200030018000000534e524502ef010001000100080000000b000000",
            "00000000"
        )
    );
}

#[test]
fn node_dedup_record_decode_rejects_truncated_response_list() {
    let mut frame = CanonicalStruct::new(NODE_DEDUP_RECORD_TYPE_ID, ENCODING_VERSION);
    frame.field_bytes(1, [0x61; 32].to_vec()).unwrap();
    frame
        .field_u16(2, HashAlgorithmId::Sha2_256.as_u16())
        .unwrap();
    frame.field_bytes(3, [0x62; 32].to_vec()).unwrap();
    frame.field_u32(4, 1).unwrap();
    // Declares one item but its length prefix claims more bytes than follow.
    let mut malformed_list = 99_u32.to_le_bytes().to_vec();
    malformed_list.extend_from_slice(&[0x01, 0x02]);
    frame.field_bytes(5, malformed_list).unwrap();
    let bytes = frame.finish().unwrap();

    assert!(matches!(
        NodeDedupRecord::decode(&bytes),
        Err(EnvelopeError::CanonicalDecoding(
            CanonicalDecodingError::Truncated { .. }
        ))
    ));
}

#[test]
fn node_dedup_record_decode_rejects_trailing_response_list_bytes() {
    let mut frame = CanonicalStruct::new(NODE_DEDUP_RECORD_TYPE_ID, ENCODING_VERSION);
    frame.field_bytes(1, [0x63; 32].to_vec()).unwrap();
    frame
        .field_u16(2, HashAlgorithmId::Sha2_256.as_u16())
        .unwrap();
    frame.field_bytes(3, [0x64; 32].to_vec()).unwrap();
    frame.field_u32(4, 0).unwrap();
    frame.field_bytes(5, vec![0xFF]).unwrap();
    let trailing_bytes = frame.finish().unwrap();

    assert_eq!(
        NodeDedupRecord::decode(&trailing_bytes),
        Err(EnvelopeError::TrailingNestedListBytes(1))
    );
}

#[test]
fn node_dedup_record_decode_rejects_response_count_over_the_shared_bound() {
    let mut frame = CanonicalStruct::new(NODE_DEDUP_RECORD_TYPE_ID, ENCODING_VERSION);
    frame.field_bytes(1, [0x65; 32].to_vec()).unwrap();
    frame
        .field_u16(2, HashAlgorithmId::Sha2_256.as_u16())
        .unwrap();
    frame.field_bytes(3, [0x66; 32].to_vec()).unwrap();
    let over = u32::try_from(MAX_NODE_OUTPUT_ITEMS + 1).unwrap();
    frame.field_u32(4, over).unwrap();
    frame.field_bytes(5, Vec::new()).unwrap();
    let overflow_bytes = frame.finish().unwrap();
    let expected_overflow_count = MAX_NODE_OUTPUT_ITEMS + 1;

    assert_eq!(
        NodeDedupRecord::decode(&overflow_bytes),
        Err(EnvelopeError::TooManyOutputItems {
            collection: "dedup responses",
            count: expected_overflow_count,
        })
    );
}

#[test]
fn node_dedup_record_decode_rejects_a_response_bound_to_another_request() {
    let outer_request = request(0x71);
    let inner_request = request(0x72);
    let inner_response =
        NodeResponse::new(inner_request, NodeResponseStatus::Accepted, None).unwrap();
    let inner_bytes = inner_response.encode().unwrap();

    let mut frame = CanonicalStruct::new(NODE_DEDUP_RECORD_TYPE_ID, ENCODING_VERSION);
    frame
        .field_bytes(1, outer_request.as_bytes().to_vec())
        .unwrap();
    frame
        .field_u16(2, HashAlgorithmId::Sha2_256.as_u16())
        .unwrap();
    frame.field_bytes(3, [0x73; 32].to_vec()).unwrap();
    frame.field_u32(4, 1).unwrap();
    let mut mismatch_list = u32::try_from(inner_bytes.len())
        .unwrap()
        .to_le_bytes()
        .to_vec();
    mismatch_list.extend_from_slice(&inner_bytes);
    frame.field_bytes(5, mismatch_list).unwrap();
    let mismatch_bytes = frame.finish().unwrap();

    assert_eq!(
        NodeDedupRecord::decode(&mismatch_bytes),
        Err(EnvelopeError::ResponseRequestMismatch {
            expected: outer_request,
            actual: inner_request,
        })
    );
}
