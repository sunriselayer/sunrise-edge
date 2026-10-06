// DR-0201 phase A baseline. These tests freeze `HttpNodeResult`'s
// zero/one/two-response canonical bytes *before* any envelope/acknowledgement
// ownership migration. `HttpNodeResult` has no prior stable-vector test;
// every vector here is new.
//
// Expected byte strings are fixed literals from the wire-format
// specification (the canonical-encoding magic, then little-endian
// `type_id`, `version`, `field_count`, then one `field_id`(u16) +
// `length`(u32) + content per field, in ascending field-id order),
// independent of the `encode`/`decode` implementations under test.
// Node-wire cannot see node-core's private `NODE_RESPONSE_TYPE_ID`/
// `ENCODING_VERSION`, so the nested `NodeResponse` type id (0xE002) and
// encoding version (1) are reconstructed as literal constants below.

use super::*;
use node_core::NodeResponseStatus;

const NODE_RESPONSE_WIRE_TYPE_ID: u16 = 0xE002;
const NODE_RESPONSE_WIRE_VERSION: u16 = 1;
const PAYLOAD_WIRE_TYPE_ID: u16 = 0xEF41;

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn payload_frame(value: u64) -> Vec<u8> {
    let mut frame = CanonicalStruct::new(PAYLOAD_WIRE_TYPE_ID, 1);
    frame.field_u64(1, value).unwrap();
    frame.finish().unwrap()
}

#[test]
fn http_node_result_zero_responses_has_independent_stable_vector() {
    let request_id = RequestId::new([0x81; 32]).unwrap();
    let result = HttpNodeResult::new(request_id, Vec::new()).unwrap();
    let encoded = result.encode().unwrap();

    assert_eq!(HttpNodeResult::decode(&encoded).unwrap(), result);
    assert_eq!(
        hex_string(&encoded),
        concat!(
            "534e524501e10100030001002000000081818181818181818181818181818181",
            "8181818181818181818181818181818102000400000000000000030000000000"
        )
    );
}

#[test]
fn http_node_result_one_response_has_independent_stable_vector() {
    let request_id = RequestId::new([0x82; 32]).unwrap();
    let response = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
    let result = HttpNodeResult::new(request_id, vec![response]).unwrap();
    let encoded = result.encode().unwrap();

    assert_eq!(HttpNodeResult::decode(&encoded).unwrap(), result);

    assert_eq!(
        hex_string(&encoded),
        concat!(
            "534e524501e10100030001002000000082828282828282828282828282828282",
            "828282828282828282828282828282820200040000000100000003003c000000",
            "38000000534e524502e001000200010020000000828282828282828282828282",
            "82828282828282828282828282828282828282820200020000000100"
        )
    );
}

#[test]
fn http_node_result_two_responses_has_independent_stable_vector() {
    let request_id = RequestId::new([0x83; 32]).unwrap();
    let payload = payload_frame(9);
    let accepted = NodeResponse::new(request_id, NodeResponseStatus::Accepted, None).unwrap();
    let rejected = NodeResponse::new(
        request_id,
        NodeResponseStatus::Rejected,
        Some(payload.clone()),
    )
    .unwrap();
    let result = HttpNodeResult::new(request_id, vec![accepted, rejected]).unwrap();
    let encoded = result.encode().unwrap();

    assert_eq!(HttpNodeResult::decode(&encoded).unwrap(), result);

    assert_eq!(
        hex_string(&encoded),
        concat!(
            "534e524501e10100030001002000000083838383838383838383838383838383",
            "8383838383838383838383838383838302000400000002000000030096000000",
            "38000000534e524502e001000200010020000000838383838383838383838383",
            "8383838383838383838383838383838383838383020002000000010056000000",
            "534e524502e00100030001002000000083838383838383838383838383838383",
            "838383838383838383838383838383830200020000000200030018000000534e",
            "524541ef010001000100080000000900000000000000"
        )
    );
}

#[test]
fn http_node_result_decode_rejects_response_count_over_the_shared_bound() {
    let mut frame = CanonicalStruct::new(HTTP_RESULT_TYPE_ID, HTTP_RESULT_ENCODING_VERSION);
    frame.field_bytes(1, [0x84; 32].to_vec()).unwrap();
    let over = u32::try_from(MAX_NODE_OUTPUT_ITEMS + 1).unwrap();
    frame.field_u32(2, over).unwrap();
    frame.field_bytes(3, Vec::new()).unwrap();
    let bytes = frame.finish().unwrap();

    assert_eq!(
        HttpNodeResult::decode(&bytes),
        Err(HttpContractError::TooManyResponses(
            MAX_NODE_OUTPUT_ITEMS + 1
        ))
    );
}

#[test]
fn http_node_result_new_rejects_a_response_bound_to_another_request() {
    let outer = RequestId::new([0x85; 32]).unwrap();
    let inner = RequestId::new([0x86; 32]).unwrap();
    let response = NodeResponse::new(inner, NodeResponseStatus::Accepted, None).unwrap();

    assert_eq!(
        HttpNodeResult::new(outer, vec![response]),
        Err(HttpContractError::RequestMismatch {
            expected: outer,
            actual: inner,
        })
    );
}

#[test]
fn http_node_result_decode_rejects_truncated_response_list() {
    let mut frame = CanonicalStruct::new(HTTP_RESULT_TYPE_ID, HTTP_RESULT_ENCODING_VERSION);
    frame.field_bytes(1, [0x87; 32].to_vec()).unwrap();
    frame.field_u32(2, 1).unwrap();
    let mut malformed_list = 99_u32.to_le_bytes().to_vec();
    malformed_list.extend_from_slice(&[0x01, 0x02]);
    frame.field_bytes(3, malformed_list).unwrap();
    let bytes = frame.finish().unwrap();

    assert_eq!(
        HttpNodeResult::decode(&bytes),
        Err(HttpContractError::TruncatedResponseList)
    );
}

#[test]
fn http_node_result_decode_rejects_trailing_response_list_bytes() {
    let mut frame = CanonicalStruct::new(HTTP_RESULT_TYPE_ID, HTTP_RESULT_ENCODING_VERSION);
    frame.field_bytes(1, [0x88; 32].to_vec()).unwrap();
    frame.field_u32(2, 0).unwrap();
    frame.field_bytes(3, vec![0xFF]).unwrap();
    let bytes = frame.finish().unwrap();

    assert_eq!(
        HttpNodeResult::decode(&bytes),
        Err(HttpContractError::TrailingResponseListBytes(1))
    );
}

#[test]
fn http_node_result_decode_rejects_invalid_request_id_length() {
    let mut frame = CanonicalStruct::new(HTTP_RESULT_TYPE_ID, HTTP_RESULT_ENCODING_VERSION);
    frame.field_bytes(1, vec![0x89; 31]).unwrap();
    frame.field_u32(2, 0).unwrap();
    frame.field_bytes(3, Vec::new()).unwrap();
    let bytes = frame.finish().unwrap();

    assert_eq!(
        HttpNodeResult::decode(&bytes),
        Err(HttpContractError::InvalidRequestIdLength(31))
    );
}

#[test]
fn http_node_result_decode_propagates_a_malformed_nested_response() {
    let mut inner = CanonicalStruct::new(NODE_RESPONSE_WIRE_TYPE_ID, NODE_RESPONSE_WIRE_VERSION);
    inner.field_bytes(1, [0x8A; 32].to_vec()).unwrap();
    inner.field_u16(2, 0x00FF).unwrap();
    let inner_bytes = inner.finish().unwrap();

    let mut frame = CanonicalStruct::new(HTTP_RESULT_TYPE_ID, HTTP_RESULT_ENCODING_VERSION);
    frame.field_bytes(1, [0x8A; 32].to_vec()).unwrap();
    frame.field_u32(2, 1).unwrap();
    let mut list = u32::try_from(inner_bytes.len())
        .unwrap()
        .to_le_bytes()
        .to_vec();
    list.extend_from_slice(&inner_bytes);
    frame.field_bytes(3, list).unwrap();
    let bytes = frame.finish().unwrap();

    assert_eq!(
        HttpNodeResult::decode(&bytes),
        Err(HttpContractError::Envelope(
            EnvelopeError::UnknownResponseStatus(0x00FF)
        ))
    );
}

fn raw_result(outer: RequestId, responses: &[NodeResponse]) -> Vec<u8> {
    let mut list: Vec<u8> = Vec::new();
    for response in responses {
        let bytes: Vec<u8> = response.encode().unwrap();
        list.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
        list.extend_from_slice(&bytes);
    }
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(HTTP_RESULT_TYPE_ID, HTTP_RESULT_ENCODING_VERSION);
    frame.field_bytes(1, outer.as_bytes().to_vec()).unwrap();
    frame
        .field_u32(2, u32::try_from(responses.len()).unwrap())
        .unwrap();
    frame.field_bytes(3, list).unwrap();
    frame.finish().unwrap()
}

#[test]
fn outer_bound_generic_result_preserves_zero_and_multiple_responses() {
    let id: RequestId = RequestId::new([0x8B; 32]).unwrap();
    let response: NodeResponse = NodeResponse::new(id, NodeResponseStatus::Rejected, None).unwrap();
    for responses in [vec![], vec![response.clone(), response]] {
        let result: HttpNodeResult = HttpNodeResult::new(id, responses).unwrap();
        let bound: BoundHttpNodeResult =
            HttpNodeResult::decode_bound(&result.encode().unwrap(), id).unwrap();
        assert_eq!(bound.into_result(), result);
    }
}

#[test]
fn outer_binding_keeps_nested_id_failure_before_outer_mismatch() {
    let expected: RequestId = RequestId::new([0x8B; 32]).unwrap();
    let outer: RequestId = RequestId::new([0x8C; 32]).unwrap();
    let inner: RequestId = RequestId::new([0x8D; 32]).unwrap();
    let response: NodeResponse =
        NodeResponse::new(inner, NodeResponseStatus::Accepted, Some(payload_frame(7))).unwrap();
    assert_eq!(
        HttpNodeResult::decode_bound(&raw_result(outer, &[response]), expected),
        Err(HttpResultBindingError::Contract(
            HttpContractError::RequestMismatch {
                expected: outer,
                actual: inner
            }
        ))
    );
    assert_eq!(
        HttpNodeResult::decode_bound(&raw_result(outer, &[]), expected),
        Err(HttpResultBindingError::RequestMismatch {
            expected,
            actual: outer
        })
    );
}

#[test]
fn single_ack_view_checks_only_cardinality_and_payload_presence() {
    let id: RequestId = RequestId::new([0x8B; 32]).unwrap();
    let payload: Vec<u8> = payload_frame(7);
    let rejected: NodeResponse =
        NodeResponse::new(id, NodeResponseStatus::Rejected, Some(payload.clone())).unwrap();
    let bound: BoundHttpNodeResult = HttpNodeResult::new(id, vec![rejected.clone()])
        .unwrap()
        .bind_request(id)
        .unwrap();
    let acknowledgement: SingleAcknowledgement<'_> = bound.single_acknowledgement().unwrap();
    // A syntactic view must never reinterpret Rejected as successful authority.
    assert_eq!(acknowledgement.status(), NodeResponseStatus::Rejected);
    assert_eq!(acknowledgement.payload(), payload);
    for (responses, expected) in [
        (vec![], SingleAcknowledgementError::ResponseCount(0)),
        (
            vec![rejected.clone(), rejected],
            SingleAcknowledgementError::ResponseCount(2),
        ),
        (
            vec![NodeResponse::new(id, NodeResponseStatus::Accepted, None).unwrap()],
            SingleAcknowledgementError::MissingPayload,
        ),
    ] {
        let bound: BoundHttpNodeResult = HttpNodeResult::new(id, responses)
            .unwrap()
            .bind_request(id)
            .unwrap();
        assert_eq!(bound.single_acknowledgement().unwrap_err(), expected);
    }
}

#[test]
fn shared_list_preserves_http_list_and_nested_item_error_categories() {
    assert_eq!(
        HttpContractError::from(NestedListDecodeError::OffsetOverflow),
        HttpContractError::TruncatedResponseList
    );
    assert_eq!(
        HttpContractError::from(NestedListDecodeError::LengthOverflow(usize::MAX)),
        HttpContractError::ResponseLengthOverflow(usize::MAX)
    );
    let mut list: Vec<u8> = 3_u32.to_le_bytes().to_vec();
    list.extend_from_slice(&[1, 2, 3]);
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(HTTP_RESULT_TYPE_ID, HTTP_RESULT_ENCODING_VERSION);
    frame.field_bytes(1, [0x8B; 32]).unwrap();
    frame.field_u32(2, 1).unwrap();
    frame.field_bytes(3, list).unwrap();
    assert!(matches!(
        HttpNodeResult::decode(&frame.finish().unwrap()),
        Err(HttpContractError::Envelope(
            EnvelopeError::CanonicalDecoding(_)
        ))
    ));
}

fn sized_payload(length: usize) -> Vec<u8> {
    // One-field canonical payload: 10-byte header and 6-byte field framing.
    let mut frame: CanonicalStruct = CanonicalStruct::new(PAYLOAD_WIRE_TYPE_ID, 1);
    frame.field_bytes(1, vec![0xAA; length - 16]).unwrap();
    let bytes: Vec<u8> = frame.finish().unwrap();
    assert_eq!(bytes.len(), length);
    bytes
}

#[test]
fn http_encoding_retains_canonical_frame_bound_not_a_new_state_budget() {
    use canonical_encoding::MAX_CANONICAL_FRAME_BYTES;
    use node_core::MAX_NODE_PAYLOAD_BYTES;

    let id: RequestId = RequestId::new([0x8B; 32]).unwrap();
    // The HTTP frame has 64 bytes of outer framing; each of these two
    // payload-bearing responses adds 62 bytes plus its four-byte list length.
    // This independently specified 196-byte overhead places the result at
    // the actual canonical frame limit, not a fictitious >32MiB valid frame.
    let payload: Vec<u8> = sized_payload((MAX_CANONICAL_FRAME_BYTES - 196) / 2);
    let response: NodeResponse =
        NodeResponse::new(id, NodeResponseStatus::Accepted, Some(payload)).unwrap();
    let result: HttpNodeResult = HttpNodeResult::new(id, vec![response.clone(), response]).unwrap();
    let encoded: Vec<u8> = result.encode().unwrap();
    assert_eq!(encoded.len(), MAX_CANONICAL_FRAME_BYTES);
    assert_eq!(HttpNodeResult::decode(&encoded).unwrap(), result);
    drop(encoded);
    drop(result);

    let response: NodeResponse = NodeResponse::new(
        id,
        NodeResponseStatus::Accepted,
        Some(sized_payload(MAX_NODE_PAYLOAD_BYTES)),
    )
    .unwrap();
    let result: HttpNodeResult = HttpNodeResult::new(id, vec![response.clone(), response]).unwrap();
    assert_eq!(
        result.encode(),
        Err(HttpContractError::CanonicalEncoding(
            CanonicalEncodingError::FrameTooLarge(MAX_CANONICAL_FRAME_BYTES + 196)
        ))
    );
}
