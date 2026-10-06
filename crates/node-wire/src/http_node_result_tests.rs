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
        Err(HttpContractError::NodeCore(
            NodeCoreError::UnknownResponseStatus(0x00FF)
        ))
    );
}
