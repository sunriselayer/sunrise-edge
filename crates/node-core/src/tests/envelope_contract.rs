//! DR-0201 ownership and refusal-order tests, distinct from the pre-move vectors.

use super::*;
use crate::envelope::{
    NestedListDecodeError, decode_response_list, encode_response_list, validate_output_bytes,
};

fn digest() -> Digest32 {
    Digest32::new(HashAlgorithmId::Sha2_256, [0xA2; 32])
}

fn dedup_frame(request_bytes: Vec<u8>, algorithm: u16, count: u32, list: Vec<u8>) -> Vec<u8> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(NODE_DEDUP_RECORD_TYPE_ID, ENCODING_VERSION);
    frame.field_bytes(1, request_bytes).unwrap();
    frame.field_u16(2, algorithm).unwrap();
    frame.field_bytes(3, [0xA2; 32]).unwrap();
    frame.field_u32(4, count).unwrap();
    frame.field_bytes(5, list).unwrap();
    frame.finish().unwrap()
}

#[test]
fn dedup_constructor_checks_count_then_payload_total_then_request_binding() {
    let outer: RequestId = request(0xA1);
    let inner: RequestId = request(0xA3);
    let wrong: NodeResponse = NodeResponse::new(inner, NodeResponseStatus::Accepted, None).unwrap();
    assert_eq!(
        NodeDedupRecord::new(outer, digest(), vec![wrong; MAX_NODE_OUTPUT_ITEMS + 1]),
        Err(EnvelopeError::TooManyOutputItems {
            collection: "responses",
            count: MAX_NODE_OUTPUT_ITEMS + 1,
        })
    );

    // Each response is valid; the aggregate is not. A mismatched ID must not
    // replace the original aggregate refusal with a later binding error.
    let mut frame: CanonicalStruct = CanonicalStruct::new(TEST_PAYLOAD_TYPE_ID, 1);
    frame
        .field_bytes(1, vec![0xAA; MAX_NODE_PAYLOAD_BYTES / 2])
        .unwrap();
    let payload: Vec<u8> = frame.finish().unwrap();
    let total: usize = payload.len() * 4;
    let wrong: NodeResponse =
        NodeResponse::new(inner, NodeResponseStatus::Accepted, Some(payload)).unwrap();
    assert_eq!(
        NodeDedupRecord::new(outer, digest(), vec![wrong; 4]),
        Err(EnvelopeError::OutputTooLarge(total))
    );
    assert_eq!(
        validate_output_bytes([usize::MAX, 1].into_iter()),
        Err(EnvelopeError::OutputTooLarge(usize::MAX))
    );
}

#[test]
fn dedup_decode_checks_request_then_digest_then_count_before_list() {
    let count: u32 = u32::try_from(MAX_NODE_OUTPUT_ITEMS + 1).unwrap();
    let invalid: Vec<u8> = dedup_frame(vec![0; 31], 0xFFFF, count, vec![0xFF]);
    assert_eq!(
        NodeDedupRecord::decode(&invalid),
        Err(EnvelopeError::InvalidRequestIdLength(31))
    );
    let invalid: Vec<u8> = dedup_frame(vec![0xA1; 32], 0xFFFF, count, vec![0xFF]);
    assert_eq!(
        NodeDedupRecord::decode(&invalid),
        Err(EnvelopeError::InvalidHashAlgorithm(
            protocol_types::TypeError::UnknownHashAlgorithmId(0xFFFF)
        ))
    );
    let invalid: Vec<u8> = dedup_frame(vec![0xA1; 32], 1, count, vec![0xFF]);
    assert_eq!(
        NodeDedupRecord::decode(&invalid),
        Err(EnvelopeError::TooManyOutputItems {
            collection: "dedup responses",
            count: MAX_NODE_OUTPUT_ITEMS + 1,
        })
    );
}

#[test]
fn shared_list_distinguishes_list_framing_from_inner_envelope_framing() {
    assert_eq!(
        decode_response_list(&[], usize::MAX),
        Err(NestedListDecodeError::TooManyItems(usize::MAX))
    );
    let truncated: NestedListDecodeError = decode_response_list(&[1, 2], 1).unwrap_err();
    assert_eq!(
        truncated,
        NestedListDecodeError::Truncated {
            offset: 0,
            needed: 4,
            remaining: 2
        }
    );
    assert_eq!(
        EnvelopeError::from(truncated),
        EnvelopeError::CanonicalDecoding(CanonicalDecodingError::Truncated {
            offset: 0,
            needed: 4,
            remaining: 2
        })
    );
    let mut list: Vec<u8> = 3_u32.to_le_bytes().to_vec();
    list.extend_from_slice(&[1, 2, 3]);
    assert!(matches!(
        decode_response_list(&list, 1),
        Err(NestedListDecodeError::Item(
            EnvelopeError::CanonicalDecoding(_)
        ))
    ));
    assert_eq!(
        EnvelopeError::from(NestedListDecodeError::OffsetOverflow),
        EnvelopeError::NestedItemLengthOverflow(usize::MAX)
    );
}

#[test]
fn shared_response_encoder_uses_only_the_explicit_owning_budget() {
    let response: NodeResponse =
        NodeResponse::new(request(0xA1), NodeResponseStatus::Rejected, None).unwrap();
    let list: Vec<u8> = encode_response_list(std::slice::from_ref(&response), None).unwrap();
    assert_eq!(
        decode_response_list(&list, 1).unwrap(),
        vec![response.clone()]
    );
    assert_eq!(
        encode_response_list(std::slice::from_ref(&response), Some(list.len())).unwrap(),
        list
    );
    assert_eq!(
        encode_response_list(&[response], Some(list.len() - 1)),
        Err(EnvelopeError::StateTooLarge(list.len()))
    );
}
