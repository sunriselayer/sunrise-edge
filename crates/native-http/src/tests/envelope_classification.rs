// DR-0201 phase A baseline. Freezes `node_error_response`'s current
// classification for the envelope-construction/framing/bounds NodeCoreError
// subset DR-0201 identifies as migrating to a narrow `EnvelopeError`, so a
// later flattening conversion is checked against this evidence rather than
// assumed mechanical. In particular it pins that `PayloadTooLarge` (413) and
// `TooManyOutputItems`/`ResponseRequestMismatch` (500) stay distinct from the
// catch-all 400 `invalid-node-event` that every other envelope-framing
// variant below currently receives.

use super::*;
use canonical_encoding::CanonicalEncodingError;
use node_core::{
    EnvelopeError, MAX_NODE_OUTPUT_BYTES, MAX_NODE_OUTPUT_ITEMS, MAX_NODE_PAYLOAD_BYTES,
    MAX_NODE_STATE_BYTES,
};

#[tokio::test]
async fn native_error_mapping_keeps_envelope_framing_errors_distinct_from_bounds_errors() {
    let outer: RequestId = request_id(0x91);
    let inner: RequestId = request_id(0x92);
    let cases: Vec<(NodeCoreError, StatusCode, &'static str)> = vec![
        (
            NodeCoreError::UnknownEventKind(0xFFFF),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::InvalidChainId(protocol_types::TypeError::EmptyChainId),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::ChainIdTooLong(MAX_CHAIN_ID_BYTES + 1),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::ZeroRequestId,
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::InvalidRequestIdLength(31),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::UnknownResponseStatus(0xFFFF),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::CanonicalDecoding(CanonicalDecodingError::MissingField(1)),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::CanonicalEncoding(CanonicalEncodingError::DuplicateField(1)),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::PayloadTooLarge(MAX_NODE_PAYLOAD_BYTES + 1),
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload-too-large",
        ),
        (
            NodeCoreError::InvalidHashAlgorithm(protocol_types::TypeError::UnknownHashAlgorithmId(
                0xFFFF,
            )),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::InvalidDigestLength(31),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::StateTooLarge(MAX_NODE_STATE_BYTES + 1),
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::TooManyOutputItems {
                collection: "responses",
                count: MAX_NODE_OUTPUT_ITEMS + 1,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::OutputTooLarge(MAX_NODE_OUTPUT_BYTES + 1),
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::ResponseRequestMismatch {
                expected: outer,
                actual: inner,
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-node-output",
        ),
        (
            NodeCoreError::NestedItemLengthOverflow(usize::MAX),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
        (
            NodeCoreError::TrailingNestedListBytes(1),
            StatusCode::BAD_REQUEST,
            "invalid-node-event",
        ),
    ];
    assert_eq!(cases.len(), 17);
    let envelopes: Vec<EnvelopeError> = vec![
        EnvelopeError::UnknownEventKind(0xFFFF),
        EnvelopeError::InvalidChainId(protocol_types::TypeError::EmptyChainId),
        EnvelopeError::ChainIdTooLong(MAX_CHAIN_ID_BYTES + 1),
        EnvelopeError::ZeroRequestId,
        EnvelopeError::InvalidRequestIdLength(31),
        EnvelopeError::UnknownResponseStatus(0xFFFF),
        EnvelopeError::CanonicalDecoding(CanonicalDecodingError::MissingField(1)),
        EnvelopeError::CanonicalEncoding(CanonicalEncodingError::DuplicateField(1)),
        EnvelopeError::PayloadTooLarge(MAX_NODE_PAYLOAD_BYTES + 1),
        EnvelopeError::InvalidHashAlgorithm(protocol_types::TypeError::UnknownHashAlgorithmId(
            0xFFFF,
        )),
        EnvelopeError::InvalidDigestLength(31),
        EnvelopeError::StateTooLarge(MAX_NODE_STATE_BYTES + 1),
        EnvelopeError::TooManyOutputItems {
            collection: "responses",
            count: MAX_NODE_OUTPUT_ITEMS + 1,
        },
        EnvelopeError::OutputTooLarge(MAX_NODE_OUTPUT_BYTES + 1),
        EnvelopeError::ResponseRequestMismatch {
            expected: outer,
            actual: inner,
        },
        EnvelopeError::NestedItemLengthOverflow(usize::MAX),
        EnvelopeError::TrailingNestedListBytes(1),
    ];
    assert_eq!(envelopes.len(), cases.len());
    for (envelope, (error, expected_status, expected_code)) in envelopes.into_iter().zip(cases) {
        let mapped: NodeCoreError = NodeCoreError::from(envelope.clone());
        assert_eq!(mapped, error, "envelope: {envelope:?}");
        assert_eq!(envelope.to_string(), error.to_string());
        let response: Response = node_error_response(&mapped);
        assert_eq!(response.status(), expected_status, "error: {error:?}");
        let body: axum::body::Bytes = to_bytes(response.into_body(), 128).await.unwrap();
        assert_eq!(body, expected_code, "error: {error:?}");
        assert_eq!(
            query_node_error_response_parts(&mapped),
            (StatusCode::INTERNAL_SERVER_ERROR, "query-state-invalid"),
            "query conversion: {envelope:?}"
        );
    }
}

#[test]
fn receipt_query_encoding_failure_stays_in_the_existing_flat_node_category() {
    let id: RequestId = request_id(0x91);
    let mut payload: CanonicalStruct = CanonicalStruct::new(0xEF41, 1);
    // Two individually valid payloads keep aggregate payload admission below
    // 32MiB, while the persisted list's own framing exceeds its state budget.
    payload
        .field_bytes(1, vec![0xAA; MAX_NODE_PAYLOAD_BYTES - 66])
        .unwrap();
    let response: NodeResponse = NodeResponse::new(
        id,
        NodeResponseStatus::Accepted,
        Some(payload.finish().unwrap()),
    )
    .unwrap();
    let digest: Digest32 = Digest32::new(HashAlgorithmId::Sha2_256, [0x92; 32]);
    let record: NodeDedupRecord =
        NodeDedupRecord::new(id, digest, vec![response.clone(), response]).unwrap();
    let result: node_core::ReceiptQueryResult = node_core::ReceiptQueryResult::Present {
        request_id: id,
        event_digest: digest,
        record,
    };
    let refusal: QueryInvocationError = http_receipt_query_result(result)
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)
        .unwrap_err();
    match refusal {
        QueryInvocationError::Node(error) => {
            assert_eq!(
                error,
                NodeCoreError::StateTooLarge(MAX_NODE_STATE_BYTES + 32)
            );
            assert_eq!(
                query_node_error_response_parts(&error),
                (StatusCode::INTERNAL_SERVER_ERROR, "query-state-invalid")
            );
        }
        _ => panic!("receipt framing acquired a new host category"),
    }
}
