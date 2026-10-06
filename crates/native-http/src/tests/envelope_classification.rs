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
    MAX_NODE_OUTPUT_BYTES, MAX_NODE_OUTPUT_ITEMS, MAX_NODE_PAYLOAD_BYTES, MAX_NODE_STATE_BYTES,
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
    for (error, expected_status, expected_code) in cases {
        let response: Response = node_error_response(&error);
        assert_eq!(response.status(), expected_status, "error: {error:?}");
        let body: axum::body::Bytes = to_bytes(response.into_body(), 128).await.unwrap();
        assert_eq!(body, expected_code, "error: {error:?}");
    }
}
