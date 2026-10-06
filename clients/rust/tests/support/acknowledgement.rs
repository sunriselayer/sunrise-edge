// Shared untrusted-input construction only. Each SDK family retains its own
// semantic fixture, expected result and refusal assertions; this is not an oracle.
use canonical_encoding::CanonicalStruct;
use node_core::{NodeResponse, NodeResponseStatus, RequestId};
use node_wire::HttpNodeResult;

#[derive(Clone, Copy, Debug)]
pub enum AckShape {
    Exact,
    OuterMismatch,
    NestedMismatch,
    Zero,
    Two,
    MissingPayload,
}

pub const ACK_SHAPES: [AckShape; 6] = [
    AckShape::Exact,
    AckShape::OuterMismatch,
    AckShape::NestedMismatch,
    AckShape::Zero,
    AckShape::Two,
    AckShape::MissingPayload,
];

pub fn acknowledgement_bytes(
    id: RequestId,
    status: NodeResponseStatus,
    payload: &[u8],
    shape: AckShape,
) -> Vec<u8> {
    let other: RequestId = RequestId::new([0xFA; 32]).unwrap();
    assert_ne!(id, other);
    let response: NodeResponse = NodeResponse::new(
        if matches!(shape, AckShape::NestedMismatch) {
            other
        } else {
            id
        },
        status,
        if matches!(shape, AckShape::MissingPayload) {
            None
        } else {
            Some(payload.to_vec())
        },
    )
    .unwrap();
    if matches!(shape, AckShape::NestedMismatch) {
        // Bypass only the trusted constructor to model an untrusted server's
        // nested-ID forgery. The ordinary HTTP decoder must reject this before
        // any family-specific payload interpretation.
        let bytes: Vec<u8> = response.encode().unwrap();
        let mut list: Vec<u8> = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
        list.extend_from_slice(&bytes);
        let mut frame: CanonicalStruct = CanonicalStruct::new(0xE101, 1);
        frame.field_bytes(1, id.as_bytes().to_vec()).unwrap();
        frame.field_u32(2, 1).unwrap();
        frame.field_bytes(3, list).unwrap();
        return frame.finish().unwrap();
    }
    let outer: RequestId = if matches!(shape, AckShape::OuterMismatch) {
        other
    } else {
        id
    };
    let responses: Vec<NodeResponse> = match shape {
        AckShape::OuterMismatch => vec![],
        AckShape::Zero => vec![],
        AckShape::Two => vec![response.clone(), response],
        _ => vec![response],
    };
    HttpNodeResult::new(outer, responses)
        .unwrap()
        .encode()
        .unwrap()
}
