//! Bounded adapter-local split/merge preimages (DR-0249), kind 3. No
//! supplied frame is signable; this never changes the kind 1 publication or
//! kind 2 transfer wire formats.
//!
//! One message kind carries two closed operation tags (`split`/`merge`)
//! rather than two separate message kinds, since both share the same
//! owned-coin trust and fee shape; each tag has its own fixed header layout
//! and object count, and an unknown tag is refused exactly like an unknown
//! message kind.

use super::asset_split_merge::{AssetMergeRequest, AssetSplitMergeRequest, AssetSplitRequest};
use super::wire::{CUSTODY_WIRE_VERSION, CustodyWireError};
use sunrise_edge_client::{MAX_AUTHENTICATED_OBJECT_BODY_BYTES, RequestId};

/// The one currently supported split/merge message kind.
pub(super) const SIGN_SPLIT_MERGE_MESSAGE: u8 = 3;
/// Closed operation tag: split one owned coin.
pub(super) const SPLIT_OPERATION_TAG: u8 = 1;
/// Closed operation tag: merge a distinct owned source coin into a
/// destination coin.
pub(super) const MERGE_OPERATION_TAG: u8 = 2;

/// version(1) + message kind(1) + operation tag(1) + nonce(8) +
/// request_id(32) + max_fee(8) + gas_limit(8), common to both operations.
const COMMON_HEADER_BYTES: usize = 1 + 1 + 1 + 8 + 32 + 8 + 8;
/// `split`'s own trailing fixed fields: amount(8) + recipient(32) +
/// coin_len(4) + fee_len(4).
const SPLIT_HEADER_BYTES: usize = COMMON_HEADER_BYTES + 8 + 32 + 4 + 4;
/// `merge`'s own trailing fixed fields: into_len(4) + from_len(4) +
/// fee_len(4).
const MERGE_HEADER_BYTES: usize = COMMON_HEADER_BYTES + 4 + 4 + 4;

/// Merge's three bounded objects dominate split's two within the existing
/// transport length-prefix cap; valid Coin bodies are small in practice.
pub(super) const MAX_REQUEST_BYTES: usize =
    MERGE_HEADER_BYTES + 3 * MAX_AUTHENTICATED_OBJECT_BODY_BYTES;

fn checked_object_length(bytes: &[u8]) -> Result<u32, CustodyWireError> {
    if bytes.len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
        return Err(CustodyWireError::ArtifactTooLarge {
            actual: bytes.len(),
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        });
    }
    u32::try_from(bytes.len()).map_err(|_| CustodyWireError::ArtifactTooLarge {
        actual: bytes.len(),
        maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
    })
}

fn read_request_id(bytes: &[u8]) -> Result<RequestId, CustodyWireError> {
    let mut id = [0_u8; 32];
    id.copy_from_slice(bytes);
    RequestId::new(id).map_err(CustodyWireError::RequestId)
}

fn read_u32(bytes: &[u8]) -> Result<usize, CustodyWireError> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| CustodyWireError::Truncated)?) as usize)
}

fn read_u64(bytes: &[u8]) -> Result<u64, CustodyWireError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| CustodyWireError::Truncated)?,
    ))
}

/// Encodes one [`AssetSplitMergeRequest`] to its exact bounded, versioned,
/// tagged, length-framed inner bytes (without the outer transport length
/// prefix).
pub(super) fn encode(request: &AssetSplitMergeRequest) -> Result<Vec<u8>, CustodyWireError> {
    match request {
        AssetSplitMergeRequest::Split(request) => encode_split(request),
        AssetSplitMergeRequest::Merge(request) => encode_merge(request),
    }
}

fn encode_split(request: &AssetSplitRequest) -> Result<Vec<u8>, CustodyWireError> {
    let coin_len = checked_object_length(&request.coin_bytes)?;
    let fee_len = checked_object_length(&request.fee_bytes)?;
    let mut out =
        Vec::with_capacity(SPLIT_HEADER_BYTES + request.coin_bytes.len() + request.fee_bytes.len());
    out.push(CUSTODY_WIRE_VERSION);
    out.push(SIGN_SPLIT_MERGE_MESSAGE);
    out.push(SPLIT_OPERATION_TAG);
    out.extend_from_slice(&request.nonce.to_be_bytes());
    out.extend_from_slice(request.request_id.as_bytes());
    out.extend_from_slice(&request.max_fee.to_be_bytes());
    out.extend_from_slice(&request.gas_limit.to_be_bytes());
    out.extend_from_slice(&request.amount.to_be_bytes());
    out.extend_from_slice(&request.recipient);
    out.extend_from_slice(&coin_len.to_be_bytes());
    out.extend_from_slice(&fee_len.to_be_bytes());
    out.extend_from_slice(&request.coin_bytes);
    out.extend_from_slice(&request.fee_bytes);
    Ok(out)
}

fn encode_merge(request: &AssetMergeRequest) -> Result<Vec<u8>, CustodyWireError> {
    let into_len = checked_object_length(&request.into_bytes)?;
    let from_len = checked_object_length(&request.from_bytes)?;
    let fee_len = checked_object_length(&request.fee_bytes)?;
    let mut out = Vec::with_capacity(
        MERGE_HEADER_BYTES
            + request.into_bytes.len()
            + request.from_bytes.len()
            + request.fee_bytes.len(),
    );
    out.push(CUSTODY_WIRE_VERSION);
    out.push(SIGN_SPLIT_MERGE_MESSAGE);
    out.push(MERGE_OPERATION_TAG);
    out.extend_from_slice(&request.nonce.to_be_bytes());
    out.extend_from_slice(request.request_id.as_bytes());
    out.extend_from_slice(&request.max_fee.to_be_bytes());
    out.extend_from_slice(&request.gas_limit.to_be_bytes());
    out.extend_from_slice(&into_len.to_be_bytes());
    out.extend_from_slice(&from_len.to_be_bytes());
    out.extend_from_slice(&fee_len.to_be_bytes());
    out.extend_from_slice(&request.into_bytes);
    out.extend_from_slice(&request.from_bytes);
    out.extend_from_slice(&request.fee_bytes);
    Ok(out)
}

/// Decodes and strictly bounds one [`AssetSplitMergeRequest`]; rejects an
/// unknown version/message kind/operation tag and any trailing or short
/// bytes.
pub(super) fn decode(bytes: &[u8]) -> Result<AssetSplitMergeRequest, CustodyWireError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_REQUEST_BYTES,
        });
    }
    if bytes.len() < COMMON_HEADER_BYTES {
        return Err(CustodyWireError::Truncated);
    }
    if bytes[0] != CUSTODY_WIRE_VERSION {
        return Err(CustodyWireError::UnsupportedVersion(bytes[0]));
    }
    if bytes[1] != SIGN_SPLIT_MERGE_MESSAGE {
        return Err(CustodyWireError::UnsupportedMessageType(bytes[1]));
    }
    let tag = bytes[2];
    let nonce = read_u64(&bytes[3..11])?;
    let request_id = read_request_id(&bytes[11..43])?;
    let max_fee = read_u64(&bytes[43..51])?;
    let gas_limit = read_u64(&bytes[51..59])?;
    match tag {
        SPLIT_OPERATION_TAG => decode_split(bytes, nonce, request_id, max_fee, gas_limit),
        MERGE_OPERATION_TAG => decode_merge(bytes, nonce, request_id, max_fee, gas_limit),
        other => Err(CustodyWireError::UnsupportedMessageType(other)),
    }
}

fn decode_split(
    bytes: &[u8],
    nonce: u64,
    request_id: RequestId,
    max_fee: u64,
    gas_limit: u64,
) -> Result<AssetSplitMergeRequest, CustodyWireError> {
    if bytes.len() < SPLIT_HEADER_BYTES {
        return Err(CustodyWireError::Truncated);
    }
    let amount = read_u64(&bytes[59..67])?;
    let mut recipient = [0_u8; 32];
    recipient.copy_from_slice(&bytes[67..99]);
    let coin_len = read_u32(&bytes[99..103])?;
    let fee_len = read_u32(&bytes[103..107])?;
    for length in [coin_len, fee_len] {
        if length > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
            return Err(CustodyWireError::ArtifactTooLarge {
                actual: length,
                maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            });
        }
    }
    let declared = SPLIT_HEADER_BYTES
        .checked_add(coin_len)
        .and_then(|value| value.checked_add(fee_len))
        .ok_or(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_REQUEST_BYTES,
        })?;
    if bytes.len() != declared {
        return Err(CustodyWireError::LengthMismatch {
            declared,
            actual: bytes.len(),
        });
    }
    let coin_bytes = bytes[SPLIT_HEADER_BYTES..SPLIT_HEADER_BYTES + coin_len].to_vec();
    let fee_bytes = bytes[SPLIT_HEADER_BYTES + coin_len..].to_vec();
    Ok(AssetSplitMergeRequest::Split(Box::new(AssetSplitRequest {
        coin_bytes,
        fee_bytes,
        amount,
        recipient,
        nonce,
        request_id,
        max_fee,
        gas_limit,
    })))
}

fn decode_merge(
    bytes: &[u8],
    nonce: u64,
    request_id: RequestId,
    max_fee: u64,
    gas_limit: u64,
) -> Result<AssetSplitMergeRequest, CustodyWireError> {
    if bytes.len() < MERGE_HEADER_BYTES {
        return Err(CustodyWireError::Truncated);
    }
    let into_len = read_u32(&bytes[59..63])?;
    let from_len = read_u32(&bytes[63..67])?;
    let fee_len = read_u32(&bytes[67..71])?;
    for length in [into_len, from_len, fee_len] {
        if length > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
            return Err(CustodyWireError::ArtifactTooLarge {
                actual: length,
                maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            });
        }
    }
    let declared = MERGE_HEADER_BYTES
        .checked_add(into_len)
        .and_then(|value| value.checked_add(from_len))
        .and_then(|value| value.checked_add(fee_len))
        .ok_or(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_REQUEST_BYTES,
        })?;
    if bytes.len() != declared {
        return Err(CustodyWireError::LengthMismatch {
            declared,
            actual: bytes.len(),
        });
    }
    let into_bytes = bytes[MERGE_HEADER_BYTES..MERGE_HEADER_BYTES + into_len].to_vec();
    let from_bytes =
        bytes[MERGE_HEADER_BYTES + into_len..MERGE_HEADER_BYTES + into_len + from_len].to_vec();
    let fee_bytes = bytes[MERGE_HEADER_BYTES + into_len + from_len..].to_vec();
    Ok(AssetSplitMergeRequest::Merge(Box::new(AssetMergeRequest {
        into_bytes,
        from_bytes,
        fee_bytes,
        nonce,
        request_id,
        max_fee,
        gas_limit,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_id(byte: u8) -> RequestId {
        RequestId::new([byte; 32]).unwrap()
    }

    fn split_sample() -> AssetSplitMergeRequest {
        AssetSplitMergeRequest::Split(Box::new(AssetSplitRequest {
            coin_bytes: vec![1, 2, 3],
            fee_bytes: vec![4, 5],
            amount: 7,
            recipient: [9; 32],
            nonce: 23,
            request_id: request_id(7),
            max_fee: 17,
            gas_limit: 8000,
        }))
    }

    fn merge_sample() -> AssetSplitMergeRequest {
        AssetSplitMergeRequest::Merge(Box::new(AssetMergeRequest {
            into_bytes: vec![1, 2],
            from_bytes: vec![3, 4, 5],
            fee_bytes: vec![6],
            nonce: 9,
            request_id: request_id(8),
            max_fee: 3,
            gas_limit: 500,
        }))
    }

    #[test]
    fn split_strict_roundtrip_and_foreign_family_refusal() {
        let request = split_sample();
        let bytes = encode(&request).unwrap();
        assert_eq!(decode(&bytes).unwrap(), request);
        assert!(super::super::wire::decode_request(&bytes).is_err());
        assert!(super::super::asset_wire::decode(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }

    #[test]
    fn merge_strict_roundtrip_and_foreign_family_refusal() {
        let request = merge_sample();
        let bytes = encode(&request).unwrap();
        assert_eq!(decode(&bytes).unwrap(), request);
        assert!(super::super::wire::decode_request(&bytes).is_err());
        assert!(super::super::asset_wire::decode(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }

    #[test]
    fn decode_rejects_an_unsupported_version_or_message_kind() {
        let bytes = encode(&split_sample()).unwrap();
        let mut unknown_version = bytes.clone();
        unknown_version[0] = 9;
        assert!(matches!(
            decode(&unknown_version),
            Err(CustodyWireError::UnsupportedVersion(9))
        ));
        // Kind 1 (publication).
        let mut publication_kind = bytes.clone();
        publication_kind[1] = 1;
        assert!(matches!(
            decode(&publication_kind),
            Err(CustodyWireError::UnsupportedMessageType(1))
        ));
        // Kind 2 (transfer): the kind-3 decoder must refuse this family's own
        // sibling message kind exactly like any other unknown kind.
        let mut transfer_kind = bytes;
        transfer_kind[1] = 2;
        assert!(matches!(
            decode(&transfer_kind),
            Err(CustodyWireError::UnsupportedMessageType(2))
        ));
    }

    #[test]
    fn decode_rejects_an_unknown_operation_tag() {
        let mut bytes = encode(&split_sample()).unwrap();
        bytes[2] = 0xEE;
        assert!(matches!(
            decode(&bytes),
            Err(CustodyWireError::UnsupportedMessageType(0xEE))
        ));
    }

    #[test]
    fn decode_rejects_a_declared_length_longer_than_actual_bytes() {
        let mut split_bytes = encode(&split_sample()).unwrap();
        split_bytes[99..103].copy_from_slice(&100_u32.to_be_bytes());
        assert!(matches!(
            decode(&split_bytes),
            Err(CustodyWireError::LengthMismatch { .. })
        ));

        let mut merge_bytes = encode(&merge_sample()).unwrap();
        merge_bytes[59..63].copy_from_slice(&100_u32.to_be_bytes());
        assert!(matches!(
            decode(&merge_bytes),
            Err(CustodyWireError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn decode_rejects_an_object_length_over_the_bound() {
        let mut split_bytes = encode(&split_sample()).unwrap();
        split_bytes[99..103]
            .copy_from_slice(&(MAX_AUTHENTICATED_OBJECT_BODY_BYTES as u32 + 1).to_be_bytes());
        assert!(matches!(
            decode(&split_bytes),
            Err(CustodyWireError::ArtifactTooLarge { .. })
        ));
    }

    #[test]
    fn decode_rejects_a_zero_request_id() {
        let mut bytes = encode(&split_sample()).unwrap();
        bytes[11..43].copy_from_slice(&[0_u8; 32]);
        assert!(matches!(
            decode(&bytes),
            Err(CustodyWireError::RequestId(_))
        ));
    }

    /// Stable encoding vector: a fixed, pinned-byte split request. A change
    /// to this byte layout is an adapter wire-format break.
    #[test]
    fn split_encoding_is_stable() {
        let request = split_sample();
        let encoded = encode(&request).unwrap();
        let mut expected = vec![
            CUSTODY_WIRE_VERSION,
            SIGN_SPLIT_MERGE_MESSAGE,
            SPLIT_OPERATION_TAG,
        ];
        expected.extend_from_slice(&23_u64.to_be_bytes());
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&17_u64.to_be_bytes());
        expected.extend_from_slice(&8000_u64.to_be_bytes());
        expected.extend_from_slice(&7_u64.to_be_bytes());
        expected.extend_from_slice(&[9; 32]);
        expected.extend_from_slice(&3_u32.to_be_bytes());
        expected.extend_from_slice(&2_u32.to_be_bytes());
        expected.extend_from_slice(&[1, 2, 3]);
        expected.extend_from_slice(&[4, 5]);
        assert_eq!(encoded, expected);
    }

    /// Stable encoding vector: a fixed, pinned-byte merge request.
    #[test]
    fn merge_encoding_is_stable() {
        let request = merge_sample();
        let encoded = encode(&request).unwrap();
        let mut expected = vec![
            CUSTODY_WIRE_VERSION,
            SIGN_SPLIT_MERGE_MESSAGE,
            MERGE_OPERATION_TAG,
        ];
        expected.extend_from_slice(&9_u64.to_be_bytes());
        expected.extend_from_slice(&[8; 32]);
        expected.extend_from_slice(&3_u64.to_be_bytes());
        expected.extend_from_slice(&500_u64.to_be_bytes());
        expected.extend_from_slice(&2_u32.to_be_bytes());
        expected.extend_from_slice(&3_u32.to_be_bytes());
        expected.extend_from_slice(&1_u32.to_be_bytes());
        expected.extend_from_slice(&[1, 2]);
        expected.extend_from_slice(&[3, 4, 5]);
        expected.extend_from_slice(&[6]);
        assert_eq!(encoded, expected);
    }
}
