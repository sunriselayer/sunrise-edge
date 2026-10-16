//! Bounded adapter-local mint/burn preimages (DR-0253), kind 4. No supplied
//! frame is signable; this never changes the kind 1 publication, kind 2
//! transfer, or kind 3 split/merge wire formats.
//!
//! One message kind carries two closed operation tags (`mint`/`burn`)
//! rather than two separate message kinds, since both share the same
//! owned-`TreasuryCap` trust and fee shape; each tag has its own fixed
//! header layout and object count, and an unknown tag is refused exactly
//! like an unknown message kind.

use super::asset_mint_burn::{AssetBurnRequest, AssetMintBurnRequest, AssetMintRequest};
use super::wire::{CUSTODY_WIRE_VERSION, CustodyWireError};
use sunrise_edge_client::{MAX_AUTHENTICATED_OBJECT_BODY_BYTES, RequestId};

/// The one currently supported mint/burn message kind.
pub(super) const SIGN_MINT_BURN_MESSAGE: u8 = 4;
/// Closed operation tag: mint new supply into a fresh owned coin.
pub(super) const MINT_OPERATION_TAG: u8 = 1;
/// Closed operation tag: burn a whole owned coin, reducing supply.
pub(super) const BURN_OPERATION_TAG: u8 = 2;

/// version(1) + message kind(1) + operation tag(1) + nonce(8) +
/// request_id(32) + max_fee(8) + gas_limit(8), common to both operations.
const COMMON_HEADER_BYTES: usize = 1 + 1 + 1 + 8 + 32 + 8 + 8;
/// `mint`'s own trailing fixed fields: amount(8) + recipient(32) +
/// cap_len(4) + fee_len(4).
const MINT_HEADER_BYTES: usize = COMMON_HEADER_BYTES + 8 + 32 + 4 + 4;
/// `burn`'s own trailing fixed fields: cap_len(4) + coin_len(4) + fee_len(4).
const BURN_HEADER_BYTES: usize = COMMON_HEADER_BYTES + 4 + 4 + 4;

/// Burn's three bounded objects dominate mint's two within the existing
/// transport length-prefix cap; valid Coin/TreasuryCap bodies are small in
/// practice.
pub(super) const MAX_REQUEST_BYTES: usize =
    BURN_HEADER_BYTES + 3 * MAX_AUTHENTICATED_OBJECT_BODY_BYTES;

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

/// Encodes one [`AssetMintBurnRequest`] to its exact bounded, versioned,
/// tagged, length-framed inner bytes (without the outer transport length
/// prefix).
pub(super) fn encode(request: &AssetMintBurnRequest) -> Result<Vec<u8>, CustodyWireError> {
    match request {
        AssetMintBurnRequest::Mint(request) => encode_mint(request),
        AssetMintBurnRequest::Burn(request) => encode_burn(request),
    }
}

fn encode_mint(request: &AssetMintRequest) -> Result<Vec<u8>, CustodyWireError> {
    let cap_len = checked_object_length(&request.cap_bytes)?;
    let fee_len = checked_object_length(&request.fee_bytes)?;
    let mut out =
        Vec::with_capacity(MINT_HEADER_BYTES + request.cap_bytes.len() + request.fee_bytes.len());
    out.push(CUSTODY_WIRE_VERSION);
    out.push(SIGN_MINT_BURN_MESSAGE);
    out.push(MINT_OPERATION_TAG);
    out.extend_from_slice(&request.nonce.to_be_bytes());
    out.extend_from_slice(request.request_id.as_bytes());
    out.extend_from_slice(&request.max_fee.to_be_bytes());
    out.extend_from_slice(&request.gas_limit.to_be_bytes());
    out.extend_from_slice(&request.amount.to_be_bytes());
    out.extend_from_slice(&request.recipient);
    out.extend_from_slice(&cap_len.to_be_bytes());
    out.extend_from_slice(&fee_len.to_be_bytes());
    out.extend_from_slice(&request.cap_bytes);
    out.extend_from_slice(&request.fee_bytes);
    Ok(out)
}

fn encode_burn(request: &AssetBurnRequest) -> Result<Vec<u8>, CustodyWireError> {
    let cap_len = checked_object_length(&request.cap_bytes)?;
    let coin_len = checked_object_length(&request.coin_bytes)?;
    let fee_len = checked_object_length(&request.fee_bytes)?;
    let mut out = Vec::with_capacity(
        BURN_HEADER_BYTES
            + request.cap_bytes.len()
            + request.coin_bytes.len()
            + request.fee_bytes.len(),
    );
    out.push(CUSTODY_WIRE_VERSION);
    out.push(SIGN_MINT_BURN_MESSAGE);
    out.push(BURN_OPERATION_TAG);
    out.extend_from_slice(&request.nonce.to_be_bytes());
    out.extend_from_slice(request.request_id.as_bytes());
    out.extend_from_slice(&request.max_fee.to_be_bytes());
    out.extend_from_slice(&request.gas_limit.to_be_bytes());
    out.extend_from_slice(&cap_len.to_be_bytes());
    out.extend_from_slice(&coin_len.to_be_bytes());
    out.extend_from_slice(&fee_len.to_be_bytes());
    out.extend_from_slice(&request.cap_bytes);
    out.extend_from_slice(&request.coin_bytes);
    out.extend_from_slice(&request.fee_bytes);
    Ok(out)
}

/// Decodes and strictly bounds one [`AssetMintBurnRequest`]; rejects an
/// unknown version/message kind/operation tag and any trailing or short
/// bytes.
pub(super) fn decode(bytes: &[u8]) -> Result<AssetMintBurnRequest, CustodyWireError> {
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
    if bytes[1] != SIGN_MINT_BURN_MESSAGE {
        return Err(CustodyWireError::UnsupportedMessageType(bytes[1]));
    }
    let tag = bytes[2];
    let nonce = read_u64(&bytes[3..11])?;
    let request_id = read_request_id(&bytes[11..43])?;
    let max_fee = read_u64(&bytes[43..51])?;
    let gas_limit = read_u64(&bytes[51..59])?;
    match tag {
        MINT_OPERATION_TAG => decode_mint(bytes, nonce, request_id, max_fee, gas_limit),
        BURN_OPERATION_TAG => decode_burn(bytes, nonce, request_id, max_fee, gas_limit),
        other => Err(CustodyWireError::UnsupportedMessageType(other)),
    }
}

fn decode_mint(
    bytes: &[u8],
    nonce: u64,
    request_id: RequestId,
    max_fee: u64,
    gas_limit: u64,
) -> Result<AssetMintBurnRequest, CustodyWireError> {
    if bytes.len() < MINT_HEADER_BYTES {
        return Err(CustodyWireError::Truncated);
    }
    let amount = read_u64(&bytes[59..67])?;
    let mut recipient = [0_u8; 32];
    recipient.copy_from_slice(&bytes[67..99]);
    let cap_len = read_u32(&bytes[99..103])?;
    let fee_len = read_u32(&bytes[103..107])?;
    for length in [cap_len, fee_len] {
        if length > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
            return Err(CustodyWireError::ArtifactTooLarge {
                actual: length,
                maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            });
        }
    }
    let declared = MINT_HEADER_BYTES
        .checked_add(cap_len)
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
    let cap_bytes = bytes[MINT_HEADER_BYTES..MINT_HEADER_BYTES + cap_len].to_vec();
    let fee_bytes = bytes[MINT_HEADER_BYTES + cap_len..].to_vec();
    Ok(AssetMintBurnRequest::Mint(Box::new(AssetMintRequest {
        cap_bytes,
        fee_bytes,
        amount,
        recipient,
        nonce,
        request_id,
        max_fee,
        gas_limit,
    })))
}

fn decode_burn(
    bytes: &[u8],
    nonce: u64,
    request_id: RequestId,
    max_fee: u64,
    gas_limit: u64,
) -> Result<AssetMintBurnRequest, CustodyWireError> {
    if bytes.len() < BURN_HEADER_BYTES {
        return Err(CustodyWireError::Truncated);
    }
    let cap_len = read_u32(&bytes[59..63])?;
    let coin_len = read_u32(&bytes[63..67])?;
    let fee_len = read_u32(&bytes[67..71])?;
    for length in [cap_len, coin_len, fee_len] {
        if length > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
            return Err(CustodyWireError::ArtifactTooLarge {
                actual: length,
                maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            });
        }
    }
    let declared = BURN_HEADER_BYTES
        .checked_add(cap_len)
        .and_then(|value| value.checked_add(coin_len))
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
    let cap_bytes = bytes[BURN_HEADER_BYTES..BURN_HEADER_BYTES + cap_len].to_vec();
    let coin_bytes =
        bytes[BURN_HEADER_BYTES + cap_len..BURN_HEADER_BYTES + cap_len + coin_len].to_vec();
    let fee_bytes = bytes[BURN_HEADER_BYTES + cap_len + coin_len..].to_vec();
    Ok(AssetMintBurnRequest::Burn(Box::new(AssetBurnRequest {
        cap_bytes,
        coin_bytes,
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

    fn mint_sample() -> AssetMintBurnRequest {
        AssetMintBurnRequest::Mint(Box::new(AssetMintRequest {
            cap_bytes: vec![1, 2, 3],
            fee_bytes: vec![4, 5],
            amount: 7,
            recipient: [9; 32],
            nonce: 23,
            request_id: request_id(7),
            max_fee: 17,
            gas_limit: 8000,
        }))
    }

    fn burn_sample() -> AssetMintBurnRequest {
        AssetMintBurnRequest::Burn(Box::new(AssetBurnRequest {
            cap_bytes: vec![1, 2],
            coin_bytes: vec![3, 4, 5],
            fee_bytes: vec![6],
            nonce: 9,
            request_id: request_id(8),
            max_fee: 3,
            gas_limit: 500,
        }))
    }

    #[test]
    fn mint_strict_roundtrip_and_foreign_family_refusal() {
        let request = mint_sample();
        let bytes = encode(&request).unwrap();
        assert_eq!(decode(&bytes).unwrap(), request);
        assert!(super::super::wire::decode_request(&bytes).is_err());
        assert!(super::super::asset_wire::decode(&bytes).is_err());
        assert!(super::super::asset_split_merge_wire::decode(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }

    #[test]
    fn burn_strict_roundtrip_and_foreign_family_refusal() {
        let request = burn_sample();
        let bytes = encode(&request).unwrap();
        assert_eq!(decode(&bytes).unwrap(), request);
        assert!(super::super::wire::decode_request(&bytes).is_err());
        assert!(super::super::asset_wire::decode(&bytes).is_err());
        assert!(super::super::asset_split_merge_wire::decode(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }

    #[test]
    fn decode_rejects_an_unsupported_version_or_message_kind() {
        let bytes = encode(&mint_sample()).unwrap();
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
        // Kind 2 (transfer).
        let mut transfer_kind = bytes.clone();
        transfer_kind[1] = 2;
        assert!(matches!(
            decode(&transfer_kind),
            Err(CustodyWireError::UnsupportedMessageType(2))
        ));
        // Kind 3 (split/merge): the kind-4 decoder must refuse the other
        // sibling message kind exactly like any other unknown kind.
        let mut split_merge_kind = bytes;
        split_merge_kind[1] = 3;
        assert!(matches!(
            decode(&split_merge_kind),
            Err(CustodyWireError::UnsupportedMessageType(3))
        ));
    }

    #[test]
    fn decode_rejects_an_unknown_operation_tag() {
        let mut bytes = encode(&mint_sample()).unwrap();
        bytes[2] = 0xEE;
        assert!(matches!(
            decode(&bytes),
            Err(CustodyWireError::UnsupportedMessageType(0xEE))
        ));
    }

    #[test]
    fn decode_rejects_a_declared_length_longer_than_actual_bytes() {
        let mut mint_bytes = encode(&mint_sample()).unwrap();
        mint_bytes[99..103].copy_from_slice(&100_u32.to_be_bytes());
        assert!(matches!(
            decode(&mint_bytes),
            Err(CustodyWireError::LengthMismatch { .. })
        ));

        let mut burn_bytes = encode(&burn_sample()).unwrap();
        burn_bytes[59..63].copy_from_slice(&100_u32.to_be_bytes());
        assert!(matches!(
            decode(&burn_bytes),
            Err(CustodyWireError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn decode_rejects_an_object_length_over_the_bound() {
        let mut mint_bytes = encode(&mint_sample()).unwrap();
        mint_bytes[99..103]
            .copy_from_slice(&(MAX_AUTHENTICATED_OBJECT_BODY_BYTES as u32 + 1).to_be_bytes());
        assert!(matches!(
            decode(&mint_bytes),
            Err(CustodyWireError::ArtifactTooLarge { .. })
        ));
    }

    /// Mirrors `decode_rejects_an_object_length_over_the_bound` for every
    /// one of burn's own three declared-length fields (`cap_len`,
    /// `coin_len`, `fee_len`), not only mint's single `cap_len`/`fee_len`
    /// pair: burn's own header has a distinct field layout and byte offsets
    /// (`BURN_HEADER_BYTES` vs `MINT_HEADER_BYTES`), so this bound must be
    /// independently proven for each burn field rather than assumed from
    /// mint's coverage.
    #[test]
    fn decode_rejects_a_burn_object_length_over_the_bound() {
        let over_bound: [u8; 4] = (MAX_AUTHENTICATED_OBJECT_BODY_BYTES as u32 + 1).to_be_bytes();
        for range in [59..63, 63..67, 67..71] {
            let mut burn_bytes = encode(&burn_sample()).unwrap();
            burn_bytes[range].copy_from_slice(&over_bound);
            assert!(matches!(
                decode(&burn_bytes),
                Err(CustodyWireError::ArtifactTooLarge { .. })
            ));
        }
    }

    #[test]
    fn decode_rejects_a_zero_request_id() {
        let mut bytes = encode(&mint_sample()).unwrap();
        bytes[11..43].copy_from_slice(&[0_u8; 32]);
        assert!(matches!(
            decode(&bytes),
            Err(CustodyWireError::RequestId(_))
        ));
    }

    /// Pins the literal discriminant values themselves, independently of
    /// the named constants the encoder/decoder use: if `SIGN_MINT_BURN_MESSAGE`
    /// were ever renumbered to 5, or `MINT_OPERATION_TAG`/`BURN_OPERATION_TAG`
    /// were ever swapped, a vector built from the constants (rather than
    /// literals) would silently stay "correct" and catch nothing.
    #[test]
    fn literal_version_kind_and_tag_bytes_are_pinned() {
        assert_eq!(CUSTODY_WIRE_VERSION, 1);
        assert_eq!(SIGN_MINT_BURN_MESSAGE, 4);
        assert_eq!(MINT_OPERATION_TAG, 1);
        assert_eq!(BURN_OPERATION_TAG, 2);
    }

    /// Stable encoding vector: a fixed, pinned-byte mint request, with the
    /// version/kind/tag prefix written as literal bytes (`[1, 4, 1]`), not
    /// the named constants, so a future accidental renumbering of any of
    /// `CUSTODY_WIRE_VERSION`/`SIGN_MINT_BURN_MESSAGE`/`MINT_OPERATION_TAG`
    /// cannot silently keep this vector passing. A change to this byte
    /// layout is an adapter wire-format break.
    #[test]
    fn mint_encoding_is_stable() {
        let request = mint_sample();
        let encoded = encode(&request).unwrap();
        let mut expected = vec![1_u8, 4, 1];
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

    /// Stable encoding vector: a fixed, pinned-byte burn request, with the
    /// version/kind/tag prefix written as literal bytes (`[1, 4, 2]`), for
    /// the same reason as `mint_encoding_is_stable`.
    #[test]
    fn burn_encoding_is_stable() {
        let request = burn_sample();
        let encoded = encode(&request).unwrap();
        let mut expected = vec![1_u8, 4, 2];
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
