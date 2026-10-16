//! Bounded adapter-local create-asset preimages (DR-0255), kind 5. No
//! supplied frame is signable; this never changes the kind 1 publication,
//! kind 2 transfer, kind 3 split/merge, or kind 4 mint/burn wire formats.
//!
//! Unlike every other family's codec, this request carries exactly one
//! bounded object preimage (the fee source) plus a fixed 32-byte seed —
//! never a Coin/TreasuryCap preimage, since `create-asset` has no
//! pre-existing application input.

use super::asset_create::AssetCreateRequest;
use super::wire::{CUSTODY_WIRE_VERSION, CustodyWireError};
use sunrise_edge_client::{MAX_AUTHENTICATED_OBJECT_BODY_BYTES, RequestId};

/// The one currently supported create-asset message kind.
pub(super) const SIGN_CREATE_MESSAGE: u8 = 5;

/// version(1) + message kind(1) + nonce(8) + request_id(32) + max_fee(8) +
/// gas_limit(8) + seed(32) + fee_len(4).
const HEADER_BYTES: usize = 1 + 1 + 8 + 32 + 8 + 8 + 32 + 4;
pub(super) const MAX_REQUEST_BYTES: usize = HEADER_BYTES + MAX_AUTHENTICATED_OBJECT_BODY_BYTES;

/// Encodes one [`AssetCreateRequest`] to its exact bounded, versioned,
/// length-framed inner bytes (without the outer transport length prefix).
pub(super) fn encode(request: &AssetCreateRequest) -> Result<Vec<u8>, CustodyWireError> {
    if request.fee_bytes.len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
        return Err(CustodyWireError::ArtifactTooLarge {
            actual: request.fee_bytes.len(),
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        });
    }
    let fee_len: u32 =
        u32::try_from(request.fee_bytes.len()).map_err(|_| CustodyWireError::ArtifactTooLarge {
            actual: request.fee_bytes.len(),
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        })?;
    let mut out: Vec<u8> = Vec::with_capacity(HEADER_BYTES + request.fee_bytes.len());
    out.push(CUSTODY_WIRE_VERSION);
    out.push(SIGN_CREATE_MESSAGE);
    out.extend_from_slice(&request.nonce.to_be_bytes());
    out.extend_from_slice(request.request_id.as_bytes());
    out.extend_from_slice(&request.max_fee.to_be_bytes());
    out.extend_from_slice(&request.gas_limit.to_be_bytes());
    out.extend_from_slice(&request.seed);
    out.extend_from_slice(&fee_len.to_be_bytes());
    out.extend_from_slice(&request.fee_bytes);
    Ok(out)
}

/// Decodes and strictly bounds one [`AssetCreateRequest`]; rejects an
/// unknown version/message kind and any trailing or short bytes.
pub(super) fn decode(bytes: &[u8]) -> Result<AssetCreateRequest, CustodyWireError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_REQUEST_BYTES,
        });
    }
    if bytes.len() < HEADER_BYTES {
        return Err(CustodyWireError::Truncated);
    }
    if bytes[0] != CUSTODY_WIRE_VERSION {
        return Err(CustodyWireError::UnsupportedVersion(bytes[0]));
    }
    if bytes[1] != SIGN_CREATE_MESSAGE {
        return Err(CustodyWireError::UnsupportedMessageType(bytes[1]));
    }
    let nonce: u64 = u64::from_be_bytes(
        bytes[2..10]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    );
    let request_id: RequestId = RequestId::new(
        bytes[10..42]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    )
    .map_err(CustodyWireError::RequestId)?;
    let max_fee: u64 = u64::from_be_bytes(
        bytes[42..50]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    );
    let gas_limit: u64 = u64::from_be_bytes(
        bytes[50..58]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    );
    let seed: [u8; 32] = bytes[58..90]
        .try_into()
        .map_err(|_| CustodyWireError::Truncated)?;
    let fee_len: usize = u32::from_be_bytes(
        bytes[90..94]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    ) as usize;
    if fee_len > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
        return Err(CustodyWireError::ArtifactTooLarge {
            actual: fee_len,
            maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        });
    }
    let declared: usize =
        HEADER_BYTES
            .checked_add(fee_len)
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
    Ok(AssetCreateRequest {
        seed,
        fee_bytes: bytes[HEADER_BYTES..].to_vec(),
        nonce,
        request_id,
        max_fee,
        gas_limit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AssetCreateRequest {
        AssetCreateRequest {
            seed: [5; 32],
            fee_bytes: vec![4, 5],
            nonce: 23,
            request_id: RequestId::new([7; 32]).unwrap(),
            max_fee: 17,
            gas_limit: 8000,
        }
    }

    #[test]
    fn strict_roundtrip_and_foreign_family_refusal() {
        let request: AssetCreateRequest = sample();
        let bytes: Vec<u8> = encode(&request).unwrap();
        assert_eq!(decode(&bytes).unwrap(), request);
        assert!(super::super::wire::decode_request(&bytes).is_err());
        assert!(super::super::asset_wire::decode(&bytes).is_err());
        assert!(super::super::asset_split_merge_wire::decode(&bytes).is_err());
        assert!(super::super::asset_mint_burn_wire::decode(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end]).is_err());
        }
        let mut trailing: Vec<u8> = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }

    #[test]
    fn decode_rejects_an_unsupported_version_or_message_kind() {
        let bytes: Vec<u8> = encode(&sample()).unwrap();
        let mut unknown_version: Vec<u8> = bytes.clone();
        unknown_version[0] = 9;
        assert!(matches!(
            decode(&unknown_version),
            Err(CustodyWireError::UnsupportedVersion(9))
        ));
        for kind in [1_u8, 2, 3, 4] {
            let mut unknown_kind: Vec<u8> = bytes.clone();
            unknown_kind[1] = kind;
            assert!(matches!(
                decode(&unknown_kind),
                Err(CustodyWireError::UnsupportedMessageType(k)) if k == kind
            ));
        }
    }

    #[test]
    fn decode_rejects_a_declared_length_longer_than_actual_bytes() {
        let mut bytes: Vec<u8> = encode(&sample()).unwrap();
        bytes[90..94].copy_from_slice(&100_u32.to_be_bytes());
        assert!(matches!(
            decode(&bytes),
            Err(CustodyWireError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn decode_rejects_an_object_length_over_the_bound() {
        let mut bytes: Vec<u8> = encode(&sample()).unwrap();
        bytes[90..94]
            .copy_from_slice(&(MAX_AUTHENTICATED_OBJECT_BODY_BYTES as u32 + 1).to_be_bytes());
        assert!(matches!(
            decode(&bytes),
            Err(CustodyWireError::ArtifactTooLarge { .. })
        ));
    }

    #[test]
    fn decode_rejects_a_zero_request_id() {
        let mut bytes: Vec<u8> = encode(&sample()).unwrap();
        bytes[10..42].copy_from_slice(&[0_u8; 32]);
        assert!(matches!(
            decode(&bytes),
            Err(CustodyWireError::RequestId(_))
        ));
    }

    /// Pins the literal discriminant value independently of the named
    /// constant: if `SIGN_CREATE_MESSAGE` were ever renumbered, a vector
    /// built from the constant alone would silently stay "correct."
    #[test]
    fn literal_version_and_kind_bytes_are_pinned() {
        assert_eq!(CUSTODY_WIRE_VERSION, 1);
        assert_eq!(SIGN_CREATE_MESSAGE, 5);
    }

    /// Stable encoding vector: a fixed, pinned-byte request, with the
    /// version/kind prefix written as literal bytes (`[1, 5]`), not the
    /// named constants. A change to this byte layout is an adapter
    /// wire-format break.
    #[test]
    fn encoding_is_stable() {
        let request: AssetCreateRequest = sample();
        let encoded: Vec<u8> = encode(&request).unwrap();
        let mut expected: Vec<u8> = vec![1_u8, 5];
        expected.extend_from_slice(&23_u64.to_be_bytes());
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&17_u64.to_be_bytes());
        expected.extend_from_slice(&8000_u64.to_be_bytes());
        expected.extend_from_slice(&[5; 32]);
        expected.extend_from_slice(&2_u32.to_be_bytes());
        expected.extend_from_slice(&[4, 5]);
        assert_eq!(encoded, expected);
    }
}
