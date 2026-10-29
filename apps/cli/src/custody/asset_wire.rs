//! Bounded adapter-local transfer preimages. No supplied frame is signable.

use super::asset_transfer::AssetTransferRequest;
use super::wire::{CUSTODY_WIRE_VERSION, CustodyWireError};
use sunrise_edge_client::{MAX_AUTHENTICATED_OBJECT_BODY_BYTES, RequestId};

pub(super) const SIGN_TRANSFER_MESSAGE: u8 = 2;
const HEADER_BYTES: usize = 2 + 8 + 32 + 32 + 8 + 8 + 4 + 4;
pub(super) const MAX_REQUEST_BYTES: usize = HEADER_BYTES + 2 * MAX_AUTHENTICATED_OBJECT_BODY_BYTES;

pub(super) fn encode(request: &AssetTransferRequest) -> Result<Vec<u8>, CustodyWireError> {
    for bytes in [&request.coin_bytes, &request.fee_bytes] {
        if bytes.len() > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
            return Err(CustodyWireError::ArtifactTooLarge {
                actual: bytes.len(),
                maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            });
        }
    }
    let mut output: Vec<u8> =
        Vec::with_capacity(HEADER_BYTES + request.coin_bytes.len() + request.fee_bytes.len());
    output.extend_from_slice(&[CUSTODY_WIRE_VERSION, SIGN_TRANSFER_MESSAGE]);
    output.extend_from_slice(&request.nonce.to_be_bytes());
    output.extend_from_slice(request.request_id.as_bytes());
    output.extend_from_slice(&request.recipient);
    output.extend_from_slice(&request.max_fee.to_be_bytes());
    output.extend_from_slice(&request.gas_limit.to_be_bytes());
    for bytes in [&request.coin_bytes, &request.fee_bytes] {
        let length: u32 =
            u32::try_from(bytes.len()).map_err(|_| CustodyWireError::FrameTooLarge {
                actual: bytes.len(),
                maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            })?;
        output.extend_from_slice(&length.to_be_bytes());
    }
    output.extend_from_slice(&request.coin_bytes);
    output.extend_from_slice(&request.fee_bytes);
    Ok(output)
}

pub(super) fn decode(bytes: &[u8]) -> Result<AssetTransferRequest, CustodyWireError> {
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
    if bytes[1] != SIGN_TRANSFER_MESSAGE {
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
    let recipient: [u8; 32] = bytes[42..74]
        .try_into()
        .map_err(|_| CustodyWireError::Truncated)?;
    let max_fee: u64 = u64::from_be_bytes(
        bytes[74..82]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    );
    let gas_limit: u64 = u64::from_be_bytes(
        bytes[82..90]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    );
    let coin_len: usize = u32::from_be_bytes(
        bytes[90..94]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    ) as usize;
    let fee_len: usize = u32::from_be_bytes(
        bytes[94..98]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    ) as usize;
    for length in [coin_len, fee_len] {
        if length > MAX_AUTHENTICATED_OBJECT_BODY_BYTES {
            return Err(CustodyWireError::ArtifactTooLarge {
                actual: length,
                maximum: MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
            });
        }
    }
    let declared: usize = HEADER_BYTES + coin_len + fee_len;
    if bytes.len() != declared {
        return Err(CustodyWireError::LengthMismatch {
            declared,
            actual: bytes.len(),
        });
    }
    Ok(AssetTransferRequest {
        nonce,
        request_id,
        recipient,
        max_fee,
        gas_limit,
        coin_bytes: bytes[HEADER_BYTES..HEADER_BYTES + coin_len].to_vec(),
        fee_bytes: bytes[HEADER_BYTES + coin_len..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_roundtrip_and_foreign_family_refusal() {
        let request: AssetTransferRequest = AssetTransferRequest {
            nonce: 23,
            request_id: RequestId::new([7; 32]).unwrap(),
            recipient: [3; 32],
            max_fee: 17,
            gas_limit: 8000,
            coin_bytes: vec![1, 2, 3],
            fee_bytes: vec![4, 5],
        };
        let bytes: Vec<u8> = encode(&request).unwrap();
        assert_eq!(decode(&bytes).unwrap(), request);
        assert!(super::super::wire::decode_request(&bytes).is_err());
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end]).is_err());
        }
        let mut trailing: Vec<u8> = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let mut unknown: Vec<u8> = bytes.clone();
        unknown[1] = 1;
        assert!(matches!(
            decode(&unknown),
            Err(CustodyWireError::UnsupportedMessageType(1))
        ));
        unknown[0] = 9;
        assert!(matches!(
            decode(&unknown),
            Err(CustodyWireError::UnsupportedVersion(9))
        ));
        unknown = bytes;
        unknown[90..94].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            decode(&unknown),
            Err(CustodyWireError::ArtifactTooLarge { .. })
        ));
    }
}
