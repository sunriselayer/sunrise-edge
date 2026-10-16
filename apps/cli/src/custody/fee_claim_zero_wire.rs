//! Bounded adapter-local ZeroShare fee-claim preimages, kind 7. No supplied
//! frame is signable; this never changes the kind 1 publication, kind 2
//! transfer, kind 3 split/merge, kind 4 mint/burn, or kind 5 create-asset
//! wire formats.
//!
//! Unlike every other family's codec, kind 7 carries exactly two existing
//! canonical frames back to back: the untrusted
//! [`sunrise_edge_client::FeeClaimPrepareRequest`] (`0x6461/v1`) and the
//! host-prepared [`sunrise_edge_client::FeeClaimIntent`] (`0x6437/v1`),
//! never a new schema of its own. Both payloads are decoded with their own
//! existing canonical decoders and checked to re-encode to exactly the
//! bytes carried, so this frame never accepts a non-canonical preimage.

use super::wire::{CUSTODY_WIRE_VERSION, CustodyWireError};
use sunrise_edge_client::{
    FeeClaimIntent, FeeClaimPrepareRequest, MAX_FEE_CLAIM_INTENT_BYTES,
    MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES,
};

/// The one currently supported ZeroShare fee-claim message kind.
pub(super) const SIGN_FEE_CLAIM_ZERO_MESSAGE: u8 = 7;

/// version(1) + message kind(1) + request_len(4) + intent_len(4).
const HEADER_BYTES: usize = 1 + 1 + 4 + 4;
pub(super) const MAX_FEE_CLAIM_ZERO_REQUEST_BYTES: usize =
    HEADER_BYTES + MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES + MAX_FEE_CLAIM_INTENT_BYTES;

/// The exact untrusted [`FeeClaimPrepareRequest`] and the host-prepared
/// [`FeeClaimIntent`] it was prepared against, carried together as one
/// adapter-local kind-7 message. Custody independently re-derives the
/// claimant and every other authority from these; nothing here is trusted
/// on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FeeClaimZeroRequest {
    pub(super) request: FeeClaimPrepareRequest,
    pub(super) intent: FeeClaimIntent,
}

fn boxed(error: impl std::error::Error + Send + Sync + 'static) -> CustodyWireError {
    CustodyWireError::InnerCodec(Box::new(error))
}

/// Encodes one [`FeeClaimZeroRequest`] to its exact bounded, versioned,
/// length-framed inner bytes (without the outer transport length prefix).
pub(super) fn encode(request: &FeeClaimZeroRequest) -> Result<Vec<u8>, CustodyWireError> {
    let request_bytes: Vec<u8> = request.request.encode().map_err(boxed)?;
    let intent_bytes: Vec<u8> =
        sunrise_edge_client::encode_fee_claim_intent(&request.intent).map_err(boxed)?;
    if request_bytes.len() > MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES {
        return Err(CustodyWireError::ArtifactTooLarge {
            actual: request_bytes.len(),
            maximum: MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES,
        });
    }
    if intent_bytes.len() > MAX_FEE_CLAIM_INTENT_BYTES {
        return Err(CustodyWireError::ArtifactTooLarge {
            actual: intent_bytes.len(),
            maximum: MAX_FEE_CLAIM_INTENT_BYTES,
        });
    }
    let request_len: u32 =
        u32::try_from(request_bytes.len()).map_err(|_| CustodyWireError::ArtifactTooLarge {
            actual: request_bytes.len(),
            maximum: MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES,
        })?;
    let intent_len: u32 =
        u32::try_from(intent_bytes.len()).map_err(|_| CustodyWireError::ArtifactTooLarge {
            actual: intent_bytes.len(),
            maximum: MAX_FEE_CLAIM_INTENT_BYTES,
        })?;
    let mut out: Vec<u8> =
        Vec::with_capacity(HEADER_BYTES + request_bytes.len() + intent_bytes.len());
    out.push(CUSTODY_WIRE_VERSION);
    out.push(SIGN_FEE_CLAIM_ZERO_MESSAGE);
    out.extend_from_slice(&request_len.to_be_bytes());
    out.extend_from_slice(&request_bytes);
    out.extend_from_slice(&intent_len.to_be_bytes());
    out.extend_from_slice(&intent_bytes);
    Ok(out)
}

/// Decodes and strictly bounds one [`FeeClaimZeroRequest`]; rejects an
/// unknown version/message kind, any trailing or short bytes, and any inner
/// payload that is not the exact canonical encoding of what it decodes to.
pub(super) fn decode(bytes: &[u8]) -> Result<FeeClaimZeroRequest, CustodyWireError> {
    if bytes.len() > MAX_FEE_CLAIM_ZERO_REQUEST_BYTES {
        return Err(CustodyWireError::FrameTooLarge {
            actual: bytes.len(),
            maximum: MAX_FEE_CLAIM_ZERO_REQUEST_BYTES,
        });
    }
    if bytes.len() < HEADER_BYTES {
        return Err(CustodyWireError::Truncated);
    }
    if bytes[0] != CUSTODY_WIRE_VERSION {
        return Err(CustodyWireError::UnsupportedVersion(bytes[0]));
    }
    if bytes[1] != SIGN_FEE_CLAIM_ZERO_MESSAGE {
        return Err(CustodyWireError::UnsupportedMessageType(bytes[1]));
    }
    let request_len: usize = u32::from_be_bytes(
        bytes[2..6]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    ) as usize;
    if request_len > MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES {
        return Err(CustodyWireError::ArtifactTooLarge {
            actual: request_len,
            maximum: MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES,
        });
    }
    let request_start: usize = HEADER_BYTES;
    let request_end: usize =
        request_start
            .checked_add(request_len)
            .ok_or(CustodyWireError::FrameTooLarge {
                actual: bytes.len(),
                maximum: MAX_FEE_CLAIM_ZERO_REQUEST_BYTES,
            })?;
    // `request_end + 4` (the intent length field) must exist too.
    if bytes.len() < request_end || bytes.len() - request_end < 4 {
        return Err(CustodyWireError::Truncated);
    }
    let request_bytes: &[u8] = &bytes[request_start..request_end];
    let intent_len_start: usize = request_end;
    let intent_len_end: usize = intent_len_start + 4;
    let intent_len: usize = u32::from_be_bytes(
        bytes[intent_len_start..intent_len_end]
            .try_into()
            .map_err(|_| CustodyWireError::Truncated)?,
    ) as usize;
    if intent_len > MAX_FEE_CLAIM_INTENT_BYTES {
        return Err(CustodyWireError::ArtifactTooLarge {
            actual: intent_len,
            maximum: MAX_FEE_CLAIM_INTENT_BYTES,
        });
    }
    let intent_start: usize = intent_len_end;
    let intent_end: usize =
        intent_start
            .checked_add(intent_len)
            .ok_or(CustodyWireError::FrameTooLarge {
                actual: bytes.len(),
                maximum: MAX_FEE_CLAIM_ZERO_REQUEST_BYTES,
            })?;
    if bytes.len() != intent_end {
        return Err(CustodyWireError::LengthMismatch {
            declared: intent_end,
            actual: bytes.len(),
        });
    }
    let intent_bytes: &[u8] = &bytes[intent_start..intent_end];

    let request: FeeClaimPrepareRequest =
        FeeClaimPrepareRequest::decode(request_bytes).map_err(boxed)?;
    if request.encode().map_err(boxed)? != request_bytes {
        return Err(boxed(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fee claim zero request is not the exact canonical encoding",
        )));
    }
    let intent: FeeClaimIntent =
        sunrise_edge_client::decode_fee_claim_intent(intent_bytes).map_err(boxed)?;
    if sunrise_edge_client::encode_fee_claim_intent(&intent).map_err(boxed)? != intent_bytes {
        return Err(boxed(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fee claim zero intent is not the exact canonical encoding",
        )));
    }
    Ok(FeeClaimZeroRequest { request, intent })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sunrise_edge_client::{
        Address, ChainId, Digest32, Epoch, FeeClaimOperation, HashAlgorithmId, ObjectId, ObjectRef,
        ProtocolVersion, PublicationContext, ValidatorId,
    };

    fn sample() -> FeeClaimZeroRequest {
        let context: PublicationContext = PublicationContext::new(
            ChainId::new("fee-claim-zero-wire-test").unwrap(),
            ProtocolVersion::new(3),
            Epoch::new(1),
        )
        .unwrap();
        let request: FeeClaimPrepareRequest = FeeClaimPrepareRequest {
            context: context.clone(),
            escrow_request_id: [2; 32],
            request_id: [1; 32],
            validator_id: ValidatorId::new([3; 32]),
            claimant_public_key: [4; 32],
            recipient: Address::new([5; 32]),
            signed_leg: None,
        };
        let intent: FeeClaimIntent = FeeClaimIntent {
            context,
            request_id: [1; 32],
            escrow_request_id: [2; 32],
            certificate_epoch: Epoch::new(0),
            validator_id: request.validator_id,
            resource_id: sunrise_edge_client::bond_registration::BondResourceId::new(1, [6; 32])
                .unwrap(),
            expected_generation: 7,
            expected_fee_output: ObjectRef {
                id: ObjectId::new([8; 32]),
                version: 9,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [10; 32]),
            },
            expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [11; 32]),
            expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [12; 32]),
            share_amount: 0,
            recipient: request.recipient,
            operation: FeeClaimOperation::ZeroShare,
        };
        FeeClaimZeroRequest { request, intent }
    }

    #[test]
    fn strict_roundtrip_and_foreign_family_refusal() {
        let request: FeeClaimZeroRequest = sample();
        let bytes: Vec<u8> = encode(&request).unwrap();
        assert_eq!(decode(&bytes).unwrap(), request);
        assert!(super::super::wire::decode_request(&bytes).is_err());
        assert!(super::super::asset_wire::decode(&bytes).is_err());
        assert!(super::super::asset_split_merge_wire::decode(&bytes).is_err());
        assert!(super::super::asset_mint_burn_wire::decode(&bytes).is_err());
        assert!(super::super::asset_create_wire::decode(&bytes).is_err());
        assert!(super::super::positive_fee_split_wire::decode(&bytes).is_err());
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
        for kind in [1_u8, 2, 3, 4, 5, 6] {
            let mut unknown_kind: Vec<u8> = bytes.clone();
            unknown_kind[1] = kind;
            assert!(matches!(
                decode(&unknown_kind),
                Err(CustodyWireError::UnsupportedMessageType(k)) if k == kind
            ));
        }
    }

    #[test]
    fn decode_rejects_a_declared_request_length_longer_than_actual_bytes() {
        let bytes: Vec<u8> = encode(&sample()).unwrap();
        let request_len: u32 = u32::from_be_bytes(bytes[2..6].try_into().unwrap());
        let mut altered: Vec<u8> = bytes.clone();
        // Declaring the request as the entire remaining frame leaves no room
        // for the mandatory trailing intent-length field.
        altered[2..6].copy_from_slice(&(request_len + bytes.len() as u32).to_be_bytes());
        assert!(decode(&altered).is_err());
    }

    #[test]
    fn decode_rejects_a_request_length_over_the_bound() {
        let mut bytes: Vec<u8> = encode(&sample()).unwrap();
        bytes[2..6].copy_from_slice(&(MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES as u32 + 1).to_be_bytes());
        assert!(matches!(
            decode(&bytes),
            Err(CustodyWireError::ArtifactTooLarge { .. })
        ));
    }

    #[test]
    fn decode_rejects_trailing_bytes_after_the_intent() {
        let mut bytes: Vec<u8> = encode(&sample()).unwrap();
        bytes.push(0xFF);
        assert!(matches!(
            decode(&bytes),
            Err(CustodyWireError::LengthMismatch { .. })
        ));
    }

    /// Pins the literal discriminant value independently of the named
    /// constant: if `SIGN_FEE_CLAIM_ZERO_MESSAGE` were ever renumbered, a
    /// vector built from the constant alone would silently stay "correct."
    #[test]
    fn literal_version_and_kind_bytes_are_pinned() {
        assert_eq!(CUSTODY_WIRE_VERSION, 1);
        assert_eq!(SIGN_FEE_CLAIM_ZERO_MESSAGE, 7);
    }

    /// Stable encoding vector: the frame opens with the literal bytes
    /// `[1, 7]`, not the named constants. A change to this byte layout is
    /// an adapter wire-format break.
    #[test]
    fn encoding_is_stable_and_bounded_by_length_fields() {
        let request: FeeClaimZeroRequest = sample();
        let encoded: Vec<u8> = encode(&request).unwrap();
        assert_eq!(&encoded[0..2], &[1_u8, 7]);
        let request_len: u32 = u32::from_be_bytes(encoded[2..6].try_into().unwrap());
        let request_bytes: Vec<u8> = request.request.encode().unwrap();
        assert_eq!(request_len as usize, request_bytes.len());
        assert_eq!(&encoded[6..6 + request_bytes.len()], request_bytes.as_slice());
        let intent_len_start: usize = 6 + request_bytes.len();
        let intent_len: u32 =
            u32::from_be_bytes(encoded[intent_len_start..intent_len_start + 4].try_into().unwrap());
        let intent_bytes: Vec<u8> =
            sunrise_edge_client::encode_fee_claim_intent(&request.intent).unwrap();
        assert_eq!(intent_len as usize, intent_bytes.len());
        assert_eq!(
            &encoded[intent_len_start + 4..],
            intent_bytes.as_slice()
        );
    }
}
