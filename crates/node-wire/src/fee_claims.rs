//! Bounded HTTP transport for DR-0137 read-only fee-claim preparation (see
//! `docs/architecture/decisions/0137-fastvote-release-authority.md`,
//! "Certified fee escrow and claims").
//!
//! `POST {FEE_CLAIM_PREPARE_PATH}` accepts one [`FeeClaimPrepareRequest`],
//! this module's one new frame, because "an untrusted claimant's requested
//! preparation shape plus its own transport signing-scope context" is an
//! HTTP-request shape, not itself a `node_core::fee_claims` canonical type.
//! The response reuses the existing canonical unsigned `FeeClaimIntent`
//! (`node_core::fee_claims::codec` `0x6437`) verbatim, unwrapped, under its
//! own media type -- the same transport rule `ordered_economics` and
//! `ordered_history` already follow: never duplicate a core schema. This
//! route never mutates escrow state; applying a signed claim remains a
//! separate, owning certified-apply surface.
//!
//! The request carries only untrusted request claims, never authority or a
//! private signing key: the host derives the live context/fence/checkpoint
//! and the verified historical committee from its own warrant. The
//! transport `context` field only lets the host reject a request signed for
//! the wrong chain/protocol/epoch scope explicitly, before doing any
//! further preparation work.
//!
//! `node_core::fee_claims::codec` allocated `0x6437`/`0x6438` for its own
//! canonical types; `node-wire::ordered_economics` allocated `0x6460` for
//! its HTTP wrapper. [`FEE_CLAIM_PREPARE_REQUEST_TYPE_ID`] at `0x6461`
//! stays clear of both, confirmed unused by a parent full-code sweep.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
};
use core::fmt;
use execution::publication::{
    PublicationContext, decode_publication_context, encode_publication_context,
};
use node_core::fee_claims::FeeClaimPreparationRequest;
use node_core::fee_claims::codec::MAX_FEE_CLAIM_INTENT_BYTES;
use objects::Address;
use protocol_types::ValidatorId;
use std::error::Error;

/// Canonical type identifier for [`FeeClaimPrepareRequest`].
pub const FEE_CLAIM_PREPARE_REQUEST_TYPE_ID: u16 = 0x6461;
pub const FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION: u16 = 1;

/// Read-only bounded route: prepares (never applies) one fee-claim intent.
/// Body is one [`FeeClaimPrepareRequest`]; response is the raw canonical
/// unsigned `node_core::fee_claims::codec::FeeClaimIntent` bytes (`0x6437`),
/// which the caller must sign and submit separately through the owning
/// certified-apply surface.
pub const FEE_CLAIM_PREPARE_PATH: &str = "/v1/fee-claims/prepare";

/// Media type for [`FeeClaimPrepareRequest`].
pub const FEE_CLAIM_PREPARE_REQUEST_MEDIA_TYPE: &str =
    "application/vnd.sunrise-edge.fee-claim-prepare-request";
/// Media type for a raw canonical unsigned `FeeClaimIntent` (`0x6437`).
pub const FEE_CLAIM_INTENT_MEDIA_TYPE: &str = "application/vnd.sunrise-edge.fee-claim-intent";

/// Transport bound on one encoded `signed_leg`, derived from the existing
/// core intent-family cap. Structural transport acceptance does not replace
/// the owning signed-leg codec's bounds or cryptographic authentication.
pub const MAX_FEE_CLAIM_PREPARE_LEG_BYTES: usize = MAX_FEE_CLAIM_INTENT_BYTES;
/// Bound on one complete encoded [`FeeClaimPrepareRequest`]: the leg bound
/// plus this frame's own context/ids/validator/keys/recipient overhead.
/// Well under `canonical_encoding::MAX_CANONICAL_FRAME_BYTES`.
pub const MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES: usize = MAX_FEE_CLAIM_PREPARE_LEG_BYTES + 2048;

/// Errors from encoding or decoding a [`FeeClaimPrepareRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeClaimPrepareRequestError {
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// `context` was not a valid structural publication context.
    InvalidContext,
    /// `signed_leg` was `Some(&[])`: empty bytes are reserved for `None` and
    /// cannot be distinguished from it on the wire.
    EmptySignedLeg,
    /// `signed_leg` exceeded [`MAX_FEE_CLAIM_PREPARE_LEG_BYTES`].
    LegTooLarge(usize),
    /// The decoded value's own re-encoding did not match the input bytes.
    NonCanonicalEncoding,
    /// The complete encoded request exceeded [`MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES`].
    RequestTooLarge(usize),
}

impl fmt::Display for FeeClaimPrepareRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(error) => write!(f, "canonical encoding failed: {error}"),
            Self::CanonicalDecoding(error) => write!(f, "canonical decoding failed: {error}"),
            Self::InvalidContext => f.write_str("fee claim prepare request context is invalid"),
            Self::EmptySignedLeg => f.write_str(
                "fee claim prepare request signed leg must be nonempty when present",
            ),
            Self::LegTooLarge(length) => write!(
                f,
                "fee claim prepare request signed leg is {length} bytes, maximum is {MAX_FEE_CLAIM_PREPARE_LEG_BYTES}"
            ),
            Self::NonCanonicalEncoding => {
                f.write_str("fee claim prepare request bytes are not the canonical encoding")
            }
            Self::RequestTooLarge(length) => write!(
                f,
                "fee claim prepare request is {length} bytes, maximum is {MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES}"
            ),
        }
    }
}

impl Error for FeeClaimPrepareRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CanonicalEncoding(error) => Some(error),
            Self::CanonicalDecoding(error) => Some(error),
            Self::InvalidContext
            | Self::EmptySignedLeg
            | Self::LegTooLarge(_)
            | Self::NonCanonicalEncoding
            | Self::RequestTooLarge(_) => None,
        }
    }
}

impl From<CanonicalEncodingError> for FeeClaimPrepareRequestError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for FeeClaimPrepareRequestError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

/// `POST /v1/fee-claims/prepare` request body: an untrusted claimant's
/// requested fee-claim preparation shape, plus the transport signing scope
/// it expects. This type never re-derives or reinterprets a signed leg's
/// own authority; it carries claims only. The host's own live context/
/// fence/checkpoint and verified historical committee remain the sole
/// authority for preparation and verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeClaimPrepareRequest {
    /// Expected replay/signing-scope context; lets the host reject a wrong
    /// scope explicitly instead of silently using its own.
    pub context: PublicationContext,
    /// Exact request id of the certified-apply intent that created the
    /// targeted escrow row.
    pub escrow_request_id: [u8; 32],
    /// Exact requested replay identity for the prepared claim.
    pub request_id: [u8; 32],
    /// Claimed validator identity. Never authenticated here.
    pub validator_id: ValidatorId,
    /// Claimed claimant public key. Never a private key, never authority.
    pub claimant_public_key: [u8; 32],
    /// Claimed recipient of a positive claim's released value.
    pub recipient: Address,
    /// Exact signed local-execution leg bytes for a positive claim, or
    /// `None` for a zero-share claim. Structural only: cryptographic and
    /// owning validation stay in `node_core`.
    pub signed_leg: Option<Vec<u8>>,
}

impl FeeClaimPrepareRequest {
    fn check_bounds(&self) -> Result<(), FeeClaimPrepareRequestError> {
        if let Some(leg) = &self.signed_leg {
            if leg.is_empty() {
                return Err(FeeClaimPrepareRequestError::EmptySignedLeg);
            }
            if leg.len() > MAX_FEE_CLAIM_PREPARE_LEG_BYTES {
                return Err(FeeClaimPrepareRequestError::LegTooLarge(leg.len()));
            }
        }
        Ok(())
    }

    /// Borrows this request as the core preparation selector. Grants no
    /// authority: `node_core::fee_claims::prepare_fee_claim` independently
    /// re-authenticates everything it accepts.
    #[must_use]
    pub fn as_core_request(&self) -> FeeClaimPreparationRequest<'_> {
        FeeClaimPreparationRequest {
            escrow_request_id: self.escrow_request_id,
            request_id: self.request_id,
            validator_id: self.validator_id,
            claimant_public_key: self.claimant_public_key,
            recipient: self.recipient,
            signed_leg: self.signed_leg.as_deref(),
        }
    }

    /// Encodes canonical frame `0x6461/v1`.
    pub fn encode(&self) -> Result<Vec<u8>, FeeClaimPrepareRequestError> {
        self.check_bounds()?;
        let mut frame = CanonicalStruct::new(
            FEE_CLAIM_PREPARE_REQUEST_TYPE_ID,
            FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION,
        );
        frame.field_bytes(
            1,
            encode_publication_context(&self.context)
                .map_err(|_| FeeClaimPrepareRequestError::InvalidContext)?,
        )?;
        frame.field_bytes(2, self.escrow_request_id.to_vec())?;
        frame.field_bytes(3, self.request_id.to_vec())?;
        frame.field_bytes(4, self.validator_id.as_bytes().to_vec())?;
        frame.field_bytes(5, self.claimant_public_key.to_vec())?;
        frame.field_bytes(6, self.recipient.as_bytes().to_vec())?;
        frame.field_bytes(7, self.signed_leg.clone().unwrap_or_default())?;
        let bytes: Vec<u8> = frame.finish()?;
        if bytes.len() > MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES {
            return Err(FeeClaimPrepareRequestError::RequestTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// Strictly decodes canonical frame `0x6461/v1`, rejecting an oversized
    /// input before decoding and re-checking bounds again after.
    pub fn decode(bytes: &[u8]) -> Result<Self, FeeClaimPrepareRequestError> {
        if bytes.len() > MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES {
            return Err(FeeClaimPrepareRequestError::RequestTooLarge(bytes.len()));
        }
        let frame = decode_canonical_frame(bytes)?;
        frame.require_type(FEE_CLAIM_PREPARE_REQUEST_TYPE_ID)?;
        frame.require_version(FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7])?;
        let context = decode_publication_context(frame.required_field(1)?)
            .map_err(|_| FeeClaimPrepareRequestError::InvalidContext)?;
        let escrow_request_id_bytes = frame.required_field(2)?;
        let escrow_request_id: [u8; 32] = escrow_request_id_bytes.try_into().map_err(|_| {
            CanonicalDecodingError::InvalidFieldLength {
                field_id: 2,
                expected: 32,
                actual: escrow_request_id_bytes.len(),
            }
        })?;
        let request_id_bytes = frame.required_field(3)?;
        let request_id: [u8; 32] = request_id_bytes.try_into().map_err(|_| {
            CanonicalDecodingError::InvalidFieldLength {
                field_id: 3,
                expected: 32,
                actual: request_id_bytes.len(),
            }
        })?;
        let validator_bytes = frame.required_field(4)?;
        let validator_array: [u8; 32] = validator_bytes.try_into().map_err(|_| {
            CanonicalDecodingError::InvalidFieldLength {
                field_id: 4,
                expected: 32,
                actual: validator_bytes.len(),
            }
        })?;
        let validator_id = ValidatorId::new(validator_array);
        let claimant_bytes = frame.required_field(5)?;
        let claimant_public_key: [u8; 32] = claimant_bytes.try_into().map_err(|_| {
            CanonicalDecodingError::InvalidFieldLength {
                field_id: 5,
                expected: 32,
                actual: claimant_bytes.len(),
            }
        })?;
        let recipient_bytes = frame.required_field(6)?;
        let recipient_array: [u8; 32] = recipient_bytes.try_into().map_err(|_| {
            CanonicalDecodingError::InvalidFieldLength {
                field_id: 6,
                expected: 32,
                actual: recipient_bytes.len(),
            }
        })?;
        let recipient = Address::new(recipient_array);
        let leg_bytes = frame.required_field(7)?;
        if leg_bytes.len() > MAX_FEE_CLAIM_PREPARE_LEG_BYTES {
            return Err(FeeClaimPrepareRequestError::LegTooLarge(leg_bytes.len()));
        }
        let signed_leg: Option<Vec<u8>> = if leg_bytes.is_empty() {
            None
        } else {
            Some(leg_bytes.to_vec())
        };
        let request = Self {
            context,
            escrow_request_id,
            request_id,
            validator_id,
            claimant_public_key,
            recipient,
            signed_leg,
        };
        request.check_bounds()?;
        if request.encode()?.as_slice() != bytes {
            return Err(FeeClaimPrepareRequestError::NonCanonicalEncoding);
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONTEXT_BYTES: [u8; 44] = [
        0x53, 0x4E, 0x52, 0x45, 0x01, 0x63, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x77, 0x69, 0x72, 0x65, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    fn sample_context() -> PublicationContext {
        decode_publication_context(&SAMPLE_CONTEXT_BYTES).unwrap()
    }

    fn sample_request_with_leg() -> FeeClaimPrepareRequest {
        FeeClaimPrepareRequest {
            context: sample_context(),
            escrow_request_id: [1; 32],
            request_id: [2; 32],
            validator_id: ValidatorId::new([3; 32]),
            claimant_public_key: [4; 32],
            recipient: Address::new([5; 32]),
            signed_leg: Some(vec![0xAB; 64]),
        }
    }

    fn sample_request_without_leg() -> FeeClaimPrepareRequest {
        FeeClaimPrepareRequest {
            signed_leg: None,
            ..sample_request_with_leg()
        }
    }

    #[test]
    fn round_trips_with_a_signed_leg() {
        let request = sample_request_with_leg();
        let bytes = request.encode().unwrap();
        assert_eq!(FeeClaimPrepareRequest::decode(&bytes).unwrap(), request);
    }

    #[test]
    fn round_trips_without_a_signed_leg_as_a_zero_share_request() {
        let request = sample_request_without_leg();
        let bytes = request.encode().unwrap();
        let decoded = FeeClaimPrepareRequest::decode(&bytes).unwrap();
        assert_eq!(decoded, request);
        assert!(decoded.signed_leg.is_none());
    }

    #[test]
    fn as_core_request_borrows_every_field_without_the_context() {
        let request = sample_request_with_leg();
        let core_request = request.as_core_request();
        assert_eq!(core_request.escrow_request_id, request.escrow_request_id);
        assert_eq!(core_request.request_id, request.request_id);
        assert_eq!(core_request.validator_id, request.validator_id);
        assert_eq!(
            core_request.claimant_public_key,
            request.claimant_public_key
        );
        assert_eq!(core_request.recipient, request.recipient);
        assert_eq!(core_request.signed_leg, request.signed_leg.as_deref());
    }

    #[test]
    fn rejects_an_empty_some_signed_leg_as_ambiguous_with_none() {
        let request = FeeClaimPrepareRequest {
            signed_leg: Some(Vec::new()),
            ..sample_request_with_leg()
        };
        assert_eq!(
            request.encode(),
            Err(FeeClaimPrepareRequestError::EmptySignedLeg)
        );
    }

    #[test]
    fn rejects_an_oversized_leg_on_encode() {
        let request = FeeClaimPrepareRequest {
            signed_leg: Some(vec![0u8; MAX_FEE_CLAIM_PREPARE_LEG_BYTES + 1]),
            ..sample_request_with_leg()
        };
        let length = request.signed_leg.as_ref().unwrap().len();
        assert_eq!(
            request.encode(),
            Err(FeeClaimPrepareRequestError::LegTooLarge(length))
        );
    }

    #[test]
    fn rejects_an_oversized_encoded_request_on_decode_before_parsing() {
        let oversized = vec![0u8; MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES + 1];
        let length = oversized.len();
        assert_eq!(
            FeeClaimPrepareRequest::decode(&oversized),
            Err(FeeClaimPrepareRequestError::RequestTooLarge(length))
        );
    }

    fn sample_fields() -> Vec<(u16, Vec<u8>)> {
        let request = sample_request_with_leg();
        vec![
            (1, SAMPLE_CONTEXT_BYTES.to_vec()),
            (2, request.escrow_request_id.to_vec()),
            (3, request.request_id.to_vec()),
            (4, request.validator_id.as_bytes().to_vec()),
            (5, request.claimant_public_key.to_vec()),
            (6, request.recipient.as_bytes().to_vec()),
            (7, request.signed_leg.clone().unwrap()),
        ]
    }

    fn raw_frame(type_id: u16, version: u16, fields: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = canonical_encoding::PROTOCOL_MAGIC.to_vec();
        bytes.extend_from_slice(&type_id.to_le_bytes());
        bytes.extend_from_slice(&version.to_le_bytes());
        let count = u16::try_from(fields.len()).unwrap();
        bytes.extend_from_slice(&count.to_le_bytes());
        for (field_id, value) in fields {
            bytes.extend_from_slice(&field_id.to_le_bytes());
            let length = u32::try_from(value.len()).unwrap();
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(value);
        }
        bytes
    }

    #[test]
    fn rejects_an_oversized_leg_field_on_decode() {
        let mut fields = sample_fields();
        fields[6] = (7, vec![0u8; MAX_FEE_CLAIM_PREPARE_LEG_BYTES + 1]);
        let bytes = raw_frame(
            FEE_CLAIM_PREPARE_REQUEST_TYPE_ID,
            FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION,
            &fields,
        );
        assert_eq!(
            FeeClaimPrepareRequest::decode(&bytes),
            Err(FeeClaimPrepareRequestError::LegTooLarge(
                MAX_FEE_CLAIM_PREPARE_LEG_BYTES + 1
            ))
        );
    }

    #[test]
    fn rejects_wrong_type_id() {
        let bytes = raw_frame(
            FEE_CLAIM_PREPARE_REQUEST_TYPE_ID + 1,
            FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION,
            &sample_fields(),
        );
        assert!(matches!(
            FeeClaimPrepareRequest::decode(&bytes),
            Err(FeeClaimPrepareRequestError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let bytes = raw_frame(
            FEE_CLAIM_PREPARE_REQUEST_TYPE_ID,
            FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION + 1,
            &sample_fields(),
        );
        assert!(matches!(
            FeeClaimPrepareRequest::decode(&bytes),
            Err(FeeClaimPrepareRequestError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion { .. }
            ))
        ));
    }

    #[test]
    fn rejects_an_unknown_field() {
        let mut fields = sample_fields();
        fields.push((8, vec![9]));
        let bytes = raw_frame(
            FEE_CLAIM_PREPARE_REQUEST_TYPE_ID,
            FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION,
            &fields,
        );
        assert!(matches!(
            FeeClaimPrepareRequest::decode(&bytes),
            Err(FeeClaimPrepareRequestError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(8)
            ))
        ));
    }

    #[test]
    fn rejects_a_duplicate_field() {
        let mut fields = sample_fields();
        let last = fields.last().unwrap().clone();
        fields.push(last);
        let bytes = raw_frame(
            FEE_CLAIM_PREPARE_REQUEST_TYPE_ID,
            FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION,
            &fields,
        );
        assert!(matches!(
            FeeClaimPrepareRequest::decode(&bytes),
            Err(FeeClaimPrepareRequestError::CanonicalDecoding(
                CanonicalDecodingError::NonCanonicalFieldOrder { .. }
            ))
        ));
    }

    #[test]
    fn rejects_a_missing_field() {
        let mut fields = sample_fields();
        fields.truncate(6);
        let bytes = raw_frame(
            FEE_CLAIM_PREPARE_REQUEST_TYPE_ID,
            FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION,
            &fields,
        );
        assert!(matches!(
            FeeClaimPrepareRequest::decode(&bytes),
            Err(FeeClaimPrepareRequestError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(7)
            ))
        ));
    }

    #[test]
    fn rejects_a_bad_fixed_length_field() {
        let mut fields = sample_fields();
        fields[1] = (2, vec![0u8; 31]);
        let bytes = raw_frame(
            FEE_CLAIM_PREPARE_REQUEST_TYPE_ID,
            FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION,
            &fields,
        );
        assert!(matches!(
            FeeClaimPrepareRequest::decode(&bytes),
            Err(FeeClaimPrepareRequestError::CanonicalDecoding(
                CanonicalDecodingError::InvalidFieldLength {
                    field_id: 2,
                    expected: 32,
                    actual: 31,
                }
            ))
        ));
    }

    #[test]
    fn rejects_a_malformed_context() {
        let mut fields = sample_fields();
        fields[0] = (1, vec![0u8; 4]);
        let bytes = raw_frame(
            FEE_CLAIM_PREPARE_REQUEST_TYPE_ID,
            FEE_CLAIM_PREPARE_REQUEST_ENCODING_VERSION,
            &fields,
        );
        assert_eq!(
            FeeClaimPrepareRequest::decode(&bytes),
            Err(FeeClaimPrepareRequestError::InvalidContext)
        );
    }

    #[test]
    fn rejects_truncated_bytes() {
        let request = sample_request_with_leg();
        let bytes = request.encode().unwrap();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(matches!(
            FeeClaimPrepareRequest::decode(truncated),
            Err(FeeClaimPrepareRequestError::CanonicalDecoding(_))
        ));
    }

    #[test]
    fn response_reuses_the_exact_canonical_core_fee_claim_intent() {
        use bonds::BondResourceId;
        use node_core::fee_claims::codec::{
            FeeClaimIntent, FeeClaimOperation, decode_fee_claim_intent, encode_fee_claim_intent,
        };
        use objects::{ObjectId, ObjectRef};
        use protocol_types::{Digest32, Epoch, HashAlgorithmId};

        let intent = FeeClaimIntent {
            context: sample_context(),
            request_id: [6; 32],
            escrow_request_id: [7; 32],
            certificate_epoch: Epoch::new(3),
            validator_id: ValidatorId::new([8; 32]),
            resource_id: BondResourceId::new(1, [9; 32]).unwrap(),
            expected_generation: 1,
            expected_fee_output: ObjectRef {
                id: ObjectId::new([10; 32]),
                version: 1,
                digest: Digest32::new(HashAlgorithmId::Sha2_256, [11; 32]),
            },
            expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [12; 32]),
            expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [13; 32]),
            share_amount: 0,
            recipient: Address::new([14; 32]),
            operation: FeeClaimOperation::ZeroShare,
        };
        let bytes = encode_fee_claim_intent(&intent).unwrap();
        assert_eq!(decode_fee_claim_intent(&bytes).unwrap(), intent);
    }
}
