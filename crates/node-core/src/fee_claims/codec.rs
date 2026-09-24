//! Bounded canonical wire types for one DR-0137 fee-claim intent (see
//! `docs/architecture/decisions/0137-fastvote-release-authority.md`,
//! "Certified fee escrow and claims"): a validator-signed claim against one
//! bounded `FastPathSettlementRecord` escrow row, closed to exactly one of
//! [`FeeClaimOperation::ZeroShare`] (finalized without any object mutation),
//! [`FeeClaimOperation::Split`] (a partial positive claim through the
//! policy-pinned `split` entrypoint) or [`FeeClaimOperation::FinalTransfer`]
//! (the last positive claim, through the policy-pinned `transfer`
//! entrypoint).
//!
//! This module defines encoding, decoding and stable-vector-tested canonical
//! bytes only. The exact signing domain/digest and the durable claim handler
//! are implemented separately.
use bonds::{BondResourceId, decode_bond_resource_id, encode_bond_resource_id};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame, decode_digest32, encode_digest32,
};
use core::fmt;
use execution::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES;
use execution::publication::{
    PublicationContext, decode_publication_context, encode_publication_context,
};
use objects::{Address, ObjectRef, decode_object_ref, encode_object_ref};
use protocol_types::{Digest32, Epoch, ValidatorId};
use std::error::Error;

use crate::NodeCoreError;

const FEE_CLAIM_INTENT_TYPE: u16 = 0x6437;
const SIGNED_FEE_CLAIM_INTENT_TYPE: u16 = 0x6438;
const ENCODING_VERSION: u16 = 1;

/// Bounds the complete signed envelope, which embeds at most one leg.
pub const MAX_FEE_CLAIM_INTENT_BYTES: usize = MAX_LOCAL_EXECUTION_INTENT_BYTES + 4_096;

const OPERATION_TAG_ZERO_SHARE: u16 = 1;
const OPERATION_TAG_SPLIT: u16 = 2;
const OPERATION_TAG_FINAL_TRANSFER: u16 = 3;

/// Fail-closed fee-claim codec errors, convertible to [`NodeCoreError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeClaimCodecError {
    /// Canonical encoding failed.
    Encoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    Decoding(CanonicalDecodingError),
    /// A fee-claim-specific invariant failed.
    Invalid(&'static str),
}

impl fmt::Display for FeeClaimCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => error.fmt(f),
            Self::Decoding(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}
impl Error for FeeClaimCodecError {}

impl From<CanonicalEncodingError> for FeeClaimCodecError {
    fn from(error: CanonicalEncodingError) -> Self {
        Self::Encoding(error)
    }
}
impl From<CanonicalDecodingError> for FeeClaimCodecError {
    fn from(error: CanonicalDecodingError) -> Self {
        Self::Decoding(error)
    }
}
impl From<FeeClaimCodecError> for NodeCoreError {
    fn from(error: FeeClaimCodecError) -> Self {
        match error {
            FeeClaimCodecError::Encoding(inner) => Self::CanonicalEncoding(inner),
            FeeClaimCodecError::Decoding(inner) => Self::CanonicalDecoding(inner),
            FeeClaimCodecError::Invalid(message) => Self::PersistenceInvariant(message),
        }
    }
}

/// One closed fee-claim operation against the current escrow row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeClaimOperation {
    /// A zero-amount claim: finalized without any object mutation.
    ZeroShare,
    /// A partial positive claim through the policy-pinned `split`
    /// entrypoint.
    Split {
        /// The claim's signed local-execution leg (raw canonical bytes).
        leg: Vec<u8>,
    },
    /// The final positive claim through the policy-pinned `transfer`
    /// entrypoint.
    FinalTransfer {
        /// The claim's signed local-execution leg (raw canonical bytes).
        leg: Vec<u8>,
    },
}

impl FeeClaimOperation {
    pub(crate) const fn tag(&self) -> u16 {
        match self {
            Self::ZeroShare => OPERATION_TAG_ZERO_SHARE,
            Self::Split { .. } => OPERATION_TAG_SPLIT,
            Self::FinalTransfer { .. } => OPERATION_TAG_FINAL_TRANSFER,
        }
    }
}

/// Single signed payload authorizing one closed fee-claim operation against
/// one exact bounded escrow row generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeClaimIntent {
    /// Expected replay context.
    pub context: PublicationContext,
    /// Exact replay identity covered by the signature. The embedded leg's
    /// own `CallIntent::request_id`, when present, must equal this value.
    pub request_id: [u8; 32],
    /// Exact request id of the certified-apply intent that created the
    /// targeted `FastPathSettlementRecord` escrow row.
    pub escrow_request_id: [u8; 32],
    /// Exact certificate epoch the signer binds this claim to.
    pub certificate_epoch: Epoch,
    /// Validator this claim is signed by and attributed to.
    pub validator_id: ValidatorId,
    /// Exact generic fee resource identity the signer expects the escrow
    /// row to carry.
    pub resource_id: BondResourceId,
    /// Exact current (pre-claim) generation the signer expects the escrow
    /// row to carry.
    pub expected_generation: u64,
    /// Exact current `FeeEscrow` object ref the signer expects the escrow
    /// row to carry.
    pub expected_fee_output: ObjectRef,
    /// Exact digest of the current (pre-claim) escrow row the signer
    /// expects.
    pub expected_previous_row_digest: Digest32,
    /// Exact digest of the deterministically resulting escrow row this
    /// claim must produce.
    pub expected_next_row_digest: Digest32,
    /// Exact entitlement amount this claim releases.
    pub share_amount: u64,
    /// Exact recipient of a positive claim's released value.
    pub recipient: Address,
    /// The closed operation and its embedded leg, if any.
    pub operation: FeeClaimOperation,
}

/// Unverified `fee_claim` submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedFeeClaimIntent {
    /// Exact signed payload.
    pub intent: FeeClaimIntent,
    /// Ed25519 signature, verified only against the committed escrow row's
    /// own historical validator authorization key.
    pub signature: [u8; 64],
}

/// Encodes fee-claim intent `0x6437/v1`.
pub fn encode_fee_claim_intent(intent: &FeeClaimIntent) -> Result<Vec<u8>, FeeClaimCodecError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(FEE_CLAIM_INTENT_TYPE, ENCODING_VERSION);
    frame.field_bytes(
        1,
        encode_publication_context(&intent.context)
            .map_err(|_| FeeClaimCodecError::Invalid("invalid fee claim context"))?,
    )?;
    frame.field_bytes(2, intent.request_id.to_vec())?;
    frame.field_bytes(3, intent.escrow_request_id.to_vec())?;
    frame.field_u64(4, intent.certificate_epoch.get())?;
    frame.field_bytes(5, intent.validator_id.as_bytes().to_vec())?;
    frame.field_bytes(
        6,
        encode_bond_resource_id(intent.resource_id)
            .map_err(|_| FeeClaimCodecError::Invalid("fee claim resource id"))?,
    )?;
    frame.field_u64(7, intent.expected_generation)?;
    frame.field_bytes(
        8,
        encode_object_ref(&intent.expected_fee_output)
            .map_err(|_| FeeClaimCodecError::Invalid("fee claim expected fee output"))?,
    )?;
    frame.field_bytes(9, encode_digest32(&intent.expected_previous_row_digest)?)?;
    frame.field_bytes(10, encode_digest32(&intent.expected_next_row_digest)?)?;
    frame.field_u64(11, intent.share_amount)?;
    frame.field_bytes(12, intent.recipient.as_bytes().to_vec())?;
    frame.field_u16(13, intent.operation.tag())?;
    match &intent.operation {
        FeeClaimOperation::ZeroShare => {}
        FeeClaimOperation::Split { leg } | FeeClaimOperation::FinalTransfer { leg } => {
            if leg.is_empty() {
                return Err(FeeClaimCodecError::Invalid(
                    "fee claim leg must be nonempty",
                ));
            }
            frame.field_bytes(14, leg.clone())?;
        }
    }
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_FEE_CLAIM_INTENT_BYTES {
        return Err(FeeClaimCodecError::Invalid("fee claim intent bytes"));
    }
    Ok(bytes)
}

/// Strictly decodes fee-claim intent `0x6437/v1`.
pub fn decode_fee_claim_intent(bytes: &[u8]) -> Result<FeeClaimIntent, FeeClaimCodecError> {
    if bytes.len() > MAX_FEE_CLAIM_INTENT_BYTES {
        return Err(FeeClaimCodecError::Invalid("fee claim intent bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FEE_CLAIM_INTENT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)
        .map_err(|_| FeeClaimCodecError::Invalid("invalid fee claim context"))?;
    let request_id: [u8; 32] = frame
        .required_field(2)?
        .try_into()
        .map_err(|_| FeeClaimCodecError::Invalid("fee claim request id length"))?;
    let escrow_request_id: [u8; 32] = frame
        .required_field(3)?
        .try_into()
        .map_err(|_| FeeClaimCodecError::Invalid("fee claim escrow request id length"))?;
    let certificate_epoch: Epoch = Epoch::new(frame.required_u64(4)?);
    let validator_bytes: [u8; 32] = frame
        .required_field(5)?
        .try_into()
        .map_err(|_| FeeClaimCodecError::Invalid("fee claim validator id length"))?;
    let validator_id: ValidatorId = ValidatorId::new(validator_bytes);
    let resource_id: BondResourceId = decode_bond_resource_id(frame.required_field(6)?)
        .map_err(|_| FeeClaimCodecError::Invalid("fee claim resource id"))?;
    let expected_generation: u64 = frame.required_u64(7)?;
    let expected_fee_output: ObjectRef = decode_object_ref(frame.required_field(8)?)
        .map_err(|_| FeeClaimCodecError::Invalid("fee claim expected fee output"))?;
    let expected_previous_row_digest: Digest32 = decode_digest32(frame.required_field(9)?)?;
    let expected_next_row_digest: Digest32 = decode_digest32(frame.required_field(10)?)?;
    let share_amount: u64 = frame.required_u64(11)?;
    let recipient_bytes: [u8; 32] = frame
        .required_field(12)?
        .try_into()
        .map_err(|_| FeeClaimCodecError::Invalid("fee claim recipient length"))?;
    let recipient: Address = Address::new(recipient_bytes);
    let tag: u16 = frame.required_u16(13)?;
    let fixed_fields: &[u16] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    let operation: FeeClaimOperation = match tag {
        OPERATION_TAG_ZERO_SHARE => {
            frame.require_only_fields(fixed_fields)?;
            FeeClaimOperation::ZeroShare
        }
        OPERATION_TAG_SPLIT => {
            frame.require_only_fields(&[fixed_fields, &[14]].concat())?;
            let leg: Vec<u8> = frame.required_field(14)?.to_vec();
            if leg.is_empty() {
                return Err(FeeClaimCodecError::Invalid(
                    "fee claim leg must be nonempty",
                ));
            }
            FeeClaimOperation::Split { leg }
        }
        OPERATION_TAG_FINAL_TRANSFER => {
            frame.require_only_fields(&[fixed_fields, &[14]].concat())?;
            let leg: Vec<u8> = frame.required_field(14)?.to_vec();
            if leg.is_empty() {
                return Err(FeeClaimCodecError::Invalid(
                    "fee claim leg must be nonempty",
                ));
            }
            FeeClaimOperation::FinalTransfer { leg }
        }
        _ => {
            return Err(FeeClaimCodecError::Invalid("unknown fee claim operation"));
        }
    };
    let intent: FeeClaimIntent = FeeClaimIntent {
        context,
        request_id,
        escrow_request_id,
        certificate_epoch,
        validator_id,
        resource_id,
        expected_generation,
        expected_fee_output,
        expected_previous_row_digest,
        expected_next_row_digest,
        share_amount,
        recipient,
        operation,
    };
    if encode_fee_claim_intent(&intent)? != bytes {
        return Err(FeeClaimCodecError::Invalid("noncanonical fee claim intent"));
    }
    Ok(intent)
}

/// Encodes signed fee-claim intent `0x6438/v1`.
pub fn encode_signed_fee_claim_intent(
    signed: &SignedFeeClaimIntent,
) -> Result<Vec<u8>, FeeClaimCodecError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(SIGNED_FEE_CLAIM_INTENT_TYPE, ENCODING_VERSION);
    frame.field_bytes(1, encode_fee_claim_intent(&signed.intent)?)?;
    frame.field_bytes(2, signed.signature.to_vec())?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_FEE_CLAIM_INTENT_BYTES {
        return Err(FeeClaimCodecError::Invalid("signed fee claim bytes"));
    }
    Ok(bytes)
}

/// Strictly decodes signed fee-claim intent `0x6438/v1`. Performs no
/// signature verification: node core verifies it only after reading the
/// committed escrow row's own historical validator authorization key.
pub fn decode_signed_fee_claim_intent(
    bytes: &[u8],
) -> Result<SignedFeeClaimIntent, FeeClaimCodecError> {
    if bytes.len() > MAX_FEE_CLAIM_INTENT_BYTES {
        return Err(FeeClaimCodecError::Invalid("signed fee claim bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(SIGNED_FEE_CLAIM_INTENT_TYPE)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let signed: SignedFeeClaimIntent = SignedFeeClaimIntent {
        intent: decode_fee_claim_intent(frame.required_field(1)?)?,
        signature: frame
            .required_field(2)?
            .try_into()
            .map_err(|_| FeeClaimCodecError::Invalid("fee claim signature length"))?,
    };
    if encode_signed_fee_claim_intent(&signed)? != bytes {
        return Err(FeeClaimCodecError::Invalid(
            "noncanonical signed fee claim intent",
        ));
    }
    Ok(signed)
}

#[cfg(test)]
mod tests;
