//! Canonical client-side argument encoders and body decoders.
//!
//! Encoding an argument tuple authorizes nothing: the published WASM
//! re-checks every bound (positivity, strict partiality, checked
//! arithmetic, commitment equality) against the host-validated inputs.
//! Decoding a body only reads bytes the host already validated against the
//! declared constructor layout.

use abi::call_values::{CallValue, ValueLayout, decode_call_value, encode_call_value};
use canonical_encoding::encode_digest32;
use protocol_types::Digest32;

use crate::StandardAssetError;
use crate::types::{
    coin_body_layout, empty_argument_layout, mint_argument_layout, reservation_body_layout,
    reserve_argument_layout, settle_argument_layout, split_argument_layout,
    transfer_argument_layout, treasury_cap_body_layout,
};

/// The stored, caller-attested reservation commitment.
///
/// The guest cannot verify the current invocation or fee policy. These
/// fields provide settlement continuity only; they are not proof of paid
/// admission and the host never decodes them as authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationBody {
    /// Reserved asset units.
    pub reserved: u64,
    /// Encoded self-describing invocation digest (exactly 56 bytes).
    pub invocation: Vec<u8>,
    /// Encoded self-describing fee-policy digest (exactly 56 bytes).
    pub policy: Vec<u8>,
    /// Pinned fee recipient address.
    pub fee_recipient: [u8; 32],
    /// Pinned refund recipient address.
    pub refund_recipient: [u8; 32],
}

fn encode(layout: &ValueLayout, value: &CallValue) -> Result<Vec<u8>, StandardAssetError> {
    Ok(encode_call_value(layout, value)?)
}

/// Encodes the empty argument tuple used by `burn`, `init`, and `merge`.
pub fn no_arguments() -> Result<Vec<u8>, StandardAssetError> {
    encode(&empty_argument_layout(), &CallValue::Tuple(Vec::new()))
}

/// Encodes `mint` arguments. The amount must be positive.
pub fn mint_arguments(amount: u64, recipient: &[u8; 32]) -> Result<Vec<u8>, StandardAssetError> {
    if amount == 0 {
        return Err(StandardAssetError::Invalid("mint amount must be positive"));
    }
    encode(
        &mint_argument_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(amount),
            CallValue::Bytes(recipient.to_vec()),
        ]),
    )
}

/// Encodes `split` arguments. The amount must be positive; the guest also
/// requires it to be a strict partial amount of the source balance.
pub fn split_arguments(amount: u64, recipient: &[u8; 32]) -> Result<Vec<u8>, StandardAssetError> {
    if amount == 0 {
        return Err(StandardAssetError::Invalid("split amount must be positive"));
    }
    encode(
        &split_argument_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(amount),
            CallValue::Bytes(recipient.to_vec()),
        ]),
    )
}

/// Encodes `transfer` arguments.
pub fn transfer_arguments(recipient: &[u8; 32]) -> Result<Vec<u8>, StandardAssetError> {
    encode(
        &transfer_argument_layout(),
        &CallValue::Tuple(vec![CallValue::Bytes(recipient.to_vec())]),
    )
}

/// Encodes `reserve`/`reserve_all` arguments, which are byte-identical to
/// the resulting `Reservation<A>` body. Digests keep their canonical
/// self-describing encoding.
pub fn reserve_arguments(
    reserved: u64,
    invocation: &Digest32,
    policy: &Digest32,
    fee_recipient: &[u8; 32],
    refund_recipient: &[u8; 32],
) -> Result<Vec<u8>, StandardAssetError> {
    if reserved == 0 {
        return Err(StandardAssetError::Invalid(
            "reserved units must be positive",
        ));
    }
    encode(
        &reserve_argument_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(reserved),
            CallValue::Bytes(encode_digest32(invocation)?),
            CallValue::Bytes(encode_digest32(policy)?),
            CallValue::Bytes(fee_recipient.to_vec()),
            CallValue::Bytes(refund_recipient.to_vec()),
        ]),
    )
}

/// Encodes `settle` arguments. The refund is never a caller-supplied
/// amount: the guest computes it by checked subtraction.
pub fn settle_arguments(
    actual: u64,
    invocation: &Digest32,
    policy: &Digest32,
) -> Result<Vec<u8>, StandardAssetError> {
    if actual == 0 {
        return Err(StandardAssetError::Invalid("actual units must be positive"));
    }
    encode(
        &settle_argument_layout(),
        &CallValue::Tuple(vec![
            CallValue::U64(actual),
            CallValue::Bytes(encode_digest32(invocation)?),
            CallValue::Bytes(encode_digest32(policy)?),
        ]),
    )
}

fn scalar(layout: &ValueLayout, bytes: &[u8]) -> Result<u64, StandardAssetError> {
    match decode_call_value(layout, bytes)? {
        CallValue::U64(value) => Ok(value),
        _ => Err(StandardAssetError::Invalid("expected a u64 body")),
    }
}

/// Reads a `Coin<A>` amount from a host-validated body.
pub fn coin_amount(body: &[u8]) -> Result<u64, StandardAssetError> {
    scalar(&coin_body_layout(), body)
}

/// Reads a `TreasuryCap<A>` supply from a host-validated body.
pub fn treasury_supply(body: &[u8]) -> Result<u64, StandardAssetError> {
    scalar(&treasury_cap_body_layout(), body)
}

fn fixed(value: &CallValue) -> Result<[u8; 32], StandardAssetError> {
    match value {
        CallValue::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| StandardAssetError::Invalid("expected a 32-byte address")),
        _ => Err(StandardAssetError::Invalid("expected a byte field")),
    }
}

fn digest_field(value: &CallValue) -> Result<Vec<u8>, StandardAssetError> {
    match value {
        CallValue::Bytes(bytes) if bytes.len() == crate::ENCODED_DIGEST32_BYTES as usize => {
            Ok(bytes.clone())
        }
        _ => Err(StandardAssetError::Invalid("expected an encoded digest")),
    }
}

/// Reads a `Reservation<A>` body from host-validated bytes.
pub fn reservation_body(body: &[u8]) -> Result<ReservationBody, StandardAssetError> {
    let fields: Vec<CallValue> = match decode_call_value(&reservation_body_layout(), body)? {
        CallValue::Tuple(fields) if fields.len() == 5 => fields,
        _ => return Err(StandardAssetError::Invalid("expected a reservation body")),
    };
    let reserved: u64 = match fields[0] {
        CallValue::U64(value) => value,
        _ => return Err(StandardAssetError::Invalid("expected reserved units")),
    };
    Ok(ReservationBody {
        reserved,
        invocation: digest_field(&fields[1])?,
        policy: digest_field(&fields[2])?,
        fee_recipient: fixed(&fields[3])?,
        refund_recipient: fixed(&fields[4])?,
    })
}
