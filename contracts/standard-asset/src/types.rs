//! Canonical body/argument layouts and nominal type helpers.
//!
//! These are structural declarations only: constructing a tag or layout
//! asserts no instance authority, no ownership, and no defining-code rights.
//! Two packages with equal nominal tags are still separate authorities.

use abi::call_values::ValueLayout;
use abi::package_types::{PackageOrigin, ScopedTypeArg, ScopedTypeTag};
use abi::public_abi::{PatternArgument, TypePattern};
use objects::ObjectId;

use crate::{
    ASSET_OPAQUE_DOMAIN, CONSTRUCTOR_COIN, CONSTRUCTOR_DEFINITION, CONSTRUCTOR_RESERVATION,
    CONSTRUCTOR_TREASURY_CAP, ENCODED_DIGEST32_BYTES, StandardAssetError,
};

fn fixed_bytes(len: u32) -> ValueLayout {
    ValueLayout::Bytes {
        min_len: len,
        max_len: len,
    }
}

/// Body layout of `Definition`: an empty tuple. Asset identity lives in the
/// nominal type, never in a duplicated body field.
#[must_use]
pub fn definition_body_layout() -> ValueLayout {
    ValueLayout::Tuple(Vec::new())
}

/// Body layout of `Coin<A>`: one checked `u64` amount, always positive.
#[must_use]
pub fn coin_body_layout() -> ValueLayout {
    ValueLayout::U64
}

/// Body layout of `TreasuryCap<A>`: one checked `u64` supply, possibly zero.
#[must_use]
pub fn treasury_cap_body_layout() -> ValueLayout {
    ValueLayout::U64
}

/// Body layout of `Reservation<A>`: reserved units, the encoded invocation
/// and fee-policy digests, and the pinned fee and refund recipients.
#[must_use]
pub fn reservation_body_layout() -> ValueLayout {
    ValueLayout::Tuple(vec![
        ValueLayout::U64,
        fixed_bytes(ENCODED_DIGEST32_BYTES),
        fixed_bytes(ENCODED_DIGEST32_BYTES),
        fixed_bytes(32),
        fixed_bytes(32),
    ])
}

/// Argument layout of `burn`, `init`, and `merge`.
#[must_use]
pub fn empty_argument_layout() -> ValueLayout {
    ValueLayout::Tuple(Vec::new())
}

/// Argument layout of `mint`: positive amount and recipient address.
#[must_use]
pub fn mint_argument_layout() -> ValueLayout {
    ValueLayout::Tuple(vec![ValueLayout::U64, fixed_bytes(32)])
}

/// Argument layout of `split`: positive strict-partial amount and recipient.
#[must_use]
pub fn split_argument_layout() -> ValueLayout {
    mint_argument_layout()
}

/// Argument layout of `transfer`: recipient address.
#[must_use]
pub fn transfer_argument_layout() -> ValueLayout {
    ValueLayout::Tuple(vec![fixed_bytes(32)])
}

/// Argument layout of `reserve` and `reserve_all`, identical to the
/// `Reservation<A>` body so the stored commitment is the exact signed tuple.
#[must_use]
pub fn reserve_argument_layout() -> ValueLayout {
    reservation_body_layout()
}

/// Argument layout of `settle`: actual units plus the two encoded digests.
#[must_use]
pub fn settle_argument_layout() -> ValueLayout {
    ValueLayout::Tuple(vec![
        ValueLayout::U64,
        fixed_bytes(ENCODED_DIGEST32_BYTES),
        fixed_bytes(ENCODED_DIGEST32_BYTES),
    ])
}

/// The opaque type argument carrying asset identity `A`.
///
/// `A` must be the ObjectId of a `Definition` created by this package's own
/// initializer. Passing any other value cannot forge authority: the host
/// still matches every input's recorded nominal tag exactly.
#[must_use]
pub fn asset_type_argument(asset: &ObjectId) -> ScopedTypeArg {
    ScopedTypeArg::Opaque {
        domain: ASSET_OPAQUE_DOMAIN,
        value: *asset.as_bytes(),
    }
}

fn parameterized_tag(
    origin: &PackageOrigin,
    constructor: u16,
    asset: &ObjectId,
) -> Result<ScopedTypeTag, StandardAssetError> {
    Ok(ScopedTypeTag::new(
        origin.clone(),
        constructor,
        vec![asset_type_argument(asset)],
    )?)
}

/// The nominal tag of this package's `Definition` object.
pub fn definition_type_tag(origin: &PackageOrigin) -> Result<ScopedTypeTag, StandardAssetError> {
    Ok(ScopedTypeTag::new(
        origin.clone(),
        CONSTRUCTOR_DEFINITION,
        Vec::new(),
    )?)
}

/// The nominal tag of `Coin<A>`.
pub fn coin_type_tag(
    origin: &PackageOrigin,
    asset: &ObjectId,
) -> Result<ScopedTypeTag, StandardAssetError> {
    parameterized_tag(origin, CONSTRUCTOR_COIN, asset)
}

/// The nominal tag of `TreasuryCap<A>`.
pub fn treasury_cap_type_tag(
    origin: &PackageOrigin,
    asset: &ObjectId,
) -> Result<ScopedTypeTag, StandardAssetError> {
    parameterized_tag(origin, CONSTRUCTOR_TREASURY_CAP, asset)
}

/// The nominal tag of `Reservation<A>`.
pub fn reservation_type_tag(
    origin: &PackageOrigin,
    asset: &ObjectId,
) -> Result<ScopedTypeTag, StandardAssetError> {
    parameterized_tag(origin, CONSTRUCTOR_RESERVATION, asset)
}

/// A declared pattern binding `constructor` to entrypoint type parameter
/// zero, so every input and result of one entrypoint shares one bound `A`.
pub(crate) fn bound_pattern(origin: &PackageOrigin, constructor: u16) -> TypePattern {
    TypePattern {
        origin: origin.clone(),
        constructor,
        arguments: vec![PatternArgument::Parameter(0)],
    }
}

/// The `Definition` pattern, which takes no type argument.
pub(crate) fn definition_pattern(origin: &PackageOrigin) -> TypePattern {
    TypePattern {
        origin: origin.clone(),
        constructor: CONSTRUCTOR_DEFINITION,
        arguments: Vec::new(),
    }
}
