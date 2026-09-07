#![forbid(unsafe_code)]

//! Public Standard Asset package: bounded WAT source, its executable-ABI
//! builder, and canonical client-side argument/type helpers (DR-0124).
//!
//! # Explicit non-claims
//!
//! - Amount transitions execute **only** in the published WASM. Nothing in
//!   this crate performs a native debit, credit, mint, or burn, and no
//!   helper here is an authority path.
//! - Building a package or encoding arguments grants no publication,
//!   instantiation, execution, ownership, or fee authority. Defining-code,
//!   exact-instance, and owner checks remain entirely with the host.
//! - The reserve/settle commitment fields are caller-attested continuity
//!   data. A successful manual `reserve`/`settle` pair conserves supply but
//!   proves no paid admission, no fee receipt, and no coordinator identity.
//! - There is no durable node activation, no installed fee policy, and no
//!   CLI integration in this crate.
//! - This is a fresh public package. It does not reinterpret the
//!   `crates/standard-assets` development representation, its fixture body
//!   bytes, or its seed-derived AssetId.

use canonical_encoding::CanonicalEncodingError;

mod arguments;
mod package;
mod source;
mod types;

pub use arguments::{
    ReservationBody, coin_amount, mint_arguments, no_arguments, reservation_body,
    reserve_arguments, settle_arguments, split_arguments, transfer_arguments, treasury_supply,
};
pub use package::{StandardAssetPackage, build_package, encoded_executable_abi, executable_abi};
pub use source::{contract_wasm, contract_wat};
pub use types::{
    asset_type_argument, coin_body_layout, coin_type_tag, definition_body_layout,
    definition_type_tag, empty_argument_layout, mint_argument_layout, reservation_body_layout,
    reservation_type_tag, reserve_argument_layout, settle_argument_layout, split_argument_layout,
    transfer_argument_layout, treasury_cap_body_layout, treasury_cap_type_tag,
};

/// Package-local constructor identifier for `Definition` (no type argument).
pub const CONSTRUCTOR_DEFINITION: u16 = 1;
/// Package-local constructor identifier for `Coin<A>`.
pub const CONSTRUCTOR_COIN: u16 = 2;
/// Package-local constructor identifier for `TreasuryCap<A>`.
pub const CONSTRUCTOR_TREASURY_CAP: u16 = 3;
/// Package-local constructor identifier for `Reservation<A>`.
pub const CONSTRUCTOR_RESERVATION: u16 = 4;

/// The single package-local opaque argument domain carrying the asset
/// identity `A`. `A` is the ObjectId of the initializer's own fresh
/// `Definition` object, never a caller-chosen value.
pub const ASSET_OPAQUE_DOMAIN: u16 = 1;

/// Every constructor and object parameter/result uses schema version one.
pub const SCHEMA_VERSION: u32 = 1;

/// Encoded byte length of one self-describing `Digest32` under the current
/// canonical encoding (frame header, algorithm id, and 32 digest bytes).
pub const ENCODED_DIGEST32_BYTES: u32 = 56;

/// Declared entrypoint names, in the strictly ascending order the public ABI
/// and the artifact export list both require.
pub const ENTRYPOINTS: [&str; 9] = [
    "burn",
    "init",
    "merge",
    "mint",
    "reserve",
    "reserve_all",
    "settle",
    "split",
    "transfer",
];

/// The ABI-designated initializer export name.
pub const INITIALIZER: &str = "init";

/// Required WASM profile and execution-policy profile for this package.
pub const REQUIRED_WASM_PROFILE: u32 = 4;

/// Typed failures of this package's builders, encoders, and decoders.
///
/// No variant carries or implies protocol authority; each reports a
/// structural, arithmetic, or encoding rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StandardAssetError {
    /// Canonical value/layout/ABI framing failure.
    Value(abi::call_values::ValueError),
    /// Canonical frame encoding failure.
    Encoding(CanonicalEncodingError),
    /// Scoped package type failure.
    PackageType(abi::package_types::PackageTypeError),
    /// The generated WAT source was not accepted by the text-format parser.
    Wat(String),
    /// A structural or domain invariant was violated.
    Invalid(&'static str),
}

impl core::fmt::Display for StandardAssetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Value(err) => write!(f, "canonical value error: {err}"),
            Self::Encoding(err) => write!(f, "canonical encoding error: {err}"),
            Self::PackageType(err) => write!(f, "package type error: {err}"),
            Self::Wat(message) => write!(f, "wat parse error: {message}"),
            Self::Invalid(message) => write!(f, "invalid standard asset input: {message}"),
        }
    }
}

impl std::error::Error for StandardAssetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Value(err) => Some(err),
            Self::Encoding(err) => Some(err),
            Self::PackageType(err) => Some(err),
            Self::Wat(_) | Self::Invalid(_) => None,
        }
    }
}

impl From<abi::call_values::ValueError> for StandardAssetError {
    fn from(err: abi::call_values::ValueError) -> Self {
        Self::Value(err)
    }
}

impl From<CanonicalEncodingError> for StandardAssetError {
    fn from(err: CanonicalEncodingError) -> Self {
        Self::Encoding(err)
    }
}

impl From<abi::package_types::PackageTypeError> for StandardAssetError {
    fn from(err: abi::package_types::PackageTypeError) -> Self {
        Self::PackageType(err)
    }
}
