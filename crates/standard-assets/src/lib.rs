#![forbid(unsafe_code)]

//! Canonical Standard Asset v1 identity and value schemas.
//!
//! This crate owns the general-purpose [`AssetId`] identifier (previously
//! defined inside `fees`) and the strict canonical Standard Asset v1 object
//! bodies: [`StandardAssetDefinitionV1`], [`StandardAssetCoinV1`], and
//! [`StandardAssetMintCapabilityV1`]. Module activation, `Create`, owner
//! transitions, CLI commands, minting, and fee integration remain outside this
//! foundational crate. The local protocol-4 devnet activation is specified by
//! DR-0107 and consumes these types without moving execution policy into this
//! dependency-light crate.
//!
//! **Canonical type IDs owned by this crate:**
//! - `0x7001` — [`AssetId`] (moved from its original `fees` location).
//! - `0x7100` — the canonical AssetId derivation input (private framing detail).
//! - `0x7101` — [`StandardAssetDefinitionV1`].
//! - `0x7102` — [`StandardAssetCoinV1`].
//! - `0x7103` — [`StandardAssetMintCapabilityV1`].
//! - `0x7104` — [`StandardAssetTransferArgsV1`].
//! - `0x7105` — [`StandardAssetSplitArgsV1`].
//!
//! See `docs/architecture/decisions/0104-asset-standards-gate.md` for the
//! full identifier audit and the activation boundary for this slice.
//!
//! # Typed ABI foundation
//!
//! [`constructor_registry`] declares [`abi::ConstructorId`]s that mirror the
//! three body type ids above (`STANDARD_ASSET_*_CONSTRUCTOR`). This mirroring
//! is deliberate and safe, not a namespace merge: `abi::ConstructorId` and
//! this crate's canonical wire type ids are distinct Rust types living in
//! distinct namespaces, and [`abi::ConstructorRegistry::register`] fails
//! closed if two different constructors are ever bound to the same
//! `body_type_id`. Each constructor's body projection extracts the nested
//! [`AssetId`] from canonical field 1 — the field every one of the three
//! bodies uses for `asset_id` — and rejects malformed, unknown, or trailing
//! bytes (see `abi::project_type_arg`). Activation remains the responsibility
//! of a versioned module catalog and protocol configuration; see the crate-level
//! docs above.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use core::fmt;
use hashing::{HashSuiteResolver, HashingError};
use objects::Address;
use protocol_types::{Digest32, Epoch, HashAlgorithmId, HashPurpose, ProtocolVersion, TypeError};
use std::error::Error;

const IDENTIFIER_LEN: usize = 32;
const ENCODING_VERSION: u16 = 1;

/// Stable canonical type identifier for [`AssetId`].
///
/// This value retains the original identifier because the type still has the
/// same protocol meaning; no compatibility facade remains in `fees`.
pub const ASSET_ID_TYPE_ID: u16 = 0x7001;
const ASSET_ID_DERIVATION_INPUT_TYPE_ID: u16 = 0x7100;
/// Stable canonical type identifier for [`StandardAssetDefinitionV1`].
pub const STANDARD_ASSET_DEFINITION_V1_TYPE_ID: u16 = 0x7101;
/// Stable canonical type identifier for [`StandardAssetCoinV1`].
pub const STANDARD_ASSET_COIN_V1_TYPE_ID: u16 = 0x7102;
/// Stable canonical type identifier for [`StandardAssetMintCapabilityV1`].
pub const STANDARD_ASSET_MINT_CAPABILITY_V1_TYPE_ID: u16 = 0x7103;
/// Stable canonical type identifier for [`StandardAssetTransferArgsV1`].
pub const STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID: u16 = 0x7104;
/// Stable canonical type identifier for [`StandardAssetSplitArgsV1`].
pub const STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID: u16 = 0x7105;

/// Errors returned by Standard Asset v1 helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandardAssetError {
    /// An asset identifier had the wrong length.
    InvalidAssetIdLength(usize),
    /// A creation authority address had the wrong length.
    InvalidAddressLength(usize),
    /// An asset creation seed had the wrong length.
    InvalidCreationSeedLength(usize),
    /// An asset creation seed must not be all zeroes.
    ZeroCreationSeed,
    /// A Standard Asset v1 coin amount must be explicitly non-zero.
    ZeroCoinAmount,
    /// A decoded hash algorithm identifier is unknown.
    UnknownHashAlgorithm(TypeError),
    /// The recomputed asset identifier did not match the stored value.
    AssetIdMismatch {
        /// The identifier recomputed from the definition's derivation inputs.
        expected: AssetId,
        /// The identifier stored on the definition.
        actual: AssetId,
    },
    /// The recomputed derivation algorithm did not match the stored value.
    DerivationAlgorithmMismatch {
        /// The algorithm selected by the active hash suite.
        expected: HashAlgorithmId,
        /// The algorithm stored on the definition.
        actual: HashAlgorithmId,
    },
    /// Validation used a resolver for a different protocol version than the
    /// one recorded at asset creation.
    ProtocolVersionMismatch {
        /// The protocol version recorded by the definition.
        expected: ProtocolVersion,
        /// The protocol version bound to the supplied resolver.
        actual: ProtocolVersion,
    },
    /// Hash-suite resolution or hashing failed.
    Hashing(HashingError),
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
    /// A typed-ABI operation failed.
    Abi(abi::AbiError),
}

impl fmt::Display for StandardAssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAssetIdLength(length) => write!(
                f,
                "asset identifiers must be {IDENTIFIER_LEN} bytes, got {length}"
            ),
            Self::InvalidAddressLength(length) => write!(
                f,
                "creation authority addresses must be {IDENTIFIER_LEN} bytes, got {length}"
            ),
            Self::InvalidCreationSeedLength(length) => write!(
                f,
                "asset creation seeds must be {IDENTIFIER_LEN} bytes, got {length}"
            ),
            Self::ZeroCreationSeed => write!(f, "asset creation seed must not be all zeroes"),
            Self::ZeroCoinAmount => write!(f, "standard asset coin amount must be non-zero"),
            Self::UnknownHashAlgorithm(error) => error.fmt(f),
            Self::AssetIdMismatch { expected, actual } => write!(
                f,
                "asset id mismatch: definition recomputes to {expected}, stored value is {actual}"
            ),
            Self::DerivationAlgorithmMismatch { expected, actual } => write!(
                f,
                "derivation algorithm mismatch: active suite selects {expected}, stored value is {actual}"
            ),
            Self::ProtocolVersionMismatch { expected, actual } => write!(
                f,
                "protocol version mismatch: definition records {}, resolver uses {}",
                expected.get(),
                actual.get()
            ),
            Self::Hashing(error) => error.fmt(f),
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::CanonicalDecoding(error) => error.fmt(f),
            Self::Abi(error) => error.fmt(f),
        }
    }
}

impl Error for StandardAssetError {}

impl From<TypeError> for StandardAssetError {
    fn from(value: TypeError) -> Self {
        Self::UnknownHashAlgorithm(value)
    }
}

impl From<HashingError> for StandardAssetError {
    fn from(value: HashingError) -> Self {
        Self::Hashing(value)
    }
}

impl From<CanonicalEncodingError> for StandardAssetError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for StandardAssetError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

impl From<abi::AbiError> for StandardAssetError {
    fn from(value: abi::AbiError) -> Self {
        Self::Abi(value)
    }
}

/// A stable canonical asset identifier.
///
/// Moved from `fees`: the canonical type ID (`0x7001`) is still the natural
/// identifier for this same protocol concept, now owned by its proper crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssetId {
    bytes: [u8; IDENTIFIER_LEN],
}

impl AssetId {
    /// Creates an asset identifier.
    #[must_use]
    pub const fn new(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self { bytes }
    }

    /// Parses an asset identifier from raw bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, StandardAssetError> {
        if bytes.len() != IDENTIFIER_LEN {
            return Err(StandardAssetError::InvalidAssetIdLength(bytes.len()));
        }

        let mut array = [0u8; IDENTIFIER_LEN];
        array.copy_from_slice(bytes);
        Ok(Self::new(array))
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IDENTIFIER_LEN] {
        &self.bytes
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Encodes an asset identifier.
pub fn encode_asset_id(asset_id: &AssetId) -> Result<Vec<u8>, StandardAssetError> {
    let mut canonical = CanonicalStruct::new(ASSET_ID_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, asset_id.as_bytes())?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical asset identifier.
pub fn decode_asset_id(input: &[u8]) -> Result<AssetId, StandardAssetError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(ASSET_ID_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    AssetId::try_from_slice(frame.required_field(1)?)
}

/// A non-zero, caller-supplied seed bound into Standard Asset v1
/// identity derivation.
///
/// The seed is deliberately distinct from node-core's request-idempotency
/// identifier: a caller may choose to derive it from a request ID, but the two
/// concepts cannot be accidentally interchanged at the Rust type boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssetCreationSeed {
    bytes: [u8; IDENTIFIER_LEN],
}

impl AssetCreationSeed {
    /// Creates a non-zero asset creation seed.
    pub fn new(bytes: [u8; IDENTIFIER_LEN]) -> Result<Self, StandardAssetError> {
        if bytes == [0; IDENTIFIER_LEN] {
            return Err(StandardAssetError::ZeroCreationSeed);
        }
        Ok(Self { bytes })
    }

    /// Parses an asset creation seed from raw bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, StandardAssetError> {
        if bytes.len() != IDENTIFIER_LEN {
            return Err(StandardAssetError::InvalidCreationSeedLength(bytes.len()));
        }

        let mut array = [0u8; IDENTIFIER_LEN];
        array.copy_from_slice(bytes);
        Self::new(array)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IDENTIFIER_LEN] {
        &self.bytes
    }
}

impl fmt::Display for AssetCreationSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn decode_address_field(bytes: &[u8]) -> Result<Address, StandardAssetError> {
    if bytes.len() != IDENTIFIER_LEN {
        return Err(StandardAssetError::InvalidAddressLength(bytes.len()));
    }
    let mut array = [0u8; IDENTIFIER_LEN];
    array.copy_from_slice(bytes);
    Ok(Address::from_bytes(array))
}

/// Encodes the canonical AssetId derivation input.
fn encode_asset_id_derivation_input(
    creation_authority: Address,
    creation_seed: AssetCreationSeed,
    creation_epoch: Epoch,
) -> Result<Vec<u8>, StandardAssetError> {
    let mut canonical = CanonicalStruct::new(ASSET_ID_DERIVATION_INPUT_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, creation_authority.as_bytes())?;
    canonical.field_bytes(2, creation_seed.as_bytes())?;
    canonical.field_u64(3, creation_epoch.get())?;
    Ok(canonical.finish()?)
}

/// Derives a Standard Asset v1 [`AssetId`] and returns it with the hash
/// algorithm the active suite selected.
///
/// The derivation binds Standard Asset v1 (via [`HashPurpose::AssetId`]'s
/// domain separation), the resolver's chain and protocol-version context,
/// the creation authority, the caller-supplied creation seed, and the
/// creation epoch. The active hash suite's configuration-hash algorithm is
/// always used; callers cannot select an algorithm. Unsupported algorithms
/// fail closed via [`HashingError::UnsupportedAlgorithm`].
pub fn derive_asset_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    creation_authority: Address,
    creation_seed: AssetCreationSeed,
) -> Result<(AssetId, HashAlgorithmId), StandardAssetError> {
    let payload = encode_asset_id_derivation_input(creation_authority, creation_seed, epoch)?;
    let digest = resolver.hash_for_purpose(epoch, HashPurpose::AssetId, &payload)?;
    Ok((AssetId::new(digest.bytes()), digest.algorithm()))
}

/// A Standard Asset v1 asset definition.
///
/// Deliberately excludes metadata, decimals, names, symbols, freeze,
/// allowances, burn, and supply accounting; those remain future slices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandardAssetDefinitionV1 {
    /// The asset's canonical identifier.
    pub asset_id: AssetId,
    /// The authenticated authority that created the asset.
    pub creation_authority: Address,
    /// The caller-supplied creation seed bound into `asset_id`.
    pub creation_seed: AssetCreationSeed,
    /// The epoch active at asset creation, bound into `asset_id`.
    pub creation_epoch: Epoch,
    /// The protocol version active at asset creation, bound into `asset_id`.
    pub creation_protocol_version: ProtocolVersion,
    /// The hash algorithm selected by the active suite at derivation time.
    pub derivation_algorithm: HashAlgorithmId,
}

impl StandardAssetDefinitionV1 {
    /// Derives a new definition from its creation inputs using the resolver's
    /// currently active hash suite.
    pub fn derive(
        resolver: &HashSuiteResolver,
        creation_authority: Address,
        creation_seed: AssetCreationSeed,
        creation_epoch: Epoch,
    ) -> Result<Self, StandardAssetError> {
        let (asset_id, derivation_algorithm) =
            derive_asset_id(resolver, creation_epoch, creation_authority, creation_seed)?;
        Ok(Self {
            asset_id,
            creation_authority,
            creation_seed,
            creation_epoch,
            creation_protocol_version: resolver.protocol_version(),
            derivation_algorithm,
        })
    }

    /// Validates that `asset_id` and `derivation_algorithm` match
    /// recomputation under the supplied resolver.
    pub fn validate(&self, resolver: &HashSuiteResolver) -> Result<(), StandardAssetError> {
        if resolver.protocol_version() != self.creation_protocol_version {
            return Err(StandardAssetError::ProtocolVersionMismatch {
                expected: self.creation_protocol_version,
                actual: resolver.protocol_version(),
            });
        }
        let (expected_asset_id, expected_algorithm) = derive_asset_id(
            resolver,
            self.creation_epoch,
            self.creation_authority,
            self.creation_seed,
        )?;
        if expected_algorithm != self.derivation_algorithm {
            return Err(StandardAssetError::DerivationAlgorithmMismatch {
                expected: expected_algorithm,
                actual: self.derivation_algorithm,
            });
        }
        if expected_asset_id != self.asset_id {
            return Err(StandardAssetError::AssetIdMismatch {
                expected: expected_asset_id,
                actual: self.asset_id,
            });
        }
        Ok(())
    }
}

/// Encodes a Standard Asset v1 definition.
pub fn encode_standard_asset_definition_v1(
    definition: &StandardAssetDefinitionV1,
) -> Result<Vec<u8>, StandardAssetError> {
    let mut canonical =
        CanonicalStruct::new(STANDARD_ASSET_DEFINITION_V1_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_asset_id(&definition.asset_id)?)?;
    canonical.field_bytes(2, definition.creation_authority.as_bytes())?;
    canonical.field_bytes(3, definition.creation_seed.as_bytes())?;
    canonical.field_u64(4, definition.creation_epoch.get())?;
    canonical.field_u16(5, definition.derivation_algorithm.as_u16())?;
    canonical.field_u32(6, definition.creation_protocol_version.get())?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical Standard Asset v1 definition without changing its
/// stable encoding. Rejects wrong type/version, missing/unknown fields,
/// malformed lengths, unknown algorithms, and trailing bytes.
pub fn decode_standard_asset_definition_v1(
    input: &[u8],
) -> Result<StandardAssetDefinitionV1, StandardAssetError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(STANDARD_ASSET_DEFINITION_V1_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
    Ok(StandardAssetDefinitionV1 {
        asset_id: decode_asset_id(frame.required_field(1)?)?,
        creation_authority: decode_address_field(frame.required_field(2)?)?,
        creation_seed: AssetCreationSeed::try_from_slice(frame.required_field(3)?)?,
        creation_epoch: Epoch::new(frame.required_u64(4)?),
        derivation_algorithm: HashAlgorithmId::try_from(frame.required_u16(5)?)?,
        creation_protocol_version: ProtocolVersion::new(frame.required_u32(6)?),
    })
}

/// A Standard Asset v1 owned coin value.
///
/// Contains exactly one [`AssetId`] and one non-zero integer amount. Ownership
/// and versioning remain properties of the enclosing [`objects::Object`]; the
/// local devnet's committed module now interprets this body for whole transfer,
/// partial split, and two-coin merge without adding a second balance model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandardAssetCoinV1 {
    asset_id: AssetId,
    amount: u64,
}

impl StandardAssetCoinV1 {
    /// Creates a coin value, rejecting a zero amount.
    pub fn new(asset_id: AssetId, amount: u64) -> Result<Self, StandardAssetError> {
        if amount == 0 {
            return Err(StandardAssetError::ZeroCoinAmount);
        }
        Ok(Self { asset_id, amount })
    }

    /// Returns the coin's asset identifier.
    #[must_use]
    pub const fn asset_id(&self) -> AssetId {
        self.asset_id
    }

    /// Returns the coin's amount.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }
}

/// Encodes a Standard Asset v1 coin.
pub fn encode_standard_asset_coin_v1(
    coin: &StandardAssetCoinV1,
) -> Result<Vec<u8>, StandardAssetError> {
    let mut canonical = CanonicalStruct::new(STANDARD_ASSET_COIN_V1_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_asset_id(&coin.asset_id)?)?;
    canonical.field_u64(2, coin.amount)?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical Standard Asset v1 coin without changing its stable
/// encoding. Rejects wrong type/version, missing/unknown fields, malformed
/// lengths, a zero amount, and trailing bytes.
pub fn decode_standard_asset_coin_v1(
    input: &[u8],
) -> Result<StandardAssetCoinV1, StandardAssetError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(STANDARD_ASSET_COIN_V1_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let asset_id = decode_asset_id(frame.required_field(1)?)?;
    let amount = frame.required_u64(2)?;
    StandardAssetCoinV1::new(asset_id, amount)
}

/// A Standard Asset v1 mint capability.
///
/// Possession authorizes future, separately reviewed minting for exactly one
/// asset. This slice defines only the schema; no minting operation exists
/// yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandardAssetMintCapabilityV1 {
    /// The asset this capability authorizes minting for.
    pub asset_id: AssetId,
}

/// Encodes a Standard Asset v1 mint capability.
pub fn encode_standard_asset_mint_capability_v1(
    capability: &StandardAssetMintCapabilityV1,
) -> Result<Vec<u8>, StandardAssetError> {
    let mut canonical =
        CanonicalStruct::new(STANDARD_ASSET_MINT_CAPABILITY_V1_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_asset_id(&capability.asset_id)?)?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical Standard Asset v1 mint capability without changing
/// its stable encoding. Rejects wrong type/version, unknown fields,
/// malformed lengths, and trailing bytes.
pub fn decode_standard_asset_mint_capability_v1(
    input: &[u8],
) -> Result<StandardAssetMintCapabilityV1, StandardAssetError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(STANDARD_ASSET_MINT_CAPABILITY_V1_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    Ok(StandardAssetMintCapabilityV1 {
        asset_id: decode_asset_id(frame.required_field(1)?)?,
    })
}

/// Canonical, strict arguments for one Standard Asset v1 whole-coin transfer:
/// the sole field is the new owner's [`Address`].
///
/// Contains exactly one field id `1` carrying 32 bytes. There is no amount,
/// asset, or source field: a whole-object transfer entrypoint identifies its
/// coin and asset entirely through the signed transaction's access manifest
/// and typed-entrypoint verification, never through these arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandardAssetTransferArgsV1 {
    recipient: Address,
}

impl StandardAssetTransferArgsV1 {
    /// Creates transfer arguments for `recipient`.
    #[must_use]
    pub const fn new(recipient: Address) -> Self {
        Self { recipient }
    }

    /// Returns the new owner this transfer names.
    #[must_use]
    pub const fn recipient(&self) -> Address {
        self.recipient
    }
}

/// Encodes Standard Asset v1 transfer arguments.
pub fn encode_standard_asset_transfer_args_v1(
    args: &StandardAssetTransferArgsV1,
) -> Result<Vec<u8>, StandardAssetError> {
    let mut canonical =
        CanonicalStruct::new(STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, args.recipient.as_bytes().to_vec())?;
    Ok(canonical.finish()?)
}

/// Strictly decodes one canonical Standard Asset v1 transfer-arguments frame.
/// Rejects wrong type/version, missing/unknown fields, a malformed recipient
/// length, and trailing bytes.
pub fn decode_standard_asset_transfer_args_v1(
    input: &[u8],
) -> Result<StandardAssetTransferArgsV1, StandardAssetError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    let recipient = decode_address_field(frame.required_field(1)?)?;
    Ok(StandardAssetTransferArgsV1::new(recipient))
}

/// Canonical, strict arguments for one Standard Asset v1 partial-split
/// transfer: the nonzero `amount` moved to a new coin (field id `1`) and the
/// new coin's recipient [`Address`] (field id `2`).
///
/// There is no source or asset field: a split entrypoint identifies its
/// source coin entirely through the signed transaction's access manifest and
/// typed-entrypoint verification, exactly like
/// [`StandardAssetTransferArgsV1`]. `amount` alone does not encode the
/// intended split direction or bound it below the source coin's own amount;
/// that checked comparison happens inside the committed split module, never
/// here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandardAssetSplitArgsV1 {
    amount: u64,
    recipient: Address,
}

impl StandardAssetSplitArgsV1 {
    /// Creates split arguments, rejecting a zero `amount`.
    pub fn new(amount: u64, recipient: Address) -> Result<Self, StandardAssetError> {
        if amount == 0 {
            return Err(StandardAssetError::ZeroCoinAmount);
        }
        Ok(Self { amount, recipient })
    }

    /// Returns the amount moved to the new coin.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// Returns the new coin's recipient.
    #[must_use]
    pub const fn recipient(&self) -> Address {
        self.recipient
    }
}

/// Encodes Standard Asset v1 split arguments.
pub fn encode_standard_asset_split_args_v1(
    args: &StandardAssetSplitArgsV1,
) -> Result<Vec<u8>, StandardAssetError> {
    let mut canonical =
        CanonicalStruct::new(STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID, ENCODING_VERSION);
    canonical.field_u64(1, args.amount)?;
    canonical.field_bytes(2, args.recipient.as_bytes().to_vec())?;
    Ok(canonical.finish()?)
}

/// Strictly decodes one canonical Standard Asset v1 split-arguments frame.
/// Rejects wrong type/version, missing/unknown fields, a zero amount, a
/// malformed recipient length, and trailing bytes.
pub fn decode_standard_asset_split_args_v1(
    input: &[u8],
) -> Result<StandardAssetSplitArgsV1, StandardAssetError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let amount = frame.required_u64(1)?;
    let recipient = decode_address_field(frame.required_field(2)?)?;
    StandardAssetSplitArgsV1::new(amount, recipient)
}

// ── Typed ABI foundation ──────────────────────────────────────────────────

/// The object schema version shared by all Standard Asset v1 object bodies.
///
/// Distinct from [`ENCODING_VERSION`] (the canonical-frame wire version used
/// by this crate's own encoders, which every body also happens to pin at
/// `1`): this is the value validators compare against
/// `objects::Object::schema_version` and `abi::ParamDeclaration::schema_version`.
pub const STANDARD_ASSET_SCHEMA_VERSION_V1: u32 = 1;

/// `abi` constructor identifier for [`StandardAssetDefinitionV1`].
///
/// See the crate-level "Typed ABI foundation" docs for why mirroring
/// [`STANDARD_ASSET_DEFINITION_V1_TYPE_ID`]'s numeric value is safe here.
pub const STANDARD_ASSET_DEFINITION_V1_CONSTRUCTOR: abi::ConstructorId =
    abi::ConstructorId::new(STANDARD_ASSET_DEFINITION_V1_TYPE_ID);
/// `abi` constructor identifier for [`StandardAssetCoinV1`] (see
/// [`STANDARD_ASSET_DEFINITION_V1_CONSTRUCTOR`]).
pub const STANDARD_ASSET_COIN_V1_CONSTRUCTOR: abi::ConstructorId =
    abi::ConstructorId::new(STANDARD_ASSET_COIN_V1_TYPE_ID);
/// `abi` constructor identifier for [`StandardAssetMintCapabilityV1`] (see
/// [`STANDARD_ASSET_DEFINITION_V1_CONSTRUCTOR`]).
pub const STANDARD_ASSET_MINT_CAPABILITY_V1_CONSTRUCTOR: abi::ConstructorId =
    abi::ConstructorId::new(STANDARD_ASSET_MINT_CAPABILITY_V1_TYPE_ID);

/// The fixed-depth canonical body projection shared by all three Standard
/// Asset v1 bodies: unwrap `body_type_id`'s field 1 (the nested encoded
/// [`AssetId`]), then unwrap [`ASSET_ID_TYPE_ID`]'s field 1 (the raw 32
/// bytes).
fn asset_id_projection(body_type_id: u16) -> Vec<abi::ProjectionStep> {
    vec![
        abi::ProjectionStep {
            expected_type_id: body_type_id,
            expected_version: ENCODING_VERSION,
            field_id: 1,
        },
        abi::ProjectionStep {
            expected_type_id: ASSET_ID_TYPE_ID,
            expected_version: ENCODING_VERSION,
            field_id: 1,
        },
    ]
}

/// Builds the canonical [`abi::ConstructorDeclaration`] for
/// [`StandardAssetCoinV1`], shared by [`constructor_registry`] and any
/// committed typed-entrypoint policy that needs to declare a `Coin<A>`
/// parameter — both consult this one source of truth rather than restating
/// the declaration independently.
#[must_use]
pub fn coin_constructor_declaration() -> abi::ConstructorDeclaration {
    abi::ConstructorDeclaration {
        id: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
        body_type_id: STANDARD_ASSET_COIN_V1_TYPE_ID,
        body_version: ENCODING_VERSION,
        schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
        arity: abi::TypeArity::Variable,
        projection: asset_id_projection(STANDARD_ASSET_COIN_V1_TYPE_ID),
    }
}

/// Builds the deterministic Standard Asset v1 constructor registry.
///
/// Registers exactly the three constructors above; registration order does
/// not affect the result, since [`abi::ConstructorRegistry`] iterates in
/// stable [`abi::ConstructorId`] order. Fails only if the compiled-in
/// declarations were ever made internally inconsistent or colliding, which
/// stable tests in this module pin against.
pub fn constructor_registry() -> Result<abi::ConstructorRegistry, StandardAssetError> {
    let mut registry = abi::ConstructorRegistry::new();
    registry.register(abi::ConstructorDeclaration {
        id: STANDARD_ASSET_DEFINITION_V1_CONSTRUCTOR,
        body_type_id: STANDARD_ASSET_DEFINITION_V1_TYPE_ID,
        body_version: ENCODING_VERSION,
        schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
        arity: abi::TypeArity::Variable,
        projection: asset_id_projection(STANDARD_ASSET_DEFINITION_V1_TYPE_ID),
    })?;
    registry.register(coin_constructor_declaration())?;
    registry.register(abi::ConstructorDeclaration {
        id: STANDARD_ASSET_MINT_CAPABILITY_V1_CONSTRUCTOR,
        body_type_id: STANDARD_ASSET_MINT_CAPABILITY_V1_TYPE_ID,
        body_version: ENCODING_VERSION,
        schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
        arity: abi::TypeArity::Variable,
        projection: asset_id_projection(STANDARD_ASSET_MINT_CAPABILITY_V1_TYPE_ID),
    })?;
    Ok(registry)
}

/// Builds the canonical [`StandardAssetDefinitionV1`] type tag for `asset_id`.
#[must_use]
pub fn definition_type_tag(asset_id: AssetId) -> abi::TypeTag {
    abi::TypeTag {
        constructor: STANDARD_ASSET_DEFINITION_V1_CONSTRUCTOR,
        type_arg: Some(abi::TypeArg::AssetId(*asset_id.as_bytes())),
    }
}

/// Builds the canonical [`StandardAssetCoinV1`] type tag for `asset_id`.
#[must_use]
pub fn coin_type_tag(asset_id: AssetId) -> abi::TypeTag {
    abi::TypeTag {
        constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
        type_arg: Some(abi::TypeArg::AssetId(*asset_id.as_bytes())),
    }
}

/// Builds the canonical [`StandardAssetMintCapabilityV1`] type tag for
/// `asset_id`.
#[must_use]
pub fn mint_capability_type_tag(asset_id: AssetId) -> abi::TypeTag {
    abi::TypeTag {
        constructor: STANDARD_ASSET_MINT_CAPABILITY_V1_CONSTRUCTOR,
        type_arg: Some(abi::TypeArg::AssetId(*asset_id.as_bytes())),
    }
}

/// Derives the nominal object-type identity digest for
/// [`StandardAssetDefinitionV1`] instantiated at `asset_id`.
pub fn derive_definition_type_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
) -> Result<Digest32, StandardAssetError> {
    Ok(abi::derive_type_id(
        resolver,
        epoch,
        &definition_type_tag(asset_id),
    )?)
}

/// Derives the nominal object-type identity digest for
/// [`StandardAssetCoinV1`] instantiated at `asset_id`.
pub fn derive_coin_type_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
) -> Result<Digest32, StandardAssetError> {
    Ok(abi::derive_type_id(
        resolver,
        epoch,
        &coin_type_tag(asset_id),
    )?)
}

/// Derives the nominal object-type identity digest for
/// [`StandardAssetMintCapabilityV1`] instantiated at `asset_id`.
pub fn derive_mint_capability_type_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    asset_id: AssetId,
) -> Result<Digest32, StandardAssetError> {
    Ok(abi::derive_type_id(
        resolver,
        epoch,
        &mint_capability_type_tag(asset_id),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, HashSuite, HashSuiteId, HashSuiteSchedule, ProtocolVersion};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn sample_asset_id(byte: u8) -> AssetId {
        AssetId::new([byte; IDENTIFIER_LEN])
    }

    fn sample_address(byte: u8) -> Address {
        Address::new([byte; IDENTIFIER_LEN])
    }

    fn sample_creation_seed(byte: u8) -> AssetCreationSeed {
        AssetCreationSeed::new([byte; IDENTIFIER_LEN]).unwrap()
    }

    fn sample_resolver(chain: &str) -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap()
    }

    fn sample_resolver_with_rotation(chain: &str, rotation_epoch: Epoch) -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new(chain).unwrap(),
            ProtocolVersion::new(1),
            vec![
                HashSuiteSchedule {
                    activation_epoch: Epoch::new(0),
                    suite: HashSuite::genesis(),
                },
                HashSuiteSchedule {
                    activation_epoch: rotation_epoch,
                    suite: HashSuite::uniform(HashSuiteId::new(2), HashAlgorithmId::Sha3_256),
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn asset_id_display_is_hex() {
        let asset_id = sample_asset_id(0xAB);
        assert_eq!(asset_id.to_string(), "ab".repeat(IDENTIFIER_LEN));
    }

    #[test]
    fn asset_id_encoding_vector_is_stable() {
        let asset_id = sample_asset_id(0x91);
        let bytes = encode_asset_id(&asset_id).unwrap();

        assert_eq!(
            hex(&bytes),
            format!("534e5245017001000100010020000000{}", "91".repeat(32))
        );
    }

    #[test]
    fn asset_id_decoder_round_trips_existing_canonical_bytes() {
        let asset_id = sample_asset_id(0x91);
        let canonical: Vec<u8> = encode_asset_id(&asset_id).unwrap();
        assert_eq!(decode_asset_id(&canonical), Ok(asset_id));
    }

    #[test]
    fn asset_id_decoder_rejects_wrong_length() {
        let mut short = CanonicalStruct::new(ASSET_ID_TYPE_ID, ENCODING_VERSION);
        short.field_bytes(1, [0x11; 31]).unwrap();
        assert_eq!(
            decode_asset_id(&short.finish().unwrap()),
            Err(StandardAssetError::InvalidAssetIdLength(31))
        );
    }

    #[test]
    fn asset_id_decoder_rejects_wrong_type_and_trailing_bytes() {
        let mut wrong_type: Vec<u8> = encode_asset_id(&sample_asset_id(0x22)).unwrap();
        wrong_type[4..6].copy_from_slice(&0x7999_u16.to_le_bytes());
        assert!(matches!(
            decode_asset_id(&wrong_type),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));

        let mut trailing: Vec<u8> = encode_asset_id(&sample_asset_id(0x33)).unwrap();
        trailing.push(0);
        assert!(matches!(
            decode_asset_id(&trailing),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        ));
    }

    #[test]
    fn creation_seed_rejects_zero_and_wrong_length() {
        assert_eq!(
            AssetCreationSeed::new([0u8; IDENTIFIER_LEN]),
            Err(StandardAssetError::ZeroCreationSeed)
        );
        assert_eq!(
            AssetCreationSeed::try_from_slice(&[0x11; 31]),
            Err(StandardAssetError::InvalidCreationSeedLength(31))
        );
    }

    #[test]
    fn derivation_changes_with_creation_authority() {
        let resolver = sample_resolver("sunrise-devnet");
        let creation_seed = sample_creation_seed(0xB2);
        let epoch = Epoch::new(7);

        let (left, _) =
            derive_asset_id(&resolver, epoch, sample_address(0xA1), creation_seed).unwrap();
        let (right, _) =
            derive_asset_id(&resolver, epoch, sample_address(0xA2), creation_seed).unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn derivation_changes_with_creation_seed() {
        let resolver = sample_resolver("sunrise-devnet");
        let authority = sample_address(0xA1);
        let epoch = Epoch::new(7);

        let (left, _) =
            derive_asset_id(&resolver, epoch, authority, sample_creation_seed(0xB1)).unwrap();
        let (right, _) =
            derive_asset_id(&resolver, epoch, authority, sample_creation_seed(0xB2)).unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn derivation_changes_with_chain() {
        let authority = sample_address(0xA1);
        let creation_seed = sample_creation_seed(0xB2);
        let epoch = Epoch::new(7);

        let (left, _) = derive_asset_id(
            &sample_resolver("sunrise-devnet-a"),
            epoch,
            authority,
            creation_seed,
        )
        .unwrap();
        let (right, _) = derive_asset_id(
            &sample_resolver("sunrise-devnet-b"),
            epoch,
            authority,
            creation_seed,
        )
        .unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn derivation_changes_with_protocol_version() {
        let authority = sample_address(0xA1);
        let creation_seed = sample_creation_seed(0xB2);
        let epoch = Epoch::new(7);

        let left_resolver = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();
        let right_resolver = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(2),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();

        let (left, _) = derive_asset_id(&left_resolver, epoch, authority, creation_seed).unwrap();
        let (right, _) = derive_asset_id(&right_resolver, epoch, authority, creation_seed).unwrap();

        assert_ne!(left, right);
    }

    #[test]
    fn derivation_changes_with_epoch_and_hash_schedule() {
        let resolver = sample_resolver_with_rotation("sunrise-devnet", Epoch::new(500));
        let authority = sample_address(0xA1);
        let creation_seed = sample_creation_seed(0xB2);

        let (before_id, before_algorithm) =
            derive_asset_id(&resolver, Epoch::new(499), authority, creation_seed).unwrap();
        let (after_id, after_algorithm) =
            derive_asset_id(&resolver, Epoch::new(500), authority, creation_seed).unwrap();

        assert_eq!(before_algorithm, HashAlgorithmId::Sha2_256);
        assert_eq!(after_algorithm, HashAlgorithmId::Sha3_256);
        assert_ne!(before_id, after_id);
    }

    #[test]
    fn derivation_fails_closed_for_unsupported_algorithm() {
        let resolver = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(1),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::uniform(HashSuiteId::new(9), HashAlgorithmId::Blake3_256),
            }],
        )
        .unwrap();

        let result = derive_asset_id(
            &resolver,
            Epoch::new(0),
            sample_address(0xA1),
            sample_creation_seed(0xB2),
        );

        assert_eq!(
            result,
            Err(StandardAssetError::Hashing(
                HashingError::UnsupportedAlgorithm(HashAlgorithmId::Blake3_256)
            ))
        );
    }

    #[test]
    fn definition_derive_and_validate_round_trip() {
        let resolver = sample_resolver("sunrise-devnet");
        let definition = StandardAssetDefinitionV1::derive(
            &resolver,
            sample_address(0xA1),
            sample_creation_seed(0xB2),
            Epoch::new(7),
        )
        .unwrap();

        assert_eq!(definition.validate(&resolver), Ok(()));
    }

    #[test]
    fn definition_validate_rejects_tampered_asset_id() {
        let resolver = sample_resolver("sunrise-devnet");
        let mut definition = StandardAssetDefinitionV1::derive(
            &resolver,
            sample_address(0xA1),
            sample_creation_seed(0xB2),
            Epoch::new(7),
        )
        .unwrap();
        let stored = definition.asset_id;
        definition.asset_id = sample_asset_id(0xFF);

        assert_eq!(
            definition.validate(&resolver),
            Err(StandardAssetError::AssetIdMismatch {
                expected: stored,
                actual: sample_asset_id(0xFF),
            })
        );
    }

    #[test]
    fn definition_validate_rejects_tampered_algorithm() {
        let resolver = sample_resolver("sunrise-devnet");
        let mut definition = StandardAssetDefinitionV1::derive(
            &resolver,
            sample_address(0xA1),
            sample_creation_seed(0xB2),
            Epoch::new(7),
        )
        .unwrap();
        definition.derivation_algorithm = HashAlgorithmId::Sha3_256;

        assert_eq!(
            definition.validate(&resolver),
            Err(StandardAssetError::DerivationAlgorithmMismatch {
                expected: HashAlgorithmId::Sha2_256,
                actual: HashAlgorithmId::Sha3_256,
            })
        );
    }

    #[test]
    fn definition_validate_rejects_a_different_protocol_version() {
        let resolver_v1 = sample_resolver("sunrise-devnet");
        let definition = StandardAssetDefinitionV1::derive(
            &resolver_v1,
            sample_address(0xA1),
            sample_creation_seed(0xB2),
            Epoch::new(7),
        )
        .unwrap();
        let resolver_v2 = HashSuiteResolver::new(
            ChainId::new("sunrise-devnet").unwrap(),
            ProtocolVersion::new(2),
            vec![HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            }],
        )
        .unwrap();

        assert_eq!(
            definition.validate(&resolver_v2),
            Err(StandardAssetError::ProtocolVersionMismatch {
                expected: ProtocolVersion::new(1),
                actual: ProtocolVersion::new(2),
            })
        );
    }

    fn sample_definition() -> StandardAssetDefinitionV1 {
        StandardAssetDefinitionV1 {
            asset_id: sample_asset_id(0xC3),
            creation_authority: sample_address(0xD4),
            creation_seed: sample_creation_seed(0xE5),
            creation_epoch: Epoch::new(42),
            derivation_algorithm: HashAlgorithmId::Sha2_256,
            creation_protocol_version: ProtocolVersion::new(1),
        }
    }

    #[test]
    fn definition_encoding_vector_is_stable() {
        let bytes = encode_standard_asset_definition_v1(&sample_definition()).unwrap();

        assert_eq!(
            hex(&bytes),
            "534e5245017101000600010030000000534e5245017001000100010020000000c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3020020000000d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4030020000000e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e50400080000002a00000000000000050002000000010006000400000001000000"
        );
    }

    #[test]
    fn definition_decoder_round_trips_encoded_bytes() {
        let definition = sample_definition();
        let canonical = encode_standard_asset_definition_v1(&definition).unwrap();
        assert_eq!(
            decode_standard_asset_definition_v1(&canonical),
            Ok(definition)
        );
    }

    #[test]
    fn definition_decoder_rejects_wrong_type_missing_field_and_unknown_algorithm() {
        let definition = sample_definition();
        let mut wrong_type = encode_standard_asset_definition_v1(&definition).unwrap();
        wrong_type[4..6].copy_from_slice(&0x7999_u16.to_le_bytes());
        assert!(matches!(
            decode_standard_asset_definition_v1(&wrong_type),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));

        let mut missing =
            CanonicalStruct::new(STANDARD_ASSET_DEFINITION_V1_TYPE_ID, ENCODING_VERSION);
        missing
            .field_bytes(1, encode_asset_id(&sample_asset_id(0x01)).unwrap())
            .unwrap();
        missing
            .field_bytes(2, definition.creation_authority.as_bytes())
            .unwrap();
        missing
            .field_bytes(3, definition.creation_seed.as_bytes())
            .unwrap();
        missing
            .field_u64(4, definition.creation_epoch.get())
            .unwrap();
        assert!(matches!(
            decode_standard_asset_definition_v1(&missing.finish().unwrap()),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(5)
            ))
        ));

        let mut unknown_algorithm =
            CanonicalStruct::new(STANDARD_ASSET_DEFINITION_V1_TYPE_ID, ENCODING_VERSION);
        unknown_algorithm
            .field_bytes(1, encode_asset_id(&sample_asset_id(0x01)).unwrap())
            .unwrap();
        unknown_algorithm
            .field_bytes(2, definition.creation_authority.as_bytes())
            .unwrap();
        unknown_algorithm
            .field_bytes(3, definition.creation_seed.as_bytes())
            .unwrap();
        unknown_algorithm
            .field_u64(4, definition.creation_epoch.get())
            .unwrap();
        unknown_algorithm.field_u16(5, 0xFFFF).unwrap();
        assert!(matches!(
            decode_standard_asset_definition_v1(&unknown_algorithm.finish().unwrap()),
            Err(StandardAssetError::UnknownHashAlgorithm(
                TypeError::UnknownHashAlgorithmId(0xFFFF)
            ))
        ));
    }

    #[test]
    fn definition_decoder_rejects_short_creation_authority() {
        let definition = sample_definition();
        let mut broken =
            CanonicalStruct::new(STANDARD_ASSET_DEFINITION_V1_TYPE_ID, ENCODING_VERSION);
        broken
            .field_bytes(1, encode_asset_id(&definition.asset_id).unwrap())
            .unwrap();
        broken.field_bytes(2, [0x11; 31]).unwrap();
        broken
            .field_bytes(3, definition.creation_seed.as_bytes())
            .unwrap();
        broken
            .field_u64(4, definition.creation_epoch.get())
            .unwrap();
        broken
            .field_u16(5, definition.derivation_algorithm.as_u16())
            .unwrap();

        assert_eq!(
            decode_standard_asset_definition_v1(&broken.finish().unwrap()),
            Err(StandardAssetError::InvalidAddressLength(31))
        );
    }

    fn sample_coin() -> StandardAssetCoinV1 {
        StandardAssetCoinV1::new(sample_asset_id(0xF6), 12_345).unwrap()
    }

    #[test]
    fn coin_encoding_vector_is_stable() {
        let bytes = encode_standard_asset_coin_v1(&sample_coin()).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e5245027101000200010030000000534e5245017001000100010020000000f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f60200080000003930000000000000"
        );
    }

    #[test]
    fn coin_decoder_round_trips_encoded_bytes() {
        let coin = sample_coin();
        let canonical = encode_standard_asset_coin_v1(&coin).unwrap();
        assert_eq!(decode_standard_asset_coin_v1(&canonical), Ok(coin));
    }

    #[test]
    fn coin_constructor_and_decoder_reject_zero_amount() {
        assert_eq!(
            StandardAssetCoinV1::new(sample_asset_id(0x01), 0),
            Err(StandardAssetError::ZeroCoinAmount)
        );

        let mut zero_amount =
            CanonicalStruct::new(STANDARD_ASSET_COIN_V1_TYPE_ID, ENCODING_VERSION);
        zero_amount
            .field_bytes(1, encode_asset_id(&sample_asset_id(0x01)).unwrap())
            .unwrap();
        zero_amount.field_u64(2, 0).unwrap();
        assert_eq!(
            decode_standard_asset_coin_v1(&zero_amount.finish().unwrap()),
            Err(StandardAssetError::ZeroCoinAmount)
        );
    }

    #[test]
    fn coin_decoder_rejects_wrong_type_and_unknown_field() {
        let coin = sample_coin();
        let mut wrong_type = encode_standard_asset_coin_v1(&coin).unwrap();
        wrong_type[4..6].copy_from_slice(&0x7999_u16.to_le_bytes());
        assert!(matches!(
            decode_standard_asset_coin_v1(&wrong_type),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));

        let mut extra = CanonicalStruct::new(STANDARD_ASSET_COIN_V1_TYPE_ID, ENCODING_VERSION);
        extra
            .field_bytes(1, encode_asset_id(&coin.asset_id()).unwrap())
            .unwrap();
        extra.field_u64(2, coin.amount()).unwrap();
        extra.field_bytes(3, [0x01]).unwrap();
        assert!(matches!(
            decode_standard_asset_coin_v1(&extra.finish().unwrap()),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(3)
            ))
        ));
    }

    fn sample_capability() -> StandardAssetMintCapabilityV1 {
        StandardAssetMintCapabilityV1 {
            asset_id: sample_asset_id(0x17),
        }
    }

    #[test]
    fn mint_capability_encoding_vector_is_stable() {
        let bytes = encode_standard_asset_mint_capability_v1(&sample_capability()).unwrap();
        assert_eq!(
            hex(&bytes),
            "534e5245037101000100010030000000534e52450170010001000100200000001717171717171717171717171717171717171717171717171717171717171717"
        );
    }

    #[test]
    fn derivation_input_encoding_vector_is_stable() {
        let bytes = encode_asset_id_derivation_input(
            sample_address(0xA1),
            sample_creation_seed(0xB2),
            Epoch::new(7),
        )
        .unwrap();
        assert_eq!(
            hex(&bytes),
            "534e5245007101000300010020000000a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1020020000000b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b20300080000000700000000000000"
        );
    }

    #[test]
    fn derived_asset_id_vector_is_stable() {
        let resolver = sample_resolver("sunrise-devnet");
        let (asset_id, algorithm) = derive_asset_id(
            &resolver,
            Epoch::new(7),
            sample_address(0xA1),
            sample_creation_seed(0xB2),
        )
        .unwrap();

        assert_eq!(algorithm, HashAlgorithmId::Sha2_256);
        assert_eq!(
            hex(asset_id.as_bytes()),
            "a45cf9f36fd162bc87feab8d4d4d3ce7a39276aa6221042eebd711c1240221ad"
        );
    }

    /// Regression test: a stable, independently pinned nominal object-type
    /// identity digest for a `StandardAssetCoinV1` instantiated at a fixed
    /// `AssetId`, under a fixed deterministic hash-suite/chain context. This
    /// pins the exact digest bytes, not a computed-and-compared-to-itself
    /// expectation, so an accidental change to `TypeTag` encoding, the
    /// type-identity hash frame, or the coin constructor binding is caught.
    #[test]
    fn coin_type_commitment_vector_is_stable() {
        let resolver = sample_resolver("sunrise-devnet");
        let asset_id = sample_asset_id(0x64);
        let digest = derive_coin_type_id(&resolver, Epoch::new(0), asset_id).unwrap();

        assert_eq!(digest.algorithm(), HashAlgorithmId::Sha2_256);
        assert_eq!(
            hex(&digest.bytes()),
            "2ce8c77fdce94ae16940c5fa29e13ad72c4abb12006a7716def117320ad95653"
        );
    }

    #[test]
    fn mint_capability_decoder_round_trips_encoded_bytes() {
        let capability = sample_capability();
        let canonical = encode_standard_asset_mint_capability_v1(&capability).unwrap();
        assert_eq!(
            decode_standard_asset_mint_capability_v1(&canonical),
            Ok(capability)
        );
    }

    #[test]
    fn mint_capability_decoder_rejects_wrong_type_and_wrong_length() {
        let capability = sample_capability();
        let mut wrong_type = encode_standard_asset_mint_capability_v1(&capability).unwrap();
        wrong_type[4..6].copy_from_slice(&0x7999_u16.to_le_bytes());
        assert!(matches!(
            decode_standard_asset_mint_capability_v1(&wrong_type),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));

        let mut short =
            CanonicalStruct::new(STANDARD_ASSET_MINT_CAPABILITY_V1_TYPE_ID, ENCODING_VERSION);
        short
            .field_bytes(
                1,
                encode_asset_id(&sample_asset_id(0x11)).unwrap()[..40].to_vec(),
            )
            .unwrap();
        assert!(matches!(
            decode_standard_asset_mint_capability_v1(&short.finish().unwrap()),
            Err(StandardAssetError::CanonicalDecoding(_))
        ));
    }

    fn sample_transfer_args() -> StandardAssetTransferArgsV1 {
        StandardAssetTransferArgsV1::new(sample_address(0x64))
    }

    #[test]
    fn transfer_args_recipient_getter_round_trips() {
        let recipient = sample_address(0x64);
        assert_eq!(
            StandardAssetTransferArgsV1::new(recipient).recipient(),
            recipient
        );
    }

    #[test]
    fn transfer_args_encoding_vector_is_stable() {
        let bytes = encode_standard_asset_transfer_args_v1(&sample_transfer_args()).unwrap();
        assert_eq!(
            hex(&bytes),
            format!("534e5245047101000100010020000000{}", "64".repeat(32))
        );
    }

    #[test]
    fn transfer_args_decoder_round_trips_encoded_bytes() {
        let args = sample_transfer_args();
        let canonical = encode_standard_asset_transfer_args_v1(&args).unwrap();
        assert_eq!(decode_standard_asset_transfer_args_v1(&canonical), Ok(args));
    }

    #[test]
    fn transfer_args_decoder_rejects_wrong_type_and_version() {
        let mut wrong_type =
            encode_standard_asset_transfer_args_v1(&sample_transfer_args()).unwrap();
        wrong_type[4..6].copy_from_slice(&0x7999_u16.to_le_bytes());
        assert!(matches!(
            decode_standard_asset_transfer_args_v1(&wrong_type),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));

        let mut wrong_version = CanonicalStruct::new(STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID, 2);
        wrong_version
            .field_bytes(1, sample_address(0x64).as_bytes().to_vec())
            .unwrap();
        assert!(matches!(
            decode_standard_asset_transfer_args_v1(&wrong_version.finish().unwrap()),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion { .. }
            ))
        ));
    }

    #[test]
    fn transfer_args_decoder_rejects_missing_unknown_and_trailing_fields() {
        let empty = CanonicalStruct::new(STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID, ENCODING_VERSION);
        assert!(matches!(
            decode_standard_asset_transfer_args_v1(&empty.finish().unwrap()),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(1)
            ))
        ));

        let mut extra =
            CanonicalStruct::new(STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID, ENCODING_VERSION);
        extra
            .field_bytes(1, sample_address(0x64).as_bytes().to_vec())
            .unwrap();
        extra.field_bytes(2, [0x01]).unwrap();
        assert!(matches!(
            decode_standard_asset_transfer_args_v1(&extra.finish().unwrap()),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(2)
            ))
        ));

        let mut trailing = encode_standard_asset_transfer_args_v1(&sample_transfer_args()).unwrap();
        trailing.push(0);
        assert!(matches!(
            decode_standard_asset_transfer_args_v1(&trailing),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        ));
    }

    #[test]
    fn transfer_args_decoder_rejects_a_malformed_recipient_length() {
        let mut short =
            CanonicalStruct::new(STANDARD_ASSET_TRANSFER_ARGS_V1_TYPE_ID, ENCODING_VERSION);
        short.field_bytes(1, [0x11; 31]).unwrap();
        assert_eq!(
            decode_standard_asset_transfer_args_v1(&short.finish().unwrap()),
            Err(StandardAssetError::InvalidAddressLength(31))
        );
    }

    fn sample_split_args() -> StandardAssetSplitArgsV1 {
        StandardAssetSplitArgsV1::new(42, sample_address(0x65)).unwrap()
    }

    #[test]
    fn split_args_rejects_zero_amount() {
        assert_eq!(
            StandardAssetSplitArgsV1::new(0, sample_address(0x65)),
            Err(StandardAssetError::ZeroCoinAmount)
        );
    }

    #[test]
    fn split_args_getters_round_trip() {
        let recipient = sample_address(0x65);
        let args = StandardAssetSplitArgsV1::new(42, recipient).unwrap();
        assert_eq!(args.amount(), 42);
        assert_eq!(args.recipient(), recipient);
    }

    #[test]
    fn split_args_encoding_vector_is_stable() {
        let bytes = encode_standard_asset_split_args_v1(&sample_split_args()).unwrap();
        assert_eq!(
            hex(&bytes),
            format!(
                "534e5245057101000200010008000000{}020020000000{}",
                "2a00000000000000",
                "65".repeat(32)
            )
        );
    }

    #[test]
    fn split_args_decoder_round_trips_encoded_bytes() {
        let args = sample_split_args();
        let canonical = encode_standard_asset_split_args_v1(&args).unwrap();
        assert_eq!(decode_standard_asset_split_args_v1(&canonical), Ok(args));
    }

    #[test]
    fn split_args_decoder_rejects_wrong_type_and_version() {
        let mut wrong_type = encode_standard_asset_split_args_v1(&sample_split_args()).unwrap();
        wrong_type[4..6].copy_from_slice(&0x7999_u16.to_le_bytes());
        assert!(matches!(
            decode_standard_asset_split_args_v1(&wrong_type),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));

        let mut wrong_version = CanonicalStruct::new(STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID, 2);
        wrong_version.field_u64(1, 42).unwrap();
        wrong_version
            .field_bytes(2, sample_address(0x65).as_bytes().to_vec())
            .unwrap();
        assert!(matches!(
            decode_standard_asset_split_args_v1(&wrong_version.finish().unwrap()),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion { .. }
            ))
        ));
    }

    #[test]
    fn split_args_decoder_rejects_missing_unknown_zero_amount_and_trailing_fields() {
        let empty = CanonicalStruct::new(STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID, ENCODING_VERSION);
        assert!(matches!(
            decode_standard_asset_split_args_v1(&empty.finish().unwrap()),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::MissingField(1)
            ))
        ));

        let mut zero_amount =
            CanonicalStruct::new(STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID, ENCODING_VERSION);
        zero_amount.field_u64(1, 0).unwrap();
        zero_amount
            .field_bytes(2, sample_address(0x65).as_bytes().to_vec())
            .unwrap();
        assert_eq!(
            decode_standard_asset_split_args_v1(&zero_amount.finish().unwrap()),
            Err(StandardAssetError::ZeroCoinAmount)
        );

        let mut extra =
            CanonicalStruct::new(STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID, ENCODING_VERSION);
        extra.field_u64(1, 42).unwrap();
        extra
            .field_bytes(2, sample_address(0x65).as_bytes().to_vec())
            .unwrap();
        extra.field_bytes(3, [0x01]).unwrap();
        assert!(matches!(
            decode_standard_asset_split_args_v1(&extra.finish().unwrap()),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(3)
            ))
        ));

        let mut trailing = encode_standard_asset_split_args_v1(&sample_split_args()).unwrap();
        trailing.push(0);
        assert!(matches!(
            decode_standard_asset_split_args_v1(&trailing),
            Err(StandardAssetError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        ));
    }

    #[test]
    fn split_args_decoder_rejects_a_malformed_recipient_length() {
        let mut short =
            CanonicalStruct::new(STANDARD_ASSET_SPLIT_ARGS_V1_TYPE_ID, ENCODING_VERSION);
        short.field_u64(1, 42).unwrap();
        short.field_bytes(2, [0x11; 31]).unwrap();
        assert_eq!(
            decode_standard_asset_split_args_v1(&short.finish().unwrap()),
            Err(StandardAssetError::InvalidAddressLength(31))
        );
    }

    #[test]
    fn coin_constructor_declaration_matches_registry_entry() {
        let registry = constructor_registry().unwrap();
        let from_registry = registry.get(STANDARD_ASSET_COIN_V1_CONSTRUCTOR).unwrap();
        assert_eq!(from_registry, &coin_constructor_declaration());
    }

    // ── typed-ABI foundation tests ──────────────────────────────────────

    use abi::{
        AbiError, EntrypointSignature, ParamDeclaration, ResolvedInput, TypeArg,
        verify_entrypoint_inputs,
    };
    use objects::{AccessMode, Object, ObjectId, Owner};

    #[test]
    fn constructor_registry_has_three_constructors_in_stable_order() {
        let registry = constructor_registry().unwrap();
        assert_eq!(registry.len(), 3);
        let ids: Vec<_> = registry.iter().map(|decl| decl.id).collect();
        assert_eq!(
            ids,
            vec![
                STANDARD_ASSET_DEFINITION_V1_CONSTRUCTOR,
                STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                STANDARD_ASSET_MINT_CAPABILITY_V1_CONSTRUCTOR,
            ]
        );
    }

    #[test]
    fn tag_constructors_bind_the_expected_constructor_and_asset_id() {
        let asset_id = sample_asset_id(0x9A);
        assert_eq!(
            coin_type_tag(asset_id).type_arg,
            Some(TypeArg::AssetId(*asset_id.as_bytes()))
        );
        assert_eq!(
            coin_type_tag(asset_id).constructor,
            STANDARD_ASSET_COIN_V1_CONSTRUCTOR
        );
        assert_eq!(
            definition_type_tag(asset_id).constructor,
            STANDARD_ASSET_DEFINITION_V1_CONSTRUCTOR
        );
        assert_eq!(
            mint_capability_type_tag(asset_id).constructor,
            STANDARD_ASSET_MINT_CAPABILITY_V1_CONSTRUCTOR
        );
    }

    #[test]
    fn type_id_helper_matches_abi_derive_type_id() {
        let resolver = sample_resolver("sunrise-devnet");
        let asset_id = sample_asset_id(0x21);
        let expected =
            abi::derive_type_id(&resolver, Epoch::new(0), &coin_type_tag(asset_id)).unwrap();
        assert_eq!(
            derive_coin_type_id(&resolver, Epoch::new(0), asset_id).unwrap(),
            expected
        );
    }

    fn coin_object(
        resolver: &HashSuiteResolver,
        id_byte: u8,
        asset_id: AssetId,
        amount: u64,
    ) -> Object {
        let coin = StandardAssetCoinV1::new(asset_id, amount).unwrap();
        let data = encode_standard_asset_coin_v1(&coin).unwrap();
        let type_hash = derive_coin_type_id(resolver, Epoch::new(0), asset_id).unwrap();
        Object {
            id: ObjectId::new([id_byte; 32]),
            version: 1,
            owner: Owner::Shared,
            type_hash,
            schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            data,
        }
    }

    fn mint_cap_object(resolver: &HashSuiteResolver, id_byte: u8, asset_id: AssetId) -> Object {
        let capability = StandardAssetMintCapabilityV1 { asset_id };
        let data = encode_standard_asset_mint_capability_v1(&capability).unwrap();
        let type_hash = derive_mint_capability_type_id(resolver, Epoch::new(0), asset_id).unwrap();
        Object {
            id: ObjectId::new([id_byte; 32]),
            version: 1,
            owner: Owner::Shared,
            type_hash,
            schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            data,
        }
    }

    fn transfer_signature() -> EntrypointSignature {
        EntrypointSignature::new(
            "transfer",
            vec![ParamDeclaration {
                mode: AccessMode::Write,
                constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
            }],
        )
        .unwrap()
    }

    fn mint_signature() -> EntrypointSignature {
        EntrypointSignature::new(
            "mint",
            vec![
                ParamDeclaration {
                    mode: AccessMode::Read,
                    constructor: STANDARD_ASSET_MINT_CAPABILITY_V1_CONSTRUCTOR,
                    schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
                },
                ParamDeclaration {
                    mode: AccessMode::Write,
                    constructor: STANDARD_ASSET_COIN_V1_CONSTRUCTOR,
                    schema_version: STANDARD_ASSET_SCHEMA_VERSION_V1,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn end_to_end_verification_accepts_a_well_formed_coin() {
        let resolver = sample_resolver("sunrise-devnet");
        let asset_id = sample_asset_id(0x44);
        let coin = coin_object(&resolver, 0x01, asset_id, 500);
        let registry = constructor_registry().unwrap();
        let signature = transfer_signature();
        let inputs = [ResolvedInput {
            mode: AccessMode::Write,
            object: &coin,
        }];

        assert!(
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs)
                .is_ok()
        );
    }

    #[test]
    fn end_to_end_projection_rejects_coin_a_claimed_as_coin_b() {
        let resolver = sample_resolver("sunrise-devnet");
        let asset_a = sample_asset_id(0xA1);
        let asset_b = sample_asset_id(0xB2);
        let mut coin = coin_object(&resolver, 0x01, asset_a, 500);
        // The stored `type_hash` is honestly derived for asset A, but the
        // body is swapped to encode asset B afterward.
        coin.data = encode_standard_asset_coin_v1(&StandardAssetCoinV1::new(asset_b, 500).unwrap())
            .unwrap();

        let registry = constructor_registry().unwrap();
        let signature = transfer_signature();
        let inputs = [ResolvedInput {
            mode: AccessMode::Write,
            object: &coin,
        }];

        assert!(matches!(
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs),
            Err(AbiError::TypeIdentityMismatch { .. })
        ));
    }

    #[test]
    fn end_to_end_mint_cap_a_and_coin_a_accepted() {
        let resolver = sample_resolver("sunrise-devnet");
        let asset_a = sample_asset_id(0x55);
        let cap = mint_cap_object(&resolver, 0x02, asset_a);
        let coin = coin_object(&resolver, 0x03, asset_a, 10);

        let registry = constructor_registry().unwrap();
        let signature = mint_signature();
        let inputs = [
            ResolvedInput {
                mode: AccessMode::Read,
                object: &cap,
            },
            ResolvedInput {
                mode: AccessMode::Write,
                object: &coin,
            },
        ];

        assert!(
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs)
                .is_ok()
        );
    }

    #[test]
    fn end_to_end_mint_cap_b_and_coin_a_rejected() {
        let resolver = sample_resolver("sunrise-devnet");
        let asset_a = sample_asset_id(0x55);
        let asset_b = sample_asset_id(0x66);
        let cap = mint_cap_object(&resolver, 0x02, asset_b);
        let coin = coin_object(&resolver, 0x03, asset_a, 10);

        let registry = constructor_registry().unwrap();
        let signature = mint_signature();
        let inputs = [
            ResolvedInput {
                mode: AccessMode::Read,
                object: &cap,
            },
            ResolvedInput {
                mode: AccessMode::Write,
                object: &coin,
            },
        ];

        assert!(matches!(
            verify_entrypoint_inputs(&signature, &registry, &resolver, Epoch::new(0), &inputs),
            Err(AbiError::TypeVariableMismatch { .. })
        ));
    }

    #[test]
    fn amount_mutation_preserves_type_identity_but_asset_id_mutation_breaks_it() {
        let asset_id = sample_asset_id(0x30);
        let coin_low = StandardAssetCoinV1::new(asset_id, 1).unwrap();
        let coin_high = StandardAssetCoinV1::new(asset_id, 999_999).unwrap();

        let registry = constructor_registry().unwrap();
        let decl = registry.get(STANDARD_ASSET_COIN_V1_CONSTRUCTOR).unwrap();
        let arg_low =
            abi::project_type_arg(decl, &encode_standard_asset_coin_v1(&coin_low).unwrap())
                .unwrap();
        let arg_high =
            abi::project_type_arg(decl, &encode_standard_asset_coin_v1(&coin_high).unwrap())
                .unwrap();
        assert_eq!(
            arg_low, arg_high,
            "amount must not affect nominal type identity"
        );

        let other_asset_id = sample_asset_id(0x31);
        let coin_other_asset = StandardAssetCoinV1::new(other_asset_id, 1).unwrap();
        let arg_other = abi::project_type_arg(
            decl,
            &encode_standard_asset_coin_v1(&coin_other_asset).unwrap(),
        )
        .unwrap();
        assert_ne!(
            arg_low, arg_other,
            "AssetId mutation must break nominal type identity"
        );
    }
}
