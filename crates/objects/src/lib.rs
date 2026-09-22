#![forbid(unsafe_code)]

//! Versioned object identifiers and canonical object references.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame, decode_digest32, encode_digest32,
};
use core::fmt;
use protocol_types::{ChainId, Digest32, TypeError as ChainIdError};
use protocol_upgrades::{MigrationDescriptor, ProtocolUpgradeError};
use std::error::Error;

const OBJECT_ID_TYPE_ID: u16 = 0x4001;
const ADDRESS_TYPE_ID: u16 = 0x4002;
const OWNER_TYPE_ID: u16 = 0x4003;
const OBJECT_REF_TYPE_ID: u16 = 0x4004;
/// Stable canonical type identifier for an [`Object`] record.
pub const OBJECT_CANONICAL_TYPE_ID: u16 = 0x4005;
const ACCESS_MODE_TYPE_ID: u16 = 0x4006;
/// Stable canonical type identifier for a [`ProtocolCustodyScope`] (DR-0135).
const PROTOCOL_CUSTODY_SCOPE_TYPE_ID: u16 = 0x4007;
const ENCODING_VERSION: u16 = 1;
/// Stable canonical encoding version for an [`Object`] record.
pub const OBJECT_CANONICAL_ENCODING_VERSION: u16 = ENCODING_VERSION;
const IDENTIFIER_LEN: usize = 32;

/// Errors returned by object model helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectError {
    /// An object identifier had the wrong length.
    InvalidObjectIdLength(usize),
    /// An address had the wrong length.
    InvalidAddressLength(usize),
    /// The access mode identifier is unknown.
    UnknownAccessMode(u8),
    /// The owner variant identifier is unknown.
    UnknownOwnerTag(u16),
    /// The protocol custody purpose identifier is unknown (DR-0135).
    UnknownProtocolCustodyPurpose(u16),
    /// The protocol custody scope named an invalid chain identifier (DR-0135).
    InvalidProtocolCustodyChainId(ChainIdError),
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding failed.
    CanonicalDecoding(CanonicalDecodingError),
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidObjectIdLength(length) => write!(
                f,
                "object identifiers must be {IDENTIFIER_LEN} bytes, got {length}"
            ),
            Self::InvalidAddressLength(length) => {
                write!(f, "addresses must be {IDENTIFIER_LEN} bytes, got {length}")
            }
            Self::UnknownAccessMode(mode) => write!(f, "unknown access mode: {mode}"),
            Self::UnknownOwnerTag(tag) => write!(f, "unknown object owner tag: {tag}"),
            Self::UnknownProtocolCustodyPurpose(tag) => {
                write!(f, "unknown protocol custody purpose: {tag}")
            }
            Self::InvalidProtocolCustodyChainId(error) => error.fmt(f),
            Self::CanonicalEncoding(error) => error.fmt(f),
            Self::CanonicalDecoding(error) => error.fmt(f),
        }
    }
}

impl Error for ObjectError {}

impl From<CanonicalEncodingError> for ObjectError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

impl From<CanonicalDecodingError> for ObjectError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(value)
    }
}

/// Errors returned while applying a deterministic lazy object migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    /// The committed migration descriptor is invalid.
    InvalidDescriptor(ProtocolUpgradeError),
    /// The object's type does not match the migration's committed type.
    ObjectTypeMismatch {
        /// Type required by the migration.
        expected: Digest32,
        /// Type present on the object.
        actual: Digest32,
    },
    /// The object's schema does not match the migration source schema.
    SchemaVersionMismatch {
        /// Schema required by the migration.
        expected: u32,
        /// Schema present on the object.
        actual: u32,
    },
    /// The object version cannot be incremented.
    ObjectVersionOverflow,
    /// The deterministic migration implementation rejected the object data.
    ExecutionFailed(String),
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDescriptor(error) => error.fmt(f),
            Self::ObjectTypeMismatch { expected, actual } => {
                write!(f, "migration expected object type {expected}, got {actual}")
            }
            Self::SchemaVersionMismatch { expected, actual } => write!(
                f,
                "migration expected schema version {expected}, got {actual}"
            ),
            Self::ObjectVersionOverflow => write!(f, "object version overflow during migration"),
            Self::ExecutionFailed(message) => write!(f, "object migration failed: {message}"),
        }
    }
}

impl Error for MigrationError {}

impl From<ProtocolUpgradeError> for MigrationError {
    fn from(value: ProtocolUpgradeError) -> Self {
        Self::InvalidDescriptor(value)
    }
}

/// A stable 32-byte object identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId {
    bytes: [u8; IDENTIFIER_LEN],
}

impl ObjectId {
    /// Creates an object identifier.
    #[must_use]
    pub const fn new(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self { bytes }
    }

    /// Creates an object identifier from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self::new(bytes)
    }

    /// Parses an object identifier from a byte slice.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ObjectError> {
        if bytes.len() != IDENTIFIER_LEN {
            return Err(ObjectError::InvalidObjectIdLength(bytes.len()));
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

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A stable 32-byte address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address {
    bytes: [u8; IDENTIFIER_LEN],
}

impl Address {
    /// Creates an address.
    #[must_use]
    pub const fn new(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self { bytes }
    }

    /// Creates an address from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; IDENTIFIER_LEN]) -> Self {
        Self::new(bytes)
    }

    /// Parses an address from a byte slice.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ObjectError> {
        if bytes.len() != IDENTIFIER_LEN {
            return Err(ObjectError::InvalidAddressLength(bytes.len()));
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

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Ownership model for objects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    /// An address-owned object.
    Address(Address),
    /// A shared object.
    Shared,
    /// An immutable object.
    Immutable,
    /// A system-owned object.
    System,
    /// A non-signable protocol custody object (DR-0135).
    ///
    /// Protocol custody has no signing key and is not an address. Unless a
    /// decision explicitly allows an operation, execution must treat this
    /// variant exactly like the fail-closed branch used for unsupported
    /// non-address owners: it must never authenticate a sender, be supplied
    /// as a sender-authorized `Write`/`Consume` input, be used as a paid fee
    /// source, change owner through the ordinary transferable-object path,
    /// be acquired as a FastVote sender-owned lock, or be created by an
    /// ordinary contract result. The only creation path in this slice is a
    /// signed genesis manifest whose scope chain matches the manifest chain.
    ProtocolCustody(ProtocolCustodyScope),
}

impl Owner {
    const fn tag(&self) -> u16 {
        match self {
            Self::Address(_) => 1,
            Self::Shared => 2,
            Self::Immutable => 3,
            Self::System => 4,
            Self::ProtocolCustody(_) => 5,
        }
    }
}

/// Closed protocol custody purpose (DR-0135, DR-0137).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolCustodyPurpose {
    /// Immobilized validator bond collateral.
    ///
    /// A higher layer interprets [`ProtocolCustodyScope::subject`] as a
    /// `ValidatorId` and [`ProtocolCustodyScope::resource`] as an opaque
    /// resource identity. Those meanings are not imported into this crate.
    BondCollateral,
    /// Certified fee output awaiting deterministic signer claims.
    FeeEscrow,
    /// Fully forfeited validator collateral retained for a later explicit
    /// disposal policy.
    ForfeitedCollateral,
}

impl ProtocolCustodyPurpose {
    const fn tag(self) -> u16 {
        match self {
            Self::BondCollateral => 1,
            Self::FeeEscrow => 2,
            Self::ForfeitedCollateral => 3,
        }
    }
}

/// Canonical, chain-bound, closed-purpose protocol custody ownership scope
/// (DR-0135).
///
/// This scope cannot be confused with an address: it carries no public key
/// and no signature-shaped authorization path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolCustodyScope {
    /// Closed custody purpose.
    pub purpose: ProtocolCustodyPurpose,
    /// Exact chain replay boundary this scope is bound to.
    pub chain_id: ChainId,
    /// Higher-layer-interpreted subject identifier.
    pub subject: [u8; IDENTIFIER_LEN],
    /// Higher-layer-interpreted resource identifier.
    pub resource: [u8; IDENTIFIER_LEN],
}

/// A versioned protocol object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    /// Stable object identifier.
    pub id: ObjectId,
    /// Monotonic object version.
    pub version: u64,
    /// Current ownership mode.
    pub owner: Owner,
    /// Type fingerprint for the object's schema.
    pub type_hash: Digest32,
    /// Object schema version.
    pub schema_version: u32,
    /// Canonically encoded object bytes.
    pub data: Vec<u8>,
}

/// A transaction-stable object reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRef {
    /// Stable object identifier.
    pub id: ObjectId,
    /// Version used for replay protection.
    pub version: u64,
    /// Digest of the referenced object version.
    pub digest: Digest32,
}

/// Runtime implementation of one governance-committed deterministic migration.
///
/// Only the descriptor is protocol state. Implementations are runtime wiring
/// and must be selected by the descriptor's `migration_hash`.
pub trait ObjectMigration {
    /// Returns the canonical descriptor committed by protocol configuration.
    fn descriptor(&self) -> &MigrationDescriptor;

    /// Migrates canonical object data without accessing global state.
    fn migrate_data(&self, canonical_data: &[u8]) -> Result<Vec<u8>, MigrationError>;
}

/// Applies one migration to a single object when that object is read or written.
///
/// The input is left untouched. The returned object preserves identity,
/// ownership, and type, increments its object version, and adopts the target
/// schema version. No state scan is required.
pub fn apply_lazy_migration(
    object: &Object,
    migration: &impl ObjectMigration,
) -> Result<Object, MigrationError> {
    let descriptor = migration.descriptor();
    descriptor.validate()?;
    if object.type_hash != descriptor.object_type {
        return Err(MigrationError::ObjectTypeMismatch {
            expected: descriptor.object_type,
            actual: object.type_hash,
        });
    }
    if object.schema_version != descriptor.from_schema_version {
        return Err(MigrationError::SchemaVersionMismatch {
            expected: descriptor.from_schema_version,
            actual: object.schema_version,
        });
    }

    let mut migrated = object.clone();
    migrated.version = migrated
        .version
        .checked_add(1)
        .ok_or(MigrationError::ObjectVersionOverflow)?;
    migrated.schema_version = descriptor.to_schema_version;
    migrated.data = migration.migrate_data(&object.data)?;
    Ok(migrated)
}

/// Access mode requested for an object.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessMode {
    /// Read-only access.
    Read = 1,
    /// Mutable access.
    Write = 2,
    /// Consuming access.
    Consume = 3,
}

impl AccessMode {
    /// Returns the wire identifier.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AccessMode {
    type Error = ObjectError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::Consume),
            other => Err(ObjectError::UnknownAccessMode(other)),
        }
    }
}

/// Encodes an object identifier.
pub fn encode_object_id(id: &ObjectId) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(OBJECT_ID_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, id.as_bytes())?;
    Ok(canonical.finish()?)
}

/// Encodes an address.
pub fn encode_address(address: &Address) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(ADDRESS_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, address.as_bytes())?;
    Ok(canonical.finish()?)
}

/// Encodes an owner value.
pub fn encode_owner(owner: &Owner) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(OWNER_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, owner.tag())?;
    if let Owner::Address(address) = owner {
        canonical.field_bytes(2, encode_address(address)?)?;
    }
    if let Owner::ProtocolCustody(scope) = owner {
        canonical.field_bytes(3, encode_protocol_custody_scope(scope)?)?;
    }
    Ok(canonical.finish()?)
}

/// Encodes a protocol custody scope (DR-0135).
pub fn encode_protocol_custody_scope(scope: &ProtocolCustodyScope) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(PROTOCOL_CUSTODY_SCOPE_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, scope.purpose.tag())?;
    canonical.field_str(2, scope.chain_id.as_str())?;
    canonical.field_bytes(3, scope.subject)?;
    canonical.field_bytes(4, scope.resource)?;
    Ok(canonical.finish()?)
}

/// Encodes an object reference.
pub fn encode_object_ref(object_ref: &ObjectRef) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(OBJECT_REF_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, encode_object_id(&object_ref.id)?)?;
    canonical.field_u64(2, object_ref.version)?;
    canonical.field_bytes(3, encode_digest32(&object_ref.digest)?)?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`ObjectRef`] without changing its stable encoding.
pub fn decode_object_ref(input: &[u8]) -> Result<ObjectRef, ObjectError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(OBJECT_REF_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;
    Ok(ObjectRef {
        id: decode_object_id(frame.required_field(1)?)?,
        version: frame.required_u64(2)?,
        digest: decode_digest32(frame.required_field(3)?)?,
    })
}

/// Encodes an object.
pub fn encode_object(object: &Object) -> Result<Vec<u8>, ObjectError> {
    let mut canonical =
        CanonicalStruct::new(OBJECT_CANONICAL_TYPE_ID, OBJECT_CANONICAL_ENCODING_VERSION);
    canonical.field_bytes(1, encode_object_id(&object.id)?)?;
    canonical.field_u64(2, object.version)?;
    canonical.field_bytes(3, encode_owner(&object.owner)?)?;
    canonical.field_bytes(4, encode_digest32(&object.type_hash)?)?;
    canonical.field_u32(5, object.schema_version)?;
    canonical.field_bytes(6, object.data.as_slice())?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`ObjectId`] frame without changing its stable encoding.
pub fn decode_object_id(input: &[u8]) -> Result<ObjectId, ObjectError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(OBJECT_ID_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    ObjectId::try_from_slice(frame.required_field(1)?)
}

fn decode_address(input: &[u8]) -> Result<Address, ObjectError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(ADDRESS_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    Address::try_from_slice(frame.required_field(1)?)
}

/// Decodes one canonical owner projection and rejects non-canonical fields.
pub fn decode_owner(input: &[u8]) -> Result<Owner, ObjectError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(OWNER_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    let tag: u16 = frame.required_u16(1)?;
    match tag {
        1 => {
            frame.require_only_fields(&[1, 2])?;
            Ok(Owner::Address(decode_address(frame.required_field(2)?)?))
        }
        2 => {
            frame.require_only_fields(&[1])?;
            Ok(Owner::Shared)
        }
        3 => {
            frame.require_only_fields(&[1])?;
            Ok(Owner::Immutable)
        }
        4 => {
            frame.require_only_fields(&[1])?;
            Ok(Owner::System)
        }
        5 => {
            frame.require_only_fields(&[1, 3])?;
            Ok(Owner::ProtocolCustody(decode_protocol_custody_scope(
                frame.required_field(3)?,
            )?))
        }
        other => Err(ObjectError::UnknownOwnerTag(other)),
    }
}

/// Decodes one canonical [`ProtocolCustodyScope`] (DR-0135).
fn decode_protocol_custody_scope(input: &[u8]) -> Result<ProtocolCustodyScope, ObjectError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(PROTOCOL_CUSTODY_SCOPE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let purpose_tag: u16 = frame.required_u16(1)?;
    let purpose: ProtocolCustodyPurpose = match purpose_tag {
        1 => ProtocolCustodyPurpose::BondCollateral,
        2 => ProtocolCustodyPurpose::FeeEscrow,
        3 => ProtocolCustodyPurpose::ForfeitedCollateral,
        other => return Err(ObjectError::UnknownProtocolCustodyPurpose(other)),
    };
    let chain_id: ChainId = ChainId::new(frame.required_str(2)?.to_owned())
        .map_err(ObjectError::InvalidProtocolCustodyChainId)?;
    let subject_bytes: &[u8] = frame.required_field(3)?;
    let subject: [u8; IDENTIFIER_LEN] =
        subject_bytes
            .try_into()
            .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                field_id: 3,
                expected: IDENTIFIER_LEN,
                actual: subject_bytes.len(),
            })?;
    let resource_bytes: &[u8] = frame.required_field(4)?;
    let resource: [u8; IDENTIFIER_LEN] =
        resource_bytes
            .try_into()
            .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                field_id: 4,
                expected: IDENTIFIER_LEN,
                actual: resource_bytes.len(),
            })?;
    Ok(ProtocolCustodyScope {
        purpose,
        chain_id,
        subject,
        resource,
    })
}

/// Decodes one existing canonical [`Object`] record without changing its bytes.
pub fn decode_object(input: &[u8]) -> Result<Object, ObjectError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(OBJECT_CANONICAL_TYPE_ID)?;
    frame.require_version(OBJECT_CANONICAL_ENCODING_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
    Ok(Object {
        id: decode_object_id(frame.required_field(1)?)?,
        version: frame.required_u64(2)?,
        owner: decode_owner(frame.required_field(3)?)?,
        type_hash: decode_digest32(frame.required_field(4)?)?,
        schema_version: frame.required_u32(5)?,
        data: frame.required_field(6)?.to_vec(),
    })
}

/// Encodes an access mode.
pub fn encode_access_mode(mode: AccessMode) -> Result<Vec<u8>, ObjectError> {
    let mut canonical = CanonicalStruct::new(ACCESS_MODE_TYPE_ID, ENCODING_VERSION);
    canonical.field_bytes(1, [mode.as_u8()])?;
    Ok(canonical.finish()?)
}

/// Decodes one canonical [`AccessMode`], rejecting unknown mode tags.
pub fn decode_access_mode(input: &[u8]) -> Result<AccessMode, ObjectError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(input)?;
    frame.require_type(ACCESS_MODE_TYPE_ID)?;
    frame.require_version(ENCODING_VERSION)?;
    frame.require_only_fields(&[1])?;
    let bytes = frame.required_field(1)?;
    let array: [u8; 1] =
        bytes
            .try_into()
            .map_err(|_| CanonicalDecodingError::InvalidFieldLength {
                field_id: 1,
                expected: 1,
                actual: bytes.len(),
            })?;
    AccessMode::try_from(array[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{Digest32, HashAlgorithmId};
    use protocol_upgrades::MigrationDescriptor;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn object_id_display_is_hex() {
        let id = ObjectId::new([0xab; IDENTIFIER_LEN]);
        assert_eq!(id.to_string(), "ab".repeat(IDENTIFIER_LEN));
    }

    #[test]
    fn object_ref_encodes_deterministically() {
        let object_ref = ObjectRef {
            id: ObjectId::new([0x11; IDENTIFIER_LEN]),
            version: 7,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x22; IDENTIFIER_LEN]),
        };

        let left = encode_object_ref(&object_ref).unwrap();
        let right = encode_object_ref(&object_ref).unwrap();

        assert_eq!(left, right);
        assert_eq!(
            hex(&left),
            concat!(
                "534e5245044001000300",
                "010030000000",
                "534e5245014001000100",
                "0100200000001111111111111111111111111111111111111111111111111111111111111111",
                "0200080000000700000000000000",
                "030038000000",
                "534e5245030101000200",
                "0100020000000100",
                "0200200000002222222222222222222222222222222222222222222222222222222222222222"
            )
        );
    }

    #[test]
    fn owner_variants_encode_differently() {
        let address_owner =
            encode_owner(&Owner::Address(Address::new([0x44; IDENTIFIER_LEN]))).unwrap();
        let shared_owner = encode_owner(&Owner::Shared).unwrap();
        let immutable_owner = encode_owner(&Owner::Immutable).unwrap();
        let system_owner = encode_owner(&Owner::System).unwrap();

        assert_ne!(address_owner, shared_owner);
        assert_ne!(shared_owner, immutable_owner);
        assert_ne!(immutable_owner, system_owner);
        assert_ne!(address_owner, system_owner);
    }

    #[test]
    fn pre_dr0135_owner_encodings_are_byte_for_byte_unchanged() {
        assert_eq!(
            hex(&encode_owner(&Owner::Address(Address::new([0x44; IDENTIFIER_LEN]))).unwrap()),
            "534e52450340010002000100020000000100020030000000534e5245024001000100010020000000\
             4444444444444444444444444444444444444444444444444444444444444444"
        );
        assert_eq!(
            hex(&encode_owner(&Owner::Shared).unwrap()),
            "534e52450340010001000100020000000200"
        );
        assert_eq!(
            hex(&encode_owner(&Owner::Immutable).unwrap()),
            "534e52450340010001000100020000000300"
        );
        assert_eq!(
            hex(&encode_owner(&Owner::System).unwrap()),
            "534e52450340010001000100020000000400"
        );
    }

    #[test]
    fn immutable_and_system_owners_round_trip() {
        for owner in [Owner::Immutable, Owner::System] {
            let canonical: Vec<u8> = encode_owner(&owner).unwrap();
            assert_eq!(decode_owner(&canonical), Ok(owner));
        }
    }

    #[test]
    fn non_address_owners_reject_stray_address_field() {
        for tag in [2_u16, 3_u16, 4_u16] {
            let mut owner = CanonicalStruct::new(OWNER_TYPE_ID, ENCODING_VERSION);
            owner.field_u16(1, tag).unwrap();
            owner.field_bytes(2, [0xAA]).unwrap();
            assert!(matches!(
                decode_owner(&owner.finish().unwrap()),
                Err(ObjectError::CanonicalDecoding(_))
            ));
        }
    }

    fn sample_custody_scope() -> ProtocolCustodyScope {
        ProtocolCustodyScope {
            purpose: ProtocolCustodyPurpose::BondCollateral,
            chain_id: ChainId::new("dr0135-vectors").unwrap(),
            subject: [0x61; IDENTIFIER_LEN],
            resource: [0x62; IDENTIFIER_LEN],
        }
    }

    #[test]
    fn protocol_custody_scope_encodes_stable_vector() {
        let scope: ProtocolCustodyScope = sample_custody_scope();
        assert_eq!(
            hex(&encode_protocol_custody_scope(&scope).unwrap()),
            "534e5245074001000400\
             0100020000000100\
             02000e0000006472303133352d766563746f7273\
             0300200000006161616161616161616161616161616161616161616161616161616161616161\
             0400200000006262626262626262626262626262626262626262626262626262626262626262"
        );
    }

    #[test]
    fn protocol_custody_owner_round_trips_through_owner_tag_five() {
        let owner = Owner::ProtocolCustody(sample_custody_scope());
        let canonical: Vec<u8> = encode_owner(&owner).unwrap();
        assert_eq!(decode_owner(&canonical), Ok(owner));
    }

    #[test]
    fn every_protocol_custody_purpose_round_trips_with_a_distinct_tag() {
        let purposes: [ProtocolCustodyPurpose; 3] = [
            ProtocolCustodyPurpose::BondCollateral,
            ProtocolCustodyPurpose::FeeEscrow,
            ProtocolCustodyPurpose::ForfeitedCollateral,
        ];
        let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(purposes.len());
        for purpose in purposes {
            let mut scope: ProtocolCustodyScope = sample_custody_scope();
            scope.purpose = purpose;
            let bytes: Vec<u8> = encode_protocol_custody_scope(&scope).unwrap();
            assert_eq!(decode_protocol_custody_scope(&bytes), Ok(scope));
            encoded.push(bytes);
        }
        assert_ne!(encoded[0], encoded[1]);
        assert_ne!(encoded[1], encoded[2]);
        assert_ne!(encoded[0], encoded[2]);
    }

    #[test]
    fn protocol_custody_owner_encodes_stable_vector() {
        let owner = Owner::ProtocolCustody(sample_custody_scope());
        assert_eq!(
            hex(&encode_owner(&owner).unwrap()),
            "534e5245034001000200\
             0100020000000500\
             030072000000534e5245074001000400\
             0100020000000100\
             02000e0000006472303133352d766563746f7273\
             0300200000006161616161616161616161616161616161616161616161616161616161616161\
             0400200000006262626262626262626262626262626262626262626262626262626262626262"
        );
    }

    #[test]
    fn protocol_custody_scope_rejects_unknown_purpose() {
        let mut scope = CanonicalStruct::new(PROTOCOL_CUSTODY_SCOPE_TYPE_ID, ENCODING_VERSION);
        scope.field_u16(1, 99).unwrap();
        scope.field_str(2, "dr0135-vectors").unwrap();
        scope.field_bytes(3, [0x61; IDENTIFIER_LEN]).unwrap();
        scope.field_bytes(4, [0x62; IDENTIFIER_LEN]).unwrap();
        assert_eq!(
            decode_protocol_custody_scope(&scope.finish().unwrap()),
            Err(ObjectError::UnknownProtocolCustodyPurpose(99))
        );
    }

    #[test]
    fn protocol_custody_scope_rejects_malformed_identifiers() {
        let mut short_subject =
            CanonicalStruct::new(PROTOCOL_CUSTODY_SCOPE_TYPE_ID, ENCODING_VERSION);
        short_subject.field_u16(1, 1).unwrap();
        short_subject.field_str(2, "dr0135-vectors").unwrap();
        short_subject
            .field_bytes(3, [0x61; IDENTIFIER_LEN - 1])
            .unwrap();
        short_subject
            .field_bytes(4, [0x62; IDENTIFIER_LEN])
            .unwrap();
        assert_eq!(
            decode_protocol_custody_scope(&short_subject.finish().unwrap()),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::InvalidFieldLength {
                    field_id: 3,
                    expected: IDENTIFIER_LEN,
                    actual: IDENTIFIER_LEN - 1,
                }
            ))
        );

        let mut short_resource =
            CanonicalStruct::new(PROTOCOL_CUSTODY_SCOPE_TYPE_ID, ENCODING_VERSION);
        short_resource.field_u16(1, 1).unwrap();
        short_resource.field_str(2, "dr0135-vectors").unwrap();
        short_resource
            .field_bytes(3, [0x61; IDENTIFIER_LEN])
            .unwrap();
        short_resource
            .field_bytes(4, [0x62; IDENTIFIER_LEN + 1])
            .unwrap();
        assert_eq!(
            decode_protocol_custody_scope(&short_resource.finish().unwrap()),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::InvalidFieldLength {
                    field_id: 4,
                    expected: IDENTIFIER_LEN,
                    actual: IDENTIFIER_LEN + 1,
                }
            ))
        );

        let mut empty_chain =
            CanonicalStruct::new(PROTOCOL_CUSTODY_SCOPE_TYPE_ID, ENCODING_VERSION);
        empty_chain.field_u16(1, 1).unwrap();
        empty_chain.field_str(2, "   ").unwrap();
        empty_chain.field_bytes(3, [0x61; IDENTIFIER_LEN]).unwrap();
        empty_chain.field_bytes(4, [0x62; IDENTIFIER_LEN]).unwrap();
        assert!(matches!(
            decode_protocol_custody_scope(&empty_chain.finish().unwrap()),
            Err(ObjectError::InvalidProtocolCustodyChainId(_))
        ));
    }

    #[test]
    fn protocol_custody_scope_rejects_wrong_frame_type_and_version() {
        let scope: ProtocolCustodyScope = sample_custody_scope();
        let mut wrong_type: Vec<u8> = encode_protocol_custody_scope(&scope).unwrap();
        wrong_type[4..6].copy_from_slice(&0x4999_u16.to_le_bytes());
        assert!(matches!(
            decode_protocol_custody_scope(&wrong_type),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));

        let mut wrong_version: Vec<u8> = encode_protocol_custody_scope(&scope).unwrap();
        wrong_version[6..8].copy_from_slice(&9_u16.to_le_bytes());
        assert!(matches!(
            decode_protocol_custody_scope(&wrong_version),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedVersion { .. }
            ))
        ));
    }

    #[test]
    fn protocol_custody_scope_rejects_extra_fields_and_trailing_bytes() {
        let mut extra_field =
            CanonicalStruct::new(PROTOCOL_CUSTODY_SCOPE_TYPE_ID, ENCODING_VERSION);
        extra_field.field_u16(1, 1).unwrap();
        extra_field.field_str(2, "dr0135-vectors").unwrap();
        extra_field.field_bytes(3, [0x61; IDENTIFIER_LEN]).unwrap();
        extra_field.field_bytes(4, [0x62; IDENTIFIER_LEN]).unwrap();
        extra_field.field_bytes(5, [0x00]).unwrap();
        assert_eq!(
            decode_protocol_custody_scope(&extra_field.finish().unwrap()),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(5)
            ))
        );

        let scope: ProtocolCustodyScope = sample_custody_scope();
        let mut trailing: Vec<u8> = encode_protocol_custody_scope(&scope).unwrap();
        trailing.push(0xFF);
        assert!(matches!(
            decode_protocol_custody_scope(&trailing),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::TrailingBytes(1)
            ))
        ));
    }

    #[test]
    fn protocol_custody_owner_rejects_wrong_owner_field_selection() {
        // Tag 5 with the address field (2) instead of the custody field (3).
        let mut wrong_field = CanonicalStruct::new(OWNER_TYPE_ID, ENCODING_VERSION);
        wrong_field.field_u16(1, 5).unwrap();
        wrong_field
            .field_bytes(
                2,
                encode_address(&Address::new([0x63; IDENTIFIER_LEN])).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            decode_owner(&wrong_field.finish().unwrap()),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(2)
            ))
        ));

        // Tag 5 with both the address field (2) and the custody field (3).
        let mut both_fields = CanonicalStruct::new(OWNER_TYPE_ID, ENCODING_VERSION);
        both_fields.field_u16(1, 5).unwrap();
        both_fields
            .field_bytes(
                2,
                encode_address(&Address::new([0x63; IDENTIFIER_LEN])).unwrap(),
            )
            .unwrap();
        both_fields
            .field_bytes(
                3,
                encode_protocol_custody_scope(&sample_custody_scope()).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            decode_owner(&both_fields.finish().unwrap()),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(2)
            ))
        ));

        // Tag 1 (Address) with the custody field (3) instead of field 2.
        let mut address_with_custody_field = CanonicalStruct::new(OWNER_TYPE_ID, ENCODING_VERSION);
        address_with_custody_field.field_u16(1, 1).unwrap();
        address_with_custody_field
            .field_bytes(
                3,
                encode_protocol_custody_scope(&sample_custody_scope()).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            decode_owner(&address_with_custody_field.finish().unwrap()),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedField(3)
            ))
        ));
    }

    #[test]
    fn object_decoder_round_trips_existing_canonical_bytes() {
        let object = Object {
            id: ObjectId::new([0x21; IDENTIFIER_LEN]),
            version: 9,
            owner: Owner::Address(Address::new([0x22; IDENTIFIER_LEN])),
            type_hash: Digest32::new(HashAlgorithmId::Sha3_256, [0x23; IDENTIFIER_LEN]),
            schema_version: 7,
            data: vec![0x24, 0x25],
        };
        let canonical: Vec<u8> = encode_object(&object).unwrap();
        assert_eq!(decode_object(&canonical), Ok(object));
    }

    #[test]
    fn object_decoder_rejects_wrong_type_and_unknown_owner() {
        let object = Object {
            id: ObjectId::new([0x31; IDENTIFIER_LEN]),
            version: 1,
            owner: Owner::Shared,
            type_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x32; IDENTIFIER_LEN]),
            schema_version: 1,
            data: vec![0x33],
        };
        let mut wrong_type: Vec<u8> = encode_object(&object).unwrap();
        wrong_type[4..6].copy_from_slice(&0x4999_u16.to_le_bytes());
        assert!(matches!(
            decode_object(&wrong_type),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));

        let mut owner = CanonicalStruct::new(OWNER_TYPE_ID, ENCODING_VERSION);
        owner.field_u16(1, 99).unwrap();
        assert_eq!(
            decode_owner(&owner.finish().unwrap()),
            Err(ObjectError::UnknownOwnerTag(99))
        );
    }

    #[test]
    fn object_ref_decoder_round_trips_existing_canonical_bytes() {
        let object_ref = ObjectRef {
            id: ObjectId::new([0x51; IDENTIFIER_LEN]),
            version: 11,
            digest: Digest32::new(HashAlgorithmId::Sha3_256, [0x52; IDENTIFIER_LEN]),
        };
        let canonical: Vec<u8> = encode_object_ref(&object_ref).unwrap();
        assert_eq!(decode_object_ref(&canonical), Ok(object_ref));
    }

    #[test]
    fn object_ref_decoder_rejects_wrong_type_and_short_id() {
        let object_ref = ObjectRef {
            id: ObjectId::new([0x53; IDENTIFIER_LEN]),
            version: 1,
            digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x54; IDENTIFIER_LEN]),
        };
        let mut wrong_type: Vec<u8> = encode_object_ref(&object_ref).unwrap();
        wrong_type[4..6].copy_from_slice(&0x4999_u16.to_le_bytes());
        assert!(matches!(
            decode_object_ref(&wrong_type),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::UnexpectedTypeId { .. }
            ))
        ));

        let mut short_id = CanonicalStruct::new(OBJECT_ID_TYPE_ID, ENCODING_VERSION);
        short_id.field_bytes(1, [0x11; 31]).unwrap();
        let short_id_bytes = short_id.finish().unwrap();
        let mut broken = CanonicalStruct::new(OBJECT_REF_TYPE_ID, ENCODING_VERSION);
        broken.field_bytes(1, short_id_bytes).unwrap();
        broken.field_u64(2, 1).unwrap();
        broken
            .field_bytes(
                3,
                encode_digest32(&Digest32::new(HashAlgorithmId::Sha2_256, [0x55; 32])).unwrap(),
            )
            .unwrap();
        assert_eq!(
            decode_object_ref(&broken.finish().unwrap()),
            Err(ObjectError::InvalidObjectIdLength(31))
        );
    }

    #[test]
    fn access_mode_decoder_round_trips_every_variant() {
        for mode in [AccessMode::Read, AccessMode::Write, AccessMode::Consume] {
            let canonical: Vec<u8> = encode_access_mode(mode).unwrap();
            assert_eq!(decode_access_mode(&canonical), Ok(mode));
        }
    }

    #[test]
    fn access_mode_decoder_rejects_unknown_tag_and_wrong_length() {
        let mut unknown = CanonicalStruct::new(ACCESS_MODE_TYPE_ID, ENCODING_VERSION);
        unknown.field_bytes(1, [0x09]).unwrap();
        assert_eq!(
            decode_access_mode(&unknown.finish().unwrap()),
            Err(ObjectError::UnknownAccessMode(0x09))
        );

        let mut wrong_length = CanonicalStruct::new(ACCESS_MODE_TYPE_ID, ENCODING_VERSION);
        wrong_length.field_bytes(1, [0x01, 0x02]).unwrap();
        assert_eq!(
            decode_access_mode(&wrong_length.finish().unwrap()),
            Err(ObjectError::CanonicalDecoding(
                CanonicalDecodingError::InvalidFieldLength {
                    field_id: 1,
                    expected: 1,
                    actual: 2,
                }
            ))
        );
    }

    #[test]
    fn short_identifier_slices_are_rejected() {
        assert_eq!(
            ObjectId::try_from_slice(&[0u8; 31]),
            Err(ObjectError::InvalidObjectIdLength(31))
        );
        assert_eq!(
            Address::try_from_slice(&[0u8; 31]),
            Err(ObjectError::InvalidAddressLength(31))
        );
    }

    struct AppendMigration {
        descriptor: MigrationDescriptor,
    }

    impl ObjectMigration for AppendMigration {
        fn descriptor(&self) -> &MigrationDescriptor {
            &self.descriptor
        }

        fn migrate_data(&self, canonical_data: &[u8]) -> Result<Vec<u8>, MigrationError> {
            let mut migrated = canonical_data.to_vec();
            migrated.push(0xFF);
            Ok(migrated)
        }
    }

    #[test]
    fn lazy_migration_updates_only_the_requested_object() {
        let object_type = Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]);
        let original = Object {
            id: ObjectId::new([0x11; 32]),
            version: 7,
            owner: Owner::Shared,
            type_hash: object_type,
            schema_version: 1,
            data: vec![1, 2],
        };
        let migration = AppendMigration {
            descriptor: MigrationDescriptor {
                migration_version: 1,
                object_type,
                from_schema_version: 1,
                to_schema_version: 2,
                migration_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x44; 32]),
            },
        };

        let migrated = apply_lazy_migration(&original, &migration).unwrap();
        assert_eq!(original.version, 7);
        assert_eq!(original.schema_version, 1);
        assert_eq!(migrated.id, original.id);
        assert_eq!(migrated.version, 8);
        assert_eq!(migrated.schema_version, 2);
        assert_eq!(migrated.data, vec![1, 2, 0xFF]);
    }

    #[test]
    fn lazy_migration_rejects_wrong_schema() {
        let object_type = Digest32::new(HashAlgorithmId::Sha2_256, [0x33; 32]);
        let object = Object {
            id: ObjectId::new([0x11; 32]),
            version: 7,
            owner: Owner::Shared,
            type_hash: object_type,
            schema_version: 2,
            data: vec![],
        };
        let migration = AppendMigration {
            descriptor: MigrationDescriptor {
                migration_version: 1,
                object_type,
                from_schema_version: 1,
                to_schema_version: 2,
                migration_hash: Digest32::new(HashAlgorithmId::Sha2_256, [0x44; 32]),
            },
        };

        assert_eq!(
            apply_lazy_migration(&object, &migration),
            Err(MigrationError::SchemaVersionMismatch {
                expected: 1,
                actual: 2
            })
        );
    }
}
