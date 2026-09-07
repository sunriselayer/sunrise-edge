//! Bounded package-scoped nominal references, not authenticated authority.
//!
//! Origins compare their structured fields, not digest bytes. Code revisions,
//! instance identity, schema version, and hashing context do not redefine the
//! nominal tag. Publication must authenticate the publisher and full request,
//! validate the owning key, and atomically enforce origin absence. Neither
//! these codecs nor a successful digest verification proves those conditions.

use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use hashing::{HashSuiteResolver, HashingError};
use protocol_types::{ChainId, Digest32, Epoch, TypeError};

/// Maximum length of a package chain identifier in UTF-8 bytes.
pub const MAX_PACKAGE_CHAIN_ID_BYTES: usize = 128;

/// Maximum number of arguments in a scoped type tag.
pub const MAX_SCOPED_TYPE_ARGS: usize = 8;

/// Maximum nominal type nesting depth (root tag is at depth 1).
pub const MAX_SCOPED_TYPE_DEPTH: usize = 4;

/// Maximum number of total nodes (tags and arguments) in a scoped type tree.
pub const MAX_SCOPED_TYPE_NODES: usize = 64;

/// Maximum encoded byte size for a scoped type tag canonical frame.
pub const MAX_SCOPED_TYPE_BYTES: usize = 32768;

/// Maximum encoded byte size for a package origin canonical frame.
pub const MAX_PACKAGE_ORIGIN_BYTES: usize = 256;

/// Typed package and scoped type errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageTypeError {
    /// Canonical frame encoding failure.
    Encoding(CanonicalEncodingError),
    /// Canonical frame decoding failure.
    Decoding(CanonicalDecodingError),
    /// Protocol type constructor failure.
    TypeError(TypeError),
    /// Cryptographic hashing failure.
    Hashing(HashingError),
    /// Chain identifier exceeds byte length limit.
    ChainTooLong(usize),
    /// Package origin chain identifier does not match expected chain.
    ChainMismatch,
    /// Constructor identifier cannot be zero.
    ZeroConstructor,
    /// Opaque argument domain cannot be zero.
    ZeroOpaqueDomain,
    /// Signature scheme identifier is not supported.
    UnsupportedSignatureScheme(u16),
    /// Fixed 32-byte field has invalid length.
    Invalid32ByteFieldLength(usize),
    /// Scoped type nesting depth limit exceeded.
    DepthLimitExceeded(usize),
    /// Total scoped type tree node budget exceeded.
    NodeLimitExceeded(usize),
    /// Scoped type argument count limit exceeded.
    ArgCountLimitExceeded(usize),
    /// Canonical payload byte size limit exceeded.
    ByteLimitExceeded(usize),
    /// Unknown scoped type argument variant discriminant.
    UnknownArgumentVariant(u16),
}

impl std::fmt::Display for PackageTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageTypeError::Encoding(e) => write!(f, "canonical encoding error: {e}"),
            PackageTypeError::Decoding(e) => write!(f, "canonical decoding error: {e}"),
            PackageTypeError::TypeError(e) => write!(f, "protocol type error: {e}"),
            PackageTypeError::Hashing(e) => write!(f, "hashing error: {e}"),
            PackageTypeError::ChainTooLong(len) => {
                write!(f, "chain identifier exceeds maximum length: {len} bytes")
            }
            PackageTypeError::ChainMismatch => {
                write!(f, "chain identifier mismatch in package origin")
            }
            PackageTypeError::ZeroConstructor => {
                write!(f, "scoped type constructor cannot be zero")
            }
            PackageTypeError::ZeroOpaqueDomain => {
                write!(f, "opaque argument domain cannot be zero")
            }
            PackageTypeError::UnsupportedSignatureScheme(scheme) => {
                write!(f, "unsupported signature scheme id: {scheme}")
            }
            PackageTypeError::Invalid32ByteFieldLength(len) => {
                write!(f, "expected 32-byte field, found {len} bytes")
            }
            PackageTypeError::DepthLimitExceeded(depth) => {
                write!(f, "scoped type nesting depth limit exceeded: {depth}")
            }
            PackageTypeError::NodeLimitExceeded(nodes) => {
                write!(f, "scoped type tree node limit exceeded: {nodes}")
            }
            PackageTypeError::ArgCountLimitExceeded(args) => {
                write!(f, "scoped type argument count limit exceeded: {args}")
            }
            PackageTypeError::ByteLimitExceeded(bytes) => {
                write!(f, "canonical byte limit exceeded: {bytes} bytes")
            }
            PackageTypeError::UnknownArgumentVariant(v) => {
                write!(f, "unknown scoped type argument variant: {v}")
            }
        }
    }
}

impl std::error::Error for PackageTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PackageTypeError::Encoding(e) => Some(e),
            PackageTypeError::Decoding(e) => Some(e),
            PackageTypeError::TypeError(e) => Some(e),
            PackageTypeError::Hashing(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CanonicalEncodingError> for PackageTypeError {
    fn from(err: CanonicalEncodingError) -> Self {
        PackageTypeError::Encoding(err)
    }
}

impl From<CanonicalDecodingError> for PackageTypeError {
    fn from(err: CanonicalDecodingError) -> Self {
        PackageTypeError::Decoding(err)
    }
}

impl From<TypeError> for PackageTypeError {
    fn from(err: TypeError) -> Self {
        PackageTypeError::TypeError(err)
    }
}

impl From<HashingError> for PackageTypeError {
    fn from(err: HashingError) -> Self {
        PackageTypeError::Hashing(err)
    }
}

/// Untrusted structured package origin identifying the publication authority reference.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageOrigin {
    chain_id: ChainId,
    publisher: [u8; 32],
    seed: [u8; 32],
}

impl PackageOrigin {
    /// Constructs a reference, checking only the chain length bound.
    ///
    /// The publisher bytes are not validated as a key or authenticated. The
    /// seed may be zero and is not a transaction nonce or proof of freshness.
    pub fn unverified(
        chain_id: ChainId,
        publisher: [u8; 32],
        seed: [u8; 32],
    ) -> Result<Self, PackageTypeError> {
        let chain_len: usize = chain_id.as_str().len();
        if chain_len > MAX_PACKAGE_CHAIN_ID_BYTES {
            return Err(PackageTypeError::ChainTooLong(chain_len));
        }
        Ok(Self {
            chain_id,
            publisher,
            seed,
        })
    }

    /// Returns a reference to the package origin chain identifier.
    pub fn chain_id(&self) -> &ChainId {
        &self.chain_id
    }

    /// Returns a reference to the 32-byte publisher key reference.
    pub fn publisher(&self) -> &[u8; 32] {
        &self.publisher
    }

    /// Returns a reference to the 32-byte deterministic creation seed.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

/// Scoped type argument, either a nominal nested tag or an opaque argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopedTypeArg {
    /// Nested nominal scoped type tag.
    Nominal(Box<ScopedTypeTag>),
    /// Opaque argument with domain classification and 32-byte value.
    Opaque {
        /// Opaque argument domain class local to the consuming type (must be nonzero).
        domain: u16,
        /// 32-byte opaque payload.
        value: [u8; 32],
    },
}

/// Scoped nominal type tag defining a structured type identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedTypeTag {
    origin: PackageOrigin,
    constructor: u16,
    args: Vec<ScopedTypeArg>,
}

impl ScopedTypeTag {
    /// Creates and validates a new scoped nominal type tag.
    pub fn new(
        origin: PackageOrigin,
        constructor: u16,
        args: Vec<ScopedTypeArg>,
    ) -> Result<Self, PackageTypeError> {
        if constructor == 0 {
            return Err(PackageTypeError::ZeroConstructor);
        }
        let arg_count: usize = args.len();
        if arg_count > MAX_SCOPED_TYPE_ARGS {
            return Err(PackageTypeError::ArgCountLimitExceeded(arg_count));
        }
        let tag: Self = Self {
            origin,
            constructor,
            args,
        };
        validate_scoped_type_tree(&tag)?;
        Ok(tag)
    }

    /// Returns a reference to the package origin.
    pub fn origin(&self) -> &PackageOrigin {
        &self.origin
    }

    /// Returns the type constructor identifier.
    pub fn constructor(&self) -> u16 {
        self.constructor
    }

    /// Returns a slice of the scoped type arguments.
    pub fn args(&self) -> &[ScopedTypeArg] {
        &self.args
    }
}

fn validate_scoped_type_tree(tag: &ScopedTypeTag) -> Result<(), PackageTypeError> {
    let mut node_count: usize = 0;
    validate_tag_node(tag, tag.origin.chain_id(), 1, &mut node_count)
}

fn validate_tag_node(
    tag: &ScopedTypeTag,
    root_chain: &ChainId,
    depth: usize,
    node_count: &mut usize,
) -> Result<(), PackageTypeError> {
    count_node(node_count)?;
    if depth > MAX_SCOPED_TYPE_DEPTH {
        return Err(PackageTypeError::DepthLimitExceeded(depth));
    }
    if tag.origin.chain_id() != root_chain {
        return Err(PackageTypeError::ChainMismatch);
    }
    let chain_len: usize = tag.origin.chain_id().as_str().len();
    if chain_len > MAX_PACKAGE_CHAIN_ID_BYTES {
        return Err(PackageTypeError::ChainTooLong(chain_len));
    }
    if tag.constructor == 0 {
        return Err(PackageTypeError::ZeroConstructor);
    }
    let arg_count: usize = tag.args.len();
    if arg_count > MAX_SCOPED_TYPE_ARGS {
        return Err(PackageTypeError::ArgCountLimitExceeded(arg_count));
    }
    for arg in &tag.args {
        count_node(node_count)?;
        match arg {
            ScopedTypeArg::Nominal(nested_tag) => {
                validate_tag_node(nested_tag, root_chain, next_depth(depth)?, node_count)?;
            }
            ScopedTypeArg::Opaque { domain, .. } => {
                if *domain == 0 {
                    return Err(PackageTypeError::ZeroOpaqueDomain);
                }
            }
        }
    }
    Ok(())
}

fn count_node(node_count: &mut usize) -> Result<(), PackageTypeError> {
    *node_count = node_count
        .checked_add(1)
        .ok_or(PackageTypeError::NodeLimitExceeded(usize::MAX))?;
    if *node_count > MAX_SCOPED_TYPE_NODES {
        return Err(PackageTypeError::NodeLimitExceeded(*node_count));
    }
    Ok(())
}

fn next_depth(depth: usize) -> Result<usize, PackageTypeError> {
    depth
        .checked_add(1)
        .ok_or(PackageTypeError::DepthLimitExceeded(usize::MAX))
}

/// Encodes a package origin into canonical encoding frame 0x5201.
pub fn encode_package_origin(origin: &PackageOrigin) -> Result<Vec<u8>, PackageTypeError> {
    let chain_len: usize = origin.chain_id().as_str().len();
    if chain_len > MAX_PACKAGE_CHAIN_ID_BYTES {
        return Err(PackageTypeError::ChainTooLong(chain_len));
    }
    let mut s: CanonicalStruct = CanonicalStruct::new(0x5201, 1);
    s.field_str(1, origin.chain_id().as_str())?;
    s.field_u16(2, 1)?;
    s.field_bytes(3, origin.publisher().to_vec())?;
    s.field_bytes(4, origin.seed().to_vec())?;
    let encoded: Vec<u8> = s.finish()?;
    let encoded_len: usize = encoded.len();
    if encoded_len > MAX_PACKAGE_ORIGIN_BYTES {
        return Err(PackageTypeError::ByteLimitExceeded(encoded_len));
    }
    Ok(encoded)
}

/// Decodes a package origin from canonical encoding frame 0x5201.
pub fn decode_package_origin(bytes: &[u8]) -> Result<PackageOrigin, PackageTypeError> {
    let byte_len: usize = bytes.len();
    if byte_len > MAX_PACKAGE_ORIGIN_BYTES {
        return Err(PackageTypeError::ByteLimitExceeded(byte_len));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(0x5201)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;

    let chain_str: &str = frame.required_str(1)?;
    let chain_len: usize = chain_str.len();
    if chain_len > MAX_PACKAGE_CHAIN_ID_BYTES {
        return Err(PackageTypeError::ChainTooLong(chain_len));
    }
    let chain_id: ChainId = ChainId::new(chain_str)?;

    let scheme: u16 = frame.required_u16(2)?;
    if scheme != 1 {
        return Err(PackageTypeError::UnsupportedSignatureScheme(scheme));
    }

    let publisher_bytes: &[u8] = frame.required_field(3)?;
    let publisher_len: usize = publisher_bytes.len();
    if publisher_len != 32 {
        return Err(PackageTypeError::Invalid32ByteFieldLength(publisher_len));
    }
    let mut publisher: [u8; 32] = [0u8; 32];
    publisher.copy_from_slice(publisher_bytes);

    let seed_bytes: &[u8] = frame.required_field(4)?;
    let seed_len: usize = seed_bytes.len();
    if seed_len != 32 {
        return Err(PackageTypeError::Invalid32ByteFieldLength(seed_len));
    }
    let mut seed: [u8; 32] = [0u8; 32];
    seed.copy_from_slice(seed_bytes);

    PackageOrigin::unverified(chain_id, publisher, seed)
}

fn encode_scoped_type_arg(arg: &ScopedTypeArg) -> Result<Vec<u8>, PackageTypeError> {
    let mut s: CanonicalStruct = CanonicalStruct::new(0x5202, 1);
    match arg {
        ScopedTypeArg::Nominal(nested_tag) => {
            s.field_u16(1, 1)?;
            let nested_bytes: Vec<u8> = encode_scoped_type_tag_inner(nested_tag)?;
            s.field_bytes(2, nested_bytes)?;
        }
        ScopedTypeArg::Opaque { domain, value } => {
            if *domain == 0 {
                return Err(PackageTypeError::ZeroOpaqueDomain);
            }
            s.field_u16(1, 2)?;
            s.field_u16(2, *domain)?;
            s.field_bytes(3, value.to_vec())?;
        }
    }
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

fn encode_scoped_type_tag_inner(tag: &ScopedTypeTag) -> Result<Vec<u8>, PackageTypeError> {
    let mut s: CanonicalStruct = CanonicalStruct::new(0x5203, 1);
    let encoded_origin: Vec<u8> = encode_package_origin(&tag.origin)?;
    s.field_bytes(1, encoded_origin)?;
    s.field_u16(2, tag.constructor)?;
    let arg_count: usize = tag.args.len();
    s.field_u16(3, arg_count as u16)?;
    for i in 0..arg_count {
        let field_id: u16 = (4 + i) as u16;
        let arg: &ScopedTypeArg = &tag.args[i];
        let encoded_arg: Vec<u8> = encode_scoped_type_arg(arg)?;
        s.field_bytes(field_id, encoded_arg)?;
    }
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

/// Encodes a scoped type tag into canonical encoding frame 0x5203.
pub fn encode_scoped_type_tag(tag: &ScopedTypeTag) -> Result<Vec<u8>, PackageTypeError> {
    validate_scoped_type_tree(tag)?;
    let encoded: Vec<u8> = encode_scoped_type_tag_inner(tag)?;
    let encoded_len: usize = encoded.len();
    if encoded_len > MAX_SCOPED_TYPE_BYTES {
        return Err(PackageTypeError::ByteLimitExceeded(encoded_len));
    }
    Ok(encoded)
}

fn decode_scoped_type_tag_inner(
    bytes: &[u8],
    depth: usize,
    node_count: &mut usize,
    root_chain: Option<&ChainId>,
) -> Result<ScopedTypeTag, PackageTypeError> {
    count_node(node_count)?;
    if depth > MAX_SCOPED_TYPE_DEPTH {
        return Err(PackageTypeError::DepthLimitExceeded(depth));
    }

    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(0x5203)?;
    frame.require_version(1)?;

    let origin_bytes: &[u8] = frame.required_field(1)?;
    let origin_len: usize = origin_bytes.len();
    if origin_len > MAX_PACKAGE_ORIGIN_BYTES {
        return Err(PackageTypeError::ByteLimitExceeded(origin_len));
    }
    let origin: PackageOrigin = decode_package_origin(origin_bytes)?;

    let current_root_chain: &ChainId = match root_chain {
        Some(expected) => {
            if origin.chain_id() != expected {
                return Err(PackageTypeError::ChainMismatch);
            }
            expected
        }
        None => origin.chain_id(),
    };

    let constructor: u16 = frame.required_u16(2)?;
    if constructor == 0 {
        return Err(PackageTypeError::ZeroConstructor);
    }

    let arg_count_u16: u16 = frame.required_u16(3)?;
    let arg_count: usize = arg_count_u16 as usize;
    if arg_count > MAX_SCOPED_TYPE_ARGS {
        return Err(PackageTypeError::ArgCountLimitExceeded(arg_count));
    }

    let mut expected_fields: Vec<u16> = Vec::with_capacity(3 + arg_count);
    expected_fields.push(1);
    expected_fields.push(2);
    expected_fields.push(3);
    for i in 0..arg_count {
        let field_id: u16 = (4 + i) as u16;
        expected_fields.push(field_id);
    }
    frame.require_only_fields(&expected_fields)?;

    let mut args: Vec<ScopedTypeArg> = Vec::with_capacity(arg_count);
    for i in 0..arg_count {
        count_node(node_count)?;

        let field_id: u16 = (4 + i) as u16;
        let arg_bytes: &[u8] = frame.required_field(field_id)?;

        let arg_frame: CanonicalFrame<'_> = decode_canonical_frame(arg_bytes)?;
        arg_frame.require_type(0x5202)?;
        arg_frame.require_version(1)?;

        let variant: u16 = arg_frame.required_u16(1)?;
        match variant {
            1 => {
                arg_frame.require_only_fields(&[1, 2])?;
                let nested_bytes: &[u8] = arg_frame.required_field(2)?;
                let nested_len: usize = nested_bytes.len();
                if nested_len > MAX_SCOPED_TYPE_BYTES {
                    return Err(PackageTypeError::ByteLimitExceeded(nested_len));
                }
                let nested_tag: ScopedTypeTag = decode_scoped_type_tag_inner(
                    nested_bytes,
                    next_depth(depth)?,
                    node_count,
                    Some(current_root_chain),
                )?;
                args.push(ScopedTypeArg::Nominal(Box::new(nested_tag)));
            }
            2 => {
                arg_frame.require_only_fields(&[1, 2, 3])?;
                let domain: u16 = arg_frame.required_u16(2)?;
                if domain == 0 {
                    return Err(PackageTypeError::ZeroOpaqueDomain);
                }
                let val_bytes: &[u8] = arg_frame.required_field(3)?;
                let val_len: usize = val_bytes.len();
                if val_len != 32 {
                    return Err(PackageTypeError::Invalid32ByteFieldLength(val_len));
                }
                let mut value: [u8; 32] = [0u8; 32];
                value.copy_from_slice(val_bytes);
                args.push(ScopedTypeArg::Opaque { domain, value });
            }
            _ => return Err(PackageTypeError::UnknownArgumentVariant(variant)),
        }
    }

    Ok(ScopedTypeTag {
        origin,
        constructor,
        args,
    })
}

/// Decodes a scoped type tag from canonical encoding frame 0x5203.
pub fn decode_scoped_type_tag(bytes: &[u8]) -> Result<ScopedTypeTag, PackageTypeError> {
    let byte_len: usize = bytes.len();
    if byte_len > MAX_SCOPED_TYPE_BYTES {
        return Err(PackageTypeError::ByteLimitExceeded(byte_len));
    }
    let mut node_count: usize = 0;
    decode_scoped_type_tag_inner(bytes, 1, &mut node_count, None)
}

/// Derives a nominal type commitment under the trusted execution epoch.
///
/// The epoch must not come from unauthenticated request input. Algorithm
/// rotation may change the digest, not the logical tag. This grants no rights.
pub fn derive_scoped_type_id(
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    tag: &ScopedTypeTag,
) -> Result<Digest32, PackageTypeError> {
    if tag.origin().chain_id() != resolver.chain_id() {
        return Err(PackageTypeError::ChainMismatch);
    }
    let payload: Vec<u8> = encode_scoped_type_tag(tag)?;
    let digest: Digest32 = hashing::hash_type_identity(resolver, epoch, &payload)?;
    Ok(digest)
}

/// Verifies a commitment to a logical tag using trusted algorithm history.
///
/// Supply the authenticated execution epoch, not a caller-selected epoch.
/// An old and new algorithm's digests can both verify the same tag after a
/// permitted rotation. Success does not authenticate the package or publisher.
pub fn verify_scoped_type_id(
    resolver: &HashSuiteResolver,
    digest: &Digest32,
    epoch: Epoch,
    tag: &ScopedTypeTag,
) -> Result<bool, PackageTypeError> {
    if tag.origin().chain_id() != resolver.chain_id() {
        return Err(PackageTypeError::ChainMismatch);
    }
    let payload: Vec<u8> = encode_scoped_type_tag(tag)?;
    let valid: bool = hashing::verify_type_identity_digest(resolver, digest, epoch, &payload)?;
    Ok(valid)
}
