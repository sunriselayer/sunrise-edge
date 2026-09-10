//! Package-scoped public object-signature ABI data and strict canonical codecs.
//!
//! # Explicit Non-Claims
//!
//! - This module provides structural declaration data only.
//! - It asserts NO execution, storage, dependency, or type authority.
//! - It performs NO runtime or host validation, dependency resolution, or type substitution.
//! - Publication authentication, constructor registry verification, and type checking are
//!   deferred to higher protocol layers. All types are unverified structural references.

use crate::package_types::{
    MAX_PACKAGE_CHAIN_ID_BYTES, PackageOrigin, PackageTypeError, decode_package_origin,
    encode_package_origin,
};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use core::fmt;
use protocol_types::ChainId;
use std::error::Error;

/// Maximum encoded byte size for a public ABI canonical frame (64 KiB).
pub const MAX_PUBLIC_ABI_BYTES: usize = 65536;

/// Maximum number of constructor declarations in a package ABI.
pub const MAX_ABI_CONSTRUCTORS: usize = 64;

/// Maximum number of entrypoint declarations in a package ABI.
pub const MAX_ABI_ENTRYPOINTS: usize = 64;

/// Maximum number of object parameters in an entrypoint declaration.
pub const MAX_ABI_OBJECT_PARAMS: usize = 32;

/// Maximum number of type parameters or constructor/pattern arguments.
pub const MAX_ABI_TYPE_PARAMS: usize = 8;

/// Maximum nominal type pattern nesting depth (root pattern is at depth 1).
pub const MAX_ABI_TYPE_DEPTH: usize = 4;

/// Maximum total pattern and argument nodes across the entire ABI tree.
pub const MAX_ABI_TYPE_NODES: usize = 1024;

const FRAME_TYPE_PACKAGE_ABI: u16 = 0x5301;
const FRAME_TYPE_CONSTRUCTOR: u16 = 0x5302;
const FRAME_TYPE_ARGUMENT_KIND: u16 = 0x5303;
const FRAME_TYPE_ENTRYPOINT: u16 = 0x5304;
const FRAME_TYPE_OBJECT_PARAM: u16 = 0x5305;
const FRAME_TYPE_TYPE_PATTERN: u16 = 0x5306;
const FRAME_TYPE_PATTERN_ARG: u16 = 0x5307;
const FRAME_TYPE_ORDERED_LIST: u16 = 0x5308;
const FRAME_TYPE_OBJECT_RESULT: u16 = 0x5309;

const FRAME_VERSION: u16 = 1;
/// Maximum UTF-8 byte length of a declared entrypoint name.
pub const MAX_ENTRYPOINT_NAME_BYTES: usize = 256;
/// Maximum number of ordered typed object result slots declared by one
/// entrypoint (DR-0124). Slots are positional and signed; a slot may permit
/// absence but a required slot must be filled on normal frame exit.
pub const MAX_ABI_OBJECT_RESULTS: usize = 4;

/// Errors occurring during public ABI encoding, decoding, or shape validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicAbiError {
    /// Canonical frame encoding failure.
    Encoding(CanonicalEncodingError),
    /// Canonical frame decoding failure.
    Decoding(CanonicalDecodingError),
    /// Underlying package type error.
    Package(PackageTypeError),
    /// Invalid ABI shape or invariant violation.
    Invalid(&'static str),
    /// Resource limit exceeded.
    Limit(&'static str),
}

impl fmt::Display for PublicAbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(e) => write!(f, "canonical encoding error: {e}"),
            Self::Decoding(e) => write!(f, "canonical decoding error: {e}"),
            Self::Package(e) => write!(f, "package type error: {e}"),
            Self::Invalid(msg) => write!(f, "invalid public abi: {msg}"),
            Self::Limit(msg) => write!(f, "public abi limit exceeded: {msg}"),
        }
    }
}

impl Error for PublicAbiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encoding(e) => Some(e),
            Self::Decoding(e) => Some(e),
            Self::Package(e) => Some(e),
            Self::Invalid(_) | Self::Limit(_) => None,
        }
    }
}

impl From<CanonicalEncodingError> for PublicAbiError {
    fn from(err: CanonicalEncodingError) -> Self {
        Self::Encoding(err)
    }
}

impl From<CanonicalDecodingError> for PublicAbiError {
    fn from(err: CanonicalDecodingError) -> Self {
        Self::Decoding(err)
    }
}

impl From<PackageTypeError> for PublicAbiError {
    fn from(err: PackageTypeError) -> Self {
        Self::Package(err)
    }
}

/// The kind of an argument or type parameter in a public ABI declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgumentKind {
    /// Nominal scoped type argument.
    Nominal,
    /// Opaque argument with a non-zero domain classification.
    Opaque(u16),
}

/// Public declaration of a package-scoped type constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstructorDeclaration {
    /// Non-zero local constructor identifier, strictly ascending within the package.
    pub local_id: u16,
    /// Non-zero schema version identifier.
    pub schema: u32,
    /// Parameter argument kinds (up to 8).
    pub arguments: Vec<ArgumentKind>,
}

/// Access mode for an object parameter in an entrypoint declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectMode {
    /// Read access.
    Read,
    /// Write access.
    Write,
    /// Consume (destroy / state-transition) access.
    Consume,
}

impl ObjectMode {
    /// Returns the stable canonical wire tag for this mode.
    #[must_use]
    pub const fn tag(self) -> u16 {
        match self {
            Self::Read => 1,
            Self::Write => 2,
            Self::Consume => 3,
        }
    }

    /// Decodes an object mode from a canonical wire tag.
    pub fn from_tag(tag: u16) -> Result<Self, PublicAbiError> {
        match tag {
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::Consume),
            _ => Err(PublicAbiError::Invalid("unknown object mode tag")),
        }
    }
}

/// Nominal type pattern declaring the expected object type structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypePattern {
    /// Package origin where the constructor is defined.
    pub origin: PackageOrigin,
    /// Non-zero constructor identifier.
    pub constructor: u16,
    /// Type pattern arguments (up to 8).
    pub arguments: Vec<PatternArgument>,
}

/// An argument within a type pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatternArgument {
    /// Nested nominal type pattern.
    Nominal(Box<TypePattern>),
    /// Opaque argument with non-zero domain and 32-byte payload.
    Opaque {
        /// Non-zero opaque domain.
        domain: u16,
        /// 32-byte payload.
        value: [u8; 32],
    },
    /// Reference to an enclosing entrypoint type parameter by index.
    Parameter(u16),
}

/// Declaration of an object parameter accepted by an entrypoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectParameter {
    /// Access mode for the object.
    pub mode: ObjectMode,
    /// Non-zero schema version identifier.
    pub schema: u32,
    /// Expected type pattern.
    pub ty: TypePattern,
}

/// Declaration of one ordered, signed typed object result slot (DR-0124).
///
/// Slots are positional, not name-addressed: `return_object(slot, handle)`
/// names a slot by its index in the entrypoint's declared result list.
/// `optional` permits the slot to be delivered absent (no handle, but the
/// slot still occupies its fixed position in delivery); a non-optional slot
/// must be filled on every normal frame exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectResultDeclaration {
    /// Maximum access mode delivered to the receiving frame.
    pub mode: ObjectMode,
    /// Non-zero schema version identifier.
    pub schema: u32,
    /// Expected type pattern.
    pub ty: TypePattern,
    /// Whether this slot may be delivered absent.
    pub optional: bool,
}

/// Declaration of a public entrypoint exposed by a package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntrypointDeclaration {
    /// Entrypoint name (1..256 bytes UTF-8, strictly ascending, unique, not "memory").
    pub name: String,
    /// Type parameter kinds (up to 8).
    pub type_parameters: Vec<ArgumentKind>,
    /// Object parameters (up to 32, ordered).
    pub objects: Vec<ObjectParameter>,
}

/// Public ABI declaration for a package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageAbi {
    /// Authority reference for the defining package.
    pub origin: PackageOrigin,
    /// Declared type constructors (0..64, strictly ascending local_id).
    pub constructors: Vec<ConstructorDeclaration>,
    /// Exposed entrypoints (1..64, strictly ascending by name).
    pub entrypoints: Vec<EntrypointDeclaration>,
}

fn list_field_id(index: usize) -> Result<u16, PublicAbiError> {
    let offset: usize = index
        .checked_add(2)
        .ok_or(PublicAbiError::Limit("list field index overflow"))?;
    u16::try_from(offset).map_err(|_| PublicAbiError::Limit("list field id exceeds u16::MAX"))
}

fn make_list_field_ids(count: usize) -> Result<Vec<u16>, PublicAbiError> {
    let capacity: usize = count
        .checked_add(1)
        .ok_or(PublicAbiError::Limit("list count overflow"))?;
    let mut fields: Vec<u16> = Vec::with_capacity(capacity);
    fields.push(1);
    for idx in 0..count {
        fields.push(list_field_id(idx)?);
    }
    Ok(fields)
}

fn encode_canonical_list(items: &[Vec<u8>], max_items: usize) -> Result<Vec<u8>, PublicAbiError> {
    let count: usize = items.len();
    if count > max_items {
        return Err(PublicAbiError::Limit("list count exceeds limit"));
    }
    let count_u16: u16 =
        u16::try_from(count).map_err(|_| PublicAbiError::Limit("list count exceeds u16::MAX"))?;

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_ORDERED_LIST, FRAME_VERSION);
    s.field_u16(1, count_u16)?;
    for (idx, item) in items.iter().enumerate() {
        let field_id: u16 = list_field_id(idx)?;
        s.field_bytes(field_id, item.as_slice())?;
    }
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

fn decode_canonical_list<T, F>(
    bytes: &[u8],
    max_items: usize,
    mut decode_item: F,
) -> Result<Vec<T>, PublicAbiError>
where
    F: FnMut(&[u8]) -> Result<T, PublicAbiError>,
{
    if bytes.len() > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit("list byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_ORDERED_LIST)?;
    frame.require_version(FRAME_VERSION)?;

    let count_u16: u16 = frame.required_u16(1)?;
    let count: usize = count_u16 as usize;
    if count > max_items {
        return Err(PublicAbiError::Limit("list count limit exceeded"));
    }
    let expected_fields: Vec<u16> = make_list_field_ids(count)?;
    frame.require_only_fields(&expected_fields)?;

    let mut items: Vec<T> = Vec::with_capacity(count);
    for idx in 0..count {
        let field_id: u16 = list_field_id(idx)?;
        let item_bytes: &[u8] = frame.required_field(field_id)?;
        if item_bytes.len() > MAX_PUBLIC_ABI_BYTES {
            return Err(PublicAbiError::Limit("item byte limit exceeded"));
        }
        items.push(decode_item(item_bytes)?);
    }
    Ok(items)
}

fn count_node(node_count: &mut usize) -> Result<(), PublicAbiError> {
    *node_count = node_count
        .checked_add(1)
        .ok_or(PublicAbiError::Limit("type node budget exceeded"))?;
    if *node_count > MAX_ABI_TYPE_NODES {
        return Err(PublicAbiError::Limit("type node budget exceeded"));
    }
    Ok(())
}

fn next_depth(depth: usize) -> Result<usize, PublicAbiError> {
    let next: usize = depth
        .checked_add(1)
        .ok_or(PublicAbiError::Limit("type pattern depth overflow"))?;
    if next > MAX_ABI_TYPE_DEPTH {
        return Err(PublicAbiError::Limit("type pattern depth exceeded"));
    }
    Ok(next)
}

fn validate_argument_kind(kind: &ArgumentKind) -> Result<(), PublicAbiError> {
    match kind {
        ArgumentKind::Nominal => Ok(()),
        ArgumentKind::Opaque(domain) => {
            if *domain == 0 {
                Err(PublicAbiError::Invalid("opaque domain cannot be zero"))
            } else {
                Ok(())
            }
        }
    }
}

fn validate_pattern_shape(
    pattern: &TypePattern,
    root_chain: &ChainId,
    type_param_count: usize,
    depth: usize,
    node_count: &mut usize,
) -> Result<(), PublicAbiError> {
    count_node(node_count)?;
    if depth > MAX_ABI_TYPE_DEPTH {
        return Err(PublicAbiError::Limit("type pattern depth exceeded"));
    }
    if pattern.origin.chain_id() != root_chain {
        return Err(PublicAbiError::Invalid(
            "chain mismatch in type pattern origin",
        ));
    }
    let chain_len: usize = pattern.origin.chain_id().as_str().len();
    if chain_len == 0 || chain_len > MAX_PACKAGE_CHAIN_ID_BYTES {
        return Err(PublicAbiError::Limit(
            "pattern origin chain id length out of bounds",
        ));
    }
    if pattern.constructor == 0 {
        return Err(PublicAbiError::Invalid(
            "type pattern constructor cannot be zero",
        ));
    }
    let arg_count: usize = pattern.arguments.len();
    if arg_count > MAX_ABI_TYPE_PARAMS {
        return Err(PublicAbiError::Limit(
            "type pattern argument count exceeds limit",
        ));
    }
    for arg in &pattern.arguments {
        count_node(node_count)?;
        match arg {
            PatternArgument::Nominal(nested) => {
                let next: usize = next_depth(depth)?;
                validate_pattern_shape(nested, root_chain, type_param_count, next, node_count)?;
            }
            PatternArgument::Opaque { domain, value: _ } => {
                if *domain == 0 {
                    return Err(PublicAbiError::Invalid(
                        "pattern argument opaque domain cannot be zero",
                    ));
                }
            }
            PatternArgument::Parameter(idx) => {
                if (*idx as usize) >= type_param_count {
                    return Err(PublicAbiError::Invalid(
                        "pattern argument parameter index out of range",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Validates the structural shape and resource bounds of a package ABI declaration.
///
/// This performs structural validation only. References to constructors or schemas
/// are not resolved or authenticated against external registries or dependencies.
pub fn validate_package_abi_shape(abi: &PackageAbi) -> Result<(), PublicAbiError> {
    let root_chain: &ChainId = abi.origin.chain_id();
    let root_chain_len: usize = root_chain.as_str().len();
    if root_chain_len == 0 || root_chain_len > MAX_PACKAGE_CHAIN_ID_BYTES {
        return Err(PublicAbiError::Limit(
            "root origin chain id length out of bounds",
        ));
    }

    let ctor_count: usize = abi.constructors.len();
    if ctor_count > MAX_ABI_CONSTRUCTORS {
        return Err(PublicAbiError::Limit("constructor count exceeds limit"));
    }

    let mut prev_local_id: Option<u16> = None;
    for ctor in &abi.constructors {
        if ctor.local_id == 0 {
            return Err(PublicAbiError::Invalid(
                "constructor local_id cannot be zero",
            ));
        }
        if let Some(prev) = prev_local_id
            && ctor.local_id <= prev
        {
            return Err(PublicAbiError::Invalid(
                "constructor local_ids must be strictly ascending",
            ));
        }
        prev_local_id = Some(ctor.local_id);

        if ctor.schema == 0 {
            return Err(PublicAbiError::Invalid("constructor schema cannot be zero"));
        }

        let arg_count: usize = ctor.arguments.len();
        if arg_count > MAX_ABI_TYPE_PARAMS {
            return Err(PublicAbiError::Limit(
                "constructor argument count exceeds limit",
            ));
        }
        for kind in &ctor.arguments {
            validate_argument_kind(kind)?;
        }
    }

    let ep_count: usize = abi.entrypoints.len();
    if ep_count < 1 {
        return Err(PublicAbiError::Invalid(
            "package abi must declare at least one entrypoint",
        ));
    }
    if ep_count > MAX_ABI_ENTRYPOINTS {
        return Err(PublicAbiError::Limit("entrypoint count exceeds limit"));
    }

    let mut prev_name: Option<&str> = None;
    let mut total_nodes: usize = 0;

    for ep in &abi.entrypoints {
        let name_len: usize = ep.name.len();
        if name_len < 1 {
            return Err(PublicAbiError::Invalid("entrypoint name cannot be empty"));
        }
        if name_len > MAX_ENTRYPOINT_NAME_BYTES {
            return Err(PublicAbiError::Limit(
                "entrypoint name exceeds maximum length",
            ));
        }
        if ep.name == "memory" {
            return Err(PublicAbiError::Invalid("reserved entrypoint name 'memory'"));
        }
        if let Some(prev) = prev_name
            && ep.name.as_str() <= prev
        {
            return Err(PublicAbiError::Invalid(
                "entrypoint names must be strictly ascending and unique",
            ));
        }
        prev_name = Some(ep.name.as_str());

        let type_param_count: usize = ep.type_parameters.len();
        if type_param_count > MAX_ABI_TYPE_PARAMS {
            return Err(PublicAbiError::Limit(
                "entrypoint type parameter count exceeds limit",
            ));
        }
        for kind in &ep.type_parameters {
            validate_argument_kind(kind)?;
        }

        let obj_count: usize = ep.objects.len();
        if obj_count > MAX_ABI_OBJECT_PARAMS {
            return Err(PublicAbiError::Limit(
                "entrypoint object parameter count exceeds limit",
            ));
        }
        for obj in &ep.objects {
            if obj.schema == 0 {
                return Err(PublicAbiError::Invalid(
                    "object parameter schema cannot be zero",
                ));
            }
            validate_pattern_shape(&obj.ty, root_chain, type_param_count, 1, &mut total_nodes)?;
        }
    }

    Ok(())
}

fn encode_argument_kind(kind: &ArgumentKind) -> Result<Vec<u8>, PublicAbiError> {
    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_ARGUMENT_KIND, FRAME_VERSION);
    match kind {
        ArgumentKind::Nominal => {
            s.field_u16(1, 1)?;
        }
        ArgumentKind::Opaque(domain) => {
            if *domain == 0 {
                return Err(PublicAbiError::Invalid("opaque domain cannot be zero"));
            }
            s.field_u16(1, 2)?;
            s.field_u16(2, *domain)?;
        }
    }
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

fn encode_constructor_declaration(
    ctor: &ConstructorDeclaration,
) -> Result<Vec<u8>, PublicAbiError> {
    if ctor.local_id == 0 {
        return Err(PublicAbiError::Invalid(
            "constructor local_id cannot be zero",
        ));
    }
    if ctor.schema == 0 {
        return Err(PublicAbiError::Invalid("constructor schema cannot be zero"));
    }
    let arg_count: usize = ctor.arguments.len();
    if arg_count > MAX_ABI_TYPE_PARAMS {
        return Err(PublicAbiError::Limit(
            "constructor argument count exceeds limit",
        ));
    }

    let mut encoded_args: Vec<Vec<u8>> = Vec::with_capacity(arg_count);
    for arg in &ctor.arguments {
        encoded_args.push(encode_argument_kind(arg)?);
    }
    let arg_list_bytes: Vec<u8> = encode_canonical_list(&encoded_args, MAX_ABI_TYPE_PARAMS)?;

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_CONSTRUCTOR, FRAME_VERSION);
    s.field_u16(1, ctor.local_id)?;
    s.field_u32(2, ctor.schema)?;
    s.field_bytes(3, arg_list_bytes)?;
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

fn encode_pattern_argument(arg: &PatternArgument) -> Result<Vec<u8>, PublicAbiError> {
    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_PATTERN_ARG, FRAME_VERSION);
    match arg {
        PatternArgument::Nominal(nested) => {
            let nested_bytes: Vec<u8> = encode_type_pattern(nested)?;
            s.field_u16(1, 1)?;
            s.field_bytes(2, nested_bytes)?;
        }
        PatternArgument::Opaque { domain, value } => {
            if *domain == 0 {
                return Err(PublicAbiError::Invalid(
                    "pattern argument opaque domain cannot be zero",
                ));
            }
            s.field_u16(1, 2)?;
            s.field_u16(2, *domain)?;
            s.field_bytes(3, value.as_slice())?;
        }
        PatternArgument::Parameter(idx) => {
            s.field_u16(1, 3)?;
            s.field_u16(2, *idx)?;
        }
    }
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

fn encode_type_pattern(pattern: &TypePattern) -> Result<Vec<u8>, PublicAbiError> {
    if pattern.constructor == 0 {
        return Err(PublicAbiError::Invalid(
            "type pattern constructor cannot be zero",
        ));
    }
    let arg_count: usize = pattern.arguments.len();
    if arg_count > MAX_ABI_TYPE_PARAMS {
        return Err(PublicAbiError::Limit(
            "type pattern argument count exceeds limit",
        ));
    }

    let origin_bytes: Vec<u8> = encode_package_origin(&pattern.origin)?;

    let mut encoded_args: Vec<Vec<u8>> = Vec::with_capacity(arg_count);
    for arg in &pattern.arguments {
        encoded_args.push(encode_pattern_argument(arg)?);
    }
    let args_list_bytes: Vec<u8> = encode_canonical_list(&encoded_args, MAX_ABI_TYPE_PARAMS)?;

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_TYPE_PATTERN, FRAME_VERSION);
    s.field_bytes(1, origin_bytes)?;
    s.field_u16(2, pattern.constructor)?;
    s.field_bytes(3, args_list_bytes)?;
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

fn encode_object_parameter(obj: &ObjectParameter) -> Result<Vec<u8>, PublicAbiError> {
    if obj.schema == 0 {
        return Err(PublicAbiError::Invalid(
            "object parameter schema cannot be zero",
        ));
    }
    let pattern_bytes: Vec<u8> = encode_type_pattern(&obj.ty)?;

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_OBJECT_PARAM, FRAME_VERSION);
    s.field_u16(1, obj.mode.tag())?;
    s.field_u32(2, obj.schema)?;
    s.field_bytes(3, pattern_bytes)?;
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

/// Canonically encodes one ordered typed object result declaration (DR-0124).
fn encode_object_result_declaration(
    result: &ObjectResultDeclaration,
) -> Result<Vec<u8>, PublicAbiError> {
    if result.schema == 0 {
        return Err(PublicAbiError::Invalid(
            "object result schema cannot be zero",
        ));
    }
    let pattern_bytes: Vec<u8> = encode_type_pattern(&result.ty)?;

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_OBJECT_RESULT, FRAME_VERSION);
    s.field_u16(1, result.mode.tag())?;
    s.field_u32(2, result.schema)?;
    s.field_bytes(3, pattern_bytes)?;
    s.field_u16(4, u16::from(result.optional))?;
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

/// Canonically encodes one entrypoint's ordered, bounded typed object result list.
pub(crate) fn encode_object_result_list(
    results: &[ObjectResultDeclaration],
) -> Result<Vec<u8>, PublicAbiError> {
    if results.len() > MAX_ABI_OBJECT_RESULTS {
        return Err(PublicAbiError::Limit("object result count exceeds limit"));
    }
    let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(results.len());
    for result in results {
        encoded.push(encode_object_result_declaration(result)?);
    }
    encode_canonical_list(&encoded, MAX_ABI_OBJECT_RESULTS)
}

fn encode_entrypoint_declaration(ep: &EntrypointDeclaration) -> Result<Vec<u8>, PublicAbiError> {
    let name_len: usize = ep.name.len();
    if name_len < 1 {
        return Err(PublicAbiError::Invalid("entrypoint name cannot be empty"));
    }
    if name_len > MAX_ENTRYPOINT_NAME_BYTES {
        return Err(PublicAbiError::Limit(
            "entrypoint name exceeds maximum length",
        ));
    }
    if ep.name == "memory" {
        return Err(PublicAbiError::Invalid("reserved entrypoint name 'memory'"));
    }

    let type_param_count: usize = ep.type_parameters.len();
    if type_param_count > MAX_ABI_TYPE_PARAMS {
        return Err(PublicAbiError::Limit(
            "entrypoint type parameter count exceeds limit",
        ));
    }
    let mut encoded_tparams: Vec<Vec<u8>> = Vec::with_capacity(type_param_count);
    for tp in &ep.type_parameters {
        encoded_tparams.push(encode_argument_kind(tp)?);
    }
    let tparam_list_bytes: Vec<u8> = encode_canonical_list(&encoded_tparams, MAX_ABI_TYPE_PARAMS)?;

    let obj_count: usize = ep.objects.len();
    if obj_count > MAX_ABI_OBJECT_PARAMS {
        return Err(PublicAbiError::Limit(
            "entrypoint object parameter count exceeds limit",
        ));
    }
    let mut encoded_objs: Vec<Vec<u8>> = Vec::with_capacity(obj_count);
    for obj in &ep.objects {
        encoded_objs.push(encode_object_parameter(obj)?);
    }
    let obj_list_bytes: Vec<u8> = encode_canonical_list(&encoded_objs, MAX_ABI_OBJECT_PARAMS)?;

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_ENTRYPOINT, FRAME_VERSION);
    s.field_str(1, ep.name.as_str())?;
    s.field_bytes(2, tparam_list_bytes)?;
    s.field_bytes(3, obj_list_bytes)?;
    let bytes: Vec<u8> = s.finish()?;
    Ok(bytes)
}

/// Canonically encodes a package ABI declaration after validating its structural shape.
///
/// Ensures the resulting wire payload does not exceed [`MAX_PUBLIC_ABI_BYTES`].
pub fn encode_package_abi(abi: &PackageAbi) -> Result<Vec<u8>, PublicAbiError> {
    validate_package_abi_shape(abi)?;

    let origin_bytes: Vec<u8> = encode_package_origin(&abi.origin)?;

    let ctor_count: usize = abi.constructors.len();
    let mut encoded_ctors: Vec<Vec<u8>> = Vec::with_capacity(ctor_count);
    for ctor in &abi.constructors {
        encoded_ctors.push(encode_constructor_declaration(ctor)?);
    }
    let ctor_list_bytes: Vec<u8> = encode_canonical_list(&encoded_ctors, MAX_ABI_CONSTRUCTORS)?;

    let ep_count: usize = abi.entrypoints.len();
    let mut encoded_eps: Vec<Vec<u8>> = Vec::with_capacity(ep_count);
    for ep in &abi.entrypoints {
        encoded_eps.push(encode_entrypoint_declaration(ep)?);
    }
    let ep_list_bytes: Vec<u8> = encode_canonical_list(&encoded_eps, MAX_ABI_ENTRYPOINTS)?;

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_PACKAGE_ABI, FRAME_VERSION);
    s.field_bytes(1, origin_bytes)?;
    s.field_bytes(2, ctor_list_bytes)?;
    s.field_bytes(3, ep_list_bytes)?;
    let encoded: Vec<u8> = s.finish()?;

    let encoded_len: usize = encoded.len();
    if encoded_len > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit(
            "encoded public abi exceeds maximum bytes",
        ));
    }
    Ok(encoded)
}

fn decode_argument_kind(bytes: &[u8]) -> Result<ArgumentKind, PublicAbiError> {
    if bytes.len() > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit("argument kind byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_ARGUMENT_KIND)?;
    frame.require_version(FRAME_VERSION)?;

    let tag: u16 = frame.required_u16(1)?;
    match tag {
        1 => {
            frame.require_only_fields(&[1])?;
            Ok(ArgumentKind::Nominal)
        }
        2 => {
            frame.require_only_fields(&[1, 2])?;
            let domain: u16 = frame.required_u16(2)?;
            if domain == 0 {
                return Err(PublicAbiError::Invalid("opaque domain cannot be zero"));
            }
            Ok(ArgumentKind::Opaque(domain))
        }
        _ => Err(PublicAbiError::Invalid(
            "unknown argument kind tag discriminant",
        )),
    }
}

fn decode_constructor_declaration(bytes: &[u8]) -> Result<ConstructorDeclaration, PublicAbiError> {
    if bytes.len() > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit("constructor byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_CONSTRUCTOR)?;
    frame.require_version(FRAME_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;

    let local_id: u16 = frame.required_u16(1)?;
    if local_id == 0 {
        return Err(PublicAbiError::Invalid(
            "constructor local_id cannot be zero",
        ));
    }
    let schema: u32 = frame.required_u32(2)?;
    if schema == 0 {
        return Err(PublicAbiError::Invalid("constructor schema cannot be zero"));
    }

    let kind_list_bytes: &[u8] = frame.required_field(3)?;
    let arguments: Vec<ArgumentKind> =
        decode_canonical_list(kind_list_bytes, MAX_ABI_TYPE_PARAMS, decode_argument_kind)?;

    Ok(ConstructorDeclaration {
        local_id,
        schema,
        arguments,
    })
}

fn decode_pattern_argument(
    bytes: &[u8],
    depth: usize,
    node_count: &mut usize,
    root_chain: &ChainId,
) -> Result<PatternArgument, PublicAbiError> {
    count_node(node_count)?;
    if bytes.len() > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit(
            "pattern argument byte limit exceeded",
        ));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_PATTERN_ARG)?;
    frame.require_version(FRAME_VERSION)?;

    let variant: u16 = frame.required_u16(1)?;
    match variant {
        1 => {
            frame.require_only_fields(&[1, 2])?;
            let next: usize = next_depth(depth)?;
            let nested_bytes: &[u8] = frame.required_field(2)?;
            let nested: TypePattern =
                decode_type_pattern_inner(nested_bytes, next, node_count, root_chain)?;
            Ok(PatternArgument::Nominal(Box::new(nested)))
        }
        2 => {
            frame.require_only_fields(&[1, 2, 3])?;
            let domain: u16 = frame.required_u16(2)?;
            if domain == 0 {
                return Err(PublicAbiError::Invalid(
                    "pattern argument opaque domain cannot be zero",
                ));
            }
            let val_bytes: &[u8] = frame.required_field(3)?;
            let val_len: usize = val_bytes.len();
            if val_len != 32 {
                return Err(PublicAbiError::Invalid(
                    "pattern argument opaque value must be 32 bytes",
                ));
            }
            let mut value: [u8; 32] = [0u8; 32];
            value.copy_from_slice(val_bytes);
            Ok(PatternArgument::Opaque { domain, value })
        }
        3 => {
            frame.require_only_fields(&[1, 2])?;
            let index: u16 = frame.required_u16(2)?;
            Ok(PatternArgument::Parameter(index))
        }
        _ => Err(PublicAbiError::Invalid(
            "unknown pattern argument variant discriminant",
        )),
    }
}

fn decode_type_pattern_inner(
    bytes: &[u8],
    depth: usize,
    node_count: &mut usize,
    root_chain: &ChainId,
) -> Result<TypePattern, PublicAbiError> {
    count_node(node_count)?;
    if depth > MAX_ABI_TYPE_DEPTH {
        return Err(PublicAbiError::Limit("type pattern depth exceeded"));
    }
    if bytes.len() > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit("pattern byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_TYPE_PATTERN)?;
    frame.require_version(FRAME_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;

    let origin_bytes: &[u8] = frame.required_field(1)?;
    if origin_bytes.len() > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit("origin byte limit exceeded"));
    }
    let origin: PackageOrigin = decode_package_origin(origin_bytes)?;
    if origin.chain_id() != root_chain {
        return Err(PublicAbiError::Invalid(
            "chain mismatch in type pattern origin",
        ));
    }

    let constructor: u16 = frame.required_u16(2)?;
    if constructor == 0 {
        return Err(PublicAbiError::Invalid(
            "type pattern constructor cannot be zero",
        ));
    }

    let args_bytes: &[u8] = frame.required_field(3)?;
    let arguments: Vec<PatternArgument> =
        decode_canonical_list(args_bytes, MAX_ABI_TYPE_PARAMS, |b: &[u8]| {
            decode_pattern_argument(b, depth, node_count, root_chain)
        })?;

    Ok(TypePattern {
        origin,
        constructor,
        arguments,
    })
}

fn decode_object_parameter(
    bytes: &[u8],
    root_chain: &ChainId,
    node_count: &mut usize,
) -> Result<ObjectParameter, PublicAbiError> {
    if bytes.len() > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit(
            "object parameter byte limit exceeded",
        ));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_OBJECT_PARAM)?;
    frame.require_version(FRAME_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;

    let mode_u16: u16 = frame.required_u16(1)?;
    let mode: ObjectMode = ObjectMode::from_tag(mode_u16)?;
    let schema: u32 = frame.required_u32(2)?;
    if schema == 0 {
        return Err(PublicAbiError::Invalid(
            "object parameter schema cannot be zero",
        ));
    }

    let pattern_bytes: &[u8] = frame.required_field(3)?;
    let ty: TypePattern = decode_type_pattern_inner(pattern_bytes, 1, node_count, root_chain)?;

    Ok(ObjectParameter { mode, schema, ty })
}

fn decode_object_result_declaration(
    bytes: &[u8],
    root_chain: &ChainId,
    node_count: &mut usize,
) -> Result<ObjectResultDeclaration, PublicAbiError> {
    if bytes.len() > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit("object result byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_OBJECT_RESULT)?;
    frame.require_version(FRAME_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;

    let mode_u16: u16 = frame.required_u16(1)?;
    let mode: ObjectMode = ObjectMode::from_tag(mode_u16)?;
    let schema: u32 = frame.required_u32(2)?;
    if schema == 0 {
        return Err(PublicAbiError::Invalid(
            "object result schema cannot be zero",
        ));
    }

    let pattern_bytes: &[u8] = frame.required_field(3)?;
    let ty: TypePattern = decode_type_pattern_inner(pattern_bytes, 1, node_count, root_chain)?;

    let optional: bool = match frame.required_u16(4)? {
        0 => false,
        1 => true,
        _ => return Err(PublicAbiError::Invalid("object result optional flag")),
    };

    Ok(ObjectResultDeclaration {
        mode,
        schema,
        ty,
        optional,
    })
}

/// Decodes one entrypoint's ordered, bounded typed object result list.
pub(crate) fn decode_object_result_list(
    bytes: &[u8],
    root_chain: &ChainId,
    node_count: &mut usize,
) -> Result<Vec<ObjectResultDeclaration>, PublicAbiError> {
    decode_canonical_list(bytes, MAX_ABI_OBJECT_RESULTS, |b: &[u8]| {
        decode_object_result_declaration(b, root_chain, node_count)
    })
}

/// Validates result-slot count, schema, and pattern shape against one
/// entrypoint's own type-parameter scope. Does not resolve constructors
/// against a dependency closure; see `execution::publication::interface`
/// for the cross-package resolution step mirrored from input parameters.
///
/// `node_count` must be threaded by the caller across every entrypoint's
/// result list within the same [`ExecutableAbi`](crate::executable_abi::ExecutableAbi),
/// exactly like [`decode_object_result_list`] accumulates it across the
/// decoded wrapper: a per-entrypoint-only counter here would let a value
/// pass validation (and therefore encode) while its wire bytes still fail
/// [`MAX_ABI_TYPE_NODES`] on decode.
pub(crate) fn validate_object_result_shape(
    results: &[ObjectResultDeclaration],
    root_chain: &ChainId,
    type_param_count: usize,
    node_count: &mut usize,
) -> Result<(), PublicAbiError> {
    if results.len() > MAX_ABI_OBJECT_RESULTS {
        return Err(PublicAbiError::Limit("object result count exceeds limit"));
    }
    for result in results {
        if result.schema == 0 {
            return Err(PublicAbiError::Invalid(
                "object result schema cannot be zero",
            ));
        }
        validate_pattern_shape(&result.ty, root_chain, type_param_count, 1, node_count)?;
    }
    Ok(())
}

fn decode_entrypoint_declaration(
    bytes: &[u8],
    root_chain: &ChainId,
    node_count: &mut usize,
) -> Result<EntrypointDeclaration, PublicAbiError> {
    if bytes.len() > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit("entrypoint byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_ENTRYPOINT)?;
    frame.require_version(FRAME_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;

    let name_str: &str = frame.required_str(1)?;
    if name_str.is_empty() || name_str == "memory" {
        return Err(PublicAbiError::Invalid("empty or reserved entrypoint name"));
    }
    if name_str.len() > MAX_ENTRYPOINT_NAME_BYTES {
        return Err(PublicAbiError::Limit(
            "entrypoint name exceeds maximum length",
        ));
    }
    let name: String = name_str.to_string();

    let typeparams_bytes: &[u8] = frame.required_field(2)?;
    let type_parameters: Vec<ArgumentKind> =
        decode_canonical_list(typeparams_bytes, MAX_ABI_TYPE_PARAMS, decode_argument_kind)?;

    let objects_bytes: &[u8] = frame.required_field(3)?;
    let objects: Vec<ObjectParameter> =
        decode_canonical_list(objects_bytes, MAX_ABI_OBJECT_PARAMS, |b: &[u8]| {
            decode_object_parameter(b, root_chain, node_count)
        })?;

    Ok(EntrypointDeclaration {
        name,
        type_parameters,
        objects,
    })
}

/// Decodes and validates a package ABI declaration from canonical wire bytes.
///
/// Enforces resource limits and canonical encoding structure before allocations,
/// and validates overall ABI shape before returning.
pub fn decode_package_abi(bytes: &[u8]) -> Result<PackageAbi, PublicAbiError> {
    let byte_len: usize = bytes.len();
    if byte_len > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit("public abi byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_PACKAGE_ABI)?;
    frame.require_version(FRAME_VERSION)?;
    frame.require_only_fields(&[1, 2, 3])?;

    let origin_bytes: &[u8] = frame.required_field(1)?;
    if origin_bytes.len() > MAX_PUBLIC_ABI_BYTES {
        return Err(PublicAbiError::Limit("origin byte limit exceeded"));
    }
    let origin: PackageOrigin = decode_package_origin(origin_bytes)?;

    let ctor_bytes: &[u8] = frame.required_field(2)?;
    let constructors: Vec<ConstructorDeclaration> = decode_canonical_list(
        ctor_bytes,
        MAX_ABI_CONSTRUCTORS,
        decode_constructor_declaration,
    )?;

    let ep_bytes: &[u8] = frame.required_field(3)?;
    let mut node_count: usize = 0;
    let entrypoints: Vec<EntrypointDeclaration> =
        decode_canonical_list(ep_bytes, MAX_ABI_ENTRYPOINTS, |b: &[u8]| {
            decode_entrypoint_declaration(b, origin.chain_id(), &mut node_count)
        })?;

    let abi: PackageAbi = PackageAbi {
        origin,
        constructors,
        entrypoints,
    };
    validate_package_abi_shape(&abi)?;
    Ok(abi)
}
