#![forbid(unsafe_code)]

//! Canonical bounded value layouts, argument values, and CallAbi envelopes.
//!
//! # Explicit Non-Claims
//!
//! - This module provides structural declaration and value framing data only.
//! - It asserts NO ownership, admission, storage, or runtime business semantics.
//! - It performs NO execution, host rights, or cryptographic authority verification.
//! - Call verification and execution binding are deferred to higher protocol layers.

use crate::public_abi::{self, PackageAbi, PublicAbiError};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame,
};
use core::fmt;
use std::error::Error;

/// Maximum encoded byte size for a canonical value, layout, or CallAbi frame (64 KiB).
pub const MAX_VALUE_BYTES: usize = 65536;

/// Maximum value layout nesting depth (root layout is at depth 1).
pub const MAX_LAYOUT_DEPTH: usize = 8;

/// Maximum total layout nodes across a layout or all layouts in a CallAbi envelope.
pub const MAX_LAYOUT_NODES: usize = 256;

/// Maximum total call value nodes across a value tree.
pub const MAX_VALUE_NODES: usize = 1024;

/// Maximum number of fields in a tuple layout or tuple value.
pub const MAX_TUPLE_FIELDS: usize = 32;

/// Maximum number of items in a list layout or list value.
pub const MAX_LIST_ITEMS: usize = 256;

/// Maximum number of argument layouts in a CallAbi envelope (matches MAX_ABI_ENTRYPOINTS).
pub const MAX_CALL_ABI_ARGUMENTS: usize = public_abi::MAX_ABI_ENTRYPOINTS;

const FRAME_TYPE_VALUE_LAYOUT: u16 = 0x5401;
const FRAME_TYPE_LAYOUT_LIST: u16 = 0x5402;
const FRAME_TYPE_CALL_VALUE: u16 = 0x5403;
const FRAME_TYPE_VALUE_LIST: u16 = 0x5404;
const FRAME_TYPE_CALL_ABI: u16 = 0x5405;

const FRAME_VERSION: u16 = 1;

const LAYOUT_KIND_BOOL: u16 = 1;
const LAYOUT_KIND_U64: u16 = 2;
const LAYOUT_KIND_U128: u16 = 3;
const LAYOUT_KIND_BYTES: u16 = 4;
const LAYOUT_KIND_UTF8: u16 = 5;
const LAYOUT_KIND_TUPLE: u16 = 6;
const LAYOUT_KIND_LIST: u16 = 7;

/// Specification of a canonical bounded value shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueLayout {
    /// Boolean value (wire u16: 0 or 1).
    Bool,
    /// Unsigned 64-bit integer (fixed-width little-endian).
    U64,
    /// Unsigned 128-bit integer (16 bytes little-endian).
    U128,
    /// Raw byte sequence with explicit bounds (min_len <= max_len <= 65536).
    Bytes {
        /// Minimum byte length.
        min_len: u32,
        /// Maximum byte length.
        max_len: u32,
    },
    /// UTF-8 string with bounded byte length (max_bytes <= 65536).
    Utf8 {
        /// Maximum UTF-8 byte length.
        max_bytes: u32,
    },
    /// Ordered heterogeneous tuple (0..=32 fields).
    Tuple(Vec<ValueLayout>),
    /// Bounded homogeneous list (0..=256 items).
    List {
        /// Element layout.
        element: Box<ValueLayout>,
        /// Maximum number of items.
        max_len: u16,
    },
}

/// A canonical bounded argument value matching a [`ValueLayout`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallValue {
    /// Boolean value.
    Bool(bool),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Unsigned 128-bit integer.
    U128(u128),
    /// Raw byte buffer.
    Bytes(Vec<u8>),
    /// Validated UTF-8 string.
    Utf8(String),
    /// Ordered tuple of values.
    Tuple(Vec<CallValue>),
    /// Homogeneous list of values.
    List(Vec<CallValue>),
}

/// Canonical envelope binding public package ABI objects to argument value layouts.
///
/// Binds exactly one root layout per declared entrypoint in matching positional order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallAbi {
    /// Public package-scoped object-signature ABI.
    pub objects: PackageAbi,
    /// Positional root argument value layout for each entrypoint.
    pub arguments: Vec<ValueLayout>,
}

/// Errors occurring during value layout, call value, or CallAbi encoding, decoding, or validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueError {
    /// Canonical frame encoding failure.
    Encoding(CanonicalEncodingError),
    /// Canonical frame decoding failure.
    Decoding(CanonicalDecodingError),
    /// Underlying public ABI error.
    Abi(PublicAbiError),
    /// Invalid shape or invariant violation.
    Invalid(&'static str),
    /// Resource limit exceeded.
    Limit(&'static str),
    /// Type mismatch between layout and value.
    TypeMismatch,
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(e) => write!(f, "canonical encoding error: {e}"),
            Self::Decoding(e) => write!(f, "canonical decoding error: {e}"),
            Self::Abi(e) => write!(f, "public abi error: {e}"),
            Self::Invalid(msg) => write!(f, "invalid call value: {msg}"),
            Self::Limit(msg) => write!(f, "call value limit exceeded: {msg}"),
            Self::TypeMismatch => f.write_str("type mismatch between layout and call value"),
        }
    }
}

impl Error for ValueError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Encoding(e) => Some(e),
            Self::Decoding(e) => Some(e),
            Self::Abi(e) => Some(e),
            Self::Invalid(_) | Self::Limit(_) | Self::TypeMismatch => None,
        }
    }
}

impl From<CanonicalEncodingError> for ValueError {
    fn from(err: CanonicalEncodingError) -> Self {
        Self::Encoding(err)
    }
}

impl From<CanonicalDecodingError> for ValueError {
    fn from(err: CanonicalDecodingError) -> Self {
        Self::Decoding(err)
    }
}

impl From<PublicAbiError> for ValueError {
    fn from(err: PublicAbiError) -> Self {
        Self::Abi(err)
    }
}

fn list_field_id(index: usize) -> Result<u16, ValueError> {
    let offset: usize = index
        .checked_add(2)
        .ok_or(ValueError::Limit("list field index overflow"))?;
    u16::try_from(offset).map_err(|_| ValueError::Limit("list field id exceeds u16::MAX"))
}

fn make_list_field_ids(count: usize) -> Result<Vec<u16>, ValueError> {
    let capacity: usize = count
        .checked_add(1)
        .ok_or(ValueError::Limit("list count overflow"))?;
    let mut fields: Vec<u16> = Vec::with_capacity(capacity);
    fields.push(1);
    for idx in 0..count {
        fields.push(list_field_id(idx)?);
    }
    Ok(fields)
}

fn count_layout_node(node_count: &mut usize) -> Result<(), ValueError> {
    *node_count = node_count
        .checked_add(1)
        .ok_or(ValueError::Limit("layout node budget exceeded"))?;
    if *node_count > MAX_LAYOUT_NODES {
        return Err(ValueError::Limit("layout node budget exceeded"));
    }
    Ok(())
}

fn next_layout_depth(depth: usize) -> Result<usize, ValueError> {
    let next: usize = depth
        .checked_add(1)
        .ok_or(ValueError::Limit("layout depth overflow"))?;
    Ok(next)
}

fn count_value_node(node_count: &mut usize) -> Result<(), ValueError> {
    *node_count = node_count
        .checked_add(1)
        .ok_or(ValueError::Limit("value node budget exceeded"))?;
    if *node_count > MAX_VALUE_NODES {
        return Err(ValueError::Limit("value node budget exceeded"));
    }
    Ok(())
}

fn next_value_depth(depth: usize) -> Result<usize, ValueError> {
    let next: usize = depth
        .checked_add(1)
        .ok_or(ValueError::Limit("value depth overflow"))?;
    Ok(next)
}

/// Validates structural shape and resource limits of a [`ValueLayout`].
pub fn validate_value_layout(layout: &ValueLayout) -> Result<(), ValueError> {
    let mut node_count: usize = 0;
    validate_value_layout_inner(layout, 1, &mut node_count)
}

fn validate_value_layout_inner(
    layout: &ValueLayout,
    depth: usize,
    node_count: &mut usize,
) -> Result<(), ValueError> {
    count_layout_node(node_count)?;
    if depth > MAX_LAYOUT_DEPTH {
        return Err(ValueError::Limit("layout depth exceeded"));
    }
    match layout {
        ValueLayout::Bool | ValueLayout::U64 | ValueLayout::U128 => Ok(()),
        ValueLayout::Bytes { min_len, max_len } => {
            if *min_len > *max_len {
                return Err(ValueError::Invalid("bytes min_len exceeds max_len"));
            }
            if (*max_len as usize) > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("bytes max_len exceeds maximum bytes"));
            }
            Ok(())
        }
        ValueLayout::Utf8 { max_bytes } => {
            if (*max_bytes as usize) > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("utf8 max_bytes exceeds maximum bytes"));
            }
            Ok(())
        }
        ValueLayout::Tuple(fields) => {
            if fields.len() > MAX_TUPLE_FIELDS {
                return Err(ValueError::Limit("tuple field count exceeds maximum limit"));
            }
            let next: usize = next_layout_depth(depth)?;
            for field in fields {
                validate_value_layout_inner(field, next, node_count)?;
            }
            Ok(())
        }
        ValueLayout::List { element, max_len } => {
            if (*max_len as usize) > MAX_LIST_ITEMS {
                return Err(ValueError::Limit("list max_len exceeds maximum limit"));
            }
            let next: usize = next_layout_depth(depth)?;
            validate_value_layout_inner(element.as_ref(), next, node_count)
        }
    }
}

fn encode_canonical_layout_list(
    layouts: &[ValueLayout],
    max_items: usize,
    depth: usize,
    node_count: &mut usize,
) -> Result<Vec<u8>, ValueError> {
    let count: usize = layouts.len();
    if count > max_items {
        return Err(ValueError::Limit("layout list count exceeds limit"));
    }
    let count_u16: u16 = u16::try_from(count)
        .map_err(|_| ValueError::Limit("layout list count exceeds u16::MAX"))?;

    let mut encoded_items: Vec<Vec<u8>> = Vec::with_capacity(count);
    for layout in layouts {
        encoded_items.push(encode_value_layout_inner(layout, depth, node_count)?);
    }

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_LAYOUT_LIST, FRAME_VERSION);
    s.field_u16(1, count_u16)?;
    for (idx, item_bytes) in encoded_items.iter().enumerate() {
        let field_id: u16 = list_field_id(idx)?;
        s.field_bytes(field_id, item_bytes.as_slice())?;
    }
    let bytes: Vec<u8> = s.finish()?;
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit(
            "encoded layout list exceeds maximum bytes",
        ));
    }
    Ok(bytes)
}

fn decode_canonical_layout_list(
    bytes: &[u8],
    max_items: usize,
    depth: usize,
    node_count: &mut usize,
) -> Result<Vec<ValueLayout>, ValueError> {
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit("layout list byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_LAYOUT_LIST)?;
    frame.require_version(FRAME_VERSION)?;

    let count_u16: u16 = frame.required_u16(1)?;
    let count: usize = count_u16 as usize;
    if count > max_items {
        return Err(ValueError::Limit("layout list count limit exceeded"));
    }
    let expected_fields: Vec<u16> = make_list_field_ids(count)?;
    frame.require_only_fields(&expected_fields)?;

    let mut layouts: Vec<ValueLayout> = Vec::with_capacity(count);
    for idx in 0..count {
        let field_id: u16 = list_field_id(idx)?;
        let item_bytes: &[u8] = frame.required_field(field_id)?;
        if item_bytes.len() > MAX_VALUE_BYTES {
            return Err(ValueError::Limit("layout item byte limit exceeded"));
        }
        layouts.push(decode_value_layout_inner(item_bytes, depth, node_count)?);
    }
    Ok(layouts)
}

fn encode_value_layout_inner(
    layout: &ValueLayout,
    depth: usize,
    node_count: &mut usize,
) -> Result<Vec<u8>, ValueError> {
    count_layout_node(node_count)?;
    if depth > MAX_LAYOUT_DEPTH {
        return Err(ValueError::Limit("layout depth exceeded"));
    }

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_VALUE_LAYOUT, FRAME_VERSION);
    match layout {
        ValueLayout::Bool => {
            s.field_u16(1, LAYOUT_KIND_BOOL)?;
        }
        ValueLayout::U64 => {
            s.field_u16(1, LAYOUT_KIND_U64)?;
        }
        ValueLayout::U128 => {
            s.field_u16(1, LAYOUT_KIND_U128)?;
        }
        ValueLayout::Bytes { min_len, max_len } => {
            if *min_len > *max_len {
                return Err(ValueError::Invalid("bytes min_len exceeds max_len"));
            }
            if (*max_len as usize) > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("bytes max_len exceeds maximum bytes"));
            }
            s.field_u16(1, LAYOUT_KIND_BYTES)?;
            s.field_u32(2, *min_len)?;
            s.field_u32(3, *max_len)?;
        }
        ValueLayout::Utf8 { max_bytes } => {
            if (*max_bytes as usize) > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("utf8 max_bytes exceeds maximum bytes"));
            }
            s.field_u16(1, LAYOUT_KIND_UTF8)?;
            s.field_u32(2, *max_bytes)?;
        }
        ValueLayout::Tuple(fields) => {
            if fields.len() > MAX_TUPLE_FIELDS {
                return Err(ValueError::Limit("tuple field count exceeds maximum limit"));
            }
            let next: usize = next_layout_depth(depth)?;
            let list_bytes: Vec<u8> =
                encode_canonical_layout_list(fields, MAX_TUPLE_FIELDS, next, node_count)?;
            s.field_u16(1, LAYOUT_KIND_TUPLE)?;
            s.field_bytes(2, list_bytes)?;
        }
        ValueLayout::List { element, max_len } => {
            if (*max_len as usize) > MAX_LIST_ITEMS {
                return Err(ValueError::Limit("list max_len exceeds maximum limit"));
            }
            let next: usize = next_layout_depth(depth)?;
            let elem_bytes: Vec<u8> =
                encode_value_layout_inner(element.as_ref(), next, node_count)?;
            s.field_u16(1, LAYOUT_KIND_LIST)?;
            s.field_u16(2, *max_len)?;
            s.field_bytes(3, elem_bytes)?;
        }
    }
    let bytes: Vec<u8> = s.finish()?;
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit(
            "encoded layout frame exceeds maximum bytes",
        ));
    }
    Ok(bytes)
}

fn decode_value_layout_inner(
    bytes: &[u8],
    depth: usize,
    node_count: &mut usize,
) -> Result<ValueLayout, ValueError> {
    count_layout_node(node_count)?;
    if depth > MAX_LAYOUT_DEPTH {
        return Err(ValueError::Limit("layout depth exceeded"));
    }
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit("value layout byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_VALUE_LAYOUT)?;
    frame.require_version(FRAME_VERSION)?;

    let kind: u16 = frame.required_u16(1)?;
    match kind {
        LAYOUT_KIND_BOOL => {
            frame.require_only_fields(&[1])?;
            Ok(ValueLayout::Bool)
        }
        LAYOUT_KIND_U64 => {
            frame.require_only_fields(&[1])?;
            Ok(ValueLayout::U64)
        }
        LAYOUT_KIND_U128 => {
            frame.require_only_fields(&[1])?;
            Ok(ValueLayout::U128)
        }
        LAYOUT_KIND_BYTES => {
            frame.require_only_fields(&[1, 2, 3])?;
            let min_len: u32 = frame.required_u32(2)?;
            let max_len: u32 = frame.required_u32(3)?;
            if min_len > max_len {
                return Err(ValueError::Invalid("bytes min_len exceeds max_len"));
            }
            if (max_len as usize) > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("bytes max_len exceeds maximum bytes"));
            }
            Ok(ValueLayout::Bytes { min_len, max_len })
        }
        LAYOUT_KIND_UTF8 => {
            frame.require_only_fields(&[1, 2])?;
            let max_bytes: u32 = frame.required_u32(2)?;
            if (max_bytes as usize) > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("utf8 max_bytes exceeds maximum bytes"));
            }
            Ok(ValueLayout::Utf8 { max_bytes })
        }
        LAYOUT_KIND_TUPLE => {
            frame.require_only_fields(&[1, 2])?;
            let list_bytes: &[u8] = frame.required_field(2)?;
            let next: usize = next_layout_depth(depth)?;
            let fields: Vec<ValueLayout> =
                decode_canonical_layout_list(list_bytes, MAX_TUPLE_FIELDS, next, node_count)?;
            Ok(ValueLayout::Tuple(fields))
        }
        LAYOUT_KIND_LIST => {
            frame.require_only_fields(&[1, 2, 3])?;
            let max_len: u16 = frame.required_u16(2)?;
            if (max_len as usize) > MAX_LIST_ITEMS {
                return Err(ValueError::Limit("list max_len exceeds maximum limit"));
            }
            let elem_bytes: &[u8] = frame.required_field(3)?;
            let next: usize = next_layout_depth(depth)?;
            let element: ValueLayout = decode_value_layout_inner(elem_bytes, next, node_count)?;
            Ok(ValueLayout::List {
                element: Box::new(element),
                max_len,
            })
        }
        _ => Err(ValueError::Invalid("unknown value layout kind tag")),
    }
}

/// Canonically encodes a [`ValueLayout`] after validating its structure.
pub fn encode_value_layout(layout: &ValueLayout) -> Result<Vec<u8>, ValueError> {
    validate_value_layout(layout)?;
    let mut node_count: usize = 0;
    let bytes: Vec<u8> = encode_value_layout_inner(layout, 1, &mut node_count)?;
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit("encoded layout exceeds maximum bytes"));
    }
    Ok(bytes)
}

/// Decodes and validates a [`ValueLayout`] from canonical wire bytes.
pub fn decode_value_layout(bytes: &[u8]) -> Result<ValueLayout, ValueError> {
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit("layout bytes exceed maximum limit"));
    }
    let mut node_count: usize = 0;
    let layout: ValueLayout = decode_value_layout_inner(bytes, 1, &mut node_count)?;
    validate_value_layout(&layout)?;
    Ok(layout)
}

fn validate_call_value(layout: &ValueLayout, value: &CallValue) -> Result<(), ValueError> {
    let mut node_count: usize = 0;
    let mut leaf_bytes: usize = 0;
    validate_call_value_inner(layout, value, 1, &mut node_count, &mut leaf_bytes)
}

fn validate_call_value_inner(
    layout: &ValueLayout,
    value: &CallValue,
    depth: usize,
    node_count: &mut usize,
    leaf_bytes: &mut usize,
) -> Result<(), ValueError> {
    count_value_node(node_count)?;
    if depth > MAX_LAYOUT_DEPTH {
        return Err(ValueError::Limit("value depth exceeded"));
    }
    match (layout, value) {
        (ValueLayout::Bool, CallValue::Bool(_)) => Ok(()),
        (ValueLayout::U64, CallValue::U64(_)) => Ok(()),
        (ValueLayout::U128, CallValue::U128(_)) => Ok(()),
        (ValueLayout::Bytes { min_len, max_len }, CallValue::Bytes(b)) => {
            let len: usize = b.len();
            if len < (*min_len as usize) {
                return Err(ValueError::Invalid("bytes length below declared min_len"));
            }
            if len > (*max_len as usize) {
                return Err(ValueError::Limit("bytes length exceeds declared max_len"));
            }
            *leaf_bytes = leaf_bytes
                .checked_add(len)
                .ok_or(ValueError::Limit("leaf data byte budget exceeded"))?;
            if *leaf_bytes > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("leaf data byte budget exceeded"));
            }
            Ok(())
        }
        (ValueLayout::Utf8 { max_bytes }, CallValue::Utf8(s)) => {
            let len: usize = s.len();
            if len > (*max_bytes as usize) {
                return Err(ValueError::Limit(
                    "utf8 byte length exceeds declared max_bytes",
                ));
            }
            *leaf_bytes = leaf_bytes
                .checked_add(len)
                .ok_or(ValueError::Limit("leaf data byte budget exceeded"))?;
            if *leaf_bytes > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("leaf data byte budget exceeded"));
            }
            Ok(())
        }
        (ValueLayout::Tuple(field_layouts), CallValue::Tuple(field_values)) => {
            if field_values.len() != field_layouts.len() {
                return Err(ValueError::Invalid(
                    "tuple value count does not match layout",
                ));
            }
            if field_values.len() > MAX_TUPLE_FIELDS {
                return Err(ValueError::Limit("tuple field count exceeds maximum limit"));
            }
            let next: usize = next_value_depth(depth)?;
            for (field_layout, field_val) in field_layouts.iter().zip(field_values.iter()) {
                validate_call_value_inner(field_layout, field_val, next, node_count, leaf_bytes)?;
            }
            Ok(())
        }
        (ValueLayout::List { element, max_len }, CallValue::List(items)) => {
            if items.len() > (*max_len as usize) {
                return Err(ValueError::Limit(
                    "list value count exceeds declared max_len",
                ));
            }
            if items.len() > MAX_LIST_ITEMS {
                return Err(ValueError::Limit("list item count exceeds maximum limit"));
            }
            let next: usize = next_value_depth(depth)?;
            for item in items {
                validate_call_value_inner(element.as_ref(), item, next, node_count, leaf_bytes)?;
            }
            Ok(())
        }
        _ => Err(ValueError::TypeMismatch),
    }
}

fn encode_canonical_value_list(items: &[Vec<u8>], max_items: usize) -> Result<Vec<u8>, ValueError> {
    let count: usize = items.len();
    if count > max_items {
        return Err(ValueError::Limit("value list count exceeds limit"));
    }
    let count_u16: u16 =
        u16::try_from(count).map_err(|_| ValueError::Limit("value list count exceeds u16::MAX"))?;

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_VALUE_LIST, FRAME_VERSION);
    s.field_u16(1, count_u16)?;
    for (idx, item_bytes) in items.iter().enumerate() {
        let field_id: u16 = list_field_id(idx)?;
        s.field_bytes(field_id, item_bytes.as_slice())?;
    }
    let bytes: Vec<u8> = s.finish()?;
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit(
            "encoded value list exceeds maximum bytes",
        ));
    }
    Ok(bytes)
}

fn encode_call_value_inner(
    layout: &ValueLayout,
    value: &CallValue,
    depth: usize,
) -> Result<Vec<u8>, ValueError> {
    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_CALL_VALUE, FRAME_VERSION);
    match (layout, value) {
        (ValueLayout::Bool, CallValue::Bool(b)) => {
            s.field_u16(1, LAYOUT_KIND_BOOL)?;
            s.field_u16(2, if *b { 1 } else { 0 })?;
        }
        (ValueLayout::U64, CallValue::U64(v)) => {
            s.field_u16(1, LAYOUT_KIND_U64)?;
            s.field_u64(2, *v)?;
        }
        (ValueLayout::U128, CallValue::U128(v)) => {
            s.field_u16(1, LAYOUT_KIND_U128)?;
            s.field_bytes(2, v.to_le_bytes().to_vec())?;
        }
        (ValueLayout::Bytes { .. }, CallValue::Bytes(b)) => {
            s.field_u16(1, LAYOUT_KIND_BYTES)?;
            s.field_bytes(2, b.as_slice())?;
        }
        (ValueLayout::Utf8 { .. }, CallValue::Utf8(st)) => {
            s.field_u16(1, LAYOUT_KIND_UTF8)?;
            s.field_str(2, st.as_str())?;
        }
        (ValueLayout::Tuple(field_layouts), CallValue::Tuple(field_values)) => {
            let next: usize = next_value_depth(depth)?;
            let mut encoded_items: Vec<Vec<u8>> = Vec::with_capacity(field_values.len());
            for (field_layout, field_val) in field_layouts.iter().zip(field_values.iter()) {
                encoded_items.push(encode_call_value_inner(field_layout, field_val, next)?);
            }
            let list_bytes: Vec<u8> =
                encode_canonical_value_list(&encoded_items, MAX_TUPLE_FIELDS)?;
            s.field_u16(1, LAYOUT_KIND_TUPLE)?;
            s.field_bytes(2, list_bytes)?;
        }
        (ValueLayout::List { element, .. }, CallValue::List(items)) => {
            let next: usize = next_value_depth(depth)?;
            let mut encoded_items: Vec<Vec<u8>> = Vec::with_capacity(items.len());
            for item in items {
                encoded_items.push(encode_call_value_inner(element.as_ref(), item, next)?);
            }
            let list_bytes: Vec<u8> = encode_canonical_value_list(&encoded_items, MAX_LIST_ITEMS)?;
            s.field_u16(1, LAYOUT_KIND_LIST)?;
            s.field_bytes(2, list_bytes)?;
        }
        _ => return Err(ValueError::TypeMismatch),
    }
    let bytes: Vec<u8> = s.finish()?;
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit(
            "encoded call value exceeds maximum bytes",
        ));
    }
    Ok(bytes)
}

/// Canonically encodes a [`CallValue`] according to its declared [`ValueLayout`].
pub fn encode_call_value(layout: &ValueLayout, value: &CallValue) -> Result<Vec<u8>, ValueError> {
    validate_value_layout(layout)?;
    validate_call_value(layout, value)?;
    let bytes: Vec<u8> = encode_call_value_inner(layout, value, 1)?;
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit(
            "encoded call value exceeds maximum bytes",
        ));
    }
    Ok(bytes)
}

fn decode_call_value_inner(
    layout: &ValueLayout,
    bytes: &[u8],
    depth: usize,
    node_count: &mut usize,
    leaf_bytes: &mut usize,
) -> Result<CallValue, ValueError> {
    count_value_node(node_count)?;
    if depth > MAX_LAYOUT_DEPTH {
        return Err(ValueError::Limit("value depth exceeded"));
    }
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit("call value bytes exceed maximum limit"));
    }

    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_CALL_VALUE)?;
    frame.require_version(FRAME_VERSION)?;
    frame.require_only_fields(&[1, 2])?;

    let kind: u16 = frame.required_u16(1)?;
    match (layout, kind) {
        (ValueLayout::Bool, LAYOUT_KIND_BOOL) => {
            let raw: u16 = frame.required_u16(2)?;
            if raw > 1 {
                return Err(ValueError::Invalid("bool value must be 0 or 1"));
            }
            Ok(CallValue::Bool(raw == 1))
        }
        (ValueLayout::U64, LAYOUT_KIND_U64) => {
            let val: u64 = frame.required_u64(2)?;
            Ok(CallValue::U64(val))
        }
        (ValueLayout::U128, LAYOUT_KIND_U128) => {
            let raw_bytes: &[u8] = frame.required_field(2)?;
            if raw_bytes.len() != 16 {
                return Err(ValueError::Invalid("u128 value must be 16 bytes"));
            }
            let array: [u8; 16] = raw_bytes
                .try_into()
                .map_err(|_| ValueError::Invalid("u128 conversion error"))?;
            Ok(CallValue::U128(u128::from_le_bytes(array)))
        }
        (ValueLayout::Bytes { min_len, max_len }, LAYOUT_KIND_BYTES) => {
            let raw_bytes: &[u8] = frame.required_field(2)?;
            let len: usize = raw_bytes.len();
            *leaf_bytes = leaf_bytes
                .checked_add(len)
                .ok_or(ValueError::Limit("leaf data byte budget exceeded"))?;
            if *leaf_bytes > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("leaf data byte budget exceeded"));
            }
            if len < (*min_len as usize) {
                return Err(ValueError::Invalid("bytes length below declared min_len"));
            }
            if len > (*max_len as usize) {
                return Err(ValueError::Limit("bytes length exceeds declared max_len"));
            }
            Ok(CallValue::Bytes(raw_bytes.to_vec()))
        }
        (ValueLayout::Utf8 { max_bytes }, LAYOUT_KIND_UTF8) => {
            let raw_bytes: &[u8] = frame.required_field(2)?;
            let len: usize = raw_bytes.len();
            *leaf_bytes = leaf_bytes
                .checked_add(len)
                .ok_or(ValueError::Limit("leaf data byte budget exceeded"))?;
            if *leaf_bytes > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("leaf data byte budget exceeded"));
            }
            if len > (*max_bytes as usize) {
                return Err(ValueError::Limit(
                    "utf8 byte length exceeds declared max_bytes",
                ));
            }
            let s_str: &str = std::str::from_utf8(raw_bytes)
                .map_err(|_| ValueError::Decoding(CanonicalDecodingError::InvalidUtf8(2)))?;
            Ok(CallValue::Utf8(s_str.to_string()))
        }
        (ValueLayout::Tuple(field_layouts), LAYOUT_KIND_TUPLE) => {
            let list_bytes: &[u8] = frame.required_field(2)?;
            if list_bytes.len() > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("tuple value list byte limit exceeded"));
            }
            let list_frame: CanonicalFrame<'_> = decode_canonical_frame(list_bytes)?;
            list_frame.require_type(FRAME_TYPE_VALUE_LIST)?;
            list_frame.require_version(FRAME_VERSION)?;

            let count_u16: u16 = list_frame.required_u16(1)?;
            let count: usize = count_u16 as usize;
            if count != field_layouts.len() {
                return Err(ValueError::Invalid(
                    "tuple value count does not match layout",
                ));
            }
            if count > MAX_TUPLE_FIELDS {
                return Err(ValueError::Limit("tuple field count exceeds maximum limit"));
            }
            let expected_fields: Vec<u16> = make_list_field_ids(count)?;
            list_frame.require_only_fields(&expected_fields)?;

            let next: usize = next_value_depth(depth)?;
            let mut values: Vec<CallValue> = Vec::with_capacity(count);
            for (idx, field_layout) in field_layouts.iter().enumerate() {
                let field_id: u16 = list_field_id(idx)?;
                let item_bytes: &[u8] = list_frame.required_field(field_id)?;
                if item_bytes.len() > MAX_VALUE_BYTES {
                    return Err(ValueError::Limit("tuple item byte limit exceeded"));
                }
                values.push(decode_call_value_inner(
                    field_layout,
                    item_bytes,
                    next,
                    node_count,
                    leaf_bytes,
                )?);
            }
            Ok(CallValue::Tuple(values))
        }
        (ValueLayout::List { element, max_len }, LAYOUT_KIND_LIST) => {
            let list_bytes: &[u8] = frame.required_field(2)?;
            if list_bytes.len() > MAX_VALUE_BYTES {
                return Err(ValueError::Limit("list value list byte limit exceeded"));
            }
            let list_frame: CanonicalFrame<'_> = decode_canonical_frame(list_bytes)?;
            list_frame.require_type(FRAME_TYPE_VALUE_LIST)?;
            list_frame.require_version(FRAME_VERSION)?;

            let count_u16: u16 = list_frame.required_u16(1)?;
            let count: usize = count_u16 as usize;
            if count > (*max_len as usize) {
                return Err(ValueError::Limit(
                    "list value count exceeds declared max_len",
                ));
            }
            if count > MAX_LIST_ITEMS {
                return Err(ValueError::Limit("list item count exceeds maximum limit"));
            }
            let expected_fields: Vec<u16> = make_list_field_ids(count)?;
            list_frame.require_only_fields(&expected_fields)?;

            let next: usize = next_value_depth(depth)?;
            let mut values: Vec<CallValue> = Vec::with_capacity(count);
            for idx in 0..count {
                let field_id: u16 = list_field_id(idx)?;
                let item_bytes: &[u8] = list_frame.required_field(field_id)?;
                if item_bytes.len() > MAX_VALUE_BYTES {
                    return Err(ValueError::Limit("list item byte limit exceeded"));
                }
                values.push(decode_call_value_inner(
                    element.as_ref(),
                    item_bytes,
                    next,
                    node_count,
                    leaf_bytes,
                )?);
            }
            Ok(CallValue::List(values))
        }
        (_, 1..=7) => Err(ValueError::TypeMismatch),
        _ => Err(ValueError::Invalid("unknown call value kind tag")),
    }
}

/// Decodes and validates a [`CallValue`] from canonical wire bytes against a [`ValueLayout`].
pub fn decode_call_value(layout: &ValueLayout, bytes: &[u8]) -> Result<CallValue, ValueError> {
    validate_value_layout(layout)?;
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit("call value bytes exceed maximum limit"));
    }
    let mut node_count: usize = 0;
    let mut leaf_bytes: usize = 0;
    decode_call_value_inner(layout, bytes, 1, &mut node_count, &mut leaf_bytes)
}

/// Canonically encodes a [`CallAbi`] envelope binding objects ABI to argument layouts.
pub fn encode_call_abi(abi: &CallAbi) -> Result<Vec<u8>, ValueError> {
    public_abi::validate_package_abi_shape(&abi.objects)?;

    let ep_count: usize = abi.objects.entrypoints.len();
    if abi.arguments.len() != ep_count {
        return Err(ValueError::Invalid(
            "call abi arguments count does not match entrypoints count",
        ));
    }
    if abi.arguments.len() > MAX_CALL_ABI_ARGUMENTS {
        return Err(ValueError::Limit("call abi arguments count exceeds limit"));
    }

    let mut total_layout_nodes: usize = 0;
    for layout in &abi.arguments {
        validate_value_layout_inner(layout, 1, &mut total_layout_nodes)?;
    }

    let encoded_objects: Vec<u8> = public_abi::encode_package_abi(&abi.objects)?;

    let mut node_count: usize = 0;
    let encoded_arguments: Vec<u8> =
        encode_canonical_layout_list(&abi.arguments, MAX_CALL_ABI_ARGUMENTS, 1, &mut node_count)?;

    let mut s: CanonicalStruct = CanonicalStruct::new(FRAME_TYPE_CALL_ABI, FRAME_VERSION);
    s.field_bytes(1, encoded_objects)?;
    s.field_bytes(2, encoded_arguments)?;
    let encoded: Vec<u8> = s.finish()?;

    if encoded.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit(
            "encoded call abi envelope exceeds maximum bytes",
        ));
    }
    Ok(encoded)
}

/// Decodes and validates a [`CallAbi`] envelope from canonical wire bytes.
pub fn decode_call_abi(bytes: &[u8]) -> Result<CallAbi, ValueError> {
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit("call abi byte limit exceeded"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(FRAME_TYPE_CALL_ABI)?;
    frame.require_version(FRAME_VERSION)?;
    frame.require_only_fields(&[1, 2])?;

    let objects_bytes: &[u8] = frame.required_field(1)?;
    if objects_bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit("package abi byte limit exceeded"));
    }
    let objects: PackageAbi = public_abi::decode_package_abi(objects_bytes)?;

    let args_bytes: &[u8] = frame.required_field(2)?;
    if args_bytes.len() > MAX_VALUE_BYTES {
        return Err(ValueError::Limit("arguments byte limit exceeded"));
    }

    let mut total_layout_nodes: usize = 0;
    let arguments: Vec<ValueLayout> = decode_canonical_layout_list(
        args_bytes,
        MAX_CALL_ABI_ARGUMENTS,
        1,
        &mut total_layout_nodes,
    )?;

    if arguments.len() != objects.entrypoints.len() {
        return Err(ValueError::Invalid(
            "call abi arguments count does not match entrypoints count",
        ));
    }

    Ok(CallAbi { objects, arguments })
}
