#![forbid(unsafe_code)]

//! Validation of object input bodies against exact signed constructor layouts.
//!
//! # Explicit Non-Claims
//!
//! - **NO executable capability or host rights:** Validating object input bodies grants NO
//!   execution capability, VM privileges, host rights, or transaction admission.
//! - **NO owner validation:** Object owners (address, shared, immutable, system) are NOT
//!   validated or checked by this module.
//! - **NO object digest verification:** Neither [`objects::ObjectRef::digest`] nor stored object data
//!   digests are authenticated or rehashed here.
//! - **NO body semantic invariants:** This module checks canonical layout shape and bounded wire
//!   decoding only; it asserts NO domain-specific invariants, business logic, or application semantics.
//! - **NO transaction signature or state freshness:** This module asserts NO transaction
//!   authenticity, replay protection, nonce validity, state freshness, or publication authority.
//! - **NO substitute for admission:** Neither manifest nor loaded state is authenticated by
//!   this helper. Arbitrary owner modifications may still match; this module cannot substitute
//!   for transaction, storage, or owner admission.
//! - **No legacy ABI or AssetId special cases:** Nominal types and constructors follow strict
//!   DR-0113 / DR-0118 rules without special privileges.

use std::error::Error;
use std::fmt;

use abi::AccessManifest;
use abi::call_values::{MAX_VALUE_BYTES, ValueError, ValueLayout, decode_call_value};
use abi::public_abi::MAX_ABI_OBJECT_PARAMS;
use hashing::HashSuiteResolver;
use protocol_types::Epoch;

use super::binding::{BindingError, BoundObjectSignature, match_object_input_metadata};

/// Checks a concrete nominal constructor and its exact signed body layout.
/// This is representation validation, not permission to create or mutate the type.
pub fn validate_nominal_body(
    interface: &super::VerifiedPublicationInterface,
    ty: &abi::package_types::ScopedTypeTag,
    schema: u32,
    bytes: &[u8],
) -> Result<(), BodyError> {
    super::binding::validate_supplied_nominal_tag(ty, interface)?;
    let constructor = interface
        .defining_abi(ty.origin())
        .and_then(|abi| {
            abi.constructors
                .iter()
                .find(|constructor| constructor.local_id == ty.constructor())
        })
        .ok_or(BindingError::UnknownConstructor)?;
    if constructor.schema != schema {
        return Err(BindingError::SchemaMismatch.into());
    }
    let layout: &ValueLayout = interface
        .body_layout(ty.origin(), ty.constructor())
        .ok_or(BindingError::UnknownConstructor)?;
    let _value = decode_call_value(layout, bytes)?;
    Ok(())
}
use crate::ResolvedObject;

/// Maximum aggregate byte size of resolved object input bodies (256 KiB).
pub const MAX_BOUND_BODY_BYTES: usize = 256 * 1024;

/// Errors occurring during object input body layout resolution, resource limiting, or decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodyError {
    /// Object metadata matching failure.
    Binding(BindingError),
    /// Body value decoding failure.
    Value(ValueError),
    /// Declared constructor body layout was not found in publication interface.
    MissingLayout,
    /// Aggregate or per-object resource limit exceeded.
    Limit,
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binding(err) => write!(f, "binding error: {err}"),
            Self::Value(err) => write!(f, "value error: {err}"),
            Self::MissingLayout => write!(f, "missing constructor body layout"),
            Self::Limit => write!(f, "body limit exceeded"),
        }
    }
}

impl Error for BodyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Binding(err) => Some(err),
            Self::Value(err) => Some(err),
            Self::MissingLayout | Self::Limit => None,
        }
    }
}

impl From<BindingError> for BodyError {
    fn from(err: BindingError) -> Self {
        Self::Binding(err)
    }
}

impl From<ValueError> for BodyError {
    fn from(err: ValueError) -> Self {
        Self::Value(err)
    }
}

/// Validates that resolved object input bodies conform to their declared constructor layouts.
///
/// # Explicit Non-Claims
///
/// This function verifies canonical layout representation conformance only. It deliberately
/// performs NO [`objects::ObjectRef::digest`] verification, data hashing, owner validation,
/// or application semantic invariant checking. It returns `Ok(())` only and grants NO executable
/// witness, storage authority, or host capability.
pub fn validate_object_input_bodies(
    signature: &BoundObjectSignature<'_>,
    resolver: &HashSuiteResolver,
    epoch: Epoch,
    manifest: &AccessManifest,
    inputs: &[ResolvedObject],
) -> Result<(), BodyError> {
    if signature.objects().len() > MAX_ABI_OBJECT_PARAMS || inputs.len() > MAX_ABI_OBJECT_PARAMS {
        return Err(BodyError::Limit);
    }

    let mut total_body_bytes: usize = 0;
    for input in inputs {
        let len: usize = input.object.data.len();
        if len > MAX_VALUE_BYTES {
            return Err(BodyError::Limit);
        }
        total_body_bytes = total_body_bytes.checked_add(len).ok_or(BodyError::Limit)?;
        if total_body_bytes > MAX_BOUND_BODY_BYTES {
            return Err(BodyError::Limit);
        }
    }

    match_object_input_metadata(signature, resolver, epoch, manifest, inputs)?;

    for (param, input) in signature.objects().iter().zip(inputs) {
        let layout: &ValueLayout = signature
            .interface()
            .body_layout(param.ty().origin(), param.ty().constructor())
            .ok_or(BodyError::MissingLayout)?;
        decode_call_value(layout, &input.object.data)?;
    }

    Ok(())
}
