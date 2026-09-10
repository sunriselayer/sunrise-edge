//! Bounded, signed generic CALL INTENT frames.
//!
//! This module defines the wire format and authentication path for a
//! contract call intent: a request naming a code reference, an instance
//! target, an entrypoint, type arguments, an access manifest, and opaque
//! call arguments, signed by the sender.
//!
//! This profile intentionally carries no fee authorization. It cannot be
//! publicly admitted for execution or used to charge fees on its own. Any
//! future fee-bearing profile must be a distinct, explicitly signed frame
//! (for example a new frame type carrying a signed fee/gas-price field);
//! it must never be retrofitted onto this frame via unsigned fee inputs.
//!
//! This module does not establish instance creation or existence, does not
//! grant executable/owner/instance/publication/nonce authority, and is not
//! a storage or legacy module/`StandardAsset` policy consumer.

use std::collections::BTreeSet;
use std::fmt;

use crate::publication::{
    BindingError, BoundObjectSignature, PublicationContext, PublicationError,
    UnverifiedDependencyRef, VerifiedPublicationInterface, bind_object_signature,
    decode_dependency_ref, decode_publication_context, encode_dependency_ref,
    encode_publication_context, validate_call_arguments,
};
use abi::call_values::ValueError;
use abi::package_types::{
    PackageTypeError, ScopedTypeArg, decode_scoped_type_arguments, encode_scoped_type_arguments,
};
use abi::public_abi::ObjectMode;
use abi::{AbiError, AccessManifest, decode_access_manifest, encode_access_manifest};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
    decode_digest32, encode_digest32,
};
use crypto::{
    CryptoError, Ed25519OwnerAddressError, Ed25519OwnerAddressPolicy, Ed25519Verifier,
    SignatureDomain, SignatureMessageType, SignatureVerifier, frame_signature_message,
    validate_ed25519_owner_address,
};
use objects::AccessMode;
use protocol_types::{Digest32, SignatureSchemeId};

/// Maximum encoded size of a [`CallIntent`] frame, in bytes.
pub const MAX_CALL_INTENT_BYTES: usize = 128 * 1024;
/// Maximum size of the opaque call argument bytes, in bytes.
pub const MAX_CALL_ARGUMENT_BYTES: usize = 64 * 1024;

const MAX_SIGNED_CALL_INTENT_BYTES: usize = MAX_CALL_INTENT_BYTES + 128;
const MAX_INSTANCE_TARGET_BYTES: usize = 256;
const MAX_ENTRYPOINT_BYTES: usize = 64;
const MAX_ACCESS_ENTRIES: usize = 32;

const INSTANCE_TARGET_TYPE: u16 = 0x6401;
const INSTANCE_TARGET_VERSION: u16 = 1;
const CALL_INTENT_TYPE: u16 = 0x6402;
const CALL_INTENT_VERSION: u16 = 1;
const SIGNED_CALL_INTENT_TYPE: u16 = 0x6403;
const SIGNED_CALL_INTENT_VERSION: u16 = 1;

const INSTANCE_FIELD_CREATOR: u16 = 1;
const INSTANCE_FIELD_SEED: u16 = 2;
const INSTANCE_FIELD_REVISION: u16 = 3;
const INSTANCE_FIELD_DIGEST: u16 = 4;

const CALL_FIELD_CONTEXT: u16 = 1;
const CALL_FIELD_REQUEST_ID: u16 = 2;
const CALL_FIELD_SENDER: u16 = 3;
const CALL_FIELD_NONCE: u16 = 4;
const CALL_FIELD_CODE: u16 = 5;
const CALL_FIELD_INSTANCE: u16 = 6;
const CALL_FIELD_ENTRYPOINT: u16 = 7;
const CALL_FIELD_TYPE_ARGS: u16 = 8;
const CALL_FIELD_ACCESS: u16 = 9;
const CALL_FIELD_ARGUMENTS: u16 = 10;
const CALL_FIELD_GAS_LIMIT: u16 = 11;

const SIGNED_FIELD_INTENT: u16 = 1;
const SIGNED_FIELD_SIGNATURE: u16 = 2;

/// An unverified application instance target, distinct from code and objects.
///
/// Logical identity is the tuple (call context chain, creator, seed),
/// independent of code and digest algorithms. `revision` is the exact
/// instance authorization record revision being asserted, not an object
/// version. This type describes shape only: it does not establish that the
/// instance was ever created or currently exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceTarget {
    /// Claimed instance creator; bytes alone are not an authenticated identity.
    pub creator: [u8; 32],
    /// Creator-scoped instance creation seed; not a code or object identifier.
    pub seed: [u8; 32],
    /// Exact instance authorization revision, strictly positive.
    pub revision: u64,
    /// Exact instance record commitment; not evidence that the record exists.
    pub record_digest: Digest32,
}

/// A generic, unauthenticated call intent naming code, an instance target,
/// an entrypoint, type arguments, an access manifest, and opaque arguments.
///
/// This profile carries no fee authorization; see the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallIntent {
    /// Expected execution replay context, compared against trusted local input.
    pub context: PublicationContext,
    /// Exact replay identity covered by the signature.
    pub request_id: [u8; 32],
    /// Ed25519 public key; strict owning-key checks occur during authentication.
    pub sender: [u8; 32],
    /// Signed sender sequence; freshness is a separate durable check.
    pub nonce: u64,
    /// Exact code revision reference using the existing 0x6302 reference codec.
    pub code: UnverifiedDependencyRef,
    /// Independent instance target; requires durable authorization before use.
    pub instance: InstanceTarget,
    /// Exact exported entrypoint name; never resolved through a latest alias.
    pub entrypoint: String,
    /// Ordered concrete nominal/opaque arguments.
    pub type_arguments: Vec<ScopedTypeArg>,
    /// Signed access order, object references and Read/Write/Consume modes.
    pub access: AccessManifest,
    /// Bounded canonical value bytes, validated against the bound ABI later.
    pub arguments: Vec<u8>,
    /// Signed nonzero execution gas ceiling; not fee authorization.
    pub gas_limit: u64,
}

/// A [`CallIntent`] together with its Ed25519 signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCallIntent {
    /// Exact unverified intent.
    pub intent: CallIntent,
    /// Fixed Ed25519 signature over the CallContractIntent domain frame.
    pub signature: [u8; 64],
}

/// A [`SignedCallIntent`] whose context, sender key, and signature have
/// been strictly validated against an expected [`PublicationContext`].
///
/// This witness carries no ABI or I/O validation and grants no
/// executable/owner/instance/publication/nonce authority on its own.
#[derive(Debug)]
pub struct AuthenticatedCallIntent {
    signed: SignedCallIntent,
}

impl AuthenticatedCallIntent {
    /// Returns the immutable signature-authenticated intent, not execution rights.
    pub fn intent(&self) -> &CallIntent {
        &self.signed.intent
    }
}

/// Errors that can occur while encoding, decoding, authenticating, or
/// binding a call intent.
#[derive(Debug)]
pub enum CallError {
    Publication(PublicationError),
    Abi(AbiError),
    Package(PackageTypeError),
    Value(ValueError),
    Binding(BindingError),
    Encoding(CanonicalEncodingError),
    Decoding(CanonicalDecodingError),
    Crypto(CryptoError),
    Owner(Ed25519OwnerAddressError),
    Invalid(&'static str),
    Limit(&'static str),
    ContextMismatch,
    InvalidSignature,
    CodeMismatch,
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallError::Publication(err) => write!(f, "publication error: {err}"),
            CallError::Abi(err) => write!(f, "abi error: {err}"),
            CallError::Package(err) => write!(f, "package type error: {err}"),
            CallError::Value(err) => write!(f, "value error: {err}"),
            CallError::Binding(err) => write!(f, "binding error: {err}"),
            CallError::Encoding(err) => write!(f, "encoding error: {err}"),
            CallError::Decoding(err) => write!(f, "decoding error: {err}"),
            CallError::Crypto(err) => write!(f, "crypto error: {err}"),
            CallError::Owner(err) => write!(f, "owner address error: {err}"),
            CallError::Invalid(msg) => write!(f, "invalid call intent: {msg}"),
            CallError::Limit(msg) => write!(f, "call intent limit exceeded: {msg}"),
            CallError::ContextMismatch => {
                write!(f, "call intent context does not match expected context")
            }
            CallError::InvalidSignature => {
                write!(f, "call intent signature verification failed")
            }
            CallError::CodeMismatch => write!(
                f,
                "call intent code does not match the bound publication interface"
            ),
        }
    }
}

impl std::error::Error for CallError {}

impl From<PublicationError> for CallError {
    fn from(err: PublicationError) -> Self {
        CallError::Publication(err)
    }
}

impl From<AbiError> for CallError {
    fn from(err: AbiError) -> Self {
        CallError::Abi(err)
    }
}

impl From<PackageTypeError> for CallError {
    fn from(err: PackageTypeError) -> Self {
        CallError::Package(err)
    }
}

impl From<ValueError> for CallError {
    fn from(err: ValueError) -> Self {
        CallError::Value(err)
    }
}

impl From<BindingError> for CallError {
    fn from(err: BindingError) -> Self {
        CallError::Binding(err)
    }
}

impl From<CanonicalEncodingError> for CallError {
    fn from(err: CanonicalEncodingError) -> Self {
        CallError::Encoding(err)
    }
}

impl From<CanonicalDecodingError> for CallError {
    fn from(err: CanonicalDecodingError) -> Self {
        CallError::Decoding(err)
    }
}

impl From<CryptoError> for CallError {
    fn from(err: CryptoError) -> Self {
        CallError::Crypto(err)
    }
}

impl From<Ed25519OwnerAddressError> for CallError {
    fn from(err: Ed25519OwnerAddressError) -> Self {
        CallError::Owner(err)
    }
}

fn to_array32(bytes: &[u8]) -> Result<[u8; 32], CallError> {
    if bytes.len() != 32 {
        return Err(CallError::Invalid("expected exactly 32 bytes"));
    }
    let mut out: [u8; 32] = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn to_array64(bytes: &[u8]) -> Result<[u8; 64], CallError> {
    if bytes.len() != 64 {
        return Err(CallError::Invalid("expected exactly 64 bytes"));
    }
    let mut out: [u8; 64] = [0u8; 64];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn validate_entrypoint(entrypoint: &str) -> Result<(), CallError> {
    if entrypoint.is_empty() {
        return Err(CallError::Invalid("entrypoint must not be empty"));
    }
    if entrypoint.len() > MAX_ENTRYPOINT_BYTES {
        return Err(CallError::Limit("entrypoint exceeds maximum size"));
    }
    if entrypoint == "memory" {
        return Err(CallError::Invalid("entrypoint must not be \"memory\""));
    }
    Ok(())
}

fn validate_access_manifest(access: &AccessManifest) -> Result<(), CallError> {
    if access.entries.len() > MAX_ACCESS_ENTRIES {
        return Err(CallError::Limit(
            "access manifest exceeds maximum entry count",
        ));
    }
    let mut seen: BTreeSet<objects::ObjectId> = BTreeSet::new();
    for entry in &access.entries {
        if !seen.insert(entry.object_ref.id) {
            return Err(CallError::Invalid(
                "access manifest contains a duplicate object id",
            ));
        }
    }
    Ok(())
}

fn validate_code_chain(
    context: &PublicationContext,
    code: &UnverifiedDependencyRef,
) -> Result<(), CallError> {
    if code.origin().chain_id() != context.chain_id() {
        return Err(CallError::CodeMismatch);
    }
    if code.context().chain_id() != context.chain_id() {
        return Err(CallError::CodeMismatch);
    }
    Ok(())
}

/// Encodes an exact unverified instance selector.
pub fn encode_instance_target(instance: &InstanceTarget) -> Result<Vec<u8>, CallError> {
    if instance.revision == 0 {
        return Err(CallError::Invalid("instance revision must be > 0"));
    }
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(INSTANCE_TARGET_TYPE, INSTANCE_TARGET_VERSION);
    frame.field_bytes(INSTANCE_FIELD_CREATOR, instance.creator.to_vec())?;
    frame.field_bytes(INSTANCE_FIELD_SEED, instance.seed.to_vec())?;
    frame.field_u64(INSTANCE_FIELD_REVISION, instance.revision)?;
    frame.field_bytes(
        INSTANCE_FIELD_DIGEST,
        encode_digest32(&instance.record_digest)?,
    )?;
    let frame: Vec<u8> = frame.finish()?;
    Ok(frame)
}

/// Strictly decodes an unverified instance selector.
pub fn decode_instance_target(bytes: &[u8]) -> Result<InstanceTarget, CallError> {
    if bytes.len() > MAX_INSTANCE_TARGET_BYTES {
        return Err(CallError::Limit("instance target bytes"));
    }
    let frame: canonical_encoding::CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(INSTANCE_TARGET_TYPE)?;
    frame.require_version(INSTANCE_TARGET_VERSION)?;
    frame.require_only_fields(&[
        INSTANCE_FIELD_CREATOR,
        INSTANCE_FIELD_SEED,
        INSTANCE_FIELD_REVISION,
        INSTANCE_FIELD_DIGEST,
    ])?;

    let creator_bytes: &[u8] = frame.required_field(INSTANCE_FIELD_CREATOR)?;
    let creator: [u8; 32] = to_array32(creator_bytes)?;

    let seed_bytes: &[u8] = frame.required_field(INSTANCE_FIELD_SEED)?;
    let seed: [u8; 32] = to_array32(seed_bytes)?;

    let revision: u64 = frame.required_u64(INSTANCE_FIELD_REVISION)?;
    if revision == 0 {
        return Err(CallError::Invalid("instance revision must be > 0"));
    }

    let digest_bytes: &[u8] = frame.required_field(INSTANCE_FIELD_DIGEST)?;
    let record_digest: Digest32 = decode_digest32(digest_bytes)?;

    Ok(InstanceTarget {
        creator,
        seed,
        revision,
        record_digest,
    })
}

/// Encodes a [`CallIntent`] into its bounded Frame0x6402 v1 wire form.
///
/// Entry/access/argument bounds precede encoding; nested type arguments use a
/// shared node/byte budget. This is shape validation, not resource admission.
pub fn encode_call_intent(intent: &CallIntent) -> Result<Vec<u8>, CallError> {
    validate_entrypoint(&intent.entrypoint)?;
    validate_access_manifest(&intent.access)?;
    if intent.gas_limit == 0 {
        return Err(CallError::Invalid("gas_limit must be > 0"));
    }
    if intent.arguments.len() > MAX_CALL_ARGUMENT_BYTES {
        return Err(CallError::Limit("call arguments exceed maximum size"));
    }
    validate_code_chain(&intent.context, &intent.code)?;

    let context_bytes: Vec<u8> = encode_publication_context(&intent.context)?;
    let code_bytes: Vec<u8> = encode_dependency_ref(&intent.code)?;

    let instance_bytes: Vec<u8> = encode_instance_target(&intent.instance)?;
    if instance_bytes.len() > MAX_INSTANCE_TARGET_BYTES {
        return Err(CallError::Limit(
            "instance target frame exceeds maximum size",
        ));
    }

    let type_args_bytes: Vec<u8> =
        encode_scoped_type_arguments(intent.context.chain_id(), &intent.type_arguments)?;
    let access_bytes: Vec<u8> = encode_access_manifest(&intent.access)?;

    let mut frame: CanonicalStruct = CanonicalStruct::new(CALL_INTENT_TYPE, CALL_INTENT_VERSION);
    frame.field_bytes(CALL_FIELD_CONTEXT, context_bytes)?;
    frame.field_bytes(CALL_FIELD_REQUEST_ID, intent.request_id.to_vec())?;
    frame.field_bytes(CALL_FIELD_SENDER, intent.sender.to_vec())?;
    frame.field_u64(CALL_FIELD_NONCE, intent.nonce)?;
    frame.field_bytes(CALL_FIELD_CODE, code_bytes)?;
    frame.field_bytes(CALL_FIELD_INSTANCE, instance_bytes)?;
    frame.field_str(CALL_FIELD_ENTRYPOINT, &intent.entrypoint)?;
    frame.field_bytes(CALL_FIELD_TYPE_ARGS, type_args_bytes)?;
    frame.field_bytes(CALL_FIELD_ACCESS, access_bytes)?;
    frame.field_bytes(CALL_FIELD_ARGUMENTS, intent.arguments.clone())?;
    frame.field_u64(CALL_FIELD_GAS_LIMIT, intent.gas_limit)?;
    let frame: Vec<u8> = frame.finish()?;

    if frame.len() > MAX_CALL_INTENT_BYTES {
        return Err(CallError::Limit("call intent frame exceeds maximum size"));
    }

    Ok(frame)
}

/// Decodes and strictly validates a Frame0x6402 v1 [`CallIntent`].
pub fn decode_call_intent(bytes: &[u8]) -> Result<CallIntent, CallError> {
    if bytes.len() > MAX_CALL_INTENT_BYTES {
        return Err(CallError::Limit("call intent frame exceeds maximum size"));
    }

    let frame: canonical_encoding::CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(CALL_INTENT_TYPE)?;
    frame.require_version(CALL_INTENT_VERSION)?;
    frame.require_only_fields(&[
        CALL_FIELD_CONTEXT,
        CALL_FIELD_REQUEST_ID,
        CALL_FIELD_SENDER,
        CALL_FIELD_NONCE,
        CALL_FIELD_CODE,
        CALL_FIELD_INSTANCE,
        CALL_FIELD_ENTRYPOINT,
        CALL_FIELD_TYPE_ARGS,
        CALL_FIELD_ACCESS,
        CALL_FIELD_ARGUMENTS,
        CALL_FIELD_GAS_LIMIT,
    ])?;

    let context_bytes: &[u8] = frame.required_field(CALL_FIELD_CONTEXT)?;
    let context: PublicationContext = decode_publication_context(context_bytes)?;

    let request_id_bytes: &[u8] = frame.required_field(CALL_FIELD_REQUEST_ID)?;
    let request_id: [u8; 32] = to_array32(request_id_bytes)?;

    let sender_bytes: &[u8] = frame.required_field(CALL_FIELD_SENDER)?;
    let sender: [u8; 32] = to_array32(sender_bytes)?;

    let nonce: u64 = frame.required_u64(CALL_FIELD_NONCE)?;

    let code_bytes: &[u8] = frame.required_field(CALL_FIELD_CODE)?;
    let code: UnverifiedDependencyRef = decode_dependency_ref(code_bytes)?;

    let instance_bytes: &[u8] = frame.required_field(CALL_FIELD_INSTANCE)?;
    if instance_bytes.len() > MAX_INSTANCE_TARGET_BYTES {
        return Err(CallError::Limit(
            "instance target frame exceeds maximum size",
        ));
    }
    let instance: InstanceTarget = decode_instance_target(instance_bytes)?;

    let entrypoint: &str = frame.required_str(CALL_FIELD_ENTRYPOINT)?;
    validate_entrypoint(entrypoint)?;

    let type_args_bytes: &[u8] = frame.required_field(CALL_FIELD_TYPE_ARGS)?;
    let type_arguments: Vec<ScopedTypeArg> =
        decode_scoped_type_arguments(context.chain_id(), type_args_bytes)?;

    let access_bytes: &[u8] = frame.required_field(CALL_FIELD_ACCESS)?;
    let access: AccessManifest = decode_access_manifest(access_bytes, MAX_ACCESS_ENTRIES)?;
    validate_access_manifest(&access)?;

    let arguments: &[u8] = frame.required_field(CALL_FIELD_ARGUMENTS)?;
    if arguments.len() > MAX_CALL_ARGUMENT_BYTES {
        return Err(CallError::Limit("call arguments exceed maximum size"));
    }

    let gas_limit: u64 = frame.required_u64(CALL_FIELD_GAS_LIMIT)?;
    if gas_limit == 0 {
        return Err(CallError::Invalid("gas_limit must be > 0"));
    }

    validate_code_chain(&context, &code)?;

    Ok(CallIntent {
        context,
        request_id,
        sender,
        nonce,
        code,
        instance,
        entrypoint: entrypoint.to_owned(),
        type_arguments,
        access,
        arguments: arguments.to_vec(),
        gas_limit,
    })
}

/// Encodes a [`SignedCallIntent`] into its bounded Frame0x6403 v1 wire form.
pub fn encode_signed_call_intent(signed: &SignedCallIntent) -> Result<Vec<u8>, CallError> {
    let intent_bytes: Vec<u8> = encode_call_intent(&signed.intent)?;

    let mut frame: CanonicalStruct =
        CanonicalStruct::new(SIGNED_CALL_INTENT_TYPE, SIGNED_CALL_INTENT_VERSION);
    frame.field_bytes(SIGNED_FIELD_INTENT, intent_bytes)?;
    frame.field_bytes(SIGNED_FIELD_SIGNATURE, signed.signature.to_vec())?;
    let frame: Vec<u8> = frame.finish()?;

    if frame.len() > MAX_SIGNED_CALL_INTENT_BYTES {
        return Err(CallError::Limit(
            "signed call intent frame exceeds maximum size",
        ));
    }

    Ok(frame)
}

/// Decodes a Frame0x6403 v1 [`SignedCallIntent`]. Performs no context,
/// key, or signature validation; see [`authenticate_call_intent`].
pub fn decode_signed_call_intent(bytes: &[u8]) -> Result<SignedCallIntent, CallError> {
    if bytes.len() > MAX_SIGNED_CALL_INTENT_BYTES {
        return Err(CallError::Limit(
            "signed call intent frame exceeds maximum size",
        ));
    }

    let frame: canonical_encoding::CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(SIGNED_CALL_INTENT_TYPE)?;
    frame.require_version(SIGNED_CALL_INTENT_VERSION)?;
    frame.require_only_fields(&[SIGNED_FIELD_INTENT, SIGNED_FIELD_SIGNATURE])?;

    let intent_bytes: &[u8] = frame.required_field(SIGNED_FIELD_INTENT)?;
    if intent_bytes.len() > MAX_CALL_INTENT_BYTES {
        return Err(CallError::Limit("call intent frame exceeds maximum size"));
    }
    let intent: CallIntent = decode_call_intent(intent_bytes)?;

    let signature_bytes: &[u8] = frame.required_field(SIGNED_FIELD_SIGNATURE)?;
    let signature: [u8; 64] = to_array64(signature_bytes)?;

    Ok(SignedCallIntent { intent, signature })
}

/// Builds the exact byte frame that a sender must sign (and a verifier
/// must check the signature against) for `intent` under `expected`.
///
/// `intent.context` must equal `expected` exactly; no context is
/// reconstructed from the request itself.
pub fn call_signing_frame(
    expected: &PublicationContext,
    intent: &CallIntent,
) -> Result<Vec<u8>, CallError> {
    if &intent.context != expected {
        return Err(CallError::ContextMismatch);
    }

    let message: Vec<u8> = encode_call_intent(intent)?;
    let domain: SignatureDomain = SignatureDomain {
        chain_id: expected.chain_id().clone(),
        protocol_version: expected.protocol_version(),
        epoch: expected.epoch(),
        message_type: SignatureMessageType::new("CallContractIntent")?,
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };

    Ok(frame_signature_message(&domain, &message)?)
}

/// Strictly decodes, checks context equality, validates the sender key,
/// and verifies the Ed25519 signature of a [`SignedCallIntent`].
///
/// Performs no ABI resolution and no I/O.
pub fn authenticate_call_intent(
    expected: &PublicationContext,
    bytes: &[u8],
) -> Result<AuthenticatedCallIntent, CallError> {
    let signed: SignedCallIntent = decode_signed_call_intent(bytes)?;

    if signed.intent.context != *expected {
        return Err(CallError::ContextMismatch);
    }

    validate_ed25519_owner_address(
        &signed.intent.sender,
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )?;

    let frame: Vec<u8> = call_signing_frame(expected, &signed.intent)?;

    let verifier: Ed25519Verifier =
        Ed25519Verifier::from_verifying_key_bytes(&signed.intent.sender)?;
    if !verifier.verify_framed(&frame, &signed.signature)? {
        return Err(CallError::InvalidSignature);
    }

    Ok(AuthenticatedCallIntent { signed })
}

fn access_mode_to_object_mode(mode: AccessMode) -> ObjectMode {
    match mode {
        AccessMode::Read => ObjectMode::Read,
        AccessMode::Write => ObjectMode::Write,
        AccessMode::Consume => ObjectMode::Consume,
    }
}

/// Binds an already-authenticated call intent to a verified publication
/// interface: checks that the signed code reference exactly matches the
/// interface's underlying request, binds the entrypoint and type
/// arguments, and validates arguments and access manifest against the
/// resulting object signature.
///
/// Establishes no durable code or instance authority and grants no
/// owner/access claims beyond this single call binding.
pub fn bind_authenticated_call<'a>(
    call: &'a AuthenticatedCallIntent,
    interface: &'a VerifiedPublicationInterface,
) -> Result<BoundObjectSignature<'a>, CallError> {
    bind_call_intent(call.intent(), interface)
}

/// Binds declaration data only. Authentication and durable authority are separate.
pub fn bind_call_intent<'a>(
    intent: &'a CallIntent,
    interface: &'a VerifiedPublicationInterface,
) -> Result<BoundObjectSignature<'a>, CallError> {
    let candidate = interface.candidate();
    let artifact: &crate::publication::CodeArtifact = candidate.artifact();

    if intent.code.origin() != artifact.origin() {
        return Err(CallError::CodeMismatch);
    }
    if intent.code.revision() != artifact.revision() {
        return Err(CallError::CodeMismatch);
    }
    if intent.code.context() != artifact.context() {
        return Err(CallError::CodeMismatch);
    }
    if intent.code.artifact_digest() != candidate.digest() {
        return Err(CallError::CodeMismatch);
    }

    let signature: BoundObjectSignature<'a> =
        bind_object_signature(interface, &intent.entrypoint, &intent.type_arguments)?;

    validate_call_arguments(&signature, &intent.arguments)?;

    if signature.objects().len() != intent.access.entries.len() {
        return Err(CallError::Invalid(
            "access manifest entry count does not match the bound object signature",
        ));
    }

    for (object, entry) in signature.objects().iter().zip(intent.access.entries.iter()) {
        if object.mode() != access_mode_to_object_mode(entry.mode) {
            return Err(CallError::Invalid(
                "access manifest mode does not match the bound object signature",
            ));
        }
    }

    Ok(signature)
}
