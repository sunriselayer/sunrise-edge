//! Explicit signed zero-fee local execution profile and immutable instance wires.
//! These data types do not establish durable owner, publication or instance authority.
use crate::call::{
    CallError, CallIntent, InstanceTarget, bind_call_intent, decode_call_intent,
    decode_instance_target, encode_call_intent, encode_instance_target,
};
use crate::publication::{
    BoundObjectSignature, PublicationContext, PublicationError, UnverifiedDependencyRef,
    VerifiedPublicationInterface, decode_dependency_ref, decode_publication_context,
    encode_dependency_ref, encode_publication_context,
};
use crate::{
    ExecutionEffects, ExecutionError, ExecutionStatus, ResolvedObject, decode_execution_effects,
    encode_execution_effects,
};
use abi::package_types::{
    PackageTypeError, ScopedTypeTag, decode_scoped_type_tag, encode_scoped_type_tag,
};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame, decode_digest32, encode_digest32,
};
use crypto::{
    CryptoError, Ed25519OwnerAddressError, Ed25519OwnerAddressPolicy, Ed25519Verifier,
    SignatureDomain, SignatureMessageType, SignatureVerifier, frame_signature_message,
    validate_ed25519_owner_address,
};
use hashing::{HashSuiteResolver, HashingError};
use objects::ObjectId;
use protocol_types::{Digest32, HashPurpose, SignatureSchemeId};

/// Global fuel ceiling; the same budget covers synchronous library frames.
pub const MAX_LOCAL_EXECUTION_GAS: u64 = 1_000_000;
/// Maximum synchronous root plus nested frame depth.
pub const MAX_LOCAL_EXECUTION_DEPTH: u32 = 8;
/// Maximum total root plus library invocations.
pub const MAX_LOCAL_EXECUTION_CALLS: u32 = 64;
/// Closed host authority, transfer, library dispatch and trap normalization rules.
pub const LOCAL_EXECUTION_RULES_VERSION: u32 = 1;
/// Pinned interpreter implementation and its default fuel-cost model.
pub const LOCAL_WASMI_VERSION: &str = "wasmi-1.1.0";
/// Initial value-stack allocation in bytes, as defined by Wasmi 1.1 Config.
pub const LOCAL_WASM_INITIAL_STACK: usize = 128;
/// Maximum value-stack bytes for Wasmi execution (not a count of value slots).
pub const LOCAL_WASM_MAX_STACK: usize = 8192;
/// Maximum internal WASM call recursion.
pub const LOCAL_WASM_MAX_RECURSION: usize = 128;
/// Exact typed sunrise imports and return conventions.
pub const LOCAL_TYPED_HOST_ABI_VERSION: u32 = 1;
/// Sole consensus-visible execution trap reason; engine diagnostics stay local.
pub const LOCAL_EXECUTION_TRAP_REASON: &str = "local contract trapped";
/// Maximum event records retained by one invocation.
pub const MAX_LOCAL_EXECUTION_EVENTS: usize = 1024;
/// Aggregate simultaneously retained module memory.
pub const MAX_LOCAL_EXECUTION_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
/// Aggregate output data and canonical result bound.
pub const MAX_LOCAL_EXECUTION_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// Global creation counter bound, including objects later consumed.
pub const MAX_LOCAL_CREATED_OBJECTS: u32 = 128;
/// Maximum globally allocated handles, including consumed ones.
pub const MAX_LOCAL_OBJECT_HANDLES: u32 = 256;
/// Base deterministic charge for each host operation.
pub const LOCAL_HOST_BASE_GAS: u64 = 10;
/// Additional deterministic charge per byte read/written by host operations.
pub const LOCAL_HOST_BYTE_GAS: u64 = 1;
/// Fixed charge before each bounded library view/binding operation, in addition
/// to host byte charges. Covers traversal of the at-most-33-node verified graph.
pub const LOCAL_LIBRARY_BINDING_GAS: u64 = 2048;
/// Maximum complete signed execution submission.
pub const MAX_LOCAL_EXECUTION_INTENT_BYTES: usize = crate::call::MAX_CALL_INTENT_BYTES + 1024;

/// Closed typed-host semantics descriptor, distinct from profile-one nonexecution.
pub fn encode_local_execution_semantics() -> Result<Vec<u8>, CanonicalEncodingError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x630B, 2);
    frame.field_str(1, "local-devnet-typed-host-execution")?;
    frame.field_u32(2, 2)?;
    frame.field_u32(3, LOCAL_EXECUTION_RULES_VERSION)?;
    frame.field_str(4, LOCAL_WASMI_VERSION)?;
    frame.field_u32(5, 1)?;
    frame.field_u32(6, LOCAL_WASM_INITIAL_STACK as u32)?;
    frame.field_u32(7, LOCAL_WASM_MAX_STACK as u32)?;
    frame.field_u32(8, LOCAL_WASM_MAX_RECURSION as u32)?;
    frame.field_u32(9, LOCAL_TYPED_HOST_ABI_VERSION)?;
    frame.field_u64(10, MAX_LOCAL_EXECUTION_MEMORY_BYTES)?;
    frame.finish()
}
/// Exact artifact semantics required by the separately committed profile-two policy.
pub fn local_execution_semantics(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
) -> Result<Digest32, PublicationError> {
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(PublicationError::ContextMismatch);
    }
    Ok(resolver.hash_for_purpose(
        context.epoch(),
        HashPurpose::ContractCode,
        &encode_local_execution_semantics()?,
    )?)
}

/// Closed errors without runtime-specific dependencies.
#[derive(Debug)]
pub enum LocalExecutionError {
    /// Shape, selector or authorization-profile mismatch.
    Invalid(&'static str),
    /// Deterministic resource bound exceeded.
    Limit(&'static str),
    /// Canonical encoder error.
    Encoding(CanonicalEncodingError),
    /// Canonical decoder error.
    Decoding(CanonicalDecodingError),
    /// Existing call codec or binding error.
    Call(CallError),
    /// Existing publication codec error.
    Publication(PublicationError),
    /// Scoped nominal type error.
    Package(PackageTypeError),
    /// Central hashing error.
    Hashing(HashingError),
    /// Central signature error.
    Crypto(CryptoError),
    /// Noncanonical owning key.
    Owner(Ed25519OwnerAddressError),
    /// Existing effects or execution error.
    Execution(ExecutionError),
}
impl std::fmt::Display for LocalExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid local execution: {message}"),
            Self::Limit(message) => write!(f, "local execution limit: {message}"),
            Self::Encoding(error) => error.fmt(f),
            Self::Decoding(error) => error.fmt(f),
            Self::Call(error) => error.fmt(f),
            Self::Publication(error) => error.fmt(f),
            Self::Package(error) => error.fmt(f),
            Self::Hashing(error) => error.fmt(f),
            Self::Crypto(error) => error.fmt(f),
            Self::Owner(error) => error.fmt(f),
            Self::Execution(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for LocalExecutionError {}
macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for LocalExecutionError {
            fn from(value: $source) -> Self {
                Self::$variant(value)
            }
        }
    };
}
from_error!(CanonicalEncodingError, Encoding);
from_error!(CanonicalDecodingError, Decoding);
from_error!(CallError, Call);
from_error!(PublicationError, Publication);
from_error!(PackageTypeError, Package);
from_error!(HashingError, Hashing);
from_error!(CryptoError, Crypto);
from_error!(Ed25519OwnerAddressError, Owner);
from_error!(ExecutionError, Execution);

fn trusted_hash(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    purpose: HashPurpose,
    bytes: &[u8],
) -> Result<Digest32, LocalExecutionError> {
    if resolver.chain_id() != context.chain_id()
        || resolver.protocol_version() != context.protocol_version()
    {
        return Err(LocalExecutionError::Invalid("trusted hash context"));
    }
    Ok(resolver.hash_for_purpose(context.epoch(), purpose, bytes)?)
}
fn fixed32(bytes: &[u8]) -> Result<[u8; 32], LocalExecutionError> {
    bytes
        .try_into()
        .map_err(|_| LocalExecutionError::Invalid("fixed 32-byte field"))
}
fn owning_key(key: &[u8; 32]) -> Result<(), LocalExecutionError> {
    Ok(validate_ed25519_owner_address(
        key,
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )?)
}

/// Trusted local opt-in policy. Version one explicitly permits zero fees only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalExecutionPolicy {
    context: PublicationContext,
}
impl LocalExecutionPolicy {
    /// Creates the fixed local policy, which must separately be durably committed.
    #[must_use]
    pub const fn new(context: PublicationContext) -> Self {
        Self { context }
    }
    /// Original trusted policy context.
    #[must_use]
    pub fn context(&self) -> &PublicationContext {
        &self.context
    }
    /// Explicit global fuel bound.
    #[must_use]
    pub const fn max_gas(&self) -> u64 {
        MAX_LOCAL_EXECUTION_GAS
    }
    /// Canonical closed policy frame 0x6409/v1.
    pub fn encode(&self) -> Result<Vec<u8>, LocalExecutionError> {
        let mut frame: CanonicalStruct = CanonicalStruct::new(0x6409, 1);
        frame.field_bytes(1, encode_publication_context(&self.context)?)?;
        frame.field_u32(2, 2)?;
        frame.field_u16(3, 0)?;
        frame.field_u64(4, MAX_LOCAL_EXECUTION_GAS)?;
        frame.field_u32(5, MAX_LOCAL_EXECUTION_DEPTH)?;
        frame.field_u32(6, MAX_LOCAL_EXECUTION_CALLS)?;
        frame.field_u64(7, MAX_LOCAL_EXECUTION_MEMORY_BYTES)?;
        frame.field_u64(8, MAX_LOCAL_EXECUTION_OUTPUT_BYTES as u64)?;
        frame.field_u32(9, MAX_LOCAL_CREATED_OBJECTS)?;
        frame.field_u32(10, MAX_LOCAL_OBJECT_HANDLES)?;
        frame.field_u64(11, LOCAL_HOST_BASE_GAS)?;
        frame.field_u64(12, LOCAL_HOST_BYTE_GAS)?;
        frame.field_u32(13, LOCAL_EXECUTION_RULES_VERSION)?;
        frame.field_u32(14, MAX_LOCAL_EXECUTION_EVENTS as u32)?;
        frame.field_bytes(15, encode_local_execution_semantics()?)?;
        frame.field_u64(16, LOCAL_LIBRARY_BINDING_GAS)?;
        Ok(frame.finish()?)
    }
    /// Rejects any unknown or changed v1 policy limit; no implicit defaults.
    pub fn decode(bytes: &[u8]) -> Result<Self, LocalExecutionError> {
        if bytes.len() > 1024 {
            return Err(LocalExecutionError::Limit("policy bytes"));
        }
        let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
        frame.require_type(0x6409)?;
        frame.require_version(1)?;
        frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])?;
        let policy: Self = Self::new(decode_publication_context(frame.required_field(1)?)?);
        if policy.encode()? != bytes {
            return Err(LocalExecutionError::Invalid("unsupported execution policy"));
        }
        Ok(policy)
    }
    /// Commits the exact policy under centralized ProtocolConfig hashing.
    pub fn digest(&self, resolver: &HashSuiteResolver) -> Result<Digest32, LocalExecutionError> {
        trusted_hash(
            resolver,
            &self.context,
            HashPurpose::ProtocolConfig,
            &self.encode()?,
        )
    }
}

/// Immutable independently initialized instance. Public fields remain unverified data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceRecord {
    /// Original verification context, preserved across upgrades.
    pub context: PublicationContext,
    /// Authenticated initial creator.
    pub creator: [u8; 32],
    /// Creator-scoped logical seed.
    pub seed: [u8; 32],
    /// Exact code selected for initialization and later calls.
    pub code: UnverifiedDependencyRef,
    /// Initial immutable authorization revision, exactly one.
    pub revision: u64,
    /// ABI-designated initializer, never inferred from ordinary call args.
    pub initializer: String,
}
/// Encodes and validates instance record 0x6404/v1.
pub fn encode_instance_record(record: &InstanceRecord) -> Result<Vec<u8>, LocalExecutionError> {
    owning_key(&record.creator)?;
    if record.revision != 1
        || record.code.origin().chain_id() != record.context.chain_id()
        || record.initializer.is_empty()
        || record.initializer.len() > 64
    {
        return Err(LocalExecutionError::Invalid("instance record"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6404, 1);
    frame.field_bytes(1, encode_publication_context(&record.context)?)?;
    frame.field_bytes(2, record.creator.to_vec())?;
    frame.field_bytes(3, record.seed.to_vec())?;
    frame.field_bytes(4, encode_dependency_ref(&record.code)?)?;
    frame.field_u64(5, record.revision)?;
    frame.field_str(6, &record.initializer)?;
    Ok(frame.finish()?)
}
/// Strictly decodes one bounded immutable instance record.
pub fn decode_instance_record(bytes: &[u8]) -> Result<InstanceRecord, LocalExecutionError> {
    if bytes.len() > 2048 {
        return Err(LocalExecutionError::Limit("instance bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(0x6404)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
    let record: InstanceRecord = InstanceRecord {
        context: decode_publication_context(frame.required_field(1)?)?,
        creator: fixed32(frame.required_field(2)?)?,
        seed: fixed32(frame.required_field(3)?)?,
        code: decode_dependency_ref(frame.required_field(4)?)?,
        revision: frame.required_u64(5)?,
        initializer: frame.required_str(6)?.to_owned(),
    };
    if encode_instance_record(&record)? != bytes {
        return Err(LocalExecutionError::Invalid("noncanonical instance"));
    }
    Ok(record)
}
/// Hashes the typed record under its original context, not the active call context.
pub fn hash_instance_record(
    resolver: &HashSuiteResolver,
    record: &InstanceRecord,
) -> Result<Digest32, LocalExecutionError> {
    trusted_hash(
        resolver,
        &record.context,
        HashPurpose::Object,
        &encode_instance_record(record)?,
    )
}
/// Computes the exact signed target before initializer execution.
pub fn instance_target(
    resolver: &HashSuiteResolver,
    record: &InstanceRecord,
) -> Result<InstanceTarget, LocalExecutionError> {
    Ok(InstanceTarget {
        creator: record.creator,
        seed: record.seed,
        revision: record.revision,
        record_digest: hash_instance_record(resolver, record)?,
    })
}

/// Domain-separated typed creation identity. Both VM and durable effect validation
/// use the original global ordinal, including gaps left by consumed creations.
pub fn derive_local_created_object_id(
    resolver: &HashSuiteResolver,
    call_context: &PublicationContext,
    instance_context: &PublicationContext,
    instance: &InstanceTarget,
    defining_code: &UnverifiedDependencyRef,
    event_digest: Digest32,
    creation_ordinal: u32,
) -> Result<ObjectId, LocalExecutionError> {
    if creation_ordinal >= MAX_LOCAL_CREATED_OBJECTS
        || instance_context.chain_id() != call_context.chain_id()
        || defining_code.origin().chain_id() != call_context.chain_id()
    {
        return Err(LocalExecutionError::Invalid("creation context or ordinal"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x640A, 1);
    frame.field_bytes(1, encode_publication_context(call_context)?)?;
    frame.field_bytes(2, encode_publication_context(instance_context)?)?;
    frame.field_bytes(3, encode_instance_target(instance)?)?;
    frame.field_bytes(4, encode_dependency_ref(defining_code)?)?;
    frame.field_bytes(5, encode_digest32(&event_digest)?)?;
    frame.field_u32(6, creation_ordinal)?;
    let digest: Digest32 = trusted_hash(
        resolver,
        call_context,
        HashPurpose::Object,
        &frame.finish()?,
    )?;
    Ok(ObjectId::new(digest.bytes()))
}

/// Closed signed execution action; ordinary calls cannot enter initialization mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum LocalExecutionMode {
    /// Create the exact independently scoped instance.
    Instantiate = 1,
    /// Invoke an already initialized instance.
    Call = 2,
}
impl LocalExecutionMode {
    fn decode(value: u16) -> Result<Self, LocalExecutionError> {
        match value {
            1 => Ok(Self::Instantiate),
            2 => Ok(Self::Call),
            _ => Err(LocalExecutionError::Invalid("execution mode")),
        }
    }
}
/// Single signed payload binding explicit local policy and complete call fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalExecutionIntent {
    /// Instantiate or ordinary call.
    pub mode: LocalExecutionMode,
    /// Exact committed execution-policy digest.
    pub policy_digest: Digest32,
    /// Existing canonical request/code/instance/access data.
    pub call: CallIntent,
}
/// Unverified Ed25519 execution submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedLocalExecutionIntent {
    /// Exact signed payload.
    pub intent: LocalExecutionIntent,
    /// Signature in ExecuteLocalContract domain.
    pub signature: [u8; 64],
}
/// Cryptographic witness only; no durable instance/owner/nonce authority.
#[derive(Debug)]
pub struct AuthenticatedLocalExecutionIntent {
    signed: SignedLocalExecutionIntent,
}
impl AuthenticatedLocalExecutionIntent {
    /// Returns authenticated immutable payload.
    #[must_use]
    pub fn intent(&self) -> &LocalExecutionIntent {
        &self.signed.intent
    }
    /// Returns exact signed input for receipt digest reconciliation.
    #[must_use]
    pub fn signed(&self) -> &SignedLocalExecutionIntent {
        &self.signed
    }
}
/// Encodes closed local execution intent 0x6405/v1.
pub fn encode_local_execution_intent(
    intent: &LocalExecutionIntent,
) -> Result<Vec<u8>, LocalExecutionError> {
    if intent.mode == LocalExecutionMode::Instantiate
        && (intent.call.sender != intent.call.instance.creator
            || !intent.call.access.entries.is_empty()
            || !intent.call.type_arguments.is_empty())
    {
        return Err(LocalExecutionError::Invalid(
            "initializer creator or inputs",
        ));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6405, 1);
    frame.field_u16(1, intent.mode as u16)?;
    frame.field_bytes(2, encode_digest32(&intent.policy_digest)?)?;
    frame.field_bytes(3, encode_call_intent(&intent.call)?)?;
    Ok(frame.finish()?)
}
/// Strictly decodes a bounded execution payload.
pub fn decode_local_execution_intent(
    bytes: &[u8],
) -> Result<LocalExecutionIntent, LocalExecutionError> {
    if bytes.len() > MAX_LOCAL_EXECUTION_INTENT_BYTES {
        return Err(LocalExecutionError::Limit("intent bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(0x6405)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3])?;
    let intent: LocalExecutionIntent = LocalExecutionIntent {
        mode: LocalExecutionMode::decode(frame.required_u16(1)?)?,
        policy_digest: decode_digest32(frame.required_field(2)?)?,
        call: decode_call_intent(frame.required_field(3)?)?,
    };
    if encode_local_execution_intent(&intent)? != bytes {
        return Err(LocalExecutionError::Invalid("noncanonical intent"));
    }
    Ok(intent)
}
/// Encodes signed local execution 0x6406/v1.
pub fn encode_signed_local_execution(
    signed: &SignedLocalExecutionIntent,
) -> Result<Vec<u8>, LocalExecutionError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6406, 1);
    frame.field_bytes(1, encode_local_execution_intent(&signed.intent)?)?;
    frame.field_bytes(2, signed.signature.to_vec())?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_LOCAL_EXECUTION_INTENT_BYTES {
        return Err(LocalExecutionError::Limit("signed intent"));
    }
    Ok(bytes)
}
/// Strictly decodes a signed local execution request.
pub fn decode_signed_local_execution(
    bytes: &[u8],
) -> Result<SignedLocalExecutionIntent, LocalExecutionError> {
    if bytes.len() > MAX_LOCAL_EXECUTION_INTENT_BYTES {
        return Err(LocalExecutionError::Limit("signed intent"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(0x6406)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2])?;
    Ok(SignedLocalExecutionIntent {
        intent: decode_local_execution_intent(frame.required_field(1)?)?,
        signature: frame
            .required_field(2)?
            .try_into()
            .map_err(|_| LocalExecutionError::Invalid("signature length"))?,
    })
}
/// Signature frame explicitly binds local zero-fee policy consent.
pub fn local_execution_signing_frame(
    expected: &PublicationContext,
    intent: &LocalExecutionIntent,
) -> Result<Vec<u8>, LocalExecutionError> {
    if &intent.call.context != expected {
        return Err(LocalExecutionError::Invalid("execution context"));
    }
    let domain: SignatureDomain = SignatureDomain {
        chain_id: expected.chain_id().clone(),
        protocol_version: expected.protocol_version(),
        epoch: expected.epoch(),
        message_type: SignatureMessageType::new("ExecuteLocalContract")?,
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    Ok(frame_signature_message(
        &domain,
        &encode_local_execution_intent(intent)?,
    )?)
}
/// Authenticates signed context, strict sender and explicit trusted local policy.
pub fn authenticate_local_execution(
    resolver: &HashSuiteResolver,
    policy: &LocalExecutionPolicy,
    bytes: &[u8],
) -> Result<AuthenticatedLocalExecutionIntent, LocalExecutionError> {
    let signed: SignedLocalExecutionIntent = decode_signed_local_execution(bytes)?;
    if signed.intent.policy_digest != policy.digest(resolver)?
        || signed.intent.call.gas_limit > policy.max_gas()
    {
        return Err(LocalExecutionError::Invalid("execution policy or gas"));
    }
    owning_key(&signed.intent.call.sender)?;
    let frame: Vec<u8> = local_execution_signing_frame(policy.context(), &signed.intent)?;
    if !Ed25519Verifier::from_verifying_key_bytes(&signed.intent.call.sender)?
        .verify_framed(&frame, &signed.signature)?
    {
        return Err(LocalExecutionError::Invalid("execution signature"));
    }
    Ok(AuthenticatedLocalExecutionIntent { signed })
}
/// Complete signed input digest shared with receipt and deterministic creation IDs.
pub fn local_execution_event_digest(
    resolver: &HashSuiteResolver,
    signed: &SignedLocalExecutionIntent,
) -> Result<Digest32, LocalExecutionError> {
    trusted_hash(
        resolver,
        &signed.intent.call.context,
        HashPurpose::NodeEvent,
        &encode_signed_local_execution(signed)?,
    )
}
/// Binds the authenticated execution intent to exact signed executable metadata.
pub fn bind_local_execution<'a>(
    intent: &'a AuthenticatedLocalExecutionIntent,
    interface: &'a VerifiedPublicationInterface,
) -> Result<BoundObjectSignature<'a>, LocalExecutionError> {
    let call: &CallIntent = &intent.intent().call;
    let metadata = interface
        .executable_abi(call.code.origin())
        .ok_or(LocalExecutionError::Invalid("nonexecutable code"))?;
    match intent.intent().mode {
        LocalExecutionMode::Instantiate => {
            if metadata.initializer.as_deref() != Some(call.entrypoint.as_str()) {
                return Err(LocalExecutionError::Invalid("initializer designation"));
            }
        }
        LocalExecutionMode::Call => {
            if metadata.initializer.as_deref() == Some(call.entrypoint.as_str()) {
                return Err(LocalExecutionError::Invalid("initializer replay"));
            }
        }
    }
    Ok(bind_call_intent(call, interface)?)
}

/// Host-stamped immutable object authority. Persistence admission must revalidate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectAuthority {
    /// Exact object identity, preventing sidecar substitution.
    pub object_id: ObjectId,
    /// Original instance context.
    pub instance_context: PublicationContext,
    /// Exact immutable target authorizing this scope.
    pub instance: InstanceTarget,
    /// Defining code, possibly an exact library in the instance's closure.
    pub code: UnverifiedDependencyRef,
    /// Complete nominal type, not an attacker-chosen naked fingerprint.
    pub ty: ScopedTypeTag,
}
/// Encodes bounded object authority 0x6407/v1, without changing Object bytes.
pub fn encode_object_authority(
    authority: &ObjectAuthority,
) -> Result<Vec<u8>, LocalExecutionError> {
    if authority.instance_context.chain_id() != authority.code.origin().chain_id()
        || authority.ty.origin() != authority.code.origin()
    {
        return Err(LocalExecutionError::Invalid("object authority origin"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6407, 1);
    frame.field_bytes(1, authority.object_id.as_bytes().to_vec())?;
    frame.field_bytes(2, encode_publication_context(&authority.instance_context)?)?;
    frame.field_bytes(3, encode_instance_target(&authority.instance)?)?;
    frame.field_bytes(4, encode_dependency_ref(&authority.code)?)?;
    frame.field_bytes(5, encode_scoped_type_tag(&authority.ty)?)?;
    Ok(frame.finish()?)
}
/// Strictly decodes a sidecar; its data alone is not durable authority.
pub fn decode_object_authority(bytes: &[u8]) -> Result<ObjectAuthority, LocalExecutionError> {
    if bytes.len() > 36 * 1024 {
        return Err(LocalExecutionError::Limit("object authority bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(0x6407)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5])?;
    let authority: ObjectAuthority = ObjectAuthority {
        object_id: ObjectId::new(fixed32(frame.required_field(1)?)?),
        instance_context: decode_publication_context(frame.required_field(2)?)?,
        instance: decode_instance_target(frame.required_field(3)?)?,
        code: decode_dependency_ref(frame.required_field(4)?)?,
        ty: decode_scoped_type_tag(frame.required_field(5)?)?,
    };
    if encode_object_authority(&authority)? != bytes {
        return Err(LocalExecutionError::Invalid("noncanonical authority"));
    }
    Ok(authority)
}

/// Public acknowledged execution result, including normalized success/failure and gas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalExecutionResult {
    /// Exact signed request identity.
    pub request_id: [u8; 32],
    /// Exact target and resulting instance bytes.
    pub instance: InstanceRecord,
    /// Executed signed mode.
    pub mode: LocalExecutionMode,
    /// Canonical effects (Failure has no application effects/events).
    pub effects: ExecutionEffects,
}
/// Encodes bounded public result 0x6408/v1.
pub fn encode_local_execution_result(
    result: &LocalExecutionResult,
) -> Result<Vec<u8>, LocalExecutionError> {
    if result.request_id == [0; 32] || result.effects.gas_used > MAX_LOCAL_EXECUTION_GAS {
        return Err(LocalExecutionError::Invalid("result identity or gas"));
    }
    if result.effects.object_effects.len() > MAX_LOCAL_OBJECT_HANDLES as usize
        || result.effects.events.len() > MAX_LOCAL_EXECUTION_EVENTS
    {
        return Err(LocalExecutionError::Limit("result items"));
    }
    if let ExecutionStatus::Failure { reason } = &result.effects.status
        && reason != LOCAL_EXECUTION_TRAP_REASON
    {
        return Err(LocalExecutionError::Invalid("unnormalized trap"));
    }
    if matches!(result.effects.status, ExecutionStatus::Failure { .. })
        && (!result.effects.object_effects.is_empty() || !result.effects.events.is_empty())
    {
        return Err(LocalExecutionError::Invalid("trap effects"));
    }
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x6408, 1);
    frame.field_bytes(1, result.request_id.to_vec())?;
    frame.field_bytes(2, encode_instance_record(&result.instance)?)?;
    frame.field_u16(3, result.mode as u16)?;
    frame.field_bytes(4, encode_execution_effects(&result.effects)?)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_LOCAL_EXECUTION_OUTPUT_BYTES {
        return Err(LocalExecutionError::Limit("result bytes"));
    }
    Ok(bytes)
}
/// Strict result decode; transport success alone is never accepted as execution success.
pub fn decode_local_execution_result(
    bytes: &[u8],
) -> Result<LocalExecutionResult, LocalExecutionError> {
    if bytes.len() > MAX_LOCAL_EXECUTION_OUTPUT_BYTES {
        return Err(LocalExecutionError::Limit("result bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(0x6408)?;
    frame.require_version(1)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let result: LocalExecutionResult = LocalExecutionResult {
        request_id: fixed32(frame.required_field(1)?)?,
        instance: decode_instance_record(frame.required_field(2)?)?,
        mode: LocalExecutionMode::decode(frame.required_u16(3)?)?,
        effects: decode_execution_effects(frame.required_field(4)?)?,
    };
    if encode_local_execution_result(&result)? != bytes {
        return Err(LocalExecutionError::Invalid("noncanonical result"));
    }
    Ok(result)
}
/// Checks a public acknowledgement against exact signed code/instance/request and gas.
pub fn validate_local_execution_result(
    resolver: &HashSuiteResolver,
    instance_resolver: &HashSuiteResolver,
    signed: &SignedLocalExecutionIntent,
    result: &LocalExecutionResult,
) -> Result<(), LocalExecutionError> {
    let call: &CallIntent = &signed.intent.call;
    if result.request_id != call.request_id
        || result.mode != signed.intent.mode
        || result.instance.code != call.code
        || instance_target(instance_resolver, &result.instance)? != call.instance
        || result.effects.tx_hash != local_execution_event_digest(resolver, signed)?
        || result.effects.gas_used > call.gas_limit
    {
        return Err(LocalExecutionError::Invalid(
            "result selector or effects mismatch",
        ));
    }
    let _bytes: Vec<u8> = encode_local_execution_result(result)?;
    Ok(())
}

/// One integrity/authority-checked object supplied by durable admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedResolvedObject {
    /// Existing object body and declared mode.
    pub resolved: ResolvedObject,
    /// Exact independently checked host authority.
    pub authority: ObjectAuthority,
}
/// Creation provenance preserves ordinal gaps when intermediate creations are consumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedObjectAuthority {
    /// Original global invocation creation ordinal.
    pub creation_ordinal: u32,
    /// Authority for the surviving created object.
    pub authority: ObjectAuthority,
}
/// One invocation input assembled only after durable admission.
pub struct LocalExecutionRequest<'a> {
    /// Verified exact root and library closure.
    pub interface: &'a VerifiedPublicationInterface,
    /// Authenticated explicit execution input.
    pub intent: &'a AuthenticatedLocalExecutionIntent,
    /// Trusted current hash history.
    pub resolver: &'a HashSuiteResolver,
    /// Immutable admitted instance.
    pub instance: &'a InstanceRecord,
    /// Explicit committed limits and fee mode.
    pub policy: &'a LocalExecutionPolicy,
    /// Complete signed event digest.
    pub event_digest: Digest32,
    /// Declared, scoped inputs in signed order.
    pub inputs: &'a [ScopedResolvedObject],
}
/// Provisional bounded VM outcome; the node independently verifies every effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalExecutionOutcome {
    /// Normalized effects and global gas consumption.
    pub effects: ExecutionEffects,
    /// Surviving creations with original ordinals.
    pub created_authorities: Vec<CreatedObjectAuthority>,
}
/// Typed-host engine boundary; implementations use one arena/fuel budget across
/// same-instance library calls. Cross-instance dispatch is not part of this profile.
pub trait LocalContractEngine {
    /// Executes one fully scoped invocation without persistence.
    fn execute(
        &self,
        request: LocalExecutionRequest<'_>,
    ) -> Result<LocalExecutionOutcome, LocalExecutionError>;
}
