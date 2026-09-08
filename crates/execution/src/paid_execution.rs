//! DR-0124 execution-fee consent and policy wire boundary (2026-09-08).
//!
//! One `PaidIntent` and one `ExecutePaidContract` Ed25519 signature domain
//! covers Call, Instantiate and Publish. [`authenticate_paid_intent`] proves
//! only that the sender's Ed25519 key signed exact bytes under the expected
//! context: it is cryptographic authentication, not durable admission. It
//! proves neither current object ownership/version nor installed policy,
//! nonce freshness, publication provenance or available balance, and never
//! consults a fee policy. [`quote_paid_intent`] is the separate policy-check
//! and quote step: it takes the already-authenticated intent and a trusted
//! expected base/fee policy pair, checks context and digest equality, and
//! derives the immutable [`fees::reservation::Admission`] from the signed
//! application gas limit `L` and `max_fee`. Neither function grants durable
//! admission, and an authenticated zero-fee [`crate::local_execution`]
//! intent can never be converted into a paid wrapper by any function here.
//!
//! This module defines the paid wire types, their structural/cryptographic
//! validation, the injectable [`PaidContractEngine`] boundary with its public
//! request/outcome types, and [`verify_paid_execution_result`], the
//! independent receipt check. It runs no WASM itself and exports no
//! phase/grant/source API: the private reserve/application/settle coordinator
//! stays inside `crate::local_wasm`, whose [`crate::LocalWasmExecutionEngine`]
//! provides the only in-crate trait implementation. Nothing here is connected
//! to node-core, HTTP or the CLI.
use std::collections::BTreeSet;
use std::fmt;

use crate::call::{
    CallError, CallIntent, InstanceTarget, decode_instance_target, encode_instance_target,
};
use crate::call_authorization::{
    CallAuthorization, MAX_AUTHORIZED_INPUTS, MAX_CALL_AUTHORIZATION_BYTES,
    MAX_CALL_AUTHORIZATIONS, decode_call_authorizations, encode_call_authorizations,
    validate_call_authorizations,
};
use crate::local_execution::{LocalExecutionError, LocalExecutionPolicy};
use crate::publication::{
    CodeArtifact, MAX_PUBLICATION_BYTES, PublicationContext, PublicationError,
    UnverifiedDependencyRef, decode_code_artifact, decode_dependency_ref,
    decode_publication_context, encode_code_artifact, encode_dependency_ref,
    encode_publication_context,
};
use abi::AbiError;
use abi::package_types::{
    PackageTypeError, ScopedTypeArg, ScopedTypeTag, decode_scoped_type_arguments,
    decode_scoped_type_tag, encode_scoped_type_arguments, encode_scoped_type_tag,
};
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalStruct, decode_canonical_frame,
    decode_digest32, encode_digest32,
};
use crypto::{
    CryptoError, Ed25519OwnerAddressError, Ed25519OwnerAddressPolicy, Ed25519Verifier,
    SignatureDomain, SignatureMessageType, SignatureVerifier, frame_signature_message,
    validate_ed25519_owner_address,
};
use fees::reservation::{Admission, ReservationError, ReservationPricer};
use fees::{Amount, FeeError, GasSchedule, decode_gas_schedule, encode_gas_schedule};
use hashing::{HashSuiteResolver, HashingError};
use objects::{ObjectError, ObjectId, ObjectRef, decode_object_ref, encode_object_ref};
use protocol_types::{Digest32, HashPurpose, SignatureSchemeId};

pub(crate) mod engine;
mod result;
mod verify;

pub use engine::{
    PaidApplicationScopes, PaidContractEngine, PaidExecutionOutcome, PaidExecutionRequest,
    authenticate_paid_publication_candidate,
};
pub use result::{
    MAX_PAID_EXECUTION_RESULT_BYTES, PaidChargedOutcome, PaidExecutionResult, PaidExecutionStatus,
    PaidResultKind, PaidResultTarget, decode_paid_execution_result, encode_paid_execution_result,
};
pub use verify::verify_paid_execution_result;

/// Maximum bytes of one encoded [`FeeSourceConsent`].
pub const MAX_CONSENT_BYTES: usize = 256;
/// Maximum bytes of one encoded Call/Instantiate [`PaidApplication`].
pub const MAX_CALL_APPLICATION_BYTES: usize = crate::call::MAX_CALL_INTENT_BYTES + 64;
/// Maximum bytes of one encoded Publish [`PaidApplication`].
pub const MAX_PUBLISH_APPLICATION_BYTES: usize = MAX_PUBLICATION_BYTES + 64;
/// Maximum bytes of one encoded nonempty authorization table.
pub const MAX_AUTHORIZATION_TABLE_BYTES: usize = MAX_CALL_AUTHORIZATION_BYTES;
/// Maximum bytes of one encoded [`PaidIntent`] carrying a Publish application.
pub const MAX_PAID_INTENT_BYTES: usize =
    MAX_PUBLISH_APPLICATION_BYTES + MAX_CONSENT_BYTES + MAX_AUTHORIZATION_TABLE_BYTES + 1024;
/// Maximum bytes of one encoded [`PaidIntent`] carrying a Call/Instantiate application.
pub const MAX_PAID_INTENT_NONPUBLISH_BYTES: usize =
    MAX_CALL_APPLICATION_BYTES + MAX_CONSENT_BYTES + MAX_AUTHORIZATION_TABLE_BYTES + 1024;
/// Maximum bytes of one encoded [`SignedPaidIntent`] carrying a Publish application.
pub const MAX_SIGNED_PAID_INTENT_BYTES: usize = MAX_PAID_INTENT_BYTES + 128;
/// Maximum bytes of one encoded [`SignedPaidIntent`] carrying a Call/Instantiate application.
pub const MAX_SIGNED_PAID_INTENT_NONPUBLISH_BYTES: usize = MAX_PAID_INTENT_NONPUBLISH_BYTES + 128;
/// Maximum bytes of one encoded [`PaidFeePolicy`].
pub const MAX_PAID_FEE_POLICY_BYTES: usize = 16 * 1024;

// DR-0124 first-profile reserve/settle phase ceilings. `crate::phase_limits`
// is the single neutral crate-internal copy, read by both this policy wire
// boundary (which binds them as policy fields 17..22) and the private VM
// phase coordinator (which enforces them). The wire boundary therefore never
// makes the private coordinator module a public prerequisite, and there is
// no second independent ceiling.
use crate::phase_limits::{
    PHASE_CALLS, PHASE_CREATIONS, PHASE_EVENTS, PHASE_HANDLES, PHASE_MEMORY_BYTES,
    PHASE_OUTPUT_BYTES,
};

const CONSENT_TYPE: u16 = 0x6410;
const APPLICATION_TYPE: u16 = 0x6411;
const INTENT_TYPE: u16 = 0x6412;
const SIGNED_INTENT_TYPE: u16 = 0x6413;
const POLICY_TYPE: u16 = 0x6414;
const VERSION_1: u16 = 1;

const RESERVATION_ACCESS_WRITE: u16 = 1;
const RESERVATION_ACCESS_CONSUME: u16 = 2;

const APPLICATION_KIND_INSTANTIATE: u16 = 1;
const APPLICATION_KIND_CALL: u16 = 2;
const APPLICATION_KIND_PUBLISH: u16 = 3;

/// Errors from encoding, decoding, structural validation, authentication or
/// policy quoting in this wire boundary.
#[derive(Debug)]
pub enum PaidExecutionError {
    Invalid(&'static str),
    Limit(&'static str),
    Encoding(CanonicalEncodingError),
    Decoding(CanonicalDecodingError),
    Call(CallError),
    Publication(PublicationError),
    Package(PackageTypeError),
    Abi(AbiError),
    Object(ObjectError),
    Fee(FeeError),
    Reservation(ReservationError),
    /// Publication dependency-closure verification failed while pricing or
    /// authenticating a paid Publish application.
    Interface(crate::publication::InterfaceError),
    Local(LocalExecutionError),
    /// Existing effects codec or engine error.
    Execution(crate::ExecutionError),
    Hashing(HashingError),
    Crypto(CryptoError),
    Owner(Ed25519OwnerAddressError),
    /// Signed intent context differs from the expected/policy context.
    ContextMismatch,
    /// Ed25519 signature verification failed.
    InvalidSignature,
    /// The signed `fee_policy_digest` does not match the recomputed digest
    /// of the trusted expected [`PaidFeePolicy`].
    PolicyMismatch,
    /// The trusted expected [`PaidFeePolicy`]'s `base_policy_digest` does
    /// not match the trusted base [`LocalExecutionPolicy`], or that base
    /// policy is not the profile-four generic-object-result policy.
    BasePolicyMismatch,
}

impl fmt::Display for PaidExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid paid execution wire: {message}"),
            Self::Limit(message) => write!(f, "paid execution wire limit: {message}"),
            Self::Encoding(error) => error.fmt(f),
            Self::Decoding(error) => error.fmt(f),
            Self::Call(error) => error.fmt(f),
            Self::Publication(error) => error.fmt(f),
            Self::Package(error) => error.fmt(f),
            Self::Abi(error) => error.fmt(f),
            Self::Object(error) => error.fmt(f),
            Self::Fee(error) => error.fmt(f),
            Self::Reservation(error) => error.fmt(f),
            Self::Interface(error) => error.fmt(f),
            Self::Local(error) => error.fmt(f),
            Self::Execution(error) => error.fmt(f),
            Self::Hashing(error) => error.fmt(f),
            Self::Crypto(error) => error.fmt(f),
            Self::Owner(error) => error.fmt(f),
            Self::ContextMismatch => write!(f, "paid intent context does not match expected"),
            Self::InvalidSignature => write!(f, "paid intent signature verification failed"),
            Self::PolicyMismatch => write!(f, "paid intent fee-policy digest mismatch"),
            Self::BasePolicyMismatch => write!(f, "paid fee policy base-policy digest mismatch"),
        }
    }
}

impl std::error::Error for PaidExecutionError {}

macro_rules! from_error {
    ($source:ty, $variant:ident) => {
        impl From<$source> for PaidExecutionError {
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
from_error!(AbiError, Abi);
from_error!(ObjectError, Object);
from_error!(FeeError, Fee);
from_error!(ReservationError, Reservation);
from_error!(crate::publication::InterfaceError, Interface);
from_error!(LocalExecutionError, Local);
from_error!(crate::ExecutionError, Execution);
from_error!(HashingError, Hashing);
from_error!(CryptoError, Crypto);
from_error!(Ed25519OwnerAddressError, Owner);

#[inline]
fn bound(field: &'static str, actual: usize, maximum: usize) -> Result<(), PaidExecutionError> {
    if actual > maximum {
        Err(PaidExecutionError::Limit(field))
    } else {
        Ok(())
    }
}

fn to_array32(bytes: &[u8]) -> Result<[u8; 32], PaidExecutionError> {
    bytes
        .try_into()
        .map_err(|_| PaidExecutionError::Invalid("expected exactly 32 bytes"))
}

fn to_array64(bytes: &[u8]) -> Result<[u8; 64], PaidExecutionError> {
    bytes
        .try_into()
        .map_err(|_| PaidExecutionError::Invalid("expected exactly 64 bytes"))
}

fn validate_entrypoint_name(name: &str) -> Result<(), PaidExecutionError> {
    if name.is_empty() || name.len() > 64 || name == "memory" {
        return Err(PaidExecutionError::Invalid("policy entrypoint"));
    }
    Ok(())
}

/// The signed reservation access mode (DR-0124): `Write` debits the source
/// in place; `Consume` consumes the whole source and forbids the source
/// from also occurring in the application's declared access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationAccessKind {
    Write,
    Consume,
}

/// Consent fields 1..4: the original fee source [`ObjectRef`], the
/// reservation access mode, the maximum asset charge and the refund
/// recipient. The original owner is the envelope's sender; sponsorship or a
/// separately selected source owner is not part of this profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeSourceConsent {
    pub source: ObjectRef,
    pub access: ReservationAccessKind,
    pub max_fee: Amount,
    pub refund_recipient: [u8; 32],
}

/// Encodes Frame0x6410/v1.
pub fn encode_fee_source_consent(
    consent: &FeeSourceConsent,
) -> Result<Vec<u8>, PaidExecutionError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(CONSENT_TYPE, VERSION_1);
    frame.field_bytes(1, encode_object_ref(&consent.source)?)?;
    frame.field_u16(
        2,
        match consent.access {
            ReservationAccessKind::Write => RESERVATION_ACCESS_WRITE,
            ReservationAccessKind::Consume => RESERVATION_ACCESS_CONSUME,
        },
    )?;
    frame.field_u64(3, consent.max_fee.get())?;
    frame.field_bytes(4, consent.refund_recipient.to_vec())?;
    let bytes: Vec<u8> = frame.finish()?;
    bound("fee_source_consent", bytes.len(), MAX_CONSENT_BYTES)?;
    Ok(bytes)
}

/// Strictly decodes Frame0x6410/v1.
pub fn decode_fee_source_consent(bytes: &[u8]) -> Result<FeeSourceConsent, PaidExecutionError> {
    bound("fee_source_consent", bytes.len(), MAX_CONSENT_BYTES)?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(CONSENT_TYPE)?;
    frame.require_version(VERSION_1)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let source: ObjectRef = decode_object_ref(frame.required_field(1)?)?;
    let access: ReservationAccessKind = match frame.required_u16(2)? {
        RESERVATION_ACCESS_WRITE => ReservationAccessKind::Write,
        RESERVATION_ACCESS_CONSUME => ReservationAccessKind::Consume,
        _ => {
            return Err(PaidExecutionError::Invalid(
                "unknown reservation access mode",
            ));
        }
    };
    let max_fee: Amount = Amount::new(frame.required_u64(3)?);
    let refund_recipient: [u8; 32] = to_array32(frame.required_field(4)?)?;
    let consent: FeeSourceConsent = FeeSourceConsent {
        source,
        access,
        max_fee,
        refund_recipient,
    };
    if encode_fee_source_consent(&consent)? != bytes {
        return Err(PaidExecutionError::Invalid(
            "noncanonical fee source consent",
        ));
    }
    Ok(consent)
}

/// Application field 1 is kind (Instantiate=1, Call=2, Publish=3). Kinds
/// 1/2 carry an unsigned [`CallIntent`]; kind 3 carries an unsigned
/// [`CodeArtifact`]. `PublicationRequest` already contains a signature and
/// must never be nested here or populated with a dummy signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaidApplication {
    Instantiate(CallIntent),
    Call(CallIntent),
    Publish(CodeArtifact),
}

/// Encodes Frame0x6411/v1.
pub fn encode_paid_application(app: &PaidApplication) -> Result<Vec<u8>, PaidExecutionError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(APPLICATION_TYPE, VERSION_1);
    match app {
        PaidApplication::Instantiate(intent) => {
            frame.field_u16(1, APPLICATION_KIND_INSTANTIATE)?;
            frame.field_bytes(2, crate::call::encode_call_intent(intent)?)?;
        }
        PaidApplication::Call(intent) => {
            frame.field_u16(1, APPLICATION_KIND_CALL)?;
            frame.field_bytes(2, crate::call::encode_call_intent(intent)?)?;
        }
        PaidApplication::Publish(artifact) => {
            frame.field_u16(1, APPLICATION_KIND_PUBLISH)?;
            frame.field_bytes(3, encode_code_artifact(artifact)?)?;
        }
    }
    let bytes: Vec<u8> = frame.finish()?;
    let limit: usize = match app {
        PaidApplication::Publish(_) => MAX_PUBLISH_APPLICATION_BYTES,
        _ => MAX_CALL_APPLICATION_BYTES,
    };
    bound("paid_application", bytes.len(), limit)?;
    Ok(bytes)
}

/// Strictly decodes Frame0x6411/v1.
pub fn decode_paid_application(bytes: &[u8]) -> Result<PaidApplication, PaidExecutionError> {
    bound(
        "paid_application",
        bytes.len(),
        MAX_PUBLISH_APPLICATION_BYTES,
    )?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(APPLICATION_TYPE)?;
    frame.require_version(VERSION_1)?;
    let kind: u16 = frame.required_u16(1)?;
    let app: PaidApplication = match kind {
        APPLICATION_KIND_INSTANTIATE => {
            frame.require_only_fields(&[1, 2])?;
            PaidApplication::Instantiate(crate::call::decode_call_intent(frame.required_field(2)?)?)
        }
        APPLICATION_KIND_CALL => {
            frame.require_only_fields(&[1, 2])?;
            PaidApplication::Call(crate::call::decode_call_intent(frame.required_field(2)?)?)
        }
        APPLICATION_KIND_PUBLISH => {
            frame.require_only_fields(&[1, 3])?;
            PaidApplication::Publish(decode_code_artifact(frame.required_field(3)?)?)
        }
        _ => return Err(PaidExecutionError::Invalid("unknown paid application kind")),
    };
    if encode_paid_application(&app)? != bytes {
        return Err(PaidExecutionError::Invalid("noncanonical paid application"));
    }
    Ok(app)
}

/// Intent fields 1..8: context, request ID, sender, nonce, fee-policy
/// digest, consent, application and positive application gas limit `L`.
/// Field 9 carries the existing authorization table only when nonempty; an
/// explicit empty table is noncanonical. Authorizations are valid only for
/// `Call`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidIntent {
    pub context: PublicationContext,
    pub request_id: [u8; 32],
    pub sender: [u8; 32],
    pub nonce: u64,
    pub fee_policy_digest: Digest32,
    pub consent: FeeSourceConsent,
    pub application: PaidApplication,
    pub gas_limit: u64,
    pub authorizations: Vec<CallAuthorization>,
}

fn check_nested_call_fields(
    intent: &PaidIntent,
    inner: &CallIntent,
) -> Result<(), PaidExecutionError> {
    if inner.context != intent.context
        || inner.request_id != intent.request_id
        || inner.sender != intent.sender
        || inner.nonce != intent.nonce
        || inner.gas_limit != intent.gas_limit
    {
        return Err(PaidExecutionError::Invalid(
            "nested call intent does not match the paid envelope",
        ));
    }
    Ok(())
}

/// Checks the reservation-access/application-access overlap rule and bounds
/// the union of original inputs (declared source plus application access)
/// under the existing invocation-wide object bound.
fn check_source_overlap(intent: &PaidIntent, inner: &CallIntent) -> Result<(), PaidExecutionError> {
    let mut ids: BTreeSet<ObjectId> = BTreeSet::new();
    for entry in &inner.access.entries {
        ids.insert(entry.object_ref.id);
        if entry.object_ref.id == intent.consent.source.id {
            match intent.consent.access {
                ReservationAccessKind::Consume => {
                    return Err(PaidExecutionError::Invalid(
                        "consumed source in application access",
                    ));
                }
                ReservationAccessKind::Write => {
                    if entry.object_ref != intent.consent.source {
                        return Err(PaidExecutionError::Invalid("fee source reference mismatch"));
                    }
                }
            }
        }
    }
    ids.insert(intent.consent.source.id);
    if ids.len() > MAX_AUTHORIZED_INPUTS {
        return Err(PaidExecutionError::Limit("original inputs"));
    }
    Ok(())
}

/// Validates every cross-field structural rule from DR-0124's wire
/// boundary. This is shape validation only, not durable admission.
fn validate_paid_intent_structure(intent: &PaidIntent) -> Result<(), PaidExecutionError> {
    if intent.gas_limit == 0 {
        return Err(PaidExecutionError::Invalid("gas_limit must be > 0"));
    }
    if intent.authorizations.len() > MAX_CALL_AUTHORIZATIONS {
        return Err(PaidExecutionError::Limit("authorizations"));
    }
    match &intent.application {
        PaidApplication::Call(inner) => {
            check_nested_call_fields(intent, inner)?;
            validate_call_authorizations(inner, &intent.authorizations)?;
            check_source_overlap(intent, inner)?;
        }
        PaidApplication::Instantiate(inner) => {
            if !intent.authorizations.is_empty() {
                return Err(PaidExecutionError::Invalid(
                    "authorizations are valid only for Call",
                ));
            }
            check_nested_call_fields(intent, inner)?;
            if inner.sender != inner.instance.creator {
                return Err(PaidExecutionError::Invalid(
                    "instantiate sender must equal instance creator",
                ));
            }
            if !inner.access.entries.is_empty() {
                return Err(PaidExecutionError::Invalid(
                    "instantiate forbids application object inputs",
                ));
            }
            if !inner.type_arguments.is_empty() {
                return Err(PaidExecutionError::Invalid(
                    "instantiate forbids type arguments",
                ));
            }
            check_source_overlap(intent, inner)?;
        }
        PaidApplication::Publish(artifact) => {
            if !intent.authorizations.is_empty() {
                return Err(PaidExecutionError::Invalid(
                    "authorizations are valid only for Call",
                ));
            }
            if artifact.context() != &intent.context {
                return Err(PaidExecutionError::ContextMismatch);
            }
            if artifact.origin().publisher() != &intent.sender {
                return Err(PaidExecutionError::Invalid(
                    "publish publisher must equal sender",
                ));
            }
        }
    }
    Ok(())
}

/// Encodes Frame0x6412/v1.
pub fn encode_paid_intent(intent: &PaidIntent) -> Result<Vec<u8>, PaidExecutionError> {
    validate_paid_intent_structure(intent)?;
    let context_bytes: Vec<u8> = encode_publication_context(&intent.context)?;
    let consent_bytes: Vec<u8> = encode_fee_source_consent(&intent.consent)?;
    let application_bytes: Vec<u8> = encode_paid_application(&intent.application)?;

    let mut frame: CanonicalStruct = CanonicalStruct::new(INTENT_TYPE, VERSION_1);
    frame.field_bytes(1, context_bytes)?;
    frame.field_bytes(2, intent.request_id.to_vec())?;
    frame.field_bytes(3, intent.sender.to_vec())?;
    frame.field_u64(4, intent.nonce)?;
    frame.field_bytes(5, encode_digest32(&intent.fee_policy_digest)?)?;
    frame.field_bytes(6, consent_bytes)?;
    frame.field_bytes(7, application_bytes)?;
    frame.field_u64(8, intent.gas_limit)?;
    if !intent.authorizations.is_empty() {
        frame.field_bytes(9, encode_call_authorizations(&intent.authorizations)?)?;
    }
    let bytes: Vec<u8> = frame.finish()?;
    let limit: usize = match intent.application {
        PaidApplication::Publish(_) => MAX_PAID_INTENT_BYTES,
        _ => MAX_PAID_INTENT_NONPUBLISH_BYTES,
    };
    bound("paid_intent", bytes.len(), limit)?;
    Ok(bytes)
}

/// Strictly decodes Frame0x6412/v1.
pub fn decode_paid_intent(bytes: &[u8]) -> Result<PaidIntent, PaidExecutionError> {
    bound("paid_intent", bytes.len(), MAX_PAID_INTENT_BYTES)?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(INTENT_TYPE)?;
    frame.require_version(VERSION_1)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6, 7, 8, 9])?;

    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)?;
    let request_id: [u8; 32] = to_array32(frame.required_field(2)?)?;
    let sender: [u8; 32] = to_array32(frame.required_field(3)?)?;
    let nonce: u64 = frame.required_u64(4)?;
    let fee_policy_digest: Digest32 = decode_digest32(frame.required_field(5)?)?;
    let consent: FeeSourceConsent = decode_fee_source_consent(frame.required_field(6)?)?;
    let application: PaidApplication = decode_paid_application(frame.required_field(7)?)?;
    let gas_limit: u64 = frame.required_u64(8)?;
    if gas_limit == 0 {
        return Err(PaidExecutionError::Invalid("gas_limit must be > 0"));
    }
    let authorizations: Vec<CallAuthorization> = match frame.field(9) {
        Some(bytes) => {
            let table: Vec<CallAuthorization> = decode_call_authorizations(bytes)?;
            if table.is_empty() {
                return Err(PaidExecutionError::Invalid(
                    "noncanonical empty authorization table",
                ));
            }
            table
        }
        None => Vec::new(),
    };

    let intent: PaidIntent = PaidIntent {
        context,
        request_id,
        sender,
        nonce,
        fee_policy_digest,
        consent,
        application,
        gas_limit,
        authorizations,
    };
    validate_paid_intent_structure(&intent)?;
    if encode_paid_intent(&intent)? != bytes {
        return Err(PaidExecutionError::Invalid("noncanonical paid intent"));
    }
    Ok(intent)
}

/// Signed intent fields 1/2: the complete intent and its 64-byte signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPaidIntent {
    pub intent: PaidIntent,
    pub signature: [u8; 64],
}

/// Encodes Frame0x6413/v1.
pub fn encode_signed_paid_intent(signed: &SignedPaidIntent) -> Result<Vec<u8>, PaidExecutionError> {
    let intent_bytes: Vec<u8> = encode_paid_intent(&signed.intent)?;
    let mut frame: CanonicalStruct = CanonicalStruct::new(SIGNED_INTENT_TYPE, VERSION_1);
    frame.field_bytes(1, intent_bytes)?;
    frame.field_bytes(2, signed.signature.to_vec())?;
    let bytes: Vec<u8> = frame.finish()?;
    let limit: usize = match signed.intent.application {
        PaidApplication::Publish(_) => MAX_SIGNED_PAID_INTENT_BYTES,
        _ => MAX_SIGNED_PAID_INTENT_NONPUBLISH_BYTES,
    };
    bound("signed_paid_intent", bytes.len(), limit)?;
    Ok(bytes)
}

/// Decodes Frame0x6413/v1. Performs no context, key or signature
/// validation; see [`authenticate_paid_intent`].
pub fn decode_signed_paid_intent(bytes: &[u8]) -> Result<SignedPaidIntent, PaidExecutionError> {
    bound(
        "signed_paid_intent",
        bytes.len(),
        MAX_SIGNED_PAID_INTENT_BYTES,
    )?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(SIGNED_INTENT_TYPE)?;
    frame.require_version(VERSION_1)?;
    frame.require_only_fields(&[1, 2])?;
    let intent: PaidIntent = decode_paid_intent(frame.required_field(1)?)?;
    let signature: [u8; 64] = to_array64(frame.required_field(2)?)?;
    let signed: SignedPaidIntent = SignedPaidIntent { intent, signature };
    if encode_signed_paid_intent(&signed)? != bytes {
        return Err(PaidExecutionError::Invalid(
            "noncanonical signed paid intent",
        ));
    }
    Ok(signed)
}

/// Builds the exact byte frame a sender must sign under the single
/// `ExecutePaidContract` Ed25519 signature domain shared by Call,
/// Instantiate and Publish.
pub fn paid_intent_signing_frame(
    expected: &PublicationContext,
    intent: &PaidIntent,
) -> Result<Vec<u8>, PaidExecutionError> {
    if &intent.context != expected {
        return Err(PaidExecutionError::ContextMismatch);
    }
    let message: Vec<u8> = encode_paid_intent(intent)?;
    let domain: SignatureDomain = SignatureDomain {
        chain_id: expected.chain_id().clone(),
        protocol_version: expected.protocol_version(),
        epoch: expected.epoch(),
        message_type: SignatureMessageType::new("ExecutePaidContract")?,
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    Ok(frame_signature_message(&domain, &message)?)
}

/// A [`SignedPaidIntent`] whose context, sender key and signature have been
/// strictly validated against an expected [`PublicationContext`].
///
/// This is a cryptographic authentication witness only. It proves neither
/// current object ownership/version nor installed policy, nonce freshness,
/// publication provenance or available balance, and it never consults a
/// fee policy: see [`quote_paid_intent`] for the separate policy-check and
/// pricing step. It grants no durable admitted execution authority.
#[derive(Debug)]
pub struct AuthenticatedPaidIntent {
    signed: SignedPaidIntent,
}

impl AuthenticatedPaidIntent {
    /// Returns the immutable signature-authenticated intent, not execution rights.
    pub fn intent(&self) -> &PaidIntent {
        &self.signed.intent
    }

    /// Returns the immutable signature-authenticated complete signed intent,
    /// including the Ed25519 signature, not execution rights.
    pub fn signed(&self) -> &SignedPaidIntent {
        &self.signed
    }
}

/// Strictly decodes, checks context equality, validates the sender key and
/// verifies the Ed25519 signature of a [`SignedPaidIntent`] under the
/// shared `ExecutePaidContract` domain. Performs no policy check, ABI
/// resolution or I/O; see [`quote_paid_intent`].
pub fn authenticate_paid_intent(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
    bytes: &[u8],
) -> Result<AuthenticatedPaidIntent, PaidExecutionError> {
    let signed: SignedPaidIntent = decode_signed_paid_intent(bytes)?;

    if signed.intent.context != *expected {
        return Err(PaidExecutionError::ContextMismatch);
    }
    if resolver.chain_id() != expected.chain_id()
        || resolver.protocol_version() != expected.protocol_version()
    {
        return Err(PaidExecutionError::Invalid("trusted resolver context"));
    }

    validate_ed25519_owner_address(
        &signed.intent.sender,
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )?;

    let frame: Vec<u8> = paid_intent_signing_frame(expected, &signed.intent)?;
    let verifier: Ed25519Verifier =
        Ed25519Verifier::from_verifying_key_bytes(&signed.intent.sender)?;
    if !verifier.verify_framed(&frame, &signed.signature)? {
        return Err(PaidExecutionError::InvalidSignature);
    }

    Ok(AuthenticatedPaidIntent { signed })
}

/// Policy fields 1..16 bind context, base profile-4 execution-policy
/// digest, exact instance target, exact code reference, reserve/
/// reserve_all/settle export names, type arguments, asset type,
/// reservation type, schema, fee recipient, the existing `GasSchedule`
/// encoding and conversion divisor, and positive R/S allowances. Fields
/// 17..22 bind the calls/handles/creations/events/memory/output caps
/// shared by reserve/settle, fixed to this profile's stated limits. Fields
/// 23/24 bind positive Publish artifact-byte and closure-node
/// execution-unit prices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidFeePolicy {
    pub context: PublicationContext,
    pub base_policy_digest: Digest32,
    pub instance: InstanceTarget,
    pub code: UnverifiedDependencyRef,
    pub reserve_entrypoint: String,
    pub reserve_all_entrypoint: String,
    pub settle_entrypoint: String,
    pub type_arguments: Vec<ScopedTypeArg>,
    pub asset_type: ScopedTypeTag,
    pub reservation_type: ScopedTypeTag,
    pub schema: u32,
    pub fee_recipient: [u8; 32],
    pub gas_schedule: GasSchedule,
    pub conversion_divisor: u64,
    pub reserve_allowance: u64,
    pub settle_allowance: u64,
    pub calls: u32,
    pub handles: u32,
    pub creations: u32,
    pub events: u32,
    pub memory_bytes: u64,
    pub output_bytes: u64,
    pub publish_artifact_byte_price: u64,
    pub publish_closure_node_price: u64,
}

/// Validates every fixed DR-0124 policy invariant and returns the
/// [`ReservationPricer`] the policy commits to. Rejects unsupported
/// resource prices, invalid recipients, nonpositive actual fees at `A=0`,
/// arithmetic overflow, incompatible phase caps, non-positive Publish
/// prices, a zero schema, an asset/reservation type that alias each other
/// and an asset/reservation type not scoped to the policy's own code
/// origin. These are intrinsic wire checks only; the actual ABI/storage
/// authority for these types is a separate, still-deferred admission check.
fn validate_paid_fee_policy(
    policy: &PaidFeePolicy,
) -> Result<ReservationPricer, PaidExecutionError> {
    validate_entrypoint_name(&policy.reserve_entrypoint)?;
    validate_entrypoint_name(&policy.reserve_all_entrypoint)?;
    validate_entrypoint_name(&policy.settle_entrypoint)?;
    if policy.code.origin().chain_id() != policy.context.chain_id() {
        return Err(PaidExecutionError::Invalid("policy code chain"));
    }
    if policy.schema == 0 {
        return Err(PaidExecutionError::Invalid("policy schema must be nonzero"));
    }
    if policy.asset_type == policy.reservation_type {
        return Err(PaidExecutionError::Invalid(
            "policy asset and reservation types must differ",
        ));
    }
    if policy.asset_type.origin() != policy.code.origin()
        || policy.reservation_type.origin() != policy.code.origin()
    {
        return Err(PaidExecutionError::Invalid(
            "policy asset and reservation types must originate from the policy code",
        ));
    }
    validate_ed25519_owner_address(
        &policy.fee_recipient,
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )?;
    if policy.calls != PHASE_CALLS
        || policy.handles != PHASE_HANDLES as u32
        || policy.creations != PHASE_CREATIONS
        || policy.events != PHASE_EVENTS as u32
        || policy.memory_bytes != PHASE_MEMORY_BYTES as u64
        || policy.output_bytes != PHASE_OUTPUT_BYTES as u64
    {
        return Err(PaidExecutionError::Invalid("policy phase caps"));
    }
    if policy.publish_artifact_byte_price == 0 || policy.publish_closure_node_price == 0 {
        return Err(PaidExecutionError::Invalid(
            "publish prices must be positive",
        ));
    }
    let pricer: ReservationPricer = ReservationPricer::new(
        policy.gas_schedule.clone(),
        policy.conversion_divisor,
        policy.reserve_allowance,
        policy.settle_allowance,
    )?;
    let zero_usage: Admission = pricer.admit(0, Amount::new(u64::MAX))?;
    if zero_usage.settle(0)?.actual.get() == 0 {
        return Err(PaidExecutionError::Invalid(
            "policy must price a nonzero actual fee at A=0",
        ));
    }
    Ok(pricer)
}

/// Encodes Frame0x6414/v1.
pub fn encode_paid_fee_policy(policy: &PaidFeePolicy) -> Result<Vec<u8>, PaidExecutionError> {
    validate_paid_fee_policy(policy)?;
    let context_bytes: Vec<u8> = encode_publication_context(&policy.context)?;
    let instance_bytes: Vec<u8> = encode_instance_target(&policy.instance)?;
    let code_bytes: Vec<u8> = encode_dependency_ref(&policy.code)?;
    let type_args_bytes: Vec<u8> =
        encode_scoped_type_arguments(policy.context.chain_id(), &policy.type_arguments)?;
    let asset_bytes: Vec<u8> = encode_scoped_type_tag(&policy.asset_type)?;
    let reservation_bytes: Vec<u8> = encode_scoped_type_tag(&policy.reservation_type)?;
    let schedule_bytes: Vec<u8> = encode_gas_schedule(&policy.gas_schedule)?;

    let mut frame: CanonicalStruct = CanonicalStruct::new(POLICY_TYPE, VERSION_1);
    frame.field_bytes(1, context_bytes)?;
    frame.field_bytes(2, encode_digest32(&policy.base_policy_digest)?)?;
    frame.field_bytes(3, instance_bytes)?;
    frame.field_bytes(4, code_bytes)?;
    frame.field_str(5, &policy.reserve_entrypoint)?;
    frame.field_str(6, &policy.reserve_all_entrypoint)?;
    frame.field_str(7, &policy.settle_entrypoint)?;
    frame.field_bytes(8, type_args_bytes)?;
    frame.field_bytes(9, asset_bytes)?;
    frame.field_bytes(10, reservation_bytes)?;
    frame.field_u32(11, policy.schema)?;
    frame.field_bytes(12, policy.fee_recipient.to_vec())?;
    frame.field_bytes(13, schedule_bytes)?;
    frame.field_u64(14, policy.conversion_divisor)?;
    frame.field_u64(15, policy.reserve_allowance)?;
    frame.field_u64(16, policy.settle_allowance)?;
    frame.field_u32(17, policy.calls)?;
    frame.field_u32(18, policy.handles)?;
    frame.field_u32(19, policy.creations)?;
    frame.field_u32(20, policy.events)?;
    frame.field_u64(21, policy.memory_bytes)?;
    frame.field_u64(22, policy.output_bytes)?;
    frame.field_u64(23, policy.publish_artifact_byte_price)?;
    frame.field_u64(24, policy.publish_closure_node_price)?;
    let bytes: Vec<u8> = frame.finish()?;
    bound("paid_fee_policy", bytes.len(), MAX_PAID_FEE_POLICY_BYTES)?;
    Ok(bytes)
}

/// Strictly decodes Frame0x6414/v1.
pub fn decode_paid_fee_policy(bytes: &[u8]) -> Result<PaidFeePolicy, PaidExecutionError> {
    bound("paid_fee_policy", bytes.len(), MAX_PAID_FEE_POLICY_BYTES)?;
    let frame = decode_canonical_frame(bytes)?;
    frame.require_type(POLICY_TYPE)?;
    frame.require_version(VERSION_1)?;
    frame.require_only_fields(&[
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ])?;

    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)?;
    let base_policy_digest: Digest32 = decode_digest32(frame.required_field(2)?)?;
    let instance: InstanceTarget = decode_instance_target(frame.required_field(3)?)?;
    let code: UnverifiedDependencyRef = decode_dependency_ref(frame.required_field(4)?)?;
    let reserve_entrypoint: String = frame.required_str(5)?.to_owned();
    let reserve_all_entrypoint: String = frame.required_str(6)?.to_owned();
    let settle_entrypoint: String = frame.required_str(7)?.to_owned();
    let type_arguments: Vec<ScopedTypeArg> =
        decode_scoped_type_arguments(context.chain_id(), frame.required_field(8)?)?;
    let asset_type: ScopedTypeTag = decode_scoped_type_tag(frame.required_field(9)?)?;
    let reservation_type: ScopedTypeTag = decode_scoped_type_tag(frame.required_field(10)?)?;
    let schema: u32 = frame.required_u32(11)?;
    let fee_recipient: [u8; 32] = to_array32(frame.required_field(12)?)?;
    let gas_schedule: GasSchedule = decode_gas_schedule(frame.required_field(13)?)?;
    let conversion_divisor: u64 = frame.required_u64(14)?;
    let reserve_allowance: u64 = frame.required_u64(15)?;
    let settle_allowance: u64 = frame.required_u64(16)?;
    let calls: u32 = frame.required_u32(17)?;
    let handles: u32 = frame.required_u32(18)?;
    let creations: u32 = frame.required_u32(19)?;
    let events: u32 = frame.required_u32(20)?;
    let memory_bytes: u64 = frame.required_u64(21)?;
    let output_bytes: u64 = frame.required_u64(22)?;
    let publish_artifact_byte_price: u64 = frame.required_u64(23)?;
    let publish_closure_node_price: u64 = frame.required_u64(24)?;

    let policy: PaidFeePolicy = PaidFeePolicy {
        context,
        base_policy_digest,
        instance,
        code,
        reserve_entrypoint,
        reserve_all_entrypoint,
        settle_entrypoint,
        type_arguments,
        asset_type,
        reservation_type,
        schema,
        fee_recipient,
        gas_schedule,
        conversion_divisor,
        reserve_allowance,
        settle_allowance,
        calls,
        handles,
        creations,
        events,
        memory_bytes,
        output_bytes,
        publish_artifact_byte_price,
        publish_closure_node_price,
    };
    validate_paid_fee_policy(&policy)?;
    if encode_paid_fee_policy(&policy)? != bytes {
        return Err(PaidExecutionError::Invalid("noncanonical paid fee policy"));
    }
    Ok(policy)
}

/// Hashes the complete policy under the trusted context's `ProtocolConfig`
/// purpose. The base execution policy does not reference the fee policy,
/// and neither policy references an invocation, so commitments are
/// acyclic.
pub fn paid_fee_policy_digest(
    resolver: &HashSuiteResolver,
    policy: &PaidFeePolicy,
) -> Result<Digest32, PaidExecutionError> {
    if resolver.chain_id() != policy.context.chain_id()
        || resolver.protocol_version() != policy.context.protocol_version()
    {
        return Err(PaidExecutionError::Invalid("trusted resolver context"));
    }
    let bytes: Vec<u8> = encode_paid_fee_policy(policy)?;
    Ok(resolver.hash_for_purpose(policy.context.epoch(), HashPurpose::ProtocolConfig, &bytes)?)
}

/// Hashes the complete signed intent, including its Ed25519 signature, under
/// the trusted resolver's own chain/protocol-version context and
/// HashPurpose::NodeEvent. The resolver's context is trusted node
/// configuration, not attacker-controlled request input; it is validated
/// against the signed intent's own context and the digest never uses a
/// request-derived resolver.
pub fn paid_invocation_digest(
    resolver: &HashSuiteResolver,
    signed: &SignedPaidIntent,
) -> Result<Digest32, PaidExecutionError> {
    if resolver.chain_id() != signed.intent.context.chain_id()
        || resolver.protocol_version() != signed.intent.context.protocol_version()
    {
        return Err(PaidExecutionError::Invalid("trusted resolver context"));
    }
    let bytes: Vec<u8> = encode_signed_paid_intent(signed)?;
    Ok(resolver.hash_for_purpose(
        signed.intent.context.epoch(),
        HashPurpose::NodeEvent,
        &bytes,
    )?)
}

/// The separate policy-check and quote step (DR-0124, 2026-09-08 update):
/// takes an already cryptographically authenticated intent and a trusted
/// expected base/fee policy pair, checks their contexts and digest
/// equality, and derives the immutable [`Admission`] from the signed
/// application gas limit `L` and `max_fee`. Neither this function nor
/// [`authenticate_paid_intent`] grants durable admission; policy codec
/// validity and quote validity do not establish calibrated R/S,
/// installation, governance authority or storage authority.
pub fn quote_paid_intent(
    authenticated: &AuthenticatedPaidIntent,
    resolver: &HashSuiteResolver,
    base_policy: &LocalExecutionPolicy,
    fee_policy: &PaidFeePolicy,
) -> Result<Admission, PaidExecutionError> {
    let intent: &PaidIntent = authenticated.intent();
    if intent.context != fee_policy.context || intent.context != *base_policy.context() {
        return Err(PaidExecutionError::ContextMismatch);
    }
    validate_ed25519_owner_address(
        &intent.consent.refund_recipient,
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )?;
    if base_policy.profile() != crate::GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION {
        return Err(PaidExecutionError::BasePolicyMismatch);
    }
    let base_digest: Digest32 = base_policy.digest(resolver)?;
    if fee_policy.base_policy_digest != base_digest {
        return Err(PaidExecutionError::BasePolicyMismatch);
    }

    let pricer: ReservationPricer = validate_paid_fee_policy(fee_policy)?;
    let policy_digest: Digest32 = paid_fee_policy_digest(resolver, fee_policy)?;
    if intent.fee_policy_digest != policy_digest {
        return Err(PaidExecutionError::PolicyMismatch);
    }

    Ok(pricer.admit(intent.gas_limit, intent.consent.max_fee)?)
}
