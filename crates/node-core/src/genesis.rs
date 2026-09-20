//! Generic asset-agnostic closed genesis installer (DR-0126).
//!
//! Atomically installs the genesis manifest, publication, instance,
//! policies, paid fee policy, initialized objects, object authorities,
//! and closed marker using writer-fenced durable invocation machinery.
//!
//! Node core stays asset-agnostic: no Standard Asset amount or supply
//! field is decoded here.

use core::fmt;
use std::collections::BTreeSet;

use abi::package_types::PackageTypeError;
use canonical_encoding::{
    CanonicalDecodingError, CanonicalEncodingError, CanonicalFrame, CanonicalStruct,
    decode_canonical_frame, decode_digest32, encode_digest32,
};
use crypto::{
    CryptoError, Ed25519OwnerAddressError, Ed25519OwnerAddressPolicy, Ed25519Verifier,
    SignatureDomain, SignatureMessageType, SignatureVerifier, frame_signature_message,
    validate_ed25519_owner_address,
};
use execution::local_execution::{
    InstanceRecord, LocalExecutionError, LocalExecutionMode, LocalExecutionPolicy, ObjectAuthority,
    SignedLocalExecutionIntent, authenticate_local_execution, decode_object_authority,
    decode_signed_local_execution, encode_instance_record, encode_object_authority,
    encode_signed_local_execution, instance_target,
};
use execution::paid_execution::{
    MAX_PAID_FEE_POLICY_BYTES, PaidExecutionError, PaidFeePolicy, decode_paid_fee_policy,
    encode_paid_fee_policy, validate_fee_interface_admission,
};
use execution::publication::{
    BodyError, InterfaceError, PublicationContext, PublicationError, PublicationSubmission,
    VerifiedPublicationInterface, authenticate_publication_submission, decode_publication_context,
    decode_publication_submission, encode_publication_context, encode_publication_submission,
    verify_publication_interface,
};
use hashing::{HashSuiteResolver, HashingError};
use objects::{Object, ObjectError, Owner, decode_object, encode_object};
use protocol_types::{Digest32, HashPurpose, SignatureSchemeId};
use runtime::{
    AtomicStateReadSet, AtomicityDomainId, DurableCommitOutcome, DurableCommitRejection,
    DurableInvocationError, DurableInvocationTransaction, DurableObjectChanges, DurableObjectHead,
    DurableObjectHeadRead, DurableObjectMutation, DurableObjectMutationEntry,
    DurableObjectOwnerProjection, DurableObjectProvenance, DurableObjectRoutingProjection,
    DurableObjectVersion, DurableObjectVersionRecord, DurableOperationContext, DurableReadError,
    DurableRequestId, DurableRequestReceipt, DurableStateTransaction, IndeterminateCommitReason,
    RuntimeError, StateMutation, StateMutationEntry, StateReadAssertion, StateRevision,
    StructuredDurableDomainStateStore, VersionedStateValue,
};

use crate::local_execution::LocalExecutionAdmissionError;
use crate::local_instance_state;
use crate::publication::{self, LocalPublicationPolicy, PublicationAdmissionError};
use crate::{
    MAX_AUTHENTICATED_OBJECT_BODY_BYTES, NodeCoreError, NodeDedupRecord, RequestId,
    validate_transactional_state_key,
};

#[cfg(test)]
pub mod tests;

/// Canonical frame type of an encoded [`GenesisManifest`] (DR-0126).
pub const GENESIS_MANIFEST_FRAME_TYPE: u16 = 0x6416;
/// Canonical version of [`GenesisManifest`].
pub const GENESIS_MANIFEST_VERSION: u16 = 1;

/// Signature-domain message family for a complete genesis manifest payload.
pub const GENESIS_MANIFEST_SIGNATURE_MESSAGE_TYPE: &str = "genesis-manifest-v1";

/// Canonical frame type of an encoded [`GenesisInstallMarker`] (DR-0126).
pub const GENESIS_INSTALL_MARKER_FRAME_TYPE: u16 = 0x6417;
/// Canonical version of [`GenesisInstallMarker`].
pub const GENESIS_INSTALL_MARKER_VERSION: u16 = 1;

/// Canonical frame type of an encoded [`GenesisObjectEntry`].
pub const GENESIS_OBJECT_ENTRY_FRAME_TYPE: u16 = 0x6419;
/// Canonical version of [`GenesisObjectEntry`].
pub const GENESIS_OBJECT_ENTRY_VERSION: u16 = 1;

/// Canonical frame type of an encoded genesis object entry list.
pub const GENESIS_OBJECT_LIST_FRAME_TYPE: u16 = 0x641A;
/// Canonical version of genesis object entry list.
pub const GENESIS_OBJECT_LIST_VERSION: u16 = 1;

/// Maximum number of initialized objects admitted in one genesis manifest.
pub const MAX_GENESIS_OBJECTS: usize = 32;

/// Maximum byte size of an encoded [`GenesisManifest`].
pub const MAX_GENESIS_MANIFEST_BYTES: usize =
    execution::publication::MAX_PUBLICATION_SUBMISSION_BYTES
        + execution::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES
        + MAX_PAID_FEE_POLICY_BYTES
        + (MAX_GENESIS_OBJECTS * (MAX_AUTHENTICATED_OBJECT_BODY_BYTES + 4096))
        + 8192;

/// Maximum byte size of an encoded [`GenesisInstallMarker`].
pub const MAX_GENESIS_INSTALL_MARKER_BYTES: usize = 1024;

/// One initialized object and its associated authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisObjectEntry {
    /// Initialized object (must have version 1).
    pub object: Object,
    /// Host-stamped immutable object authority.
    pub authority: ObjectAuthority,
}

/// Canonical genesis manifest frame 0x6416/v1 (DR-0126).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisManifest {
    /// Fixed genesis authority public key (Ed25519).
    pub genesis_authority: [u8; 32],
    /// Exact pre-signed publication frame.
    pub publication: PublicationSubmission,
    /// Exact pre-signed initialization frame.
    pub initialization: SignedLocalExecutionIntent,
    /// Paid fee policy to install.
    pub fee_policy: PaidFeePolicy,
    /// Initialized objects and their authorities.
    pub objects: Vec<GenesisObjectEntry>,
    /// Ed25519 signature by `genesis_authority` over fields 1 through 5.
    pub signature: [u8; 64],
}

impl GenesisManifest {
    /// Returns the publication context bound to this manifest.
    #[must_use]
    pub fn context(&self) -> &PublicationContext {
        self.publication.request().artifact().context()
    }
}

/// Canonical closed install marker frame 0x6417/v1 (DR-0126).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisInstallMarker {
    /// Original publication context.
    pub context: PublicationContext,
    /// Exact manifest commitment digest.
    pub manifest_digest: Digest32,
    /// Genesis authority that signed the manifest entries.
    pub genesis_authority: [u8; 32],
    /// Checkpoint at which genesis was installed.
    pub installed_at_checkpoint: u64,
}

/// Outcome of attempting genesis installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenesisInstallOutcome {
    /// Genesis was freshly installed and committed atomically.
    FreshInstall {
        /// Installed marker.
        marker: GenesisInstallMarker,
        /// Manifest commitment digest.
        manifest_digest: Digest32,
    },
    /// Genesis was already closed and existing installed records verified.
    VerifiedExisting {
        /// Existing verified marker.
        marker: GenesisInstallMarker,
        /// Manifest commitment digest.
        manifest_digest: Digest32,
    },
}

/// Errors returned by the genesis installer.
#[derive(Debug)]
pub enum GenesisError {
    /// Canonical encoding error.
    CanonicalEncoding(CanonicalEncodingError),
    /// Canonical decoding error.
    CanonicalDecoding(CanonicalDecodingError),
    /// Bounded size limit exceeded.
    Limit(&'static str),
    /// Invariant or validation failure.
    Invalid(&'static str),
    /// Genesis authority does not match.
    GenesisAuthorityMismatch,
    /// Context does not match.
    ContextMismatch,
    /// Manifest commitment does not match installed marker.
    ManifestCommitmentMismatch,
    /// Missing installed record on restart verification.
    MissingInstalledRecord(&'static str),
    /// Tampered installed record on restart verification.
    TamperedInstalledRecord(&'static str),
    /// Tombstoned install marker observed.
    TombstonedMarker,
    /// Partial prior state exists without a closed marker.
    PartialPriorState(&'static str),
    /// Fee interface admission failure.
    FeeInterfaceAdmission(PaidExecutionError),
    /// Publication admission error.
    PublicationAdmission(PublicationAdmissionError),
    /// Publication error.
    Publication(PublicationError),
    /// Body validation error.
    Body(BodyError),
    /// Owner address error.
    OwnerAddress(Ed25519OwnerAddressError),
    /// Local execution admission error.
    LocalExecutionAdmission(Box<LocalExecutionAdmissionError>),
    /// Local execution error.
    LocalExecution(LocalExecutionError),
    /// Object error.
    Object(ObjectError),
    /// Runtime error.
    Runtime(RuntimeError),
    /// Durable read error.
    DurableRead(DurableReadError),
    /// Durable invocation error.
    DurableInvocation(DurableInvocationError),
    /// Durable commit rejected.
    CommitRejected(DurableCommitRejection),
    /// Durable commit indeterminate.
    CommitIndeterminate(IndeterminateCommitReason),
    /// Node core error.
    NodeCore(NodeCoreError),
    /// Crypto error.
    Crypto(CryptoError),
    /// Hashing error.
    Hashing(HashingError),
    /// Package type error.
    PackageType(PackageTypeError),
    /// Interface error.
    Interface(InterfaceError),
}

impl fmt::Display for GenesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEncoding(err) => write!(f, "canonical encoding error: {err}"),
            Self::CanonicalDecoding(err) => write!(f, "canonical decoding error: {err}"),
            Self::Limit(field) => write!(f, "limit exceeded: {field}"),
            Self::Invalid(msg) => write!(f, "invalid genesis data: {msg}"),
            Self::GenesisAuthorityMismatch => write!(f, "genesis authority mismatch"),
            Self::ContextMismatch => write!(f, "genesis context mismatch"),
            Self::ManifestCommitmentMismatch => write!(f, "genesis manifest commitment mismatch"),
            Self::MissingInstalledRecord(record) => {
                write!(f, "missing installed genesis record: {record}")
            }
            Self::TamperedInstalledRecord(record) => {
                write!(f, "tampered installed genesis record: {record}")
            }
            Self::TombstonedMarker => write!(f, "genesis install marker is tombstoned"),
            Self::PartialPriorState(msg) => {
                write!(f, "partial prior state without closed marker: {msg}")
            }
            Self::FeeInterfaceAdmission(err) => {
                write!(f, "fee interface admission failure: {err}")
            }
            Self::PublicationAdmission(err) => write!(f, "publication admission error: {err}"),
            Self::Publication(err) => write!(f, "publication error: {err}"),
            Self::Body(err) => write!(f, "body validation error: {err}"),
            Self::OwnerAddress(err) => write!(f, "owner address error: {err}"),
            Self::LocalExecutionAdmission(err) => {
                write!(f, "local execution admission error: {err}")
            }
            Self::LocalExecution(err) => write!(f, "local execution error: {err}"),
            Self::Object(err) => write!(f, "object error: {err}"),
            Self::Runtime(err) => write!(f, "runtime error: {err}"),
            Self::DurableRead(err) => write!(f, "durable read error: {err:?}"),
            Self::DurableInvocation(err) => write!(f, "durable invocation error: {err}"),
            Self::CommitRejected(rejection) => write!(f, "commit rejected: {rejection:?}"),
            Self::CommitIndeterminate(reason) => write!(f, "commit indeterminate: {reason:?}"),
            Self::NodeCore(err) => write!(f, "node core error: {err}"),
            Self::Crypto(err) => write!(f, "crypto error: {err}"),
            Self::Hashing(err) => write!(f, "hashing error: {err}"),
            Self::PackageType(err) => write!(f, "package type error: {err}"),
            Self::Interface(err) => write!(f, "interface error: {err}"),
        }
    }
}

impl std::error::Error for GenesisError {}

impl From<CanonicalEncodingError> for GenesisError {
    fn from(err: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(err)
    }
}

impl From<CanonicalDecodingError> for GenesisError {
    fn from(err: CanonicalDecodingError) -> Self {
        Self::CanonicalDecoding(err)
    }
}

impl From<PaidExecutionError> for GenesisError {
    fn from(err: PaidExecutionError) -> Self {
        Self::FeeInterfaceAdmission(err)
    }
}

impl From<PublicationAdmissionError> for GenesisError {
    fn from(err: PublicationAdmissionError) -> Self {
        Self::PublicationAdmission(err)
    }
}

impl From<PublicationError> for GenesisError {
    fn from(err: PublicationError) -> Self {
        Self::Publication(err)
    }
}

impl From<BodyError> for GenesisError {
    fn from(err: BodyError) -> Self {
        Self::Body(err)
    }
}

impl From<Ed25519OwnerAddressError> for GenesisError {
    fn from(err: Ed25519OwnerAddressError) -> Self {
        Self::OwnerAddress(err)
    }
}

impl From<LocalExecutionAdmissionError> for GenesisError {
    fn from(err: LocalExecutionAdmissionError) -> Self {
        Self::LocalExecutionAdmission(Box::new(err))
    }
}

impl From<LocalExecutionError> for GenesisError {
    fn from(err: LocalExecutionError) -> Self {
        Self::LocalExecution(err)
    }
}

impl From<ObjectError> for GenesisError {
    fn from(err: ObjectError) -> Self {
        Self::Object(err)
    }
}

impl From<RuntimeError> for GenesisError {
    fn from(err: RuntimeError) -> Self {
        Self::Runtime(err)
    }
}

impl From<DurableReadError> for GenesisError {
    fn from(err: DurableReadError) -> Self {
        Self::DurableRead(err)
    }
}

impl From<DurableInvocationError> for GenesisError {
    fn from(err: DurableInvocationError) -> Self {
        Self::DurableInvocation(err)
    }
}

impl From<NodeCoreError> for GenesisError {
    fn from(err: NodeCoreError) -> Self {
        Self::NodeCore(err)
    }
}

impl From<CryptoError> for GenesisError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl From<HashingError> for GenesisError {
    fn from(err: HashingError) -> Self {
        Self::Hashing(err)
    }
}

impl From<PackageTypeError> for GenesisError {
    fn from(err: PackageTypeError) -> Self {
        Self::PackageType(err)
    }
}

impl From<InterfaceError> for GenesisError {
    fn from(err: InterfaceError) -> Self {
        Self::Interface(err)
    }
}

/// Encodes one [`GenesisObjectEntry`].
pub fn encode_genesis_object_entry(entry: &GenesisObjectEntry) -> Result<Vec<u8>, GenesisError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(
        GENESIS_OBJECT_ENTRY_FRAME_TYPE,
        GENESIS_OBJECT_ENTRY_VERSION,
    );
    frame.field_bytes(1, encode_object(&entry.object)?)?;
    frame.field_bytes(2, encode_object_authority(&entry.authority)?)?;
    Ok(frame.finish()?)
}

/// Strictly decodes one [`GenesisObjectEntry`].
pub fn decode_genesis_object_entry(bytes: &[u8]) -> Result<GenesisObjectEntry, GenesisError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(GENESIS_OBJECT_ENTRY_FRAME_TYPE)?;
    frame.require_version(GENESIS_OBJECT_ENTRY_VERSION)?;
    frame.require_only_fields(&[1, 2])?;
    let object: Object = decode_object(frame.required_field(1)?)?;
    let authority: ObjectAuthority = decode_object_authority(frame.required_field(2)?)?;
    let entry: GenesisObjectEntry = GenesisObjectEntry { object, authority };
    if encode_genesis_object_entry(&entry)? != bytes {
        return Err(GenesisError::Invalid("noncanonical genesis object entry"));
    }
    Ok(entry)
}

/// Encodes a list of [`GenesisObjectEntry`].
pub fn encode_genesis_object_entries(
    entries: &[GenesisObjectEntry],
) -> Result<Vec<u8>, GenesisError> {
    if entries.len() > MAX_GENESIS_OBJECTS {
        return Err(GenesisError::Limit("too many genesis objects"));
    }
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(GENESIS_OBJECT_LIST_FRAME_TYPE, GENESIS_OBJECT_LIST_VERSION);
    frame.field_u32(
        1,
        u32::try_from(entries.len()).map_err(|_| GenesisError::Limit("objects count"))?,
    )?;
    for (index, entry) in entries.iter().enumerate() {
        let field_id: u16 =
            u16::try_from(index + 2).map_err(|_| GenesisError::Limit("objects field id"))?;
        frame.field_bytes(field_id, encode_genesis_object_entry(entry)?)?;
    }
    Ok(frame.finish()?)
}

/// Strictly decodes a list of [`GenesisObjectEntry`].
pub fn decode_genesis_object_entries(
    bytes: &[u8],
) -> Result<Vec<GenesisObjectEntry>, GenesisError> {
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(GENESIS_OBJECT_LIST_FRAME_TYPE)?;
    frame.require_version(GENESIS_OBJECT_LIST_VERSION)?;
    let count: usize = frame.required_u32(1)? as usize;
    if count > MAX_GENESIS_OBJECTS {
        return Err(GenesisError::Limit("too many genesis objects"));
    }
    let mut expected_fields: Vec<u16> = Vec::with_capacity(count + 1);
    expected_fields.push(1);
    for idx in 0..count {
        expected_fields
            .push(u16::try_from(idx + 2).map_err(|_| GenesisError::Limit("objects field id"))?);
    }
    frame.require_only_fields(&expected_fields)?;
    let mut entries: Vec<GenesisObjectEntry> = Vec::with_capacity(count);
    for idx in 0..count {
        let field_id: u16 =
            u16::try_from(idx + 2).map_err(|_| GenesisError::Limit("objects field id"))?;
        let entry_bytes: &[u8] = frame.required_field(field_id)?;
        entries.push(decode_genesis_object_entry(entry_bytes)?);
    }
    if encode_genesis_object_entries(&entries)? != bytes {
        return Err(GenesisError::Invalid("noncanonical genesis objects list"));
    }
    Ok(entries)
}

fn encode_genesis_manifest_payload(manifest: &GenesisManifest) -> Result<Vec<u8>, GenesisError> {
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(GENESIS_MANIFEST_FRAME_TYPE, GENESIS_MANIFEST_VERSION);
    frame.field_bytes(1, manifest.genesis_authority.to_vec())?;
    frame.field_bytes(2, encode_publication_submission(&manifest.publication)?)?;
    frame.field_bytes(3, encode_signed_local_execution(&manifest.initialization)?)?;
    frame.field_bytes(4, encode_paid_fee_policy(&manifest.fee_policy)?)?;
    frame.field_bytes(5, encode_genesis_object_entries(&manifest.objects)?)?;
    Ok(frame.finish()?)
}

/// Returns the exact domain-separated bytes signed by the genesis authority.
///
/// The payload is the canonical manifest frame containing fields 1 through 5;
/// the outer stored frame adds the signature as field 6. This binds every
/// initialized object and authority without creating a circular signature.
pub fn genesis_manifest_signing_frame(manifest: &GenesisManifest) -> Result<Vec<u8>, GenesisError> {
    let context: &PublicationContext = manifest.context();
    let domain: SignatureDomain = SignatureDomain {
        chain_id: context.chain_id().clone(),
        protocol_version: context.protocol_version(),
        epoch: context.epoch(),
        message_type: SignatureMessageType::new(GENESIS_MANIFEST_SIGNATURE_MESSAGE_TYPE)?,
        signature_scheme_id: SignatureSchemeId::Ed25519,
    };
    Ok(frame_signature_message(
        &domain,
        &encode_genesis_manifest_payload(manifest)?,
    )?)
}

/// Encodes canonical frame `0x6416/v1` ([`GenesisManifest`]).
pub fn encode_genesis_manifest(manifest: &GenesisManifest) -> Result<Vec<u8>, GenesisError> {
    let payload: Vec<u8> = encode_genesis_manifest_payload(manifest)?;
    let decoded: CanonicalFrame<'_> = decode_canonical_frame(&payload)?;
    let mut frame: CanonicalStruct =
        CanonicalStruct::new(GENESIS_MANIFEST_FRAME_TYPE, GENESIS_MANIFEST_VERSION);
    for field_id in 1_u16..=5_u16 {
        frame.field_bytes(field_id, decoded.required_field(field_id)?)?;
    }
    frame.field_bytes(6, manifest.signature.to_vec())?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_GENESIS_MANIFEST_BYTES {
        return Err(GenesisError::Limit("manifest bytes"));
    }
    Ok(bytes)
}

/// Strictly decodes canonical frame `0x6416/v1` ([`GenesisManifest`]).
pub fn decode_genesis_manifest(bytes: &[u8]) -> Result<GenesisManifest, GenesisError> {
    if bytes.len() > MAX_GENESIS_MANIFEST_BYTES {
        return Err(GenesisError::Limit("manifest bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(GENESIS_MANIFEST_FRAME_TYPE)?;
    frame.require_version(GENESIS_MANIFEST_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
    let authority_bytes: &[u8] = frame.required_field(1)?;
    let genesis_authority: [u8; 32] = authority_bytes
        .try_into()
        .map_err(|_| GenesisError::Invalid("genesis authority length"))?;
    let publication: PublicationSubmission =
        decode_publication_submission(frame.required_field(2)?)?;
    let initialization: SignedLocalExecutionIntent =
        decode_signed_local_execution(frame.required_field(3)?)?;
    let fee_policy: PaidFeePolicy = decode_paid_fee_policy(frame.required_field(4)?)?;
    let objects: Vec<GenesisObjectEntry> = decode_genesis_object_entries(frame.required_field(5)?)?;
    let signature_bytes: &[u8] = frame.required_field(6)?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| GenesisError::Invalid("genesis manifest signature length"))?;
    let manifest: GenesisManifest = GenesisManifest {
        genesis_authority,
        publication,
        initialization,
        fee_policy,
        objects,
        signature,
    };
    if encode_genesis_manifest(&manifest)? != bytes {
        return Err(GenesisError::Invalid("noncanonical genesis manifest"));
    }
    Ok(manifest)
}

/// Encodes canonical frame `0x6417/v1` ([`GenesisInstallMarker`]).
pub fn encode_genesis_install_marker(
    marker: &GenesisInstallMarker,
) -> Result<Vec<u8>, GenesisError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(
        GENESIS_INSTALL_MARKER_FRAME_TYPE,
        GENESIS_INSTALL_MARKER_VERSION,
    );
    frame.field_bytes(1, encode_publication_context(&marker.context)?)?;
    frame.field_bytes(2, encode_digest32(&marker.manifest_digest)?)?;
    frame.field_bytes(3, marker.genesis_authority.to_vec())?;
    frame.field_u64(4, marker.installed_at_checkpoint)?;
    let bytes: Vec<u8> = frame.finish()?;
    if bytes.len() > MAX_GENESIS_INSTALL_MARKER_BYTES {
        return Err(GenesisError::Limit("marker bytes"));
    }
    Ok(bytes)
}

/// Strictly decodes canonical frame `0x6417/v1` ([`GenesisInstallMarker`]).
pub fn decode_genesis_install_marker(bytes: &[u8]) -> Result<GenesisInstallMarker, GenesisError> {
    if bytes.len() > MAX_GENESIS_INSTALL_MARKER_BYTES {
        return Err(GenesisError::Limit("marker bytes"));
    }
    let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
    frame.require_type(GENESIS_INSTALL_MARKER_FRAME_TYPE)?;
    frame.require_version(GENESIS_INSTALL_MARKER_VERSION)?;
    frame.require_only_fields(&[1, 2, 3, 4])?;
    let context: PublicationContext = decode_publication_context(frame.required_field(1)?)?;
    let manifest_digest: Digest32 = decode_digest32(frame.required_field(2)?)?;
    let authority_bytes: &[u8] = frame.required_field(3)?;
    let genesis_authority: [u8; 32] = authority_bytes
        .try_into()
        .map_err(|_| GenesisError::Invalid("genesis authority length"))?;
    let installed_at_checkpoint: u64 = frame.required_u64(4)?;
    let marker: GenesisInstallMarker = GenesisInstallMarker {
        context,
        manifest_digest,
        genesis_authority,
        installed_at_checkpoint,
    };
    if encode_genesis_install_marker(&marker)? != bytes {
        return Err(GenesisError::Invalid("noncanonical genesis install marker"));
    }
    Ok(marker)
}

/// Computes the exact manifest commitment digest.
pub fn genesis_manifest_commitment(
    resolver: &HashSuiteResolver,
    manifest: &GenesisManifest,
) -> Result<Digest32, GenesisError> {
    let manifest_bytes: Vec<u8> = encode_genesis_manifest(manifest)?;
    Ok(resolver.hash_for_purpose(
        manifest.context().epoch(),
        HashPurpose::ProtocolConfig,
        &manifest_bytes,
    )?)
}

/// State key for storing the genesis manifest, bound to [`PublicationContext`].
pub fn genesis_manifest_key(context: &PublicationContext) -> Result<Vec<u8>, GenesisError> {
    let mut key: Vec<u8> = local_instance_state::INSTANCE_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"v1/genesis-manifest/");
    key.extend(
        encode_publication_context(context)
            .map_err(|_| GenesisError::Invalid("invalid genesis manifest context"))?,
    );
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// State key for storing the genesis install marker, bound to [`PublicationContext`].
pub fn genesis_marker_key(context: &PublicationContext) -> Result<Vec<u8>, GenesisError> {
    let mut key: Vec<u8> = local_instance_state::INSTANCE_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"v1/genesis-marker/");
    key.extend(
        encode_publication_context(context)
            .map_err(|_| GenesisError::Invalid("invalid genesis marker context"))?,
    );
    validate_transactional_state_key(&key)?;
    Ok(key)
}

/// Fenced atomic genesis installation without historical resolvers.
pub fn install_genesis<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    manifest: &GenesisManifest,
    checkpoint: u64,
) -> Result<GenesisInstallOutcome, GenesisError> {
    install_genesis_with_history(store, context, domain, resolver, &[], manifest, checkpoint)
}

/// Fenced atomic genesis installation with explicit historical resolvers.
pub fn install_genesis_with_history<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    manifest: &GenesisManifest,
    checkpoint: u64,
) -> Result<GenesisInstallOutcome, GenesisError> {
    // 1. Strict canonical manifest round-trip and bound checks.
    let manifest_bytes: Vec<u8> = encode_genesis_manifest(manifest)?;
    let decoded_manifest: GenesisManifest = decode_genesis_manifest(&manifest_bytes)?;
    if &decoded_manifest != manifest {
        return Err(GenesisError::Invalid("manifest round-trip mismatch"));
    }

    // 2. Genesis authority shape check.
    if manifest.genesis_authority == [0; 32] {
        return Err(GenesisError::Invalid("zero genesis authority"));
    }
    validate_ed25519_owner_address(
        &manifest.genesis_authority,
        Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
    )?;

    // The publication and initializer signatures bind their own requests.
    // This additional signature binds the complete bootstrap result set,
    // including all initialized objects and authorities, before any state I/O.
    let manifest_verifier: Ed25519Verifier =
        Ed25519Verifier::from_verifying_key_bytes(&manifest.genesis_authority)?;
    let manifest_signing_frame: Vec<u8> = genesis_manifest_signing_frame(manifest)?;
    if !manifest_verifier.verify_framed(&manifest_signing_frame, &manifest.signature)? {
        return Err(GenesisError::Invalid("invalid genesis manifest signature"));
    }

    // 3. Context and genesis authority consistency checks.
    let manifest_context: &PublicationContext = manifest.context();
    if &manifest.initialization.intent.call.context != manifest_context {
        return Err(GenesisError::ContextMismatch);
    }
    if &manifest.fee_policy.context != manifest_context {
        return Err(GenesisError::ContextMismatch);
    }
    if manifest
        .publication
        .request()
        .artifact()
        .origin()
        .chain_id()
        != manifest_context.chain_id()
    {
        return Err(GenesisError::ContextMismatch);
    }

    if manifest
        .publication
        .request()
        .artifact()
        .origin()
        .publisher()
        != &manifest.genesis_authority
    {
        return Err(GenesisError::GenesisAuthorityMismatch);
    }
    if manifest.initialization.intent.call.sender != manifest.genesis_authority {
        return Err(GenesisError::GenesisAuthorityMismatch);
    }
    if manifest.initialization.intent.call.instance.creator != manifest.genesis_authority {
        return Err(GenesisError::GenesisAuthorityMismatch);
    }

    // Genesis publication must be self-contained (no external dependencies).
    if !manifest
        .publication
        .request()
        .artifact()
        .unverified_dependencies()
        .is_empty()
    {
        return Err(GenesisError::Invalid(
            "genesis publication must have no dependencies",
        ));
    }

    // 4. Authenticate publication submission.
    let publication_semantics: Digest32 =
        execution::local_execution::generic_object_result_semantics(resolver, manifest_context)?;
    let candidate = authenticate_publication_submission(
        resolver,
        manifest_context,
        &publication_semantics,
        manifest.publication.clone(),
    )?;
    let interface: VerifiedPublicationInterface =
        verify_publication_interface(candidate, Vec::new())?;
    crate::local_execution::validate_closure(resolver, history, &interface)?;

    // 5. Authenticate initialization intent.
    if manifest.initialization.intent.mode != LocalExecutionMode::Instantiate {
        return Err(GenesisError::Invalid(
            "genesis initialization mode must be Instantiate",
        ));
    }
    let metadata = interface
        .executable_abi(manifest.initialization.intent.call.code.origin())
        .ok_or(GenesisError::Invalid("nonexecutable genesis code"))?;
    if metadata.initializer.as_deref()
        != Some(manifest.initialization.intent.call.entrypoint.as_str())
    {
        return Err(GenesisError::Invalid("initializer designation mismatch"));
    }
    if manifest.initialization.intent.call.code.origin()
        != manifest.publication.request().artifact().origin()
    {
        return Err(GenesisError::Invalid("initialization code origin mismatch"));
    }
    if manifest.initialization.intent.call.code.artifact_digest()
        != manifest.publication.request().artifact_digest()
    {
        return Err(GenesisError::Invalid("initialization code digest mismatch"));
    }

    let execution_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(manifest_context.clone());
    let execution_policy_digest: Digest32 = execution_policy.digest(resolver)?;
    if manifest.initialization.intent.policy_digest != execution_policy_digest {
        return Err(GenesisError::Invalid("execution policy digest mismatch"));
    }
    let encoded_init: Vec<u8> = encode_signed_local_execution(&manifest.initialization)?;
    let _authenticated_init =
        authenticate_local_execution(resolver, &execution_policy, &encoded_init)?;

    let instance_record: InstanceRecord = InstanceRecord {
        context: manifest_context.clone(),
        creator: manifest.initialization.intent.call.instance.creator,
        seed: manifest.initialization.intent.call.instance.seed,
        code: manifest.initialization.intent.call.code.clone(),
        revision: 1,
        initializer: manifest.initialization.intent.call.entrypoint.clone(),
    };
    let expected_target = instance_target(resolver, &instance_record)?;
    if manifest.initialization.intent.call.instance != expected_target {
        return Err(GenesisError::Invalid("instance target mismatch"));
    }

    // 6. Validate paid fee policy and fee interface admission.
    let fee_bytes: Vec<u8> = encode_paid_fee_policy(&manifest.fee_policy)?;
    let _ = decode_paid_fee_policy(&fee_bytes)?;
    if manifest.fee_policy.code != manifest.initialization.intent.call.code {
        return Err(GenesisError::Invalid("fee policy code mismatch"));
    }
    if manifest.fee_policy.instance != expected_target {
        return Err(GenesisError::Invalid("fee policy instance mismatch"));
    }
    validate_fee_interface_admission(&interface, &manifest.fee_policy)?;

    // 7. Validate initialized objects.
    if manifest.objects.len() > MAX_GENESIS_OBJECTS {
        return Err(GenesisError::Limit("too many genesis objects"));
    }
    let mut seen_ids: BTreeSet<objects::ObjectId> = BTreeSet::new();
    for entry in &manifest.objects {
        if !seen_ids.insert(entry.object.id) {
            return Err(GenesisError::Invalid("duplicate genesis object id"));
        }
        if entry.object.version != 1 {
            return Err(GenesisError::Invalid("genesis object version must be 1"));
        }
        if entry.authority.object_id != entry.object.id {
            return Err(GenesisError::Invalid("object authority id mismatch"));
        }
        if entry.authority.instance != expected_target {
            return Err(GenesisError::Invalid("object authority instance mismatch"));
        }
        if entry.authority.code != manifest.initialization.intent.call.code {
            return Err(GenesisError::Invalid("object authority code mismatch"));
        }
        if &entry.authority.instance_context != manifest_context {
            return Err(GenesisError::ContextMismatch);
        }
        let Owner::Address(owner_addr) = &entry.object.owner else {
            return Err(GenesisError::Invalid(
                "genesis object owner must be an Address",
            ));
        };
        validate_ed25519_owner_address(
            owner_addr.as_bytes(),
            Ed25519OwnerAddressPolicy::CanonicalPrimeOrder,
        )?;
        execution::publication::validate_nominal_body(
            &interface,
            &entry.authority.ty,
            entry.object.schema_version,
            &entry.object.data,
        )?;
        if !abi::package_types::verify_scoped_type_id(
            resolver,
            &entry.object.type_hash,
            manifest_context.epoch(),
            &entry.authority.ty,
        )? {
            return Err(GenesisError::Invalid(
                "genesis object type fingerprint mismatch",
            ));
        }
    }

    // 8. Manifest commitment and expected payloads.
    let manifest_digest: Digest32 = genesis_manifest_commitment(resolver, manifest)?;

    let manifest_key: Vec<u8> = genesis_manifest_key(manifest_context)?;
    let marker_key: Vec<u8> = genesis_marker_key(manifest_context)?;
    let publication_key: Vec<u8> =
        publication::publication_record_key(manifest.publication.request().artifact().origin())?;
    let instance_key: Vec<u8> = local_instance_state::instance_record_key(
        manifest_context.chain_id(),
        &instance_record.creator,
        &instance_record.seed,
    )?;
    let pub_policy_key: Vec<u8> =
        publication::publication_policy_key_for_profile(manifest_context, 4)?;
    let exec_policy_key: Vec<u8> =
        local_instance_state::execution_policy_key_for_profile(manifest_context, 4)?;
    let fee_policy_key: Vec<u8> = local_instance_state::paid_fee_policy_key(manifest_context)?;

    let publication_policy: LocalPublicationPolicy =
        LocalPublicationPolicy::object_results(manifest_context.clone(), publication_semantics);
    let publication_policy_bytes: Vec<u8> = publication_policy.encode()?;
    let execution_policy_bytes: Vec<u8> = execution_policy.encode()?;
    let fee_policy_bytes: Vec<u8> = encode_paid_fee_policy(&manifest.fee_policy)?;
    let instance_bytes: Vec<u8> = encode_instance_record(&instance_record)?;
    let publication_bytes: Vec<u8> = encode_publication_submission(&manifest.publication)?;
    let publication_event_digest: Digest32 = resolver.hash_for_purpose(
        manifest_context.epoch(),
        HashPurpose::NodeEvent,
        &publication_bytes,
    )?;
    let publication_request_id: RequestId = RequestId::new(*manifest.publication.request_id())?;
    let publication_output = publication::publication_output(&manifest.publication)?;
    let publication_dedup: NodeDedupRecord = NodeDedupRecord::new(
        publication_request_id,
        publication_event_digest,
        publication_output.responses().to_vec(),
    )?;
    let publication_durable_id: DurableRequestId =
        DurableRequestId::new(*publication_request_id.as_bytes())
            .map_err(|_| GenesisError::Invalid("invalid publication request id"))?;
    let publication_receipt: DurableRequestReceipt = DurableRequestReceipt::new(
        publication_durable_id,
        publication_event_digest,
        publication_dedup.encode()?,
    )?;

    // 9. Check marker presence.
    let marker_obs: VersionedStateValue =
        store.get_versioned_durable(context, domain, &marker_key)?;

    if let Some(marker_bytes) = marker_obs.value() {
        // =================================================================
        // RESTART VERIFY-ONLY PATH
        // =================================================================
        let marker: GenesisInstallMarker = decode_genesis_install_marker(marker_bytes)?;
        if marker.manifest_digest != manifest_digest {
            return Err(GenesisError::ManifestCommitmentMismatch);
        }
        if marker.genesis_authority != manifest.genesis_authority {
            return Err(GenesisError::GenesisAuthorityMismatch);
        }
        if &marker.context != manifest_context {
            return Err(GenesisError::ContextMismatch);
        }

        // Verify installed manifest.
        let obs: VersionedStateValue =
            store.get_versioned_durable(context, domain, &manifest_key)?;
        if obs.value() != Some(manifest_bytes.as_slice()) {
            return Err(GenesisError::TamperedInstalledRecord("manifest"));
        }

        // Verify installed publication record.
        let obs: VersionedStateValue =
            store.get_versioned_durable(context, domain, &publication_key)?;
        if obs.value() != Some(publication_bytes.as_slice()) {
            return Err(GenesisError::TamperedInstalledRecord("publication record"));
        }
        let installed_receipt: DurableRequestReceipt = store
            .get_request_receipt(context, domain, publication_durable_id)?
            .ok_or(GenesisError::MissingInstalledRecord("publication receipt"))?;
        if installed_receipt != publication_receipt {
            return Err(GenesisError::TamperedInstalledRecord("publication receipt"));
        }

        // Verify installed instance record.
        let obs: VersionedStateValue =
            store.get_versioned_durable(context, domain, &instance_key)?;
        if obs.value() != Some(instance_bytes.as_slice()) {
            return Err(GenesisError::TamperedInstalledRecord("instance record"));
        }

        // Verify installed publication policy.
        let obs: VersionedStateValue =
            store.get_versioned_durable(context, domain, &pub_policy_key)?;
        if obs.value() != Some(publication_policy_bytes.as_slice()) {
            return Err(GenesisError::TamperedInstalledRecord("publication policy"));
        }

        // Verify installed execution policy.
        let obs: VersionedStateValue =
            store.get_versioned_durable(context, domain, &exec_policy_key)?;
        if obs.value() != Some(execution_policy_bytes.as_slice()) {
            return Err(GenesisError::TamperedInstalledRecord("execution policy"));
        }

        // Verify installed fee policy.
        let obs: VersionedStateValue =
            store.get_versioned_durable(context, domain, &fee_policy_key)?;
        if obs.value() != Some(fee_policy_bytes.as_slice()) {
            return Err(GenesisError::TamperedInstalledRecord("fee policy"));
        }

        // Verify initialized objects and authorities.
        for entry in &manifest.objects {
            let auth_key: Vec<u8> = local_instance_state::object_authority_key(entry.object.id);
            let auth_bytes: Vec<u8> = encode_object_authority(&entry.authority)?;
            let obs: VersionedStateValue =
                store.get_versioned_durable(context, domain, &auth_key)?;
            if obs.value() != Some(auth_bytes.as_slice()) {
                return Err(GenesisError::TamperedInstalledRecord("object authority"));
            }

            let ver_obs: Option<DurableObjectVersionRecord> = store.get_object_version(
                context,
                domain,
                entry.object.id,
                DurableObjectVersion::FIRST,
            )?;
            let Some(ver) = ver_obs else {
                return Err(GenesisError::MissingInstalledRecord("object version 1"));
            };
            if ver.provenance()
                != &DurableObjectProvenance::new(
                    manifest_context.chain_id().clone(),
                    manifest_context.protocol_version(),
                )
            {
                return Err(GenesisError::TamperedInstalledRecord("object provenance"));
            }
            let canonical_obj_bytes: Vec<u8> = encode_object(&entry.object)?;
            let expected_digest: Digest32 = resolver.hash_for_purpose(
                manifest_context.epoch(),
                HashPurpose::Object,
                &canonical_obj_bytes,
            )?;
            if ver.digest() != expected_digest {
                return Err(GenesisError::TamperedInstalledRecord("object digest"));
            }
            if ver.schema_version() != entry.object.schema_version {
                return Err(GenesisError::TamperedInstalledRecord(
                    "object schema version",
                ));
            }

            // Head must not be Absent (it can be Current at version 1, 2, etc., or Tombstoned).
            let head: DurableObjectHead =
                store.get_object_head(context, domain, entry.object.id)?;
            if head == DurableObjectHead::Absent {
                return Err(GenesisError::MissingInstalledRecord("object head absent"));
            }
        }

        Ok(GenesisInstallOutcome::VerifiedExisting {
            marker,
            manifest_digest,
        })
    } else {
        // =================================================================
        // FRESH INSTALL PATH
        // =================================================================
        // If marker is absent but revision is not INITIAL, it was tombstoned.
        if marker_obs.revision() != StateRevision::INITIAL {
            return Err(GenesisError::TombstonedMarker);
        }

        // Fail closed on partial prior state: none of the target keys or object heads may exist.
        for (name, key) in [
            ("manifest", &manifest_key),
            ("publication", &publication_key),
            ("instance", &instance_key),
            ("publication_policy", &pub_policy_key),
            ("execution_policy", &exec_policy_key),
            ("fee_policy", &fee_policy_key),
        ] {
            let obs: VersionedStateValue = store.get_versioned_durable(context, domain, key)?;
            if obs.value().is_some() || obs.revision() != StateRevision::INITIAL {
                return Err(GenesisError::PartialPriorState(name));
            }
        }

        for entry in &manifest.objects {
            let auth_key: Vec<u8> = local_instance_state::object_authority_key(entry.object.id);
            let obs: VersionedStateValue =
                store.get_versioned_durable(context, domain, &auth_key)?;
            if obs.value().is_some() || obs.revision() != StateRevision::INITIAL {
                return Err(GenesisError::PartialPriorState("object authority"));
            }
            let head: DurableObjectHead =
                store.get_object_head(context, domain, entry.object.id)?;
            if head != DurableObjectHead::Absent {
                return Err(GenesisError::PartialPriorState("object head"));
            }
        }

        // Construct marker.
        let marker: GenesisInstallMarker = GenesisInstallMarker {
            context: manifest_context.clone(),
            manifest_digest,
            genesis_authority: manifest.genesis_authority,
            installed_at_checkpoint: checkpoint,
        };
        let marker_bytes: Vec<u8> = encode_genesis_install_marker(&marker)?;

        // Construct state mutations and CAS read assertions.
        let mut mutations: Vec<StateMutationEntry> = vec![
            StateMutationEntry::new(manifest_key.clone(), StateMutation::Put(manifest_bytes))?,
            StateMutationEntry::new(
                publication_key.clone(),
                StateMutation::Put(publication_bytes),
            )?,
            StateMutationEntry::new(instance_key.clone(), StateMutation::Put(instance_bytes))?,
            StateMutationEntry::new(
                pub_policy_key.clone(),
                StateMutation::Put(publication_policy_bytes),
            )?,
            StateMutationEntry::new(
                exec_policy_key.clone(),
                StateMutation::Put(execution_policy_bytes),
            )?,
            StateMutationEntry::new(fee_policy_key.clone(), StateMutation::Put(fee_policy_bytes))?,
            StateMutationEntry::new(marker_key.clone(), StateMutation::Put(marker_bytes))?,
        ];
        let mut read_assertions: Vec<StateReadAssertion> = vec![
            StateReadAssertion::new(manifest_key, StateRevision::INITIAL)?,
            StateReadAssertion::new(publication_key, StateRevision::INITIAL)?,
            StateReadAssertion::new(instance_key, StateRevision::INITIAL)?,
            StateReadAssertion::new(pub_policy_key, StateRevision::INITIAL)?,
            StateReadAssertion::new(exec_policy_key, StateRevision::INITIAL)?,
            StateReadAssertion::new(fee_policy_key, StateRevision::INITIAL)?,
            StateReadAssertion::new(marker_key, StateRevision::INITIAL)?,
        ];

        for entry in &manifest.objects {
            let auth_key: Vec<u8> = local_instance_state::object_authority_key(entry.object.id);
            let auth_bytes: Vec<u8> = encode_object_authority(&entry.authority)?;
            mutations.push(StateMutationEntry::new(
                auth_key.clone(),
                StateMutation::Put(auth_bytes),
            )?);
            read_assertions.push(StateReadAssertion::new(auth_key, StateRevision::INITIAL)?);
        }

        let state_tx: DurableStateTransaction = DurableStateTransaction::new(
            domain,
            AtomicStateReadSet::new(read_assertions)?,
            mutations,
        )?;

        // Construct object changes.
        let mut head_reads: Vec<DurableObjectHeadRead> = Vec::with_capacity(manifest.objects.len());
        let mut object_mutations: Vec<DurableObjectMutationEntry> =
            Vec::with_capacity(manifest.objects.len());

        for entry in &manifest.objects {
            head_reads.push(DurableObjectHeadRead::new(
                entry.object.id,
                DurableObjectHead::Absent,
            ));
            let canonical_obj_bytes: Vec<u8> = encode_object(&entry.object)?;
            let digest: Digest32 = resolver.hash_for_purpose(
                manifest_context.epoch(),
                HashPurpose::Object,
                &canonical_obj_bytes,
            )?;
            let version: DurableObjectVersionRecord =
                DurableObjectVersionRecord::from_inline_object(
                    entry.object.clone(),
                    digest,
                    DurableObjectProvenance::new(
                        manifest_context.chain_id().clone(),
                        manifest_context.protocol_version(),
                    ),
                    checkpoint,
                )?;
            let owner_projection: DurableObjectOwnerProjection =
                DurableObjectOwnerProjection::from_owner(entry.object.owner.clone())?;
            object_mutations.push(DurableObjectMutationEntry::new(
                entry.object.id,
                DurableObjectMutation::Create {
                    version,
                    owner_projection,
                    routing_projection: DurableObjectRoutingProjection::default(),
                },
            ));
        }

        let object_changes: DurableObjectChanges =
            DurableObjectChanges::new(head_reads, object_mutations)?;

        // Commit the genesis publication's ordinary accepted receipt in the
        // same invocation as the complete signed manifest. Durable publication
        // loading therefore follows the exact legacy verification path after
        // genesis; there is no privileged "genesis publication" loader bypass.
        // Restart idempotence is established by the signed marker and exact
        // installed-record verification above, so a separate manifest receipt
        // would add no authority and would leave the publication unusable.
        let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
            domain,
            Some(state_tx),
            object_changes,
            publication_receipt,
            None,
        )?;

        match store.commit_invocation(context, invocation) {
            DurableCommitOutcome::Committed => Ok(GenesisInstallOutcome::FreshInstall {
                marker,
                manifest_digest,
            }),
            DurableCommitOutcome::Rejected(rejection) => {
                Err(GenesisError::CommitRejected(rejection))
            }
            DurableCommitOutcome::Indeterminate(reason) => {
                Err(GenesisError::CommitIndeterminate(reason))
            }
        }
    }
}
