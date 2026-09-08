//! Explicit local-devnet publication admission. Committed policies authorize
//! bounded, permissionless storage only: no execution, fees or dissemination.
//! All publication records are immutable and share the node's nonce/receipt
//! transaction. Transport callers must explicitly compose this local surface.

use super::*;
use abi::package_types::{PackageOrigin, encode_package_origin};
use canonical_encoding::{CanonicalFrame, decode_digest32, encode_digest32};
use execution::publication::{
    AuthenticatedPublicationCandidate, InterfaceError, MAX_INTERFACE_NODES, PublicationContext,
    PublicationError, PublicationSubmission, UnverifiedDependencyRef,
    authenticate_publication_submission, decode_publication_context, decode_publication_submission,
    encode_dependency_ref, encode_publication_context, encode_publication_submission,
    verify_publication_interface,
};

mod loader;
#[cfg(test)]
mod tests;
pub(super) use loader::{PublicationLoadBudget, load_verified_publication_with_budget};

/// Namespace reserved against generic application state accesses, across upgrades.
pub const PUBLICATION_STATE_PREFIX: &[u8] = b"se/publications/";
/// Aggregate complete submission bytes allowed in one dependency closure.
pub const MAX_PUBLICATION_CLOSURE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum explicitly supplied historical protocol resolvers.
pub const MAX_PUBLICATION_HISTORY: usize = 16;

/// Deterministic local profile commitment. This describes publication validation
/// only and must never be interpreted as an executable contract semantics grant.
pub fn local_publication_profile_semantics(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
) -> Result<Digest32, PublicationAdmissionError> {
    if resolver.chain_id() != expected.chain_id()
        || resolver.protocol_version() != expected.protocol_version()
    {
        return Err(PublicationAdmissionError::HistoricalContextUnavailable);
    }
    Ok(resolver.hash_for_purpose(
        expected.epoch(),
        HashPurpose::ContractCode,
        &encode_local_publication_profile()?,
    )?)
}

/// Separate typed-host publication commitment. Profile-one publication remains
/// nonexecuting; this commitment requires the profile-two policy key explicitly.
pub fn local_executable_publication_semantics(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
) -> Result<Digest32, PublicationAdmissionError> {
    if resolver.chain_id() != expected.chain_id()
        || resolver.protocol_version() != expected.protocol_version()
    {
        return Err(PublicationAdmissionError::HistoricalContextUnavailable);
    }
    Ok(execution::local_execution::local_execution_semantics(
        resolver, expected,
    )?)
}

/// Explicit profile-three publication commitment for generalized contract calls.
pub fn local_general_publication_semantics(
    resolver: &HashSuiteResolver,
    expected: &PublicationContext,
) -> Result<Digest32, PublicationAdmissionError> {
    Ok(execution::local_execution::general_execution_semantics(
        resolver, expected,
    )?)
}

fn encode_local_publication_profile() -> Result<Vec<u8>, PublicationAdmissionError> {
    let mut frame: CanonicalStruct = CanonicalStruct::new(0x630B, 1);
    frame.field_str(1, "local-devnet-publication-only")?;
    frame.field_u32(2, execution::CONTRACT_WASM_ADMISSION_PROFILE_VERSION)?;
    // Local publication admission rules version, not the CallAbi wire version.
    frame.field_u32(3, 1)?;
    frame.field_u32(4, MAX_INTERFACE_NODES as u32)?;
    frame.field_u64(5, MAX_PUBLICATION_CLOSURE_BYTES as u64)?;
    Ok(frame.finish()?)
}

/// Fail-closed local publication admission and durable query failures.
#[derive(Debug)]
pub enum PublicationAdmissionError {
    /// Existing durable node boundary failure, including conflict/ambiguity.
    Node(NodeCoreError),
    /// Publication decoding, cryptographic or WASM validation failed.
    Publication(PublicationError),
    /// Exact dependency or ABI validation failed.
    Interface(InterfaceError),
    /// Expected committed publication policy is absent or differs.
    PolicyMismatch,
    /// An origin is already published or was tombstoned.
    OriginExists,
    /// A required exact dependency has no durable publication.
    MissingDependency,
    /// A stored publication does not match its canonical lookup identity.
    CorruptRecord,
    /// The caller supplied no trusted resolver for an original protocol context.
    HistoricalContextUnavailable,
    /// A deterministic closure or resolver bound was exceeded.
    Limit,
}

impl fmt::Display for PublicationAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(error) => error.fmt(f),
            Self::Publication(error) => error.fmt(f),
            Self::Interface(error) => error.fmt(f),
            Self::PolicyMismatch => f.write_str("committed local publication policy mismatch"),
            Self::OriginExists => f.write_str("publication origin already exists"),
            Self::MissingDependency => f.write_str("exact durable publication dependency missing"),
            Self::CorruptRecord => f.write_str("invalid canonical durable publication record"),
            Self::HistoricalContextUnavailable => {
                f.write_str("trusted original publication context unavailable")
            }
            Self::Limit => f.write_str("publication resource bound exceeded"),
        }
    }
}
impl Error for PublicationAdmissionError {}
impl From<NodeCoreError> for PublicationAdmissionError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}
impl From<PublicationError> for PublicationAdmissionError {
    fn from(value: PublicationError) -> Self {
        Self::Publication(value)
    }
}
impl From<InterfaceError> for PublicationAdmissionError {
    fn from(value: InterfaceError) -> Self {
        Self::Interface(value)
    }
}
impl From<CanonicalEncodingError> for PublicationAdmissionError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::Publication(PublicationError::Encoding(value))
    }
}
impl From<CanonicalDecodingError> for PublicationAdmissionError {
    fn from(value: CanonicalDecodingError) -> Self {
        Self::Publication(PublicationError::Decoding(value))
    }
}
impl From<RuntimeError> for PublicationAdmissionError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(value.into())
    }
}
impl From<DurableReadError> for PublicationAdmissionError {
    fn from(value: DurableReadError) -> Self {
        Self::Node(value.into())
    }
}
impl From<DurableInvocationError> for PublicationAdmissionError {
    fn from(value: DurableInvocationError) -> Self {
        Self::Node(value.into())
    }
}
impl From<HashingError> for PublicationAdmissionError {
    fn from(value: HashingError) -> Self {
        Self::Node(value.into())
    }
}

/// Trusted local policy persisted by devnet bootstrap, never by a publisher.
/// Version one fixes permissionless revision-one publication without fees or
/// execution. Historical rows are retained at their original context key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalPublicationPolicy {
    context: PublicationContext,
    semantics: Digest32,
    profile: u32,
}
impl LocalPublicationPolicy {
    /// Builds explicit local trusted composition for the exact protocol context.
    #[must_use]
    pub const fn new(context: PublicationContext, semantics: Digest32) -> Self {
        Self {
            context,
            semantics,
            profile: 1,
        }
    }
    /// Explicit profile-two publication policy, independently installed at bootstrap.
    #[must_use]
    pub const fn executable(context: PublicationContext, semantics: Digest32) -> Self {
        Self {
            context,
            semantics,
            profile: 2,
        }
    }
    /// Separately installed profile-three publication admission.
    #[must_use]
    pub const fn general(context: PublicationContext, semantics: Digest32) -> Self {
        Self {
            context,
            semantics,
            profile: 3,
        }
    }
    /// Closed artifact admission profile.
    #[must_use]
    pub const fn profile(&self) -> u32 {
        self.profile
    }
    /// Returns the exact trusted context, including original epoch.
    #[must_use]
    pub fn context(&self) -> &PublicationContext {
        &self.context
    }
    /// Returns the trusted semantics commitment; it grants no execution rights.
    #[must_use]
    pub const fn semantics(&self) -> &Digest32 {
        &self.semantics
    }
    /// Canonical bootstrap record with explicit fixed mode and resource bounds.
    pub fn encode(&self) -> Result<Vec<u8>, PublicationAdmissionError> {
        let mut frame: CanonicalStruct = CanonicalStruct::new(0x630A, self.profile as u16);
        frame.field_bytes(1, encode_publication_context(&self.context)?)?;
        frame.field_bytes(2, encode_digest32(&self.semantics)?)?;
        frame.field_u16(3, 1)?;
        frame.field_u32(4, MAX_INTERFACE_NODES as u32)?;
        frame.field_u64(5, MAX_PUBLICATION_CLOSURE_BYTES as u64)?;
        if matches!(self.profile, 2 | 3) {
            frame.field_u32(6, self.profile)?;
        }
        Ok(frame.finish()?)
    }
    /// Strictly decodes one policy; unsupported modes and limits fail closed.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublicationAdmissionError> {
        if bytes.len() > 1024 {
            return Err(PublicationAdmissionError::Limit);
        }
        let frame: CanonicalFrame<'_> = decode_canonical_frame(bytes)?;
        frame.require_type(0x630A)?;
        if !matches!(frame.version(), 1..=3) {
            return Err(PublicationAdmissionError::PolicyMismatch);
        }
        if frame.version() == 1 {
            frame.require_only_fields(&[1, 2, 3, 4, 5])?;
        } else {
            frame.require_only_fields(&[1, 2, 3, 4, 5, 6])?;
            if frame.required_u32(6)? != u32::from(frame.version()) {
                return Err(PublicationAdmissionError::PolicyMismatch);
            }
        }
        if frame.required_u16(3)? != 1
            || frame.required_u32(4)? != MAX_INTERFACE_NODES as u32
            || frame.required_u64(5)? != MAX_PUBLICATION_CLOSURE_BYTES as u64
        {
            return Err(PublicationAdmissionError::PolicyMismatch);
        }
        Ok(Self {
            context: decode_publication_context(frame.required_field(1)?)?,
            semantics: decode_digest32(frame.required_field(2)?)?,
            profile: u32::from(frame.version()),
        })
    }
}

/// Context-keyed canonical policy key, retained for historical verification.
pub fn publication_policy_key(
    context: &PublicationContext,
) -> Result<Vec<u8>, PublicationAdmissionError> {
    publication_policy_key_for_profile(context, 1)
}
/// Exact versioned policy key; unknown profiles fail closed.
pub fn publication_policy_key_for_profile(
    context: &PublicationContext,
    profile: u32,
) -> Result<Vec<u8>, PublicationAdmissionError> {
    let mut key: Vec<u8> = PUBLICATION_STATE_PREFIX.to_vec();
    match profile {
        1 => key.extend_from_slice(b"v1/policies/"),
        2 => key.extend_from_slice(b"v2/policies/"),
        3 => key.extend_from_slice(b"v3/policies/"),
        _ => return Err(PublicationAdmissionError::PolicyMismatch),
    }
    key.extend(encode_publication_context(context)?);
    Ok(key)
}
/// Origin-keyed immutable record. Protocol upgrades never create a new origin.
pub fn publication_record_key(
    origin: &PackageOrigin,
) -> Result<Vec<u8>, PublicationAdmissionError> {
    let mut key: Vec<u8> = PUBLICATION_STATE_PREFIX.to_vec();
    key.extend_from_slice(b"v1/records/");
    key.extend(encode_package_origin(origin).map_err(PublicationError::from)?);
    Ok(key)
}

fn resolver_for<'a>(
    current: &'a HashSuiteResolver,
    history: &'a [HashSuiteResolver],
    context: &PublicationContext,
) -> Result<&'a HashSuiteResolver, PublicationAdmissionError> {
    if history.len() > MAX_PUBLICATION_HISTORY {
        return Err(PublicationAdmissionError::Limit);
    }
    if current.chain_id() == context.chain_id()
        && current.protocol_version() == context.protocol_version()
    {
        return Ok(current);
    }
    history
        .iter()
        .find(|resolver| {
            resolver.chain_id() == context.chain_id()
                && resolver.protocol_version() == context.protocol_version()
        })
        .ok_or(PublicationAdmissionError::HistoricalContextUnavailable)
}

fn read_policy<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    expected_context: &PublicationContext,
    profile: u32,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<LocalPublicationPolicy, PublicationAdmissionError> {
    let key: Vec<u8> = publication_policy_key_for_profile(expected_context, profile)?;
    let observed: VersionedStateValue = store.get_versioned_durable(context, domain, &key)?;
    let bytes: &[u8] = observed
        .value()
        .ok_or(PublicationAdmissionError::PolicyMismatch)?;
    let policy: LocalPublicationPolicy = LocalPublicationPolicy::decode(bytes)?;
    if policy.context() != expected_context
        || policy.profile() != profile
        || policy.encode()? != bytes
    {
        return Err(PublicationAdmissionError::PolicyMismatch);
    }
    insert_read(reads, key, observed.revision())?;
    Ok(policy)
}
fn insert_read(
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
    key: Vec<u8>,
    revision: StateRevision,
) -> Result<(), PublicationAdmissionError> {
    if let Some(previous) = reads.insert(key, revision)
        && previous != revision
    {
        return Err(NodeCoreError::StateConflict.into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn load_closure<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    candidate: AuthenticatedPublicationCandidate,
    root_bytes: usize,
    reads: &mut BTreeMap<Vec<u8>, StateRevision>,
) -> Result<execution::publication::VerifiedPublicationInterface, PublicationAdmissionError> {
    loader::load_unstored_root(
        store, context, domain, resolver, history, candidate, root_bytes, reads,
    )
}
fn match_reference(
    reference: &UnverifiedDependencyRef,
    artifact: &execution::publication::CodeArtifact,
    digest: &Digest32,
) -> Result<(), PublicationAdmissionError> {
    if reference.origin() != artifact.origin()
        || reference.revision() != artifact.revision()
        || reference.context() != artifact.context()
        || reference.artifact_digest() != digest
    {
        return Err(PublicationAdmissionError::CorruptRecord);
    }
    Ok(())
}

fn publication_output(
    submission: &PublicationSubmission,
) -> Result<NodeOutput, PublicationAdmissionError> {
    let artifact: &execution::publication::CodeArtifact = submission.request().artifact();
    let reference: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        artifact.revision(),
        artifact.context().clone(),
        *submission.request().artifact_digest(),
    )?;
    Ok(NodeOutput::new(
        vec![NodeResponse::new(
            RequestId::new(*submission.request_id())?,
            NodeResponseStatus::Accepted,
            Some(encode_dependency_ref(&reference)?),
        )?],
        Vec::new(),
    )?)
}

fn verify_publication_receipt<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    submission: &PublicationSubmission,
) -> Result<(), PublicationAdmissionError> {
    let event_digest: Digest32 = resolver.hash_for_purpose(
        submission.request().artifact().context().epoch(),
        HashPurpose::NodeEvent,
        &encode_publication_submission(submission)?,
    )?;
    let request_id: RequestId = RequestId::new(*submission.request_id())?;
    let output: NodeOutput = durable_reconciliation::reconcile_receipt(
        store,
        context,
        domain,
        request_id,
        event_digest,
    )?
    .ok_or(PublicationAdmissionError::CorruptRecord)?;
    if output != publication_output(submission)? {
        return Err(PublicationAdmissionError::CorruptRecord);
    }
    Ok(())
}

/// Admits one publication using the current resolver's trusted epoch history.
/// Replay returns its existing receipt before policy/dependency reads. New
/// publication atomically consumes the shared sender nonce and asserts every
/// dependency/policy read. No outbox message or executable authority is created.
pub fn handle_local_publication<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    policy: &LocalPublicationPolicy,
    submission: PublicationSubmission,
) -> Result<NodeOutput, PublicationAdmissionError> {
    handle_local_publication_with_history(store, context, domain, resolver, &[], policy, submission)
}

/// Same admission with explicit trusted resolvers for original protocol versions.
pub fn handle_local_publication_with_history<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    policy: &LocalPublicationPolicy,
    submission: PublicationSubmission,
) -> Result<NodeOutput, PublicationAdmissionError> {
    if history.len() > MAX_PUBLICATION_HISTORY {
        return Err(PublicationAdmissionError::Limit);
    }
    if submission.request().artifact().wasm_profile() != policy.profile() {
        return Err(PublicationAdmissionError::PolicyMismatch);
    }
    let authenticated: AuthenticatedPublicationCandidate = authenticate_publication_submission(
        resolver,
        policy.context(),
        policy.semantics(),
        submission.clone(),
    )?;
    let bytes: Vec<u8> = encode_publication_submission(&submission)?;
    let event_digest: Digest32 =
        resolver.hash_for_purpose(policy.context.epoch(), HashPurpose::NodeEvent, &bytes)?;
    let request_id: RequestId = RequestId::new(*submission.request_id())?;
    if let Some(output) =
        durable_reconciliation::reconcile_receipt(store, context, domain, request_id, event_digest)?
    {
        return Ok(output);
    }
    let layout: PersistenceLayout = PersistenceLayout::new(
        policy.context.chain_id().clone(),
        policy.context.protocol_version(),
    );
    let nonce: PendingSenderNonceWrite = durable_reconciliation::reserve_sender_nonce(
        store,
        context,
        domain,
        &layout,
        SenderNonceReservation {
            sender: *submission.request().artifact().origin().publisher(),
            epoch: policy.context.epoch(),
            nonce: submission.request().nonce(),
        },
    )?;
    let mut reads: BTreeMap<Vec<u8>, StateRevision> = BTreeMap::new();
    let stored_policy: LocalPublicationPolicy = read_policy(
        store,
        context,
        domain,
        policy.context(),
        policy.profile(),
        &mut reads,
    )?;
    if &stored_policy != policy {
        return Err(PublicationAdmissionError::PolicyMismatch);
    }
    let record_key: Vec<u8> = publication_record_key(submission.request().artifact().origin())?;
    let origin: VersionedStateValue = store.get_versioned_durable(context, domain, &record_key)?;
    if origin.value().is_some() || origin.revision() != StateRevision::INITIAL {
        return Err(PublicationAdmissionError::OriginExists);
    }
    insert_read(&mut reads, record_key.clone(), origin.revision())?;
    load_closure(
        store,
        context,
        domain,
        resolver,
        history,
        authenticated,
        bytes.len(),
        &mut reads,
    )?;
    insert_read(&mut reads, nonce.key.clone(), nonce.read_revision)?;
    let mutations: Vec<StateMutationEntry> = vec![
        StateMutationEntry::new(record_key, StateMutation::Put(bytes))?,
        StateMutationEntry::new(nonce.key, StateMutation::Put(nonce.record.encode()?))?,
    ];
    let assertions: Vec<StateReadAssertion> = reads
        .into_iter()
        .map(|(key, revision): (Vec<u8>, StateRevision)| StateReadAssertion::new(key, revision))
        .collect::<Result<Vec<StateReadAssertion>, RuntimeError>>()?;
    let state: DurableStateTransaction =
        DurableStateTransaction::new(domain, AtomicStateReadSet::new(assertions)?, mutations)?;
    let output: NodeOutput = publication_output(&submission)?;
    let record: NodeDedupRecord =
        NodeDedupRecord::new(request_id, event_digest, output.responses().to_vec())?;
    let durable_id: DurableRequestId = DurableRequestId::new(*request_id.as_bytes())
        .map_err(|_| PublicationAdmissionError::CorruptRecord)?;
    let receipt: DurableRequestReceipt =
        DurableRequestReceipt::new(durable_id, event_digest, record.encode()?)?;
    let invocation: DurableInvocationTransaction = DurableInvocationTransaction::new(
        domain,
        Some(state),
        DurableObjectChanges::new(Vec::new(), Vec::new())?,
        receipt,
        None,
    )?;
    Ok(durable_reconciliation::committed_output(
        store.commit_invocation(context, invocation),
        output,
    )?)
}

/// Loads canonical immutable code and independently verifies its complete closure.
pub fn query_publication<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    origin: &PackageOrigin,
) -> Result<Option<PublicationSubmission>, PublicationAdmissionError> {
    query_publication_with_history(store, context, domain, resolver, &[], origin)
}
/// Query with explicitly trusted original protocol resolvers, never reconstructed
/// from publication fields. Missing historical configuration fails closed.
pub fn query_publication_with_history<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    origin: &PackageOrigin,
) -> Result<Option<PublicationSubmission>, PublicationAdmissionError> {
    Ok(
        load_verified_publication(store, context, domain, resolver, history, origin)?
            .map(|loaded| loaded.submission),
    )
}

/// Independently verified durable code and all state revisions used to verify it.
/// Consumers must include these read assertions in their eventual atomic commit.
#[derive(Debug)]
pub struct VerifiedDurablePublication {
    /// Exact originally signed ingress, including its receipt identity.
    pub submission: PublicationSubmission,
    /// Verified ABI, executable metadata and exact authenticated closure.
    pub interface: execution::publication::VerifiedPublicationInterface,
    /// Publication and retained policy read assertions, in canonical key order.
    pub reads: Vec<StateReadAssertion>,
}
/// Loads a bounded durable closure under explicitly trusted original resolvers.
pub fn load_verified_publication<S: StructuredDurableDomainStateStore>(
    store: &S,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
    resolver: &HashSuiteResolver,
    history: &[HashSuiteResolver],
    origin: &PackageOrigin,
) -> Result<Option<VerifiedDurablePublication>, PublicationAdmissionError> {
    let mut budget: PublicationLoadBudget = PublicationLoadBudget::default();
    load_verified_publication_with_budget(
        store,
        context,
        domain,
        resolver,
        history,
        origin,
        &mut budget,
    )
}
