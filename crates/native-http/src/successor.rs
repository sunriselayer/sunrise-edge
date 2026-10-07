//! DR-0191 recurring-successor native HTTP surface (Sections 7, 9 and 12).
//!
//! [successor_router] mounts the original native route paths and wire bytes
//! for a destination whose namespace serves a verified successor chain. It is
//! a separate constructor: it never mounts the node event route or a direct
//! mutation route, and never consults an ordinary-genesis policy. Every
//! storage-touching request allocates a fresh operation context and resolves
//! [LiveAuthority] through the host [SuccessorAuthoritySource] before any
//! signing, exposure, read or commit. OriginalGenesis is a refusal here,
//! never a fallback. No warrant, policy or e+1 context outlives one request.
//!
//! Pure decoding and paid-intent authentication against the declared
//! chain/protocol/epoch still run before identity, clock or storage access.
//! Ordered envelope and candidate authentication need the verified e+1
//! committee, so they run after resolution and before the owning core entry.
//! Frontier, drain and ordered Seal controls enter the same core owners with
//! a fresh warrant. Direct-mutation paths keep the existing explicit 422
//! successor-control-unsupported. Ordered history reads serve only the
//! verified current epoch under a fresh warrant.

use super::*;
use abi::package_types::PackageOrigin;
use axum::routing::any;
use execution::LocalWasmExecutionEngine;
use execution::local_execution::{LocalExecutionPolicy, encode_instance_record};
use execution::paid_execution::{
    MAX_SIGNED_PAID_INTENT_BYTES, PaidFeePolicy, decode_paid_fee_policy, decode_signed_paid_intent,
    encode_paid_fee_policy,
};
use execution::publication::PublicationContext;
use fastvote::{DynConsensusSigner, fastpath_error_response, publication_retention_error_response};
use node_core::fee_claims::{FeeClaimError, FeeClaimPreparationRequest, PreparedFeeClaim};
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{
    self as core_ordered, OrderedEconomicsEnvironment, OrderedEconomicsError,
    OrderedEconomicsPolicy,
};
use node_core::paid_execution::authenticate_paid_execution;
use node_core::serving_authority::{
    LiveAuthority, LiveWarrant, ServingAuthorityError, SuccessorActivationError,
    SuccessorArtifactError, SuccessorFastVoteComposition, SuccessorPolicyInputs, apply_successor,
    prepare_fee_claim_successor, prepare_successor, query_request_receipt_successor,
    retain_publication_successor,
};
use node_wire::ordered_economics::{
    MAX_ORDERED_CERTIFICATE_BYTES, MAX_ORDERED_PROPOSAL_BYTES, MAX_ORDERED_PROPOSE_REQUEST_BYTES,
    ORDERED_CERTIFICATE_MEDIA_TYPE, ORDERED_ECONOMICS_CERTIFICATE_PATH,
    ORDERED_ECONOMICS_OBSERVE_PATH, ORDERED_ECONOMICS_OUTCOME_ROUTE,
    ORDERED_ECONOMICS_PROPOSAL_PATH, ORDERED_ECONOMICS_PROPOSE_PATH, ORDERED_ECONOMICS_STATUS_PATH,
    ORDERED_ECONOMICS_TICK_PATH, ORDERED_OUTCOME_MEDIA_TYPE, ORDERED_PROPOSAL_MEDIA_TYPE,
    ORDERED_PROPOSE_REQUEST_MEDIA_TYPE, ORDERED_STATUS_MEDIA_TYPE, OrderedProposeRequest,
};
use runtime::{
    DurableStateKeyScanner, outbox_guard::StructuredOutboxExclusionGuard,
    portable::DurablePortableRepository,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Direct/legacy mutation routes certified hosting already excludes. They refuse before
/// identity, clock, storage or authority access.
pub const SUCCESSOR_REFUSED_CONTROL_PATHS: &[&str] = &[
    NODE_EVENT_PATH,
    publication::PUBLICATION_PATH,
    local_execution::EXECUTION_PATH,
    paid_execution::PAID_EXECUTION_PATH,
];

/// Host-owned resolution of one invocation authority.
///
/// Implementations pin the original genesis, schedule and domain, own the
/// writer-fenced store, the retained artifact directories and the local
/// signer public key, and call
/// node_core::serving_authority::resolve_live_authority_chain afresh on every
/// call. They never cache a warrant, verified evidence or a decision.
pub trait SuccessorAuthoritySource<S>: Send + Sync {
    /// The original pinned verified genesis root, never a replacement.
    fn genesis_root(&self) -> &VerifiedGenesisRoot;
    /// The same namespace's portable blob repository for core's independent
    /// live Seal closure. A composition without this existing capability
    /// keeps Seal unavailable; the repository itself grants no authority.
    fn seal_blob_repository(&self) -> Option<&dyn runtime::portable::PortableBlobRepository> {
        None
    }
    /// One full fresh resolution under exactly this store and context.
    fn resolve<'inv>(
        &self,
        store: &'inv S,
        context: &'inv DurableOperationContext,
    ) -> Result<LiveAuthority<'inv>, ServingAuthorityError>;
}

/// Trusted local composition of one successor host. Nothing here is
/// authority: every e+1 context, committee, policy row and local-member fact
/// comes from the per-request warrant.
pub struct SuccessorHostComposition<S> {
    /// The exact writer-fenced store the authority source resolves against.
    pub store: Arc<S>,
    /// Blob store backing large object bodies of the same namespace.
    pub blobs: Arc<dyn BlobStore + Send + Sync>,
    /// Fresh per-request authority resolution.
    pub authority: Arc<dyn SuccessorAuthoritySource<S>>,
    /// Local consensus signer; core admits it only as the namespace member.
    pub signer: Arc<dyn ConsensusSigner + Send + Sync>,
    /// Trusted local clock for deadlines and the pacemaker.
    pub clock: Arc<dyn Clock + Send + Sync>,
    /// Restart-safe correlation identities.
    pub identities: Arc<dyn IndexedOutboxIdentitySource + Send + Sync>,
    /// Locally pinned original resolver (chain, protocol and schedule).
    pub resolver: HashSuiteResolver,
    /// Locally pinned historical resolvers.
    pub history: Vec<HashSuiteResolver>,
    /// Deterministic local and paid contract engine.
    pub engine: Arc<LocalWasmExecutionEngine>,
    /// Locally pinned protocol configuration reported by the context query.
    pub protocol_config: ProtocolConfig,
    /// The writer generation this host claimed once at startup.
    pub writer_fence: WriterFenceGeneration,
    /// Storage budget of one request.
    pub operation_timeout: Duration,
    /// Checkpoint recorded by FastVote prepare and recovery.
    pub created_checkpoint: u64,
    /// Bounded blocking admission shared by every route.
    pub blocking_executor: NativeBlockingExecutor,
}

/// Refusal to compose a successor router.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuccessorRouterError {
    /// The protocol configuration differs from the pinned resolver.
    ProtocolVersionMismatch,
    /// A zero request budget can never reach storage.
    ZeroOperationTimeout,
}

impl fmt::Display for SuccessorRouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ProtocolVersionMismatch => "protocol config differs from the pinned resolver",
            Self::ZeroOperationTimeout => "successor operation timeout must be nonzero",
        })
    }
}

impl Error for SuccessorRouterError {}

/// Refusal of a listen address before any socket exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuccessorListenError {
    /// Not a numeric ip:port socket address.
    Invalid,
    /// Anything other than exactly 127.0.0.1 or ::1.
    NotLoopback,
}

impl fmt::Display for SuccessorListenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "listen address must be a numeric ip:port socket address",
            Self::NotLoopback => "successor host listens only on 127.0.0.1 or ::1",
        })
    }
}

impl Error for SuccessorListenError {}

/// Failure of one successor invocation outside a route-specific codec.
#[derive(Debug)]
pub enum SuccessorInvocationError {
    /// No restart-safe correlation identity is available.
    IdentityUnavailable,
    /// The identity sequence is exhausted for this writer generation.
    IdentityExhausted,
    /// The trusted clock failed.
    ClockUnavailable,
    /// The request deadline overflowed.
    DeadlineOverflow,
    /// Live authority resolution refused or failed.
    Authority(ServingAuthorityError),
    /// The namespace is an ordinary original; a successor host never serves it.
    OriginalGenesis,
    /// Successor fee-claim preparation refused.
    FeeClaim(FeeClaimError),
}

impl fmt::Display for SuccessorInvocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityUnavailable => f.write_str("successor correlation identity unavailable"),
            Self::IdentityExhausted => f.write_str("successor correlation identity exhausted"),
            Self::ClockUnavailable => f.write_str("successor trusted clock unavailable"),
            Self::DeadlineOverflow => f.write_str("successor request deadline overflowed"),
            Self::Authority(error) => write!(f, "successor authority refused: {error}"),
            Self::OriginalGenesis => {
                f.write_str("namespace is an original genesis; successor host refuses it")
            }
            Self::FeeClaim(error) => write!(f, "successor fee claim refused: {error:?}"),
        }
    }
}

impl Error for SuccessorInvocationError {}

/// Parses a listen address, accepting exactly 127.0.0.1 or ::1. Runs before
/// any file, store or socket I/O.
pub fn require_loopback_listen(value: &str) -> Result<SocketAddr, SuccessorListenError> {
    let address: SocketAddr = value.parse().map_err(|_| SuccessorListenError::Invalid)?;
    require_loopback_address(address)
}

/// Accepts exactly 127.0.0.1 or ::1; other loopback-range, mapped or
/// unspecified addresses refuse.
pub fn require_loopback_address(address: SocketAddr) -> Result<SocketAddr, SuccessorListenError> {
    match address.ip() {
        IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST => Ok(address),
        IpAddr::V6(ip) if ip == Ipv6Addr::LOCALHOST => Ok(address),
        _ => Err(SuccessorListenError::NotLoopback),
    }
}

/// Binds the successor listener after rechecking the loopback rule, so no
/// caller can bind a nonloopback socket through this entry.
pub async fn bind_successor_loopback(address: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    require_loopback_address(address)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    tokio::net::TcpListener::bind(address).await
}

fn operation_context<S>(
    host: &SuccessorHostComposition<S>,
) -> Result<DurableOperationContext, SuccessorInvocationError> {
    let identity: IndexedOutboxAttemptIdentity = host.identities.next_attempt_identity().map_err(
        |error: IndexedOutboxIdentitySourceError| match error {
            IndexedOutboxIdentitySourceError::Unavailable => {
                SuccessorInvocationError::IdentityUnavailable
            }
            IndexedOutboxIdentitySourceError::Exhausted => {
                SuccessorInvocationError::IdentityExhausted
            }
        },
    )?;
    let now_unix_millis: u64 = host
        .clock
        .now_unix_millis()
        .map_err(|_| SuccessorInvocationError::ClockUnavailable)?;
    let timeout_millis: u64 = u64::try_from(host.operation_timeout.as_millis())
        .map_err(|_| SuccessorInvocationError::DeadlineOverflow)?;
    let deadline: StorageDeadline = now_unix_millis
        .checked_add(timeout_millis)
        .and_then(StorageDeadline::new)
        .ok_or(SuccessorInvocationError::DeadlineOverflow)?;
    Ok(DurableOperationContext::new(
        host.writer_fence,
        deadline,
        identity.correlation_id,
    ))
}

/// The one authority boundary: a fresh context, a full fresh resolution and
/// an explicit refusal of OriginalGenesis, then exactly one unit of work
/// under the borrowed warrant. Nothing outlives the call.
fn with_authority<S, T>(
    host: &SuccessorHostComposition<S>,
    work: impl FnOnce(&LiveWarrant<'_>, &DurableOperationContext) -> Result<T, SuccessorInvocationError>,
) -> Result<T, SuccessorInvocationError>
where
    S: StructuredDurableDomainStateStore,
{
    let context: DurableOperationContext = operation_context(host)?;
    let authority: LiveAuthority<'_> = host
        .authority
        .resolve(host.store.as_ref(), &context)
        .map_err(SuccessorInvocationError::Authority)?;
    let warrant: &LiveWarrant<'_> = match &authority {
        LiveAuthority::Successor(warrant) => warrant,
        LiveAuthority::OriginalGenesis => return Err(SuccessorInvocationError::OriginalGenesis),
    };
    work(warrant, &context)
}

fn serve<S>(
    host: &SuccessorHostComposition<S>,
    work: impl FnOnce(&LiveWarrant<'_>, &DurableOperationContext) -> Response,
) -> Response
where
    S: StructuredDurableDomainStateStore,
{
    match with_authority(
        host,
        |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| Ok(work(warrant, context)),
    ) {
        Ok(response) => response,
        Err(error) => invocation_error_response(&error),
    }
}

/// Classifies an invocation failure. Authority refusals are explicit 409s:
/// they are destination-state conditions a retry with other bytes cannot
/// cure, never a fallback to another authority.
fn invocation_error_response(error: &SuccessorInvocationError) -> Response {
    match error {
        SuccessorInvocationError::IdentityUnavailable
        | SuccessorInvocationError::ClockUnavailable => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "successor-host-unavailable",
        ),
        SuccessorInvocationError::IdentityExhausted
        | SuccessorInvocationError::DeadlineOverflow => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "successor-host-state-invalid",
        ),
        SuccessorInvocationError::OriginalGenesis => {
            error_response(StatusCode::CONFLICT, "successor-original-genesis-refused")
        }
        SuccessorInvocationError::Authority(ServingAuthorityError::Refused(_)) => {
            error_response(StatusCode::CONFLICT, "successor-authority-refused")
        }
        SuccessorInvocationError::Authority(ServingAuthorityError::Node(error)) => {
            node_error_response(error)
        }
        SuccessorInvocationError::Authority(ServingAuthorityError::Evidence(error)) => {
            match error.as_ref() {
                SuccessorActivationError::Artifact(SuccessorArtifactError::Io) => error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "successor-evidence-unavailable",
                ),
                SuccessorActivationError::Node(error) => node_error_response(error),
                _ => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "successor-evidence-invalid",
                ),
            }
        }
        SuccessorInvocationError::FeeClaim(_) => {
            error_response(StatusCode::BAD_REQUEST, "successor-fee-claim-rejected")
        }
    }
}

fn bytes_response(media_type: &'static str, bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, media_type),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response()
}

fn query_node_error(error: NodeCoreError) -> Response {
    query_invocation_error_response(&QueryInvocationError::Node(error))
}

fn ordered_error(error: &OrderedEconomicsError) -> Response {
    ordered_economics::ordered_economics_error_response(error)
}

/// Ordered policy and leg policy of one request, built only from the fresh
/// warrant and the original pinned root; never cached across requests.
struct OrderedScope {
    policy: OrderedEconomicsPolicy,
    leg_policy: LocalExecutionPolicy,
}

impl OrderedScope {
    #[allow(clippy::result_large_err)]
    fn from_warrant<S>(
        host: &SuccessorHostComposition<S>,
        warrant: &LiveWarrant<'_>,
    ) -> Result<Self, Response> {
        let policy: OrderedEconomicsPolicy = warrant
            .ordered_policy(host.authority.genesis_root())
            .map_err(|error: SuccessorActivationError| {
                invocation_error_response(&SuccessorInvocationError::Authority(
                    ServingAuthorityError::from(error),
                ))
            })?;
        let leg_policy: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(warrant.policy_inputs().context().clone());
        Ok(Self { policy, leg_policy })
    }

    fn env<'a, S>(
        &'a self,
        host: &'a SuccessorHostComposition<S>,
    ) -> OrderedEconomicsEnvironment<'a> {
        OrderedEconomicsEnvironment {
            policy: &self.policy,
            history: &host.history,
            leg_policy: &self.leg_policy,
            engine: host.engine.as_ref(),
            blobs: host.blobs.as_ref(),
            seal: host.authority.seal_blob_repository().map(|blobs| {
                core_ordered::OrderedSealComposition {
                    genesis_root: host.authority.genesis_root(),
                    paid_base_policy: &self.leg_policy,
                    paid_engine: host.engine.as_ref(),
                    blobs,
                }
            }),
        }
    }
}

/// Expected e+1 FastVote execution and fee policies of one request. The fee
/// policy is the installed e+1 row the warrant just CAS-verified against a
/// fresh derivation; the owning core admission rechecks equality.
struct FastVoteScope {
    base_policy: LocalExecutionPolicy,
    fee_policy: PaidFeePolicy,
}

impl FastVoteScope {
    #[allow(clippy::result_large_err)]
    fn from_warrant<S: StructuredDurableDomainStateStore>(
        host: &SuccessorHostComposition<S>,
        warrant: &LiveWarrant<'_>,
        context: &DurableOperationContext,
    ) -> Result<Self, Response> {
        let expected: &PublicationContext = warrant.policy_inputs().context();
        Ok(Self {
            base_policy: LocalExecutionPolicy::generic_object_results(expected.clone()),
            fee_policy: successor_fee_policy(host, warrant, context)?,
        })
    }

    fn composition<'a, S>(
        &'a self,
        host: &'a SuccessorHostComposition<S>,
    ) -> SuccessorFastVoteComposition<'a, LocalWasmExecutionEngine> {
        SuccessorFastVoteComposition {
            blob_store: host.blobs.as_ref(),
            resolver: &host.resolver,
            history: &host.history,
            base_policy: &self.base_policy,
            fee_policy: &self.fee_policy,
            engine: host.engine.as_ref(),
        }
    }
}

#[allow(clippy::result_large_err)]
fn successor_fee_policy<S: StructuredDurableDomainStateStore>(
    host: &SuccessorHostComposition<S>,
    warrant: &LiveWarrant<'_>,
    context: &DurableOperationContext,
) -> Result<PaidFeePolicy, Response> {
    let expected: &PublicationContext = warrant.policy_inputs().context();
    let key: Vec<u8> = node_core::local_instance_state::paid_fee_policy_key(expected)
        .map_err(|error: NodeCoreError| node_error_response(&error))?;
    let observed = host
        .store
        .get_versioned_durable(context, warrant.policy_inputs().domain(), &key)
        .map_err(|error| query_node_error(NodeCoreError::from(error)))?;
    let bytes: &[u8] = observed.value().ok_or_else(|| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "paid-fee-policy-not-installed",
        )
    })?;
    match decode_paid_fee_policy(bytes) {
        Ok(policy) if policy.context == *expected => Ok(policy),
        Ok(_) | Err(_) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "paid-fee-policy-invalid",
        )),
    }
}

/// Pure admission: structural decode and signature authentication of a
/// signed paid intent at its own declared epoch under the pinned chain and
/// protocol, before identity, clock or storage access.
#[allow(clippy::result_large_err)]
fn authenticate_declared_intent(
    resolver: &HashSuiteResolver,
    signed_bytes: &[u8],
) -> Result<PublicationContext, Response> {
    let invalid = || error_response(StatusCode::BAD_REQUEST, "invalid-fastvote-signed-intent");
    let signed = decode_signed_paid_intent(signed_bytes).map_err(|_| invalid())?;
    let declared: PublicationContext = PublicationContext::new(
        resolver.chain_id().clone(),
        resolver.protocol_version(),
        signed.intent.context.epoch(),
    )
    .map_err(|_| invalid())?;
    authenticate_paid_execution(resolver, &declared, signed_bytes)
        .map_err(|error| paid_execution::admission_error(&error))?;
    Ok(declared)
}

/// A declared context is served only when it is exactly the verified e+1
/// context of this request warrant. Original epoch-e receipts replay through
/// the receipt route, never through an e+1 signing path.
#[allow(clippy::result_large_err)]
fn require_warrant_context(
    declared: &PublicationContext,
    warrant: &LiveWarrant<'_>,
) -> Result<(), Response> {
    if *declared != *warrant.policy_inputs().context() {
        return Err(error_response(
            StatusCode::CONFLICT,
            "fastvote-epoch-repin-required",
        ));
    }
    Ok(())
}

fn request_id_of(signed_bytes: &[u8]) -> Option<RequestId> {
    decode_signed_paid_intent(signed_bytes)
        .ok()
        .and_then(|signed| RequestId::new(signed.intent.request_id).ok())
}

fn node_result_response(request_id: Option<RequestId>, output: &node_core::NodeOutput) -> Response {
    let Some(request_id) = request_id else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "fastvote-apply-request-id-invalid",
        );
    };
    match HttpNodeResult::new(request_id, output.responses().to_vec())
        .and_then(|result| result.encode())
    {
        Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "fastvote-apply-result-encoding",
        ),
    }
}

type SharedSuccessorHost<S> = Arc<SuccessorHostComposition<S>>;

async fn blocking<S, F>(host: SharedSuccessorHost<S>, work: F) -> Response
where
    S: Send + Sync + 'static,
    F: FnOnce(&SuccessorHostComposition<S>) -> Response + Send + 'static,
{
    let executor: NativeBlockingExecutor = host.blocking_executor.clone();
    publication::admitted(false, executor, move || work(&host)).await
}

fn fastvote_preflight(headers: &HeaderMap, body: &Bytes, maximum: usize) -> Option<Response> {
    if !has_supported_content_type(headers) || has_unsupported_content_encoding(headers) {
        return Some(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-fastvote-content",
        ));
    }
    if body.len() > maximum {
        return Some(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "fastvote-body-too-large",
        ));
    }
    None
}

trait SuccessorStore:
    DurableStateKeyScanner
    + DurablePortableRepository
    + StructuredOutboxExclusionGuard
    + Send
    + Sync
    + 'static
{
}
impl<
    S: DurableStateKeyScanner
        + DurablePortableRepository
        + StructuredOutboxExclusionGuard
        + Send
        + Sync
        + 'static,
> SuccessorStore for S
{
}

fn signer<S>(host: &SuccessorHostComposition<S>) -> DynConsensusSigner<'_> {
    DynConsensusSigner(host.signer.as_ref())
}

async fn ordered_propose<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = ordered_economics::reject_unsupported_request(
        &headers,
        &body,
        ORDERED_PROPOSE_REQUEST_MEDIA_TYPE,
        MAX_ORDERED_PROPOSE_REQUEST_BYTES,
    ) {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let Ok(request) = OrderedProposeRequest::decode(&body) else {
            return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-propose-request");
        };
        let candidate = match request.candidate {
            Some(bytes) => match core_ordered::decode_ordered_candidate(&bytes) {
                Ok(value) => Some(value),
                Err(_) => {
                    return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-candidate");
                }
            },
            None => None,
        };
        serve(
            host,
            |warrant: &LiveWarrant<'_>, _: &DurableOperationContext| {
                let scope: OrderedScope = match OrderedScope::from_warrant(host, warrant) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                let env: OrderedEconomicsEnvironment<'_> = scope.env(host);
                if let Some(candidate) = &candidate
                    && let Err(error) = core_ordered::authenticate_candidate(&env, candidate)
                {
                    return ordered_error(&error);
                }
                match core_ordered::propose_successor(
                    warrant,
                    host.store.as_ref(),
                    &env,
                    candidate.as_ref(),
                    &signer(host),
                ) {
                    Ok(proposal) => match core_ordered::encode_ordered_proposal(&proposal) {
                        Ok(bytes) => bytes_response(ORDERED_PROPOSAL_MEDIA_TYPE, bytes),
                        Err(_) => error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ordered-proposal-encoding",
                        ),
                    },
                    Err(error) => ordered_error(&error),
                }
            },
        )
    })
    .await
}

/// Shared ordered proposal admission for the signing vote route and the
/// signerless observe route: verify the envelope and any candidate against
/// the fresh successor policy, then run exactly one owning core entry.
async fn ordered_proposal_route<S: SuccessorStore>(
    host: SharedSuccessorHost<S>,
    headers: HeaderMap,
    body: Bytes,
    vote: bool,
) -> Response {
    if let Some(response) = ordered_economics::reject_unsupported_request(
        &headers,
        &body,
        ORDERED_PROPOSAL_MEDIA_TYPE,
        MAX_ORDERED_PROPOSAL_BYTES,
    ) {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let Ok(proposal) = core_ordered::decode_ordered_proposal(&body) else {
            return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-proposal");
        };
        serve(
            host,
            |warrant: &LiveWarrant<'_>, _: &DurableOperationContext| {
                let scope: OrderedScope = match OrderedScope::from_warrant(host, warrant) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                let env: OrderedEconomicsEnvironment<'_> = scope.env(host);
                if env
                    .policy
                    .engine()
                    .verify_proposal(
                        &proposal.proposal,
                        &consensus::Ed25519ConsensusVerifier::new(
                            consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
                        ),
                    )
                    .is_err()
                {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid-ordered-proposal-signature",
                    );
                }
                if let Some(candidate) = &proposal.candidate
                    && let Err(error) = core_ordered::authenticate_candidate(&env, candidate)
                {
                    return ordered_error(&error);
                }
                let result = if vote {
                    core_ordered::process_proposal_successor(
                        warrant,
                        host.store.as_ref(),
                        &env,
                        &proposal,
                        &signer(host),
                    )
                } else {
                    core_ordered::observe_proposal_successor(
                        warrant,
                        host.store.as_ref(),
                        &env,
                        &proposal,
                    )
                };
                match result {
                    Ok(output) => ordered_economics::encode_event_output_response(&output),
                    Err(error) => ordered_error(&error),
                }
            },
        )
    })
    .await
}

async fn ordered_proposal<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    ordered_proposal_route(host, headers, body, true).await
}

async fn ordered_observe<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    ordered_proposal_route(host, headers, body, false).await
}

async fn ordered_certificate<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = ordered_economics::reject_unsupported_request(
        &headers,
        &body,
        ORDERED_CERTIFICATE_MEDIA_TYPE,
        MAX_ORDERED_CERTIFICATE_BYTES,
    ) {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let Ok(certificate) = consensus::decode_quorum_certificate(&body) else {
            return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-certificate");
        };
        serve(
            host,
            |warrant: &LiveWarrant<'_>, _: &DurableOperationContext| {
                let scope: OrderedScope = match OrderedScope::from_warrant(host, warrant) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                let env: OrderedEconomicsEnvironment<'_> = scope.env(host);
                if env
                    .policy
                    .engine()
                    .verify_certificate(
                        &certificate,
                        &consensus::Ed25519ConsensusVerifier::new(
                            consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
                        ),
                    )
                    .is_err()
                {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid-ordered-certificate-signature",
                    );
                }
                match core_ordered::process_certificate_successor(
                    warrant,
                    host.store.as_ref(),
                    &env,
                    &certificate,
                ) {
                    Ok(output) => ordered_economics::encode_event_output_response(&output),
                    Err(error) => ordered_error(&error),
                }
            },
        )
    })
    .await
}

async fn ordered_status<S: SuccessorStore>(State(host): State<SharedSuccessorHost<S>>) -> Response {
    blocking(host, |host: &SuccessorHostComposition<S>| {
        serve(
            host,
            |warrant: &LiveWarrant<'_>, _: &DurableOperationContext| {
                let scope: OrderedScope = match OrderedScope::from_warrant(host, warrant) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                let env: OrderedEconomicsEnvironment<'_> = scope.env(host);
                match core_ordered::query_status_successor(warrant, host.store.as_ref(), &env) {
                    Ok(status) => match core_ordered::encode_ordered_status(&status) {
                        Ok(bytes) => bytes_response(ORDERED_STATUS_MEDIA_TYPE, bytes),
                        Err(_) => error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ordered-status-encoding",
                        ),
                    },
                    Err(error) => ordered_error(&error),
                }
            },
        )
    })
    .await
}

async fn ordered_outcome<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    Path(selector): Path<String>,
) -> Response {
    let Some(request_id) = decode_hex64_selector(&selector).filter(|bytes| *bytes != [0; 32])
    else {
        return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-request-id");
    };
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        serve(
            host,
            |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
                let scope: OrderedScope = match OrderedScope::from_warrant(host, warrant) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                let env: OrderedEconomicsEnvironment<'_> = scope.env(host);
                match core_ordered::query_ordered_outcome(
                    host.store.as_ref(),
                    context,
                    &env,
                    &request_id,
                ) {
                    Ok(None) => (
                        StatusCode::NO_CONTENT,
                        [(header::CACHE_CONTROL, "no-store")],
                    )
                        .into_response(),
                    Ok(Some(outcome)) => match core_ordered::encode_ordered_outcome(&outcome) {
                        Ok(bytes) => bytes_response(ORDERED_OUTCOME_MEDIA_TYPE, bytes),
                        Err(_) => error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ordered-outcome-encoding",
                        ),
                    },
                    Err(error) => ordered_error(&error),
                }
            },
        )
    })
    .await
}

/// Trusted-local-clock pacemaker. The body must be empty; now comes only
/// from the host clock, and a Tick never manufactures authority or quorum.
async fn ordered_tick<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-ordered-content-encoding",
        );
    }
    if !body.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "ordered-tick-body-must-be-empty");
    }
    blocking(host, |host: &SuccessorHostComposition<S>| {
        let Ok(now_unix_millis) = host.clock.now_unix_millis() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "ordered-economics-clock-unavailable",
            );
        };
        serve(
            host,
            |warrant: &LiveWarrant<'_>, _: &DurableOperationContext| {
                let scope: OrderedScope = match OrderedScope::from_warrant(host, warrant) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                let env: OrderedEconomicsEnvironment<'_> = scope.env(host);
                match core_ordered::process_tick_successor(
                    warrant,
                    host.store.as_ref(),
                    &env,
                    now_unix_millis,
                    &signer(host),
                ) {
                    Ok(output) => ordered_economics::encode_event_output_response(&output),
                    Err(error) => ordered_error(&error),
                }
            },
        )
    })
    .await
}

/// FastVote prepare at the verified e+1 scope; also the paid Publish,
/// Instantiate and Call admission path, including a Call on an epoch-e
/// instance. A vote is signed only by the fresh namespace member.
async fn fastvote_prepare<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = fastvote_preflight(&headers, &body, MAX_SIGNED_PAID_INTENT_BYTES) {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let declared: PublicationContext = match authenticate_declared_intent(&host.resolver, &body)
        {
            Ok(value) => value,
            Err(response) => return response,
        };
        serve(
            host,
            |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
                if let Err(response) = require_warrant_context(&declared, warrant) {
                    return response;
                }
                let scope: FastVoteScope = match FastVoteScope::from_warrant(host, warrant, context)
                {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                match prepare_successor(
                    warrant,
                    host.store.as_ref(),
                    &scope.composition(host),
                    &signer(host),
                    &body,
                    host.created_checkpoint,
                ) {
                    Ok(vote) => match consensus::encode_fast_vote(&vote) {
                        Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                        Err(_) => error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "fastvote-vote-encoding",
                        ),
                    },
                    Err(error) => fastpath_error_response(&error),
                }
            },
        )
    })
    .await
}

/// Certified apply, with or without an availability certificate. Signerless
/// recovery uses the host checkpoint exactly like the original route.
fn fastvote_apply_with<S: SuccessorStore>(
    host: &SuccessorHostComposition<S>,
    signed: &[u8],
    certificate: &[u8],
    availability: Option<&[u8]>,
) -> Response {
    let declared: PublicationContext = match authenticate_declared_intent(&host.resolver, signed) {
        Ok(value) => value,
        Err(response) => return response,
    };
    serve(
        host,
        |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
            if let Err(response) = require_warrant_context(&declared, warrant) {
                return response;
            }
            let scope: FastVoteScope = match FastVoteScope::from_warrant(host, warrant, context) {
                Ok(value) => value,
                Err(response) => return response,
            };
            match apply_successor(
                warrant,
                host.store.as_ref(),
                &scope.composition(host),
                signed,
                certificate,
                availability,
                Some(host.created_checkpoint),
            ) {
                Ok(output) => node_result_response(request_id_of(signed), &output),
                Err(error) => fastpath_error_response(&error),
            }
        },
    )
}

async fn fastvote_apply<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = fastvote_preflight(&headers, &body, MAX_FASTVOTE_APPLY_REQUEST_BYTES) {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let Ok(request) = FastVoteApplyRequest::decode(&body) else {
            return error_response(StatusCode::BAD_REQUEST, "invalid-fastvote-apply-request");
        };
        fastvote_apply_with(
            host,
            &request.signed_paid_intent,
            &request.certificate,
            None,
        )
    })
    .await
}

async fn fastvote_published_apply<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) =
        fastvote_preflight(&headers, &body, MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES)
    {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let Ok(request) = FastVotePublishedApplyRequest::decode(&body) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid-fastvote-published-apply-request",
            );
        };
        fastvote_apply_with(
            host,
            &request.signed_paid_intent,
            &request.certificate,
            Some(&request.availability_certificate),
        )
    })
    .await
}

/// Availability ACK retention: the retained or fresh vote is exposed only
/// under this fresh warrant and signed only by the namespace member.
async fn fastvote_publication_retain<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) =
        fastvote_preflight(&headers, &body, consensus::bundle::MAX_ENCODED_BUNDLE_BYTES)
    {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let Ok(bundle) = consensus::bundle::decode_publication_bundle(&body) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid-fastvote-publication-bundle",
            );
        };
        let declared: PublicationContext =
            match authenticate_declared_intent(&host.resolver, &bundle.signed_intent) {
                Ok(value) => value,
                Err(response) => return response,
            };
        serve(
            host,
            |warrant: &LiveWarrant<'_>, _: &DurableOperationContext| {
                if let Err(response) = require_warrant_context(&declared, warrant) {
                    return response;
                }
                match retain_publication_successor(
                    warrant,
                    host.store.as_ref(),
                    &host.resolver,
                    &host.history,
                    &body,
                    &signer(host),
                ) {
                    Ok(vote) => match consensus::encode_availability_vote(&vote) {
                        Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                        Err(_) => error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "fastvote-availability-vote-encoding",
                        ),
                    },
                    Err(error) => publication_retention_error_response(&error),
                }
            },
        )
    })
    .await
}

/// Read-only bundle assembly from this replica committed prepare witness,
/// at the warrant e+1 context and domain. Never executes or applies.
async fn fastvote_publication_source<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = fastvote_preflight(&headers, &body, MAX_FASTVOTE_APPLY_REQUEST_BYTES) {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let Ok(request) = FastVoteApplyRequest::decode(&body) else {
            return error_response(StatusCode::BAD_REQUEST, "invalid-fastvote-source-request");
        };
        let declared: PublicationContext =
            match authenticate_declared_intent(&host.resolver, &request.signed_paid_intent) {
                Ok(value) => value,
                Err(response) => return response,
            };
        serve(
            host,
            |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
                if let Err(response) = require_warrant_context(&declared, warrant) {
                    return response;
                }
                match node_core::fast_path::publication::assemble_publication_bundle(
                    host.store.as_ref(),
                    context,
                    warrant.policy_inputs().domain(),
                    &host.resolver,
                    &host.history,
                    warrant.policy_inputs().context(),
                    &request.signed_paid_intent,
                    &request.certificate,
                ) {
                    Ok(bundle) => match consensus::bundle::encode_publication_bundle(&bundle) {
                        Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                        Err(_) => error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "fastvote-source-bundle-encoding",
                        ),
                    },
                    Err(error) => publication_retention_error_response(&error),
                }
            },
        )
    })
    .await
}

/// Context query at the verified e+1 epoch and domain.
async fn query_context<S: SuccessorStore>(State(host): State<SharedSuccessorHost<S>>) -> Response {
    blocking(host, |host: &SuccessorHostComposition<S>| {
        serve(
            host,
            |warrant: &LiveWarrant<'_>, _: &DurableOperationContext| {
                let context: &PublicationContext = warrant.policy_inputs().context();
                let query_protocol_config: ProtocolConfig = match resolve_query_protocol_config(
                    &host.resolver,
                    context.chain_id(),
                    context.protocol_version(),
                    context.epoch(),
                    &host.protocol_config,
                ) {
                    Ok(value) => value,
                    Err(error) => return query_node_error(error),
                };
                let profile = match resolve_transaction_auth_profile(&query_protocol_config) {
                    Ok(value) => value,
                    Err(error) => return query_node_error(NodeCoreError::from(error)),
                };
                let config_bytes: Vec<u8> = match query_protocol_config.canonical_bytes() {
                    Ok(value) => value,
                    Err(error) => return query_node_error(NodeCoreError::from(error)),
                };
                let Ok(result) = HttpContextQueryResult::new(
                    context.chain_id().clone(),
                    context.protocol_version(),
                    context.epoch(),
                    query_protocol_config.hash_suite_id,
                    profile.profile_id(),
                    profile.signature_scheme_id().as_u16(),
                    profile.address_binding().as_u16(),
                    warrant.policy_inputs().domain(),
                    config_bytes,
                ) else {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "query-state-invalid",
                    );
                };
                match result.encode() {
                    Ok(bytes) => bytes_response(QUERY_RESULT_MEDIA_TYPE, bytes),
                    Err(_) => {
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "query-state-invalid")
                    }
                }
            },
        )
    })
    .await
}

async fn query_object_route<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    Path(selector): Path<String>,
) -> Response {
    let Some(object_id) = decode_hex64_selector(&selector).map(ObjectId::new) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid-object-id");
    };
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        serve(
            host,
            |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
                let inputs: &SuccessorPolicyInputs = warrant.policy_inputs();
                match query_object(
                    host.store.as_ref(),
                    context,
                    inputs.domain(),
                    inputs.context().chain_id(),
                    object_id,
                ) {
                    Ok(result) if result.object_id() == object_id => {
                        match HttpObjectQueryResult::from(result).encode() {
                            Ok(bytes) => bytes_response(QUERY_RESULT_MEDIA_TYPE, bytes),
                            Err(_) => error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "query-state-invalid",
                            ),
                        }
                    }
                    Ok(_) => {
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "query-state-invalid")
                    }
                    Err(error) => query_node_error(error),
                }
            },
        )
    })
    .await
}

/// Exact original receipt exposure, including the original Seal receipt and
/// imported epoch-e receipts, under the fresh warrant issuer.
async fn query_receipt_route<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    Path(selector): Path<String>,
) -> Response {
    let Some(request_id) =
        decode_hex64_selector(&selector).and_then(|bytes| RequestId::new(bytes).ok())
    else {
        return error_response(StatusCode::BAD_REQUEST, "invalid-request-id");
    };
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        serve(
            host,
            |warrant: &LiveWarrant<'_>, _: &DurableOperationContext| {
                match query_request_receipt_successor(warrant, host.store.as_ref(), request_id) {
                    Ok(result) if result.request_id() == request_id => {
                        match http_receipt_query_result(result) {
                            Ok(wire) => match wire.encode() {
                                Ok(bytes) => bytes_response(QUERY_RESULT_MEDIA_TYPE, bytes),
                                Err(_) => error_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "query-state-invalid",
                                ),
                            },
                            Err(error) => query_node_error(NodeCoreError::from(error)),
                        }
                    }
                    Ok(_) => {
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "query-state-invalid")
                    }
                    Err(error) => query_node_error(error),
                }
            },
        )
    })
    .await
}

async fn query_next_nonce_route<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    Path(selector): Path<String>,
) -> Response {
    let Some(sender) = decode_hex64_selector(&selector) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid-sender");
    };
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        serve(
            host,
            |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
                let expected: &PublicationContext = warrant.policy_inputs().context();
                match query_sender_next_nonce(
                    host.store.as_ref(),
                    context,
                    warrant.policy_inputs().domain(),
                    expected.chain_id().clone(),
                    expected.protocol_version(),
                    expected.epoch(),
                    sender,
                ) {
                    Ok(next_nonce) => {
                        match HttpNextNonceQueryResult::new(
                            Address::new(sender),
                            expected.epoch(),
                            next_nonce,
                        )
                        .encode()
                        {
                            Ok(bytes) => bytes_response(QUERY_RESULT_MEDIA_TYPE, bytes),
                            Err(_) => error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "query-state-invalid",
                            ),
                        }
                    }
                    Err(error) => query_node_error(error),
                }
            },
        )
    })
    .await
}

/// Code/publication query; provenance-aware frames, never a synthesized
/// legacy signature.
async fn query_publication_route<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    Path((publisher, seed)): Path<(String, String)>,
) -> Response {
    let (Some(publisher), Some(seed)) = (
        decode_hex64_selector(&publisher),
        decode_hex64_selector(&seed),
    ) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid-publication-selector");
    };
    let Ok(origin) = PackageOrigin::unverified(host.resolver.chain_id().clone(), publisher, seed)
    else {
        return error_response(StatusCode::BAD_REQUEST, "invalid-publication-selector");
    };
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        serve(
            host,
            |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
                match node_core::publication::query_publication_with_history(
                    host.store.as_ref(),
                    context,
                    warrant.policy_inputs().domain(),
                    &host.resolver,
                    &host.history,
                    &origin,
                ) {
                    Ok(Some(result)) => {
                        match node_core::publication::encode_publication_query_result(&result) {
                            Ok(bytes) => bytes_response(QUERY_RESULT_MEDIA_TYPE, bytes),
                            Err(_) => error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "publication-result-encoding",
                            ),
                        }
                    }
                    Ok(None) => error_response(StatusCode::NOT_FOUND, "publication-not-found"),
                    Err(node_core::publication::PublicationAdmissionError::Node(error)) => {
                        query_node_error(error)
                    }
                    Err(_) => error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "publication-query-failed",
                    ),
                }
            },
        )
    })
    .await
}

/// Instance query, including epoch-e instances a paid Call may target.
async fn query_instance_route<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    Path((creator, seed)): Path<(String, String)>,
) -> Response {
    let (Some(creator), Some(seed)) = (
        decode_hex64_selector(&creator),
        decode_hex64_selector(&seed),
    ) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid-instance-selector");
    };
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        serve(
            host,
            |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
                match node_core::local_execution::query_local_instance(
                    host.store.as_ref(),
                    context,
                    warrant.policy_inputs().domain(),
                    &host.resolver,
                    &host.history,
                    warrant.policy_inputs().context().chain_id(),
                    creator,
                    seed,
                ) {
                    Ok(Some(record)) => match encode_instance_record(&record) {
                        Ok(bytes) => bytes_response(QUERY_RESULT_MEDIA_TYPE, bytes),
                        Err(_) => error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "instance-result-encoding",
                        ),
                    },
                    Ok(None) => error_response(StatusCode::NOT_FOUND, "instance-not-found"),
                    Err(node_core::local_execution::LocalExecutionAdmissionError::Node(error)) => {
                        query_node_error(error)
                    }
                    Err(_) => {
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "instance-query-failed")
                    }
                }
            },
        )
    })
    .await
}

/// The exact installed e+1 fee policy a paid caller signs against.
async fn query_fee_policy_route<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
) -> Response {
    blocking(host, |host: &SuccessorHostComposition<S>| {
        serve(
            host,
            |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
                let policy: PaidFeePolicy = match successor_fee_policy(host, warrant, context) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
                match encode_paid_fee_policy(&policy) {
                    Ok(bytes) => bytes_response(QUERY_RESULT_MEDIA_TYPE, bytes),
                    Err(_) => {
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "paid-fee-policy-invalid")
                    }
                }
            },
        )
    })
    .await
}

async fn refused_control() -> Response {
    error_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        "successor-control-unsupported",
    )
}

/// Read-only fee-claim preparation, including an imported epoch-e escrow.
/// Untrusted structural decode first; then a fresh warrant, exact e+1
/// context comparison, host checkpoint and fence, and the owning pure
/// preparation. Nothing is signed or committed; the raw unsigned canonical
/// FeeClaimIntent is returned for offline claimant signing.
async fn fee_claim_prepare<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = ordered_economics::reject_unsupported_request(
        &headers,
        &body,
        node_wire::FEE_CLAIM_PREPARE_REQUEST_MEDIA_TYPE,
        node_wire::MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES,
    ) {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let Ok(request) = node_wire::FeeClaimPrepareRequest::decode(&body) else {
            return error_response(StatusCode::BAD_REQUEST, "invalid-fee-claim-prepare-request");
        };
        let outcome: Result<Result<PreparedFeeClaim, Response>, SuccessorInvocationError> =
            with_authority(
                host,
                |warrant: &LiveWarrant<'_>, _: &DurableOperationContext| {
                    if request.context != *warrant.policy_inputs().context() {
                        return Ok(Err(error_response(
                            StatusCode::CONFLICT,
                            "fee-claim-epoch-repin-required",
                        )));
                    }
                    let leg_policy: LocalExecutionPolicy =
                        LocalExecutionPolicy::generic_object_results(
                            warrant.policy_inputs().context().clone(),
                        );
                    Ok(prepare_fee_claim_successor(
                        warrant,
                        host.store.as_ref(),
                        host.blobs.as_ref(),
                        &host.resolver,
                        &host.history,
                        &leg_policy,
                        host.engine.as_ref(),
                        request.as_core_request(),
                        host.created_checkpoint,
                    )
                    .map_err(|_| {
                        error_response(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "fee-claim-preparation-refused",
                        )
                    }))
                },
            );
        match outcome {
            Ok(Ok(prepared)) => {
                match node_core::fee_claims::codec::encode_fee_claim_intent(&prepared.intent) {
                    Ok(bytes) => bytes_response(node_wire::FEE_CLAIM_INTENT_MEDIA_TYPE, bytes),
                    Err(_) => error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "fee-claim-intent-encoding",
                    ),
                }
            }
            Ok(Err(response)) => response,
            Err(error) => invocation_error_response(&error),
        }
    })
    .await
}

/// Read-only successor fee-claim preparation, including an imported epoch-e
/// escrow, under one fresh warrant. The predecessor certificate scope comes
/// only from the verified evidence inside core, never from a caller epoch.
/// The returned intent is signed offline by the claimant and submitted as an
/// ordered e+1 candidate through the propose route. Nothing is written.
pub fn prepare_successor_fee_claim<S>(
    host: &SuccessorHostComposition<S>,
    request: FeeClaimPreparationRequest<'_>,
    created_checkpoint: u64,
) -> Result<PreparedFeeClaim, SuccessorInvocationError>
where
    S: StructuredDurableDomainStateStore + DurableStateKeyScanner,
{
    with_authority(
        host,
        |warrant: &LiveWarrant<'_>, _: &DurableOperationContext| {
            let leg_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(
                warrant.policy_inputs().context().clone(),
            );
            prepare_fee_claim_successor(
                warrant,
                host.store.as_ref(),
                host.blobs.as_ref(),
                &host.resolver,
                &host.history,
                &leg_policy,
                host.engine.as_ref(),
                request,
                created_checkpoint,
            )
            .map_err(SuccessorInvocationError::FeeClaim)
        },
    )
}

/// Builds the recurring-successor router over the original route paths.
///
/// Served through a fresh warrant: liveness (no storage), the context,
/// object, receipt, next-nonce, publication, instance and fee-policy
/// queries; ordered propose, vote, certificate, observe, status, outcome and
/// tick; FastVote prepare, apply, publication source, availability ACK and
/// published apply; fee-claim preparation; frontier, drain and Seal controls;
/// and successor-scoped ordered history reads. The store must provide the
/// existing portable repository and outbox exclusion capabilities required
/// by those same core owners. [SUCCESSOR_REFUSED_CONTROL_PATHS] answer 422 before I/O.
pub fn successor_router<S>(
    host: SuccessorHostComposition<S>,
) -> Result<Router, SuccessorRouterError>
where
    S: DurableStateKeyScanner
        + DurablePortableRepository
        + StructuredOutboxExclusionGuard
        + Send
        + Sync
        + 'static,
{
    if host.resolver.protocol_version() != host.protocol_config.protocol_version {
        return Err(SuccessorRouterError::ProtocolVersionMismatch);
    }
    if host.operation_timeout.is_zero() {
        return Err(SuccessorRouterError::ZeroOperationTimeout);
    }
    let shared: SharedSuccessorHost<S> = Arc::new(host);
    let mut router: Router<SharedSuccessorHost<S>> = Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(QUERY_CONTEXT_PATH, get(query_context::<S>))
        .route(QUERY_OBJECT_PATH, get(query_object_route::<S>))
        .route(QUERY_RECEIPT_PATH, get(query_receipt_route::<S>))
        .route(QUERY_NEXT_NONCE_PATH, get(query_next_nonce_route::<S>))
        .route(publication::QUERY_PATH, get(query_publication_route::<S>))
        .route(
            local_execution::INSTANCE_PATH,
            get(query_instance_route::<S>),
        )
        .route(
            paid_execution::PAID_FEE_POLICY_PATH,
            get(query_fee_policy_route::<S>),
        )
        .route(
            ORDERED_ECONOMICS_PROPOSE_PATH,
            post(ordered_propose::<S>)
                .layer(DefaultBodyLimit::max(MAX_ORDERED_PROPOSE_REQUEST_BYTES)),
        )
        .route(
            ORDERED_ECONOMICS_PROPOSAL_PATH,
            post(ordered_proposal::<S>).layer(DefaultBodyLimit::max(MAX_ORDERED_PROPOSAL_BYTES)),
        )
        .route(
            ORDERED_ECONOMICS_OBSERVE_PATH,
            post(ordered_observe::<S>).layer(DefaultBodyLimit::max(MAX_ORDERED_PROPOSAL_BYTES)),
        )
        .route(
            ORDERED_ECONOMICS_CERTIFICATE_PATH,
            post(ordered_certificate::<S>)
                .layer(DefaultBodyLimit::max(MAX_ORDERED_CERTIFICATE_BYTES)),
        )
        .route(ORDERED_ECONOMICS_STATUS_PATH, get(ordered_status::<S>))
        .route(ORDERED_ECONOMICS_OUTCOME_ROUTE, get(ordered_outcome::<S>))
        .route(
            ORDERED_ECONOMICS_TICK_PATH,
            post(ordered_tick::<S>).layer(DefaultBodyLimit::max(1)),
        )
        .route(
            FASTVOTE_PREPARE_PATH,
            post(fastvote_prepare::<S>).layer(DefaultBodyLimit::max(MAX_SIGNED_PAID_INTENT_BYTES)),
        )
        .route(
            FASTVOTE_CERTIFICATES_PATH,
            post(fastvote_apply::<S>)
                .layer(DefaultBodyLimit::max(MAX_FASTVOTE_APPLY_REQUEST_BYTES)),
        )
        .route(
            FASTVOTE_PUBLICATION_SOURCE_PATH,
            post(fastvote_publication_source::<S>)
                .layer(DefaultBodyLimit::max(MAX_FASTVOTE_APPLY_REQUEST_BYTES)),
        )
        .route(
            FASTVOTE_PUBLICATION_RETAIN_PATH,
            post(fastvote_publication_retain::<S>).layer(DefaultBodyLimit::max(
                consensus::bundle::MAX_ENCODED_BUNDLE_BYTES,
            )),
        )
        .route(
            FASTVOTE_PUBLISHED_APPLY_PATH,
            post(fastvote_published_apply::<S>).layer(DefaultBodyLimit::max(
                MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES,
            )),
        )
        .route(
            node_wire::FEE_CLAIM_PREPARE_PATH,
            post(fee_claim_prepare::<S>).layer(DefaultBodyLimit::max(
                node_wire::MAX_FEE_CLAIM_PREPARE_REQUEST_BYTES,
            )),
        )
        .merge(history::routes::<S>())
        .merge(controls::routes::<S>());
    for path in SUCCESSOR_REFUSED_CONTROL_PATHS {
        router = router.route(path, any(refused_control));
    }
    Ok(router.with_state(shared))
}

mod controls;
mod historical;
mod history;
pub use historical::{
    SuccessorHistoricalComposition, SuccessorHistoricalPolicySource, successor_history_router,
};

#[cfg(test)]
mod tests;
