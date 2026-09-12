#![forbid(unsafe_code)]

//! Native HTTP adapter for the runtime-neutral node-core boundary.
//!
//! This crate owns HTTP routing and status mapping. It does not add HTTP types
//! to protocol crates, and it accepts only canonical binary node events.

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{DefaultBodyLimit, Path, State, rejection::BytesRejection},
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use core::fmt;
mod local_execution;
mod publication;
use execution::{ExecutionError, WasmExecutionEngine};
use hashing::HashSuiteResolver;
use http_body_util::LengthLimitError;
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use node_core::{
    FeeEffectComposer, MAX_NODE_OUTPUT_ITEMS, MAX_NODE_PAYLOAD_BYTES, NodeConfig, NodeCoreError,
    NodeEvent, NodeEventKind, NodeOutboxBatch, NodeOutboxDelivery, OutboxClaim, OutboxLeaseId,
    PreinstalledFeeComposition, PreinstalledModuleCatalog, RequestId, TransactionAuthError,
    TransactionalNodeStateMachine, acknowledge_outbox_message,
    acknowledge_outbox_message_in_domain, authenticate_submit_transaction_event,
    claim_next_outbox_message, claim_next_outbox_message_in_domain,
    handle_authenticated_resolved_durable_submit_transaction,
    handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution,
    handle_idempotent_event, handle_resolved_idempotent_event, query_object, query_request_receipt,
    query_sender_next_nonce,
};
use objects::{Address, ObjectId};
use protocol_config::{
    DomainPlacementManifest, ProtocolConfig, ProtocolConfigError, resolve_transaction_auth_profile,
};
use protocol_types::ProtocolVersion;
use runtime::{
    AtomicityDomainId, BlobStore, Clock, DomainTransactionalStateStore, DueOutboxClaimRequest,
    DurableOperationContext, DurableOutboxAcknowledgement, DurableOutboxAcknowledgementOutcome,
    DurableOutboxAcknowledgementRejection, DurableOutboxClaimOutcome, DurableOutboxClaimRejection,
    DurableOutboxLeaseId, IndeterminateCommitReason, IndexedOutboxContractError,
    IndexedOutboxRepository, InvocationCancellation, MAX_DURABLE_OUTBOX_LEASE_MILLIS,
    OutboxRequestId, PersistenceLayout, RequestOutboxClaimRequest, Runtime, RuntimeError,
    StateKeyScan, StateKeyScanner, StorageCorrelationId, StorageDeadline,
    StructuredDurableDomainStateStore, TransactionalStateStore, Transport, WriterFenceGeneration,
};
use std::{
    convert::Infallible,
    error::Error,
    future::Future,
    io,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Semaphore, TryAcquireError, watch},
    task::JoinSet,
    time::{Instant, Sleep, sleep, timeout},
};
use tower::ServiceExt;

// Canonical HTTP event/query-result codecs and route/media-type constants
// live in `node-wire` (DR-0083) and are re-exported below so existing
// callers keep their original `native-http` import paths and byte-identical
// wire behavior.
pub use node_wire::{
    CONTEXT_QUERY_RESULT_TYPE_ID, HttpContextQueryResult, HttpContractError,
    HttpNextNonceQueryResult, HttpNodeResult, HttpObjectQueryResult, HttpReceiptQueryResult,
    LIVENESS_PATH, NEXT_NONCE_QUERY_RESULT_TYPE_ID, NODE_EVENT_MEDIA_TYPE, NODE_EVENT_PATH,
    NODE_RESULT_MEDIA_TYPE, OBJECT_QUERY_RESULT_TYPE_ID, ObjectQueryStatus, QUERY_CONTEXT_PATH,
    QUERY_NEXT_NONCE_PATH, QUERY_OBJECT_PATH, QUERY_RECEIPT_PATH, QUERY_RESULT_MEDIA_TYPE,
    QueryResultError, RECEIPT_QUERY_RESULT_TYPE_ID, ReceiptQueryStatus, http_receipt_query_result,
};

/// Maximum HTTP body size. The allowance above the inner payload covers framing.
pub const MAX_HTTP_EVENT_BODY_BYTES: usize = MAX_NODE_PAYLOAD_BYTES + 512;
/// Bounded native delivery lease; expired work is deliberately redelivered.
pub const NATIVE_OUTBOX_LEASE_MILLIS: u64 = 30_000;
/// Maximum storage-operation budget accepted by indexed native recovery.
pub const MAX_INDEXED_OUTBOX_OPERATION_MILLIS: u64 = 30_000;
/// Hard ceiling for accepted native HTTP connections, including clients that
/// have not completed request headers.
pub const MAX_NATIVE_HTTP_CONNECTIONS: usize = 4_096;
/// Default number of accepted connections permitted before HTTP parsing.
pub const DEFAULT_NATIVE_HTTP_CONNECTIONS: usize = 256;
/// Hard ceiling for an HTTP/1 request-header read deadline.
pub const MAX_NATIVE_HTTP_HEADER_READ_MILLIS: u64 = 30_000;
/// Hard ceiling for the idle interval between request-body reads.
pub const MAX_NATIVE_HTTP_BODY_IDLE_MILLIS: u64 = 30_000;
/// Hard ceiling for reading one complete request body.
pub const MAX_NATIVE_HTTP_BODY_TOTAL_MILLIS: u64 = 120_000;
/// Hard ceiling for writing one complete HTTP response.
pub const MAX_NATIVE_HTTP_RESPONSE_TOTAL_MILLIS: u64 = 300_000;
/// Default request-header read deadline.
pub const DEFAULT_NATIVE_HTTP_HEADER_READ_MILLIS: u64 = 5_000;
/// Default maximum idle interval between request-body reads.
pub const DEFAULT_NATIVE_HTTP_BODY_IDLE_MILLIS: u64 = 5_000;
/// Default total request-body read deadline.
pub const DEFAULT_NATIVE_HTTP_BODY_TOTAL_MILLIS: u64 = 30_000;
/// Default total HTTP response-write deadline.
pub const DEFAULT_NATIVE_HTTP_RESPONSE_TOTAL_MILLIS: u64 = 60_000;

/// Pre-parser connection and request-read policy for the native HTTP server.
///
/// This policy is independent of [`NativeBlockingPolicy`]. It bounds clients
/// before Axum has parsed a request or acquired a synchronous-work permit.
/// HTTP/1 keep-alive is always disabled, so one accepted connection can carry
/// at most one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeHttpServePolicy {
    max_connections: NonZeroUsize,
    header_read_timeout: Duration,
    body_idle_timeout: Duration,
    body_total_timeout: Duration,
    response_total_timeout: Duration,
    local_publication: bool,
    local_execution: bool,
}

impl NativeHttpServePolicy {
    /// Creates a bounded pre-parser policy from millisecond values.
    pub fn new(
        max_connections: usize,
        header_read_timeout_millis: u64,
        body_idle_timeout_millis: u64,
        body_total_timeout_millis: u64,
        response_total_timeout_millis: u64,
    ) -> Result<Self, NativeHttpServePolicyError> {
        let max_connections: NonZeroUsize = NonZeroUsize::new(max_connections)
            .filter(|value: &NonZeroUsize| value.get() <= MAX_NATIVE_HTTP_CONNECTIONS)
            .ok_or(NativeHttpServePolicyError::InvalidConnectionLimit)?;
        let header_read_timeout_millis: NonZeroU64 = NonZeroU64::new(header_read_timeout_millis)
            .filter(|value: &NonZeroU64| value.get() <= MAX_NATIVE_HTTP_HEADER_READ_MILLIS)
            .ok_or(NativeHttpServePolicyError::InvalidHeaderReadTimeout)?;
        let body_idle_timeout_millis: NonZeroU64 = NonZeroU64::new(body_idle_timeout_millis)
            .filter(|value: &NonZeroU64| value.get() <= MAX_NATIVE_HTTP_BODY_IDLE_MILLIS)
            .ok_or(NativeHttpServePolicyError::InvalidBodyIdleTimeout)?;
        let body_total_timeout_millis: NonZeroU64 = NonZeroU64::new(body_total_timeout_millis)
            .filter(|value: &NonZeroU64| value.get() <= MAX_NATIVE_HTTP_BODY_TOTAL_MILLIS)
            .ok_or(NativeHttpServePolicyError::InvalidBodyTotalTimeout)?;
        let response_total_timeout_millis: NonZeroU64 =
            NonZeroU64::new(response_total_timeout_millis)
                .filter(|value: &NonZeroU64| value.get() <= MAX_NATIVE_HTTP_RESPONSE_TOTAL_MILLIS)
                .ok_or(NativeHttpServePolicyError::InvalidResponseTotalTimeout)?;
        if body_idle_timeout_millis > body_total_timeout_millis {
            return Err(NativeHttpServePolicyError::BodyIdleExceedsTotal);
        }
        Ok(Self {
            max_connections,
            header_read_timeout: Duration::from_millis(header_read_timeout_millis.get()),
            body_idle_timeout: Duration::from_millis(body_idle_timeout_millis.get()),
            body_total_timeout: Duration::from_millis(body_total_timeout_millis.get()),
            response_total_timeout: Duration::from_millis(response_total_timeout_millis.get()),
            local_publication: false,
            local_execution: false,
        })
    }

    /// Returns the maximum concurrently accepted connections.
    #[must_use]
    pub const fn max_connections(self) -> NonZeroUsize {
        self.max_connections
    }

    /// Explicitly applies the local publication request body bound at ingress.
    /// The embedding host must independently enable the matching router capability.
    /// Both capabilities default off; every other path retains its existing bound.
    #[must_use]
    pub const fn with_local_publication(mut self, enabled: bool) -> Self {
        self.local_publication = enabled;
        self
    }

    /// Explicit local execution pre-parser capability; router opt-in remains separate.
    #[must_use]
    pub const fn with_local_execution(mut self, enabled: bool) -> Self {
        self.local_execution = enabled;
        self
    }
}

impl Default for NativeHttpServePolicy {
    fn default() -> Self {
        Self {
            local_publication: false,
            local_execution: false,
            max_connections: NonZeroUsize::new(DEFAULT_NATIVE_HTTP_CONNECTIONS)
                .unwrap_or(NonZeroUsize::MIN),
            header_read_timeout: Duration::from_millis(DEFAULT_NATIVE_HTTP_HEADER_READ_MILLIS),
            body_idle_timeout: Duration::from_millis(DEFAULT_NATIVE_HTTP_BODY_IDLE_MILLIS),
            body_total_timeout: Duration::from_millis(DEFAULT_NATIVE_HTTP_BODY_TOTAL_MILLIS),
            response_total_timeout: Duration::from_millis(
                DEFAULT_NATIVE_HTTP_RESPONSE_TOTAL_MILLIS,
            ),
        }
    }
}

/// Invalid native HTTP connection/read admission policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeHttpServePolicyError {
    /// The connection limit was zero or above the hard ceiling.
    InvalidConnectionLimit,
    /// The header-read timeout was zero or above the hard ceiling.
    InvalidHeaderReadTimeout,
    /// The body idle timeout was zero or above the hard ceiling.
    InvalidBodyIdleTimeout,
    /// The body total timeout was zero or above the hard ceiling.
    InvalidBodyTotalTimeout,
    /// The response total timeout was zero or above the hard ceiling.
    InvalidResponseTotalTimeout,
    /// The body idle timeout exceeded the total body-read timeout.
    BodyIdleExceedsTotal,
}

impl fmt::Display for NativeHttpServePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConnectionLimit => f.write_str("native HTTP connection limit is invalid"),
            Self::InvalidHeaderReadTimeout => {
                f.write_str("native HTTP header-read timeout is invalid")
            }
            Self::InvalidBodyIdleTimeout => f.write_str("native HTTP body idle timeout is invalid"),
            Self::InvalidBodyTotalTimeout => {
                f.write_str("native HTTP body total timeout is invalid")
            }
            Self::InvalidResponseTotalTimeout => {
                f.write_str("native HTTP response total timeout is invalid")
            }
            Self::BodyIdleExceedsTotal => {
                f.write_str("native HTTP body idle timeout exceeds total timeout")
            }
        }
    }
}

impl Error for NativeHttpServePolicyError {}

/// Trusted storage authority for one normalized native request.
///
/// The embedding host fixes writer fencing and time budgets. The HTTP request
/// supplies none of these values, and node-core still resolves the logical
/// domain from the protocol manifest before any storage read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructuredDurableRequestAuthority {
    writer_fence: WriterFenceGeneration,
    operation_timeout_millis: NonZeroU64,
    lease_duration_millis: NonZeroU64,
}

impl StructuredDurableRequestAuthority {
    /// Creates bounded request authority whose storage budget is below a lease.
    pub fn new(
        writer_fence: WriterFenceGeneration,
        operation_timeout_millis: u64,
        lease_duration_millis: u64,
    ) -> Result<Self, IndexedOutboxRecoveryAuthorityError> {
        let operation_timeout_millis = NonZeroU64::new(operation_timeout_millis)
            .ok_or(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout)?;
        let lease_duration_millis = NonZeroU64::new(lease_duration_millis)
            .filter(|duration| duration.get() <= MAX_DURABLE_OUTBOX_LEASE_MILLIS)
            .ok_or(IndexedOutboxRecoveryAuthorityError::InvalidLeaseDuration)?;
        if operation_timeout_millis.get() > MAX_INDEXED_OUTBOX_OPERATION_MILLIS
            || operation_timeout_millis >= lease_duration_millis
        {
            return Err(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout);
        }
        Ok(Self {
            writer_fence,
            operation_timeout_millis,
            lease_duration_millis,
        })
    }

    /// Returns the configured authoritative writer generation.
    #[must_use]
    pub const fn writer_fence(self) -> WriterFenceGeneration {
        self.writer_fence
    }
}

/// Misconfiguration detected while composing the structured durable router.
///
/// These are host-configuration invariants checked once, at composition time,
/// so a diverging protocol-version or domain-placement authority can never
/// reach a request. [`node_core::TrustedTransactionContext`] resolves its
/// `protocol_version` and `TransactionAuthProfile` authority solely from the
/// committed [`ProtocolConfig`] passed to [`structured_durable_router`]; this
/// keeps that authority identical to the one [`NodeConfig`] uses to validate
/// every ingress [`NodeEvent`], rather than letting the two silently diverge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StructuredDurableRouterError {
    /// [`ProtocolConfig::protocol_version`] did not match
    /// [`NodeConfig::protocol_version`].
    ProtocolVersionAuthorityMismatch {
        /// Version fixed by the ingress [`NodeConfig`].
        node_config: ProtocolVersion,
        /// Version committed in the [`ProtocolConfig`].
        protocol_config: ProtocolVersion,
    },
    /// The committed [`ProtocolConfig`] carried no domain-placement manifest,
    /// so no logical domain could be resolved for storage.
    MissingDomainPlacement,
    /// An opted-in publication policy disagreed with the native context or fixed profile.
    PublicationContextAuthorityMismatch,
}

impl fmt::Display for StructuredDurableRouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolVersionAuthorityMismatch {
                node_config,
                protocol_config,
            } => write!(
                f,
                "node config protocol version {} does not match committed protocol config version {}",
                node_config.get(),
                protocol_config.get()
            ),
            Self::MissingDomainPlacement => {
                f.write_str("committed protocol config carries no domain placement manifest")
            }
            Self::PublicationContextAuthorityMismatch => f.write_str(
                "local publication policy differs from native ingress context or fixed profile",
            ),
        }
    }
}

impl Error for StructuredDurableRouterError {}

/// Explicit components used by the normalized durable native request path.
///
/// Keeping these components separate from [`Runtime`] lets normalized stores
/// avoid implementing the legacy opaque [`runtime::StateStore`] interface.
#[derive(Debug)]
pub struct StructuredDurableNativeComponents<S, B, T, C, I> {
    store: Arc<S>,
    blob_store: Arc<B>,
    transport: Arc<T>,
    clock: Arc<C>,
    identities: Arc<I>,
    cancellation: Option<Arc<dyn InvocationCancellation>>,
}

impl<S, B, T, C, I> StructuredDurableNativeComponents<S, B, T, C, I> {
    /// Creates a composition that never cancels before storage dispatch.
    ///
    /// `blob_store` is a separate explicit component from `store`: normalized
    /// stores are never required to also implement [`runtime::BlobStore`].
    /// Existing compositions retain their original behavior. Use
    /// [`Self::with_cancellation`] when the host has an explicit trusted signal.
    #[must_use]
    pub const fn new(
        store: Arc<S>,
        blob_store: Arc<B>,
        transport: Arc<T>,
        clock: Arc<C>,
        identities: Arc<I>,
    ) -> Self {
        Self {
            store,
            blob_store,
            transport,
            clock,
            identities,
            cancellation: None,
        }
    }

    /// Creates a composition with an explicit trusted pre-storage cancellation signal.
    #[must_use]
    pub fn with_cancellation(
        store: Arc<S>,
        blob_store: Arc<B>,
        transport: Arc<T>,
        clock: Arc<C>,
        identities: Arc<I>,
        cancellation: Arc<dyn InvocationCancellation>,
    ) -> Self {
        Self {
            store,
            blob_store,
            transport,
            clock,
            identities,
            cancellation: Some(cancellation),
        }
    }

    fn is_cancelled(&self) -> bool {
        match &self.cancellation {
            Some(cancellation) => cancellation.is_cancelled(),
            None => false,
        }
    }
}

/// Trusted node composition's fee-charging capability, owned so it can be
/// stored inside [`PreinstalledWasmComposition`] and cloned across requests.
///
/// `treasury_object_id` and `composer` never come from HTTP request bytes,
/// exactly like `catalog`/`engine`/`created_checkpoint`. Each request builds
/// the borrowed [`node_core::PreinstalledFeeComposition`] this crate's
/// entrypoint call needs from this owned value.
#[derive(Clone, Debug)]
pub struct PreinstalledFeeCompositionConfig {
    treasury_object_id: ObjectId,
    composer: Arc<dyn FeeEffectComposer>,
}

impl PreinstalledFeeCompositionConfig {
    /// Creates a trusted fee-charging capability.
    #[must_use]
    pub fn new(treasury_object_id: ObjectId, composer: Arc<dyn FeeEffectComposer>) -> Self {
        Self {
            treasury_object_id,
            composer,
        }
    }
}

/// Trusted preinstalled-WASM composition input for
/// [`preinstalled_wasm_structured_durable_router`].
///
/// Every field is fixed by trusted node composition, exactly like
/// [`node_core::handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`]
/// requires: `catalog` and `engine` never come from HTTP request bytes, and
/// `created_checkpoint` never comes from request bytes or wall-clock time. It
/// is the caller's already-validated chain-progress value, identical in
/// origin and trust level to the `created_checkpoint` accepted by that
/// function. `fee` is optional only as a composition capability: `None`
/// preserves byte-identical historical behavior exclusively when the
/// committed schedule's worst-case fee is zero and the transaction declares
/// neither `fee_payment` nor a treasury access. A non-zero committed schedule
/// or a declared payment fails closed when this capability is absent.
#[derive(Clone, Debug)]
pub struct PreinstalledWasmComposition {
    catalog: Arc<PreinstalledModuleCatalog>,
    engine: WasmExecutionEngine,
    created_checkpoint: u64,
    fee: Option<PreinstalledFeeCompositionConfig>,
    publication: Option<node_core::publication::LocalPublicationPolicy>,
    local_execution: Option<LocalExecutionComposition>,
}

/// Explicit durably seeded publication and zero-fee execution policy registry.
#[derive(Clone, Debug)]
pub struct LocalExecutionComposition {
    policies: Vec<(
        node_core::publication::LocalPublicationPolicy,
        execution::local_execution::LocalExecutionPolicy,
    )>,
    engine: execution::LocalWasmExecutionEngine,
}
impl LocalExecutionComposition {
    /// Supplies trusted policies, never selected or constructed from HTTP inputs.
    #[must_use]
    pub fn new(
        publication: node_core::publication::LocalPublicationPolicy,
        policy: execution::local_execution::LocalExecutionPolicy,
    ) -> Self {
        Self {
            policies: vec![(publication, policy)],
            engine: execution::LocalWasmExecutionEngine::new(),
        }
    }

    /// Adds an explicitly trusted policy pair. Router construction rejects
    /// duplicate, unknown, mismatched or more than two executable profiles.
    #[must_use]
    pub fn with_policy(
        mut self,
        publication: node_core::publication::LocalPublicationPolicy,
        policy: execution::local_execution::LocalExecutionPolicy,
    ) -> Self {
        self.policies.push((publication, policy));
        self
    }
}

impl PreinstalledWasmComposition {
    /// Creates a trusted preinstalled-WASM composition input with no fee
    /// composition wired. This is executable only under a committed zero-fee
    /// schedule with no declared `fee_payment`; fee-bearing requests fail
    /// closed until [`Self::with_fee_composition`] is applied.
    ///
    /// `created_checkpoint` must be non-decreasing across process restarts
    /// for every object this composition may mutate: node-core rejects a
    /// Write whose `created_checkpoint` is lower than the previous immutable
    /// version's own stored checkpoint
    /// (`NodeCoreError::ObjectCreatedCheckpointRegression`), and that check
    /// fails closed rather than silently accepting a regressed value. This
    /// function does not derive or persist `created_checkpoint` itself; the
    /// caller must source it from its own already-validated, durably
    /// advancing chain progress (never wall-clock time, never HTTP request
    /// bytes), exactly like the node-core entrypoint this composition feeds.
    #[must_use]
    pub const fn new(
        catalog: Arc<PreinstalledModuleCatalog>,
        engine: WasmExecutionEngine,
        created_checkpoint: u64,
    ) -> Self {
        Self {
            catalog,
            engine,
            created_checkpoint,
            fee: None,
            publication: None,
            local_execution: None,
        }
    }

    /// Returns an equivalent composition with a trusted fee-charging
    /// capability wired in.
    #[must_use]
    pub fn with_fee_composition(mut self, fee: PreinstalledFeeCompositionConfig) -> Self {
        self.fee = Some(fee);
        self
    }

    /// Explicitly enables bounded, fee-free local-development publication.
    /// The identical policy must already be committed in the durable store.
    #[must_use]
    pub fn with_local_publication(
        mut self,
        policy: node_core::publication::LocalPublicationPolicy,
    ) -> Self {
        self.publication = Some(policy);
        self
    }

    /// Enables the separately seeded typed publication and execution capability.
    #[must_use]
    pub fn with_local_execution(mut self, composition: LocalExecutionComposition) -> Self {
        self.local_execution = Some(composition);
        self
    }
}

/// Admission policy for synchronous node and runtime work.
///
/// The limit is intentionally supplied by the embedding process because its
/// safe value depends on the database connection strategy and host capacity.
/// There is no hidden unbounded queue: excess requests fail immediately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeBlockingPolicy {
    max_concurrent_invocations: NonZeroUsize,
}

impl NativeBlockingPolicy {
    /// Creates a policy with an explicit non-zero concurrency limit.
    #[must_use]
    pub const fn new(max_concurrent_invocations: NonZeroUsize) -> Self {
        Self {
            max_concurrent_invocations,
        }
    }

    /// Returns the maximum synchronous invocations admitted at once.
    #[must_use]
    pub const fn max_concurrent_invocations(self) -> NonZeroUsize {
        self.max_concurrent_invocations
    }
}

/// Shared admission pool for native HTTP and scheduler-triggered recovery.
///
/// Clone and pass the same executor to request routing and either one-shot
/// recovery entrypoint so recovery cannot bypass request capacity.
#[derive(Clone, Debug)]
pub struct NativeBlockingExecutor {
    permits: Arc<Semaphore>,
}

impl NativeBlockingExecutor {
    /// Creates a shared executor from an explicit host capacity policy.
    #[must_use]
    pub fn new(policy: NativeBlockingPolicy) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(policy.max_concurrent_invocations().get())),
        }
    }

    fn try_acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit, TryAcquireError> {
        Arc::clone(&self.permits).try_acquire_owned()
    }
}

/// Supplies process-independent identities for persisted outbox leases.
///
/// An implementation must not reuse an identifier for the same request, even
/// across process restarts. Reuse could allow a delayed acknowledgement from
/// an expired attempt to acknowledge a newer delivery attempt.
pub trait OutboxLeaseIdSource {
    /// Returns the next unique lease identity for one request-scoped outbox.
    fn next_lease_id(
        &self,
        request_id: RequestId,
    ) -> Result<OutboxLeaseId, OutboxLeaseIdSourceError>;
}

/// Failures from the adapter-owned lease identity source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxLeaseIdSourceError {
    /// The backing entropy or durable sequence is temporarily unavailable.
    Unavailable,
    /// The source exhausted its non-repeating identity space.
    Exhausted,
}

impl fmt::Display for OutboxLeaseIdSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("outbox lease identity source is unavailable"),
            Self::Exhausted => f.write_str("outbox lease identity source is exhausted"),
        }
    }
}

impl Error for OutboxLeaseIdSourceError {}

/// Trusted deployment authority for one indexed outbox recovery domain.
///
/// The embedding host derives this from fenced physical placement. An
/// untrusted scheduler may trigger recovery but must never construct or alter
/// this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedOutboxRecoveryAuthority {
    domain: AtomicityDomainId,
    writer_fence: WriterFenceGeneration,
    operation_timeout_millis: NonZeroU64,
    lease_duration_millis: NonZeroU64,
}

impl IndexedOutboxRecoveryAuthority {
    /// Creates bounded recovery authority for one logical domain.
    pub fn new(
        domain: AtomicityDomainId,
        writer_fence: WriterFenceGeneration,
        operation_timeout_millis: u64,
        lease_duration_millis: u64,
    ) -> Result<Self, IndexedOutboxRecoveryAuthorityError> {
        let operation_timeout_millis = NonZeroU64::new(operation_timeout_millis)
            .ok_or(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout)?;
        let lease_duration_millis = NonZeroU64::new(lease_duration_millis)
            .filter(|duration| duration.get() <= MAX_DURABLE_OUTBOX_LEASE_MILLIS)
            .ok_or(IndexedOutboxRecoveryAuthorityError::InvalidLeaseDuration)?;
        if operation_timeout_millis.get() > MAX_INDEXED_OUTBOX_OPERATION_MILLIS
            || operation_timeout_millis >= lease_duration_millis
        {
            return Err(IndexedOutboxRecoveryAuthorityError::InvalidOperationTimeout);
        }
        Ok(Self {
            domain,
            writer_fence,
            operation_timeout_millis,
            lease_duration_millis,
        })
    }

    /// Returns the configured logical domain.
    #[must_use]
    pub const fn domain(self) -> AtomicityDomainId {
        self.domain
    }

    /// Returns the configured authoritative writer generation.
    #[must_use]
    pub const fn writer_fence(self) -> WriterFenceGeneration {
        self.writer_fence
    }
}

/// Invalid indexed recovery authority configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexedOutboxRecoveryAuthorityError {
    /// The operation timeout was zero, above its bound, or not below the lease.
    InvalidOperationTimeout,
    /// The lease duration was zero or above the shared durable bound.
    InvalidLeaseDuration,
}

impl fmt::Display for IndexedOutboxRecoveryAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOperationTimeout => {
                f.write_str("indexed outbox operation timeout is invalid")
            }
            Self::InvalidLeaseDuration => f.write_str("indexed outbox lease duration is invalid"),
        }
    }
}

impl Error for IndexedOutboxRecoveryAuthorityError {}

/// One pair of restart-safe operational identities for an indexed claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedOutboxAttemptIdentity {
    lease_id: DurableOutboxLeaseId,
    correlation_id: StorageCorrelationId,
}

impl IndexedOutboxAttemptIdentity {
    /// Creates one already-validated identity pair.
    #[must_use]
    pub const fn new(lease_id: DurableOutboxLeaseId, correlation_id: StorageCorrelationId) -> Self {
        Self {
            lease_id,
            correlation_id,
        }
    }
}

/// Supplies restart-safe lease and correlation identities before work is known.
pub trait IndexedOutboxIdentitySource {
    /// Returns identities that have never been used by another claim attempt.
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError>;
}

/// Failures from the indexed recovery identity source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexedOutboxIdentitySourceError {
    /// The backing entropy or durable sequence is temporarily unavailable.
    Unavailable,
    /// The source exhausted its non-repeating identity space.
    Exhausted,
}

impl fmt::Display for IndexedOutboxIdentitySourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("indexed outbox identity source is unavailable"),
            Self::Exhausted => f.write_str("indexed outbox identity source is exhausted"),
        }
    }
}

impl Error for IndexedOutboxIdentitySourceError {}

struct NativeHttpState<R, M, L> {
    runtime: Arc<R>,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_executor: NativeBlockingExecutor,
}

struct ResolvedDomainNativeHttpState<R, M, L> {
    runtime: Arc<R>,
    placement: DomainPlacementManifest,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_executor: NativeBlockingExecutor,
}

struct StructuredDurableNativeHttpState<S, B, M, T, C, I> {
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_executor: NativeBlockingExecutor,
}

type SharedStructuredDurableNativeHttpState<S, B, M, T, C, I> =
    Arc<StructuredDurableNativeHttpState<S, B, M, T, C, I>>;

struct PreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I> {
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    preinstalled_wasm: PreinstalledWasmComposition,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_executor: NativeBlockingExecutor,
}

type SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I> =
    Arc<PreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>;

/// Builds the recoverable native HTTP router.
///
/// Application state, request deduplication, responses, and the ordered outbox
/// commit atomically. Outbound messages are sent only through persisted
/// lease/ack state, so a retry can recover a committed invocation.
pub fn router<R, M, L>(
    runtime: Arc<R>,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_policy: NativeBlockingPolicy,
) -> Router
where
    R: Runtime + Send + Sync + 'static,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    router_with_executor(
        runtime,
        config,
        resolver,
        machine,
        lease_ids,
        NativeBlockingExecutor::new(blocking_policy),
    )
}

/// Builds the native router with a reusable blocking admission executor.
///
/// Native embeddings that run unattended outbox recovery should share this
/// executor with [`recover_outboxes_once`].
pub fn router_with_executor<R, M, L>(
    runtime: Arc<R>,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_executor: NativeBlockingExecutor,
) -> Router
where
    R: Runtime + Send + Sync + 'static,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    let state = Arc::new(NativeHttpState {
        runtime,
        config,
        resolver,
        machine,
        lease_ids,
        blocking_executor,
    });
    Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(NODE_EVENT_PATH, post(submit_event::<R, M, L>))
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .with_state(state)
}

/// Builds a native router that resolves state authority from protocol config.
///
/// This route is available only for stores implementing the explicit-domain
/// transaction contract. It never accepts a domain from the HTTP request and
/// carries node-core's resolved domain into request-scoped outbox delivery.
pub fn resolved_domain_router<R, M, L>(
    runtime: Arc<R>,
    placement: DomainPlacementManifest,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_policy: NativeBlockingPolicy,
) -> Router
where
    R: Runtime + Send + Sync + 'static,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    resolved_domain_router_with_executor(
        runtime,
        placement,
        config,
        resolver,
        machine,
        lease_ids,
        NativeBlockingExecutor::new(blocking_policy),
    )
}

/// Builds a resolved-domain router with shared blocking admission.
pub fn resolved_domain_router_with_executor<R, M, L>(
    runtime: Arc<R>,
    placement: DomainPlacementManifest,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    lease_ids: Arc<L>,
    blocking_executor: NativeBlockingExecutor,
) -> Router
where
    R: Runtime + Send + Sync + 'static,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    let state = Arc::new(ResolvedDomainNativeHttpState {
        runtime,
        placement,
        config,
        resolver,
        machine,
        lease_ids,
        blocking_executor,
    });
    Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(
            NODE_EVENT_PATH,
            post(submit_resolved_domain_event::<R, M, L>),
        )
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .with_state(state)
}

/// Builds the normalized durable native router.
///
/// This is the production-oriented composition seam: node-core commits typed
/// state, receipt, and outbox sections through one fenced transaction, then
/// native delivery claims only that committed request through the indexed
/// repository. Storage authority and operational identities come solely from
/// the embedding host.
///
/// This and [`preinstalled_wasm_structured_durable_router`] are the two native
/// route families that authenticate `SubmitTransaction` events. This router
/// uses the read-only execution path, while the preinstalled router additionally
/// executes its composition-trusted catalog. For `SubmitTransaction`,
/// [`authenticate_submit_transaction_event`] runs from `protocol_config` and
/// the validated ingress context before any access-plan derivation, identity
/// allocation, clock read, storage I/O, transition, outbox claim, or send.
/// `protocol_config.protocol_version` must equal
/// `config.protocol_version()` and `protocol_config` must carry a
/// domain-placement manifest, checked once here rather than per request, so
/// this route never resolves its logical domain and its transaction-auth
/// authority from two silently diverging sources.
pub fn structured_durable_router<S, B, M, T, C, I>(
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_policy: NativeBlockingPolicy,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    structured_durable_router_with_executor(
        components,
        protocol_config,
        authority,
        config,
        resolver,
        machine,
        NativeBlockingExecutor::new(blocking_policy),
    )
}

/// Builds the normalized durable router with shared blocking admission.
pub fn structured_durable_router_with_executor<S, B, M, T, C, I>(
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_executor: NativeBlockingExecutor,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    validate_structured_durable_router_authority(&protocol_config, &config)?;
    let state = Arc::new(StructuredDurableNativeHttpState {
        components,
        protocol_config,
        authority,
        config,
        resolver,
        machine,
        blocking_executor,
    });
    Ok(Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(
            NODE_EVENT_PATH,
            post(submit_structured_durable_event::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_CONTEXT_PATH,
            get(get_structured_durable_context::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_OBJECT_PATH,
            get(get_structured_durable_object::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_RECEIPT_PATH,
            get(get_structured_durable_receipt::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_NEXT_NONCE_PATH,
            get(get_structured_durable_next_nonce::<S, B, M, T, C, I>),
        )
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .with_state(state))
}

/// Builds the normalized durable native router with preinstalled-WASM
/// `SubmitTransaction` execution.
///
/// This is [`structured_durable_router`] with one difference: a
/// `SubmitTransaction` event is committed through
/// [`node_core::handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`]
/// instead of the read-only entrypoint, so a signed owned `Write`/`Consume`
/// object access can execute a trusted preinstalled deterministic WASM
/// contract call and commit its object effects. Under DR-0099, every other
/// event kind fails closed at native HTTP ingress before identity, clock,
/// storage, machine, outbox, or transport work. The generic
/// [`TransactionalNodeStateMachine`] machinery remains available internally
/// in node-core for a future family-specific authenticated route.
/// `preinstalled_wasm`'s catalog, engine, and `created_checkpoint` are fixed,
/// composition-trusted values
/// (see [`PreinstalledWasmComposition`]); none of them is ever derived from
/// an HTTP request or wall-clock time. [`structured_durable_router`] itself
/// is unaffected by this composition and remains read-only.
#[allow(clippy::too_many_arguments)]
pub fn preinstalled_wasm_structured_durable_router<S, B, M, T, C, I>(
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    preinstalled_wasm: PreinstalledWasmComposition,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_policy: NativeBlockingPolicy,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    preinstalled_wasm_structured_durable_router_with_executor(
        components,
        preinstalled_wasm,
        protocol_config,
        authority,
        config,
        resolver,
        machine,
        NativeBlockingExecutor::new(blocking_policy),
    )
}

/// Builds the preinstalled-WASM durable router with shared blocking admission.
#[allow(clippy::too_many_arguments)]
pub fn preinstalled_wasm_structured_durable_router_with_executor<S, B, M, T, C, I>(
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    preinstalled_wasm: PreinstalledWasmComposition,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    machine: Arc<M>,
    blocking_executor: NativeBlockingExecutor,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    validate_structured_durable_router_authority(&protocol_config, &config)?;
    if let Some(policy) = preinstalled_wasm.publication.as_ref()
        && (policy.profile() != 1
            || policy.context().chain_id() != config.chain_id()
            || policy.context().protocol_version() != config.protocol_version()
            || policy.context().epoch() != config.epoch()
            || resolver.chain_id() != config.chain_id()
            || resolver.protocol_version() != config.protocol_version()
            || node_core::publication::local_publication_profile_semantics(
                &resolver,
                policy.context(),
            )
            .ok()
            .as_ref()
                != Some(policy.semantics()))
    {
        return Err(StructuredDurableRouterError::PublicationContextAuthorityMismatch);
    }
    if let Some(local) = preinstalled_wasm.local_execution.as_ref() {
        let mut profiles: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        if local.policies.is_empty() || local.policies.len() > 2 {
            return Err(StructuredDurableRouterError::PublicationContextAuthorityMismatch);
        }
        for (publication, policy) in &local.policies {
            let semantics = match policy.profile() {
                2 => execution::local_execution::local_execution_semantics(
                    &resolver,
                    policy.context(),
                ),
                3 => execution::local_execution::general_execution_semantics(
                    &resolver,
                    policy.context(),
                ),
                _ => return Err(StructuredDurableRouterError::PublicationContextAuthorityMismatch),
            };
            if !profiles.insert(policy.profile())
                || publication.profile() != policy.profile()
                || policy.context() != publication.context()
                || policy.context().chain_id() != config.chain_id()
                || policy.context().protocol_version() != config.protocol_version()
                || policy.context().epoch() != config.epoch()
                || resolver.chain_id() != config.chain_id()
                || resolver.protocol_version() != config.protocol_version()
                || semantics.ok().as_ref() != Some(publication.semantics())
            {
                return Err(StructuredDurableRouterError::PublicationContextAuthorityMismatch);
            }
        }
    }
    let state = Arc::new(PreinstalledWasmStructuredDurableNativeHttpState {
        components,
        preinstalled_wasm,
        protocol_config,
        authority,
        config,
        resolver,
        machine,
        blocking_executor,
    });
    Ok(Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(
            NODE_EVENT_PATH,
            post(submit_preinstalled_wasm_structured_durable_event::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_CONTEXT_PATH,
            get(get_preinstalled_wasm_structured_durable_context::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_OBJECT_PATH,
            get(get_preinstalled_wasm_structured_durable_object::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_RECEIPT_PATH,
            get(get_preinstalled_wasm_structured_durable_receipt::<S, B, M, T, C, I>),
        )
        .route(
            QUERY_NEXT_NONCE_PATH,
            get(get_preinstalled_wasm_structured_durable_next_nonce::<S, B, M, T, C, I>),
        )
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .merge(publication::routes(
            state.preinstalled_wasm.publication.is_some()
                || state.preinstalled_wasm.local_execution.is_some(),
        ))
        .merge(local_execution::routes(
            state.preinstalled_wasm.local_execution.is_some(),
        ))
        .with_state(state))
}

/// Checked once at composition time by both [`structured_durable_router`] and
/// [`preinstalled_wasm_structured_durable_router`]: see
/// [`StructuredDurableRouterError`] for why this must never diverge per
/// request.
fn validate_structured_durable_router_authority(
    protocol_config: &ProtocolConfig,
    config: &NodeConfig,
) -> Result<(), StructuredDurableRouterError> {
    if protocol_config.protocol_version != config.protocol_version() {
        return Err(
            StructuredDurableRouterError::ProtocolVersionAuthorityMismatch {
                node_config: config.protocol_version(),
                protocol_config: protocol_config.protocol_version,
            },
        );
    }
    if protocol_config.domain_placement.is_none() {
        return Err(StructuredDurableRouterError::MissingDomainPlacement);
    }
    Ok(())
}

/// Serves a configured native router with the default bounded connection and
/// request-read policy until the shutdown future completes.
///
/// Build `app` with [`router`], [`structured_durable_router`], or
/// [`preinstalled_wasm_structured_durable_router`] so the blocking admission
/// policy is explicit at the composition boundary. Use [`serve_with_policy`]
/// when an embedding host needs a smaller, explicitly validated limit.
pub async fn serve<F>(listener: tokio::net::TcpListener, app: Router, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_with_policy(listener, app, NativeHttpServePolicy::default(), shutdown).await
}

/// Serves a configured native router with explicit pre-parser admission.
///
/// A connection permit is acquired immediately after `accept` and before
/// Hyper parses request bytes. Connections above the limit are closed without
/// parsing or queueing application work. Header reads have one total deadline,
/// every socket read has an idle deadline, collecting the one allowed request
/// body has a separate total deadline, and response writes have idle and total
/// deadlines. HTTP/1 keep-alive is disabled,
/// bounding every accepted connection to one request. These controls are
/// independent of, and preserve, [`NativeBlockingExecutor`] admission for
/// synchronous state-machine and storage work.
pub async fn serve_with_policy<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    policy: NativeHttpServePolicy,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let connection_permits: Arc<Semaphore> = Arc::new(Semaphore::new(policy.max_connections.get()));
    let (shutdown_sender, _shutdown_receiver) = watch::channel(false);
    let mut connections: JoinSet<()> = JoinSet::new();
    let mut shutdown = Box::pin(shutdown);
    let mut consecutive_accept_errors: u32 = 0;

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _remote_address) = match accepted {
                    Ok(accepted) => accepted,
                    Err(_error) => {
                        consecutive_accept_errors = consecutive_accept_errors.saturating_add(1);
                        let backoff = accept_error_backoff(consecutive_accept_errors);
                        tokio::select! {
                            _ = &mut shutdown => break,
                            () = sleep(backoff) => {}
                        }
                        continue;
                    }
                };
                consecutive_accept_errors = 0;
                let permit = match Arc::clone(&connection_permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(TryAcquireError::NoPermits | TryAcquireError::Closed) => {
                        drop(stream);
                        continue;
                    }
                };
                let connection_app: Router = app.clone();
                let connection_shutdown = shutdown_sender.subscribe();
                connections.spawn(async move {
                    let _permit = permit;
                    serve_connection(
                        stream,
                        connection_app,
                        policy,
                        connection_shutdown,
                    )
                    .await;
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                let _completed = completed;
            }
        }
    }

    let _sent = shutdown_sender.send(true);
    while connections.join_next().await.is_some() {}
    Ok(())
}

/// Bounded, non-spinning backoff for a run of consecutive [`TcpListener::accept`]
/// errors (for example transient `EMFILE`/`ENFILE` resource exhaustion or
/// `ECONNABORTED`). Never returns zero, so a tight accept-fail loop cannot
/// spin the executor, and growth is capped so recovery after a burst of
/// errors is bounded by [`ACCEPT_ERROR_BACKOFF_CEILING`].
///
/// [`TcpListener::accept`]: tokio::net::TcpListener::accept
fn accept_error_backoff(consecutive_errors: u32) -> Duration {
    const MAX_DOUBLINGS: u32 = 8;
    let doublings = consecutive_errors.saturating_sub(1).min(MAX_DOUBLINGS);
    let multiplier = 1u32.checked_shl(doublings).unwrap_or(u32::MAX);
    ACCEPT_ERROR_BACKOFF_FLOOR
        .saturating_mul(multiplier)
        .min(ACCEPT_ERROR_BACKOFF_CEILING)
}

const ACCEPT_ERROR_BACKOFF_FLOOR: Duration = Duration::from_millis(5);
const ACCEPT_ERROR_BACKOFF_CEILING: Duration = Duration::from_secs(1);

async fn serve_connection(
    stream: tokio::net::TcpStream,
    app: Router,
    policy: NativeHttpServePolicy,
    mut shutdown: watch::Receiver<bool>,
) {
    let stream = IoIdleTimeoutStream::new(
        stream,
        policy.body_idle_timeout,
        policy.response_total_timeout,
    );
    let io = TokioIo::new(stream);
    let service = service_fn(move |request: Request<Incoming>| {
        dispatch_bounded_request(
            app.clone(),
            request,
            policy.body_total_timeout,
            policy.local_publication,
            policy.local_execution,
        )
    });
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(64)
        .max_buf_size(64 * 1024)
        .timer(TokioTimer::new())
        .header_read_timeout(policy.header_read_timeout);
    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);

    tokio::select! {
        _result = &mut connection => {}
        _changed = shutdown.changed() => {
            connection.as_mut().graceful_shutdown();
            let _result = connection.await;
        }
    }
}

async fn dispatch_bounded_request(
    app: Router,
    request: Request<Incoming>,
    body_total_timeout: Duration,
    local_publication: bool,
    local_execution: bool,
) -> Result<Response, Infallible> {
    let (parts, incoming) = request.into_parts();
    let body = Body::new(incoming);
    let limit: usize = if local_publication
        && parts.method == axum::http::Method::POST
        && parts.uri.path() == publication::PUBLICATION_PATH
    {
        execution::publication::MAX_PUBLICATION_SUBMISSION_BYTES
    } else if local_execution
        && parts.method == axum::http::Method::POST
        && parts.uri.path() == local_execution::EXECUTION_PATH
    {
        execution::local_execution::MAX_LOCAL_EXECUTION_INTENT_BYTES
    } else {
        MAX_HTTP_EVENT_BODY_BYTES
    };
    let bytes = match timeout(body_total_timeout, to_bytes(body, limit)).await {
        Err(_) => {
            return Ok(error_response(
                StatusCode::REQUEST_TIMEOUT,
                "body-read-timeout",
            ));
        }
        Ok(Err(error)) => {
            let source = error.into_inner();
            let status = if source.downcast_ref::<LengthLimitError>().is_some() {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            return Ok(error_response(status, "body-rejected"));
        }
        Ok(Ok(bytes)) => bytes,
    };
    let request = Request::from_parts(parts, Body::from(bytes));
    let response = match app.oneshot(request).await {
        Ok(response) => response,
        Err(error) => match error {},
    };
    Ok(response)
}

struct IoIdleTimeoutStream<S> {
    stream: S,
    idle_timeout: Duration,
    response_total_timeout: Duration,
    read_deadline: Pin<Box<Sleep>>,
    write_idle_deadline: Option<Pin<Box<Sleep>>>,
    write_total_deadline: Option<Pin<Box<Sleep>>>,
}

impl<S> IoIdleTimeoutStream<S> {
    fn new(stream: S, idle_timeout: Duration, response_total_timeout: Duration) -> Self {
        Self {
            stream,
            idle_timeout,
            response_total_timeout,
            read_deadline: Box::pin(tokio::time::sleep(idle_timeout)),
            write_idle_deadline: None,
            write_total_deadline: None,
        }
    }
}

impl<S> AsyncRead for IoIdleTimeoutStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before: usize = buffer.filled().len();
        match Pin::new(&mut this.stream).poll_read(context, buffer) {
            Poll::Ready(Ok(())) if buffer.filled().len() > filled_before => {
                this.read_deadline
                    .as_mut()
                    .reset(Instant::now() + this.idle_timeout);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match this.read_deadline.as_mut().poll(context) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native HTTP request read idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<S> AsyncWrite for IoIdleTimeoutStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let total_deadline: &mut Pin<Box<Sleep>> = this
            .write_total_deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(this.response_total_timeout)));
        if total_deadline.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native HTTP response write total timeout",
            )));
        }
        match Pin::new(&mut this.stream).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) if written > 0 => {
                let idle_deadline: &mut Pin<Box<Sleep>> = this
                    .write_idle_deadline
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(this.idle_timeout)));
                idle_deadline
                    .as_mut()
                    .reset(Instant::now() + this.idle_timeout);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => {
                let idle_deadline: &mut Pin<Box<Sleep>> = this
                    .write_idle_deadline
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(this.idle_timeout)));
                match idle_deadline.as_mut().poll(context) {
                    Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "native HTTP response write idle timeout",
                    ))),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

/// Result of one bounded scheduler-triggered recovery invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeOutboxRecoveryOutcome {
    /// This page contained no expired or unleased pending outbox.
    NoEligibleOutbox,
    /// One pending outbox was delivered through its persisted cursor.
    Recovered(RequestId),
    /// Another invocation won the lease or state transaction race.
    Contended(RequestId),
}

/// Bounded progress returned to an untrusted external scheduler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeOutboxRecoveryReport {
    outcome: NativeOutboxRecoveryOutcome,
    continuation_cursor: Option<Vec<u8>>,
}

impl NativeOutboxRecoveryReport {
    /// Returns what this invocation observed or recovered.
    #[must_use]
    pub const fn outcome(&self) -> &NativeOutboxRecoveryOutcome {
        &self.outcome
    }

    /// Returns the exclusive key cursor for the next page/invocation.
    ///
    /// `None` ends this sweep. A later scheduled sweep must start from `None`
    /// again to discover concurrent inserts and expired leases.
    #[must_use]
    pub fn continuation_cursor(&self) -> Option<&[u8]> {
        self.continuation_cursor.as_deref()
    }
}

/// Failures from one scheduler-triggered recovery invocation.
#[derive(Debug)]
pub enum NativeOutboxRecoveryError {
    /// Request work already occupies the configured blocking capacity.
    CapacityExhausted,
    /// The shared admission pool was closed.
    AdmissionClosed,
    /// Tokio could not join the blocking task.
    BlockingTaskFailed,
    /// Key discovery or durable state access failed.
    Runtime(RuntimeError),
    /// Persisted outbox state or a lease transition failed validation.
    Node(NodeCoreError),
    /// The outbound transport rejected a leased message.
    Send,
    /// A restart-safe lease identifier could not be allocated.
    LeaseId(OutboxLeaseIdSourceError),
}

impl fmt::Display for NativeOutboxRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExhausted => f.write_str("native blocking capacity is exhausted"),
            Self::AdmissionClosed => f.write_str("native blocking admission is closed"),
            Self::BlockingTaskFailed => f.write_str("native blocking recovery task failed"),
            Self::Runtime(error) => write!(f, "outbox discovery failed: {error}"),
            Self::Node(error) => write!(f, "outbox recovery failed: {error}"),
            Self::Send => f.write_str("outbox recovery transport send failed"),
            Self::LeaseId(error) => write!(f, "outbox recovery lease identity failed: {error}"),
        }
    }
}

impl Error for NativeOutboxRecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Node(error) => Some(error),
            Self::LeaseId(error) => Some(error),
            _ => None,
        }
    }
}

/// Failures from one indexed production outbox recovery invocation.
#[derive(Debug)]
pub enum IndexedOutboxRecoveryError {
    /// Request work already occupies the configured blocking capacity.
    CapacityExhausted,
    /// The shared admission pool was closed.
    AdmissionClosed,
    /// Tokio could not join the bounded blocking task.
    BlockingTaskFailed,
    /// Trusted clock or transport runtime failed.
    Runtime(RuntimeError),
    /// Deadline or lease arithmetic overflowed.
    TimeOverflow,
    /// Restart-safe operational identities could not be allocated.
    Identity(IndexedOutboxIdentitySourceError),
    /// The indexed claim request or returned claim violated shared bounds.
    Contract(IndexedOutboxContractError),
    /// The repository proved that no claim lease was installed.
    ClaimRejected(DurableOutboxClaimRejection),
    /// The claim lease may have committed but could not be reconciled.
    ClaimIndeterminate(IndeterminateCommitReason),
    /// The repository returned a claim that did not match the requested lease.
    ClaimIdentityMismatch,
    /// The claimed canonical outbound event was invalid.
    Node(NodeCoreError),
    /// The outbound transport rejected the claimed canonical bytes.
    Send,
    /// The repository proved that the sent message was not acknowledged.
    AcknowledgementRejected(DurableOutboxAcknowledgementRejection),
    /// The acknowledgement may have committed but could not be reconciled.
    AcknowledgementIndeterminate(IndeterminateCommitReason),
}

impl fmt::Display for IndexedOutboxRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExhausted => f.write_str("native blocking capacity is exhausted"),
            Self::AdmissionClosed => f.write_str("native blocking admission is closed"),
            Self::BlockingTaskFailed => f.write_str("indexed recovery blocking task failed"),
            Self::Runtime(error) => write!(f, "indexed recovery runtime failed: {error}"),
            Self::TimeOverflow => f.write_str("indexed recovery time arithmetic overflowed"),
            Self::Identity(error) => write!(f, "indexed recovery identity failed: {error}"),
            Self::Contract(error) => write!(f, "indexed recovery contract failed: {error}"),
            Self::ClaimRejected(reason) => {
                write!(f, "indexed outbox claim was rejected: {reason:?}")
            }
            Self::ClaimIndeterminate(reason) => {
                write!(f, "indexed outbox claim is indeterminate: {reason:?}")
            }
            Self::ClaimIdentityMismatch => {
                f.write_str("indexed outbox claim identity did not match request")
            }
            Self::Node(error) => write!(f, "indexed outbox payload is invalid: {error}"),
            Self::Send => f.write_str("indexed outbox transport send failed"),
            Self::AcknowledgementRejected(reason) => {
                write!(f, "indexed outbox acknowledgement was rejected: {reason:?}")
            }
            Self::AcknowledgementIndeterminate(reason) => write!(
                f,
                "indexed outbox acknowledgement is indeterminate: {reason:?}"
            ),
        }
    }
}

impl Error for IndexedOutboxRecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Node(error) => Some(error),
            _ => None,
        }
    }
}

/// Claims, sends, and acknowledges at most one indexed due outbox message.
///
/// The scheduler supplies no cursor, domain, clock, fence, or deadline. Trusted
/// embedding composition supplies immutable authority and identity sources.
/// Claim and acknowledgement ambiguity each receive one same-identity
/// reconciliation attempt; an unreconciled claim is never sent.
pub async fn recover_indexed_outbox_once<R, I>(
    runtime: Arc<R>,
    authority: IndexedOutboxRecoveryAuthority,
    identities: Arc<I>,
    blocking_executor: NativeBlockingExecutor,
) -> Result<NativeOutboxRecoveryReport, IndexedOutboxRecoveryError>
where
    R: Runtime + Send + Sync + 'static,
    R::State: IndexedOutboxRepository,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let permit = match blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => {
            return Err(IndexedOutboxRecoveryError::CapacityExhausted);
        }
        Err(TryAcquireError::Closed) => {
            return Err(IndexedOutboxRecoveryError::AdmissionClosed);
        }
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        recover_indexed_outbox_once_blocking(runtime.as_ref(), authority, identities.as_ref())
    })
    .await
    .map_err(|_| IndexedOutboxRecoveryError::BlockingTaskFailed)?
}

fn recover_indexed_outbox_once_blocking<R, I>(
    runtime: &R,
    authority: IndexedOutboxRecoveryAuthority,
    identities: &I,
) -> Result<NativeOutboxRecoveryReport, IndexedOutboxRecoveryError>
where
    R: Runtime,
    R::State: IndexedOutboxRepository,
    I: IndexedOutboxIdentitySource,
{
    let now_unix_millis = runtime
        .clock()
        .now_unix_millis()
        .map_err(IndexedOutboxRecoveryError::Runtime)?;
    let deadline_unix_millis = now_unix_millis
        .checked_add(authority.operation_timeout_millis.get())
        .ok_or(IndexedOutboxRecoveryError::TimeOverflow)?;
    let lease_expires_at_unix_millis = now_unix_millis
        .checked_add(authority.lease_duration_millis.get())
        .ok_or(IndexedOutboxRecoveryError::TimeOverflow)?;
    let identity = identities
        .next_attempt_identity()
        .map_err(IndexedOutboxRecoveryError::Identity)?;
    let context = DurableOperationContext::new(
        authority.writer_fence,
        StorageDeadline::new(deadline_unix_millis)
            .ok_or(IndexedOutboxRecoveryError::TimeOverflow)?,
        identity.correlation_id,
    );
    let claim_request = DueOutboxClaimRequest::new(
        authority.domain,
        now_unix_millis,
        identity.lease_id,
        lease_expires_at_unix_millis,
    )
    .map_err(IndexedOutboxRecoveryError::Contract)?;

    let claim = reconcile_indexed_claim(runtime.state_store(), &context, claim_request)?;
    let Some(claim) = claim else {
        return Ok(NativeOutboxRecoveryReport {
            outcome: NativeOutboxRecoveryOutcome::NoEligibleOutbox,
            continuation_cursor: None,
        });
    };
    if claim.lease_id() != identity.lease_id
        || claim.lease_expires_at_unix_millis() != lease_expires_at_unix_millis
    {
        return Err(IndexedOutboxRecoveryError::ClaimIdentityMismatch);
    }
    let event =
        NodeEvent::decode(claim.canonical_payload()).map_err(IndexedOutboxRecoveryError::Node)?;
    let canonical_payload = event.encode().map_err(IndexedOutboxRecoveryError::Node)?;
    if canonical_payload != claim.canonical_payload() {
        return Err(IndexedOutboxRecoveryError::Node(
            NodeCoreError::PersistenceInvariant("indexed outbox payload is not canonical"),
        ));
    }
    runtime
        .transport()
        .send(canonical_payload)
        .map_err(|_| IndexedOutboxRecoveryError::Send)?;

    let acknowledgement = DurableOutboxAcknowledgement::new(
        authority.domain,
        claim.request_id(),
        claim.message_index(),
        claim.lease_id(),
    );
    reconcile_indexed_acknowledgement(runtime.state_store(), &context, acknowledgement)?;
    let request_id =
        RequestId::new(*claim.request_id().as_bytes()).map_err(IndexedOutboxRecoveryError::Node)?;
    Ok(NativeOutboxRecoveryReport {
        outcome: NativeOutboxRecoveryOutcome::Recovered(request_id),
        continuation_cursor: None,
    })
}

fn reconcile_indexed_claim<S>(
    store: &S,
    context: &DurableOperationContext,
    request: DueOutboxClaimRequest,
) -> Result<Option<runtime::DurableOutboxClaim>, IndexedOutboxRecoveryError>
where
    S: IndexedOutboxRepository,
{
    match store.claim_due_outbox(context, request) {
        DurableOutboxClaimOutcome::Claimed(claim) => Ok(Some(claim)),
        DurableOutboxClaimOutcome::NoDueWork => Ok(None),
        DurableOutboxClaimOutcome::Rejected(reason) => {
            Err(IndexedOutboxRecoveryError::ClaimRejected(reason))
        }
        DurableOutboxClaimOutcome::Indeterminate(first_reason) => {
            match store.claim_due_outbox(context, request) {
                DurableOutboxClaimOutcome::Claimed(claim) => Ok(Some(claim)),
                _ => Err(IndexedOutboxRecoveryError::ClaimIndeterminate(first_reason)),
            }
        }
    }
}

fn reconcile_indexed_acknowledgement<S>(
    store: &S,
    context: &DurableOperationContext,
    acknowledgement: DurableOutboxAcknowledgement,
) -> Result<(), IndexedOutboxRecoveryError>
where
    S: IndexedOutboxRepository,
{
    match store.acknowledge_outbox(context, acknowledgement) {
        DurableOutboxAcknowledgementOutcome::Acknowledged => Ok(()),
        DurableOutboxAcknowledgementOutcome::Rejected(reason) => {
            Err(IndexedOutboxRecoveryError::AcknowledgementRejected(reason))
        }
        DurableOutboxAcknowledgementOutcome::Indeterminate(first_reason) => {
            match store.acknowledge_outbox(context, acknowledgement) {
                DurableOutboxAcknowledgementOutcome::Acknowledged => Ok(()),
                _ => Err(IndexedOutboxRecoveryError::AcknowledgementIndeterminate(
                    first_reason,
                )),
            }
        }
    }
}

/// Recovers at most one unattended outbox without requiring a live request.
///
/// The caller is an untrusted scheduler: it supplies only a bounded scan cursor
/// and page size, and must invoke this function again while a continuation is
/// returned. A later sweep restarts with `after = None`. This function creates
/// no loop or background task and shares admission with HTTP when given the
/// same [`NativeBlockingExecutor`].
pub async fn recover_outboxes_once<R, L>(
    runtime: Arc<R>,
    config: NodeConfig,
    lease_ids: Arc<L>,
    blocking_executor: NativeBlockingExecutor,
    after: Option<Vec<u8>>,
    scan_limit: NonZeroUsize,
) -> Result<NativeOutboxRecoveryReport, NativeOutboxRecoveryError>
where
    R: Runtime + Send + Sync + 'static,
    R::State: TransactionalStateStore + StateKeyScanner,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
    let scan = StateKeyScan::new(layout.outbox_prefix(), after, scan_limit)
        .map_err(NativeOutboxRecoveryError::Runtime)?;
    let permit = match blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => {
            return Err(NativeOutboxRecoveryError::CapacityExhausted);
        }
        Err(TryAcquireError::Closed) => {
            return Err(NativeOutboxRecoveryError::AdmissionClosed);
        }
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        recover_outboxes_once_blocking(runtime.as_ref(), &config, lease_ids.as_ref(), &scan)
    })
    .await
    .map_err(|_| NativeOutboxRecoveryError::BlockingTaskFailed)?
}

fn recover_outboxes_once_blocking<R, L>(
    runtime: &R,
    config: &NodeConfig,
    lease_ids: &L,
    scan: &StateKeyScan,
) -> Result<NativeOutboxRecoveryReport, NativeOutboxRecoveryError>
where
    R: Runtime,
    R::State: TransactionalStateStore + StateKeyScanner,
    L: OutboxLeaseIdSource,
{
    let page = runtime
        .state_store()
        .scan_keys(scan)
        .map_err(NativeOutboxRecoveryError::Runtime)?;
    let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
    let now_unix_millis = runtime
        .clock()
        .now_unix_millis()
        .map_err(NativeOutboxRecoveryError::Runtime)?;

    for (index, key) in page.keys().iter().enumerate() {
        if !key.ends_with(b"/delivery") {
            continue;
        }
        let delivery_value = runtime
            .state_store()
            .get_versioned(key)
            .map_err(NativeOutboxRecoveryError::Runtime)?;
        let Some(delivery_bytes) = delivery_value.value() else {
            continue;
        };
        let delivery =
            NodeOutboxDelivery::decode(delivery_bytes).map_err(NativeOutboxRecoveryError::Node)?;
        let request_id = delivery.request_id();
        if layout.outbox_delivery_key(*request_id.as_bytes()) != *key {
            return Err(NativeOutboxRecoveryError::Node(
                NodeCoreError::PersistenceInvariant("outbox delivery key does not match record"),
            ));
        }
        let batch_value = runtime
            .state_store()
            .get_versioned(&layout.outbox_batch_key(*request_id.as_bytes()))
            .map_err(NativeOutboxRecoveryError::Runtime)?;
        let batch = NodeOutboxBatch::decode(batch_value.value().ok_or({
            NativeOutboxRecoveryError::Node(NodeCoreError::PersistenceInvariant(
                "outbox delivery exists without batch",
            ))
        })?)
        .map_err(NativeOutboxRecoveryError::Node)?;
        if batch.request_id() != request_id || batch.event_digest() != delivery.event_digest() {
            return Err(NativeOutboxRecoveryError::Node(
                NodeCoreError::PersistenceInvariant("outbox batch and delivery identities differ"),
            ));
        }
        let next_index = usize::try_from(delivery.next_index()).map_err(|_| {
            NativeOutboxRecoveryError::Node(NodeCoreError::OutboxArithmeticOverflow)
        })?;
        if next_index > batch.messages().len() {
            return Err(NativeOutboxRecoveryError::Node(
                NodeCoreError::PersistenceInvariant("outbox cursor exceeds batch length"),
            ));
        }
        if next_index == batch.messages().len()
            || delivery
                .lease()
                .is_some_and(|(_, expires_at)| expires_at > now_unix_millis)
        {
            continue;
        }

        let has_later_keys = index + 1 < page.keys().len() || page.continuation_cursor().is_some();
        let continuation_cursor = has_later_keys.then(|| key.clone());
        let outcome = match deliver_request_outbox(runtime, config, lease_ids, request_id) {
            Ok(0) => NativeOutboxRecoveryOutcome::Contended(request_id),
            Ok(_) => NativeOutboxRecoveryOutcome::Recovered(request_id),
            Err(OutboxDeliveryError::Node(
                NodeCoreError::OutboxLeaseActive { .. } | NodeCoreError::StateConflict,
            )) => NativeOutboxRecoveryOutcome::Contended(request_id),
            Err(error) => return Err(recovery_delivery_error(error)),
        };
        return Ok(NativeOutboxRecoveryReport {
            outcome,
            continuation_cursor,
        });
    }

    Ok(NativeOutboxRecoveryReport {
        outcome: NativeOutboxRecoveryOutcome::NoEligibleOutbox,
        continuation_cursor: page.continuation_cursor().map(<[u8]>::to_vec),
    })
}

async fn liveness() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn submit_event<R, M, L>(
    State(state): State<Arc<NativeHttpState<R, M, L>>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    R: Runtime + Send + Sync + 'static,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    if !has_supported_content_type(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-type",
        );
    }
    if has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-encoding",
        );
    }
    let body = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    let permit = match state.blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => return overload_response(),
        Err(TryAcquireError::Closed) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "blocking-admission-closed");
        }
    };
    let blocking_state = Arc::clone(&state);
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        invoke_event(blocking_state.as_ref(), &body)
    });
    let result = match work.await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return invocation_error_response(&error),
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "blocking-task-failed");
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        result,
    )
        .into_response()
}

async fn submit_resolved_domain_event<R, M, L>(
    State(state): State<Arc<ResolvedDomainNativeHttpState<R, M, L>>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    R: Runtime + Send + Sync + 'static,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    L: OutboxLeaseIdSource + Send + Sync + 'static,
{
    if !has_supported_content_type(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-type",
        );
    }
    if has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-encoding",
        );
    }
    let body = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    let permit = match state.blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => return overload_response(),
        Err(TryAcquireError::Closed) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "blocking-admission-closed");
        }
    };
    let blocking_state = Arc::clone(&state);
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        invoke_resolved_domain_event(blocking_state.as_ref(), &body)
    });
    let result = match work.await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return invocation_error_response(&error),
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "blocking-task-failed");
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        result,
    )
        .into_response()
}

/// Shared request-shape/admission/cancellation plumbing behind both
/// [`submit_structured_durable_event`] and
/// [`submit_preinstalled_wasm_structured_durable_event`].
///
/// `initial_cancelled` is the caller's own pre-storage cancellation
/// observation, taken from its typed state before this call; the inner
/// structured-durable core (`invoke_structured_durable_event_with_execution`)
/// still re-checks cancellation itself once the durable operation context is
/// built, so cancellation is checked at both points on every route, not only
/// here. `work` runs the caller's exact blocking invocation (`invoke_*`)
/// against the extracted body bytes inside the shared blocking-admission
/// isolation.
async fn submit_structured_durable_event_common<F>(
    initial_cancelled: bool,
    blocking_executor: NativeBlockingExecutor,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
    work: F,
) -> Response
where
    F: FnOnce(Bytes) -> Result<Vec<u8>, InvocationError> + Send + 'static,
{
    if !has_supported_content_type(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-type",
        );
    }
    if has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-content-encoding",
        );
    }
    let body = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if initial_cancelled {
        return cancelled_before_storage_response();
    }
    let permit = match blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => return overload_response(),
        Err(TryAcquireError::Closed) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "blocking-admission-closed");
        }
    };
    let blocking_work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work(body)
    });
    let result = match blocking_work.await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return invocation_error_response(&error),
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "blocking-task-failed");
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        result,
    )
        .into_response()
}

async fn submit_structured_durable_event<S, B, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    submit_structured_durable_event_common(
        initial_cancelled,
        blocking_executor,
        headers,
        body,
        move |body| invoke_structured_durable_event(state.as_ref(), &body),
    )
    .await
}

async fn submit_preinstalled_wasm_structured_durable_event<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    submit_structured_durable_event_common(
        initial_cancelled,
        blocking_executor,
        headers,
        body,
        move |body| invoke_preinstalled_wasm_structured_durable_event(state.as_ref(), &body),
    )
    .await
}

/// Failures from one bounded query invocation (DR-0082).
///
/// A syntactically valid, admitted query maps transient host/storage
/// conditions to an opaque `503` and invalid persisted state or permanent
/// host failures to an opaque `500`; caller-supplied malformed selectors are
/// rejected before this point.
enum QueryInvocationError {
    CancelledBeforeStorage,
    /// The restart-safe identity source could not allocate an identity right
    /// now: a transient host condition, classified `503`.
    IdentityUnavailable,
    /// The restart-safe identity source permanently exhausted its identity
    /// space: a host/operator failure distinct from transient unavailability,
    /// classified `500`.
    IdentityExhausted,
    Node(NodeCoreError),
    ResultEncoding,
}

async fn query_structured_durable_common<F>(
    initial_cancelled: bool,
    blocking_executor: NativeBlockingExecutor,
    work: F,
) -> Response
where
    F: FnOnce() -> Result<Vec<u8>, QueryInvocationError> + Send + 'static,
{
    if initial_cancelled {
        return cancelled_before_storage_response();
    }
    let permit = match blocking_executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => return overload_response(),
        Err(TryAcquireError::Closed) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "blocking-admission-closed");
        }
    };
    let blocking_work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    });
    let result = match blocking_work.await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return query_invocation_error_response(&error),
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "blocking-task-failed");
        }
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, QUERY_RESULT_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        result,
    )
        .into_response()
}

fn query_invocation_error_response(error: &QueryInvocationError) -> Response {
    match error {
        QueryInvocationError::CancelledBeforeStorage => cancelled_before_storage_response(),
        QueryInvocationError::IdentityUnavailable => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "query-unavailable")
        }
        QueryInvocationError::IdentityExhausted | QueryInvocationError::ResultEncoding => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "query-state-invalid")
        }
        QueryInvocationError::Node(error) => {
            let (status, code) = query_node_error_response_parts(error);
            error_response(status, code)
        }
    }
}

/// Classifies a query-path [`NodeCoreError`] into one of exactly two opaque
/// query responses (DR-0082).
///
/// `503 query-unavailable` covers a transient host or storage-availability
/// condition: clock/runtime failure, a durable read that proves writer
/// fencing, deadline exhaustion, or backend unavailability, an unsupported
/// durable schema identity/generation
/// (`runtime::DurableReadError::SchemaMismatch`), or committed
/// `ProtocolConfig` inactivity/misconfiguration (missing domain placement,
/// an inactive placement at the current epoch, or a missing/invalid
/// transaction-auth profile). `500 query-state-invalid` covers everything
/// else: corrupt or unverifiable persisted content and result-encoding
/// failure, which by construction can only arise from storage corruption or
/// a host bug, never from caller-supplied input (malformed selectors are
/// rejected before any of this runs).
///
/// `SchemaMismatch` is deliberately grouped with `503`, not `500`: it proves
/// the adapter's durable schema generation disagrees with what was persisted
/// — an operator/deployment condition an operator can resolve by restoring a
/// compatible adapter or completing a migration — never that the persisted
/// bytes themselves are corrupt or unverifiable.
fn query_node_error_response_parts(error: &NodeCoreError) -> (StatusCode, &'static str) {
    let unavailable = matches!(
        error,
        NodeCoreError::Runtime(_)
            | NodeCoreError::ProtocolConfig(_)
            | NodeCoreError::DurableRead(
                runtime::DurableReadError::WriterFenced { .. }
                    | runtime::DurableReadError::DeadlineExceeded
                    | runtime::DurableReadError::Unavailable
                    | runtime::DurableReadError::SchemaMismatch,
            )
    );
    if unavailable {
        (StatusCode::SERVICE_UNAVAILABLE, "query-unavailable")
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "query-state-invalid")
    }
}

/// Decodes exactly 64 lowercase ASCII hex characters into 32 bytes.
///
/// Every path selector accepted by the bounded query API must be validated
/// through this function before any identity allocation, clock access, or
/// storage I/O runs.
fn decode_hex64_selector(input: &str) -> Option<[u8; 32]> {
    let bytes = input.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        out[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Resolves the logical domain for a query request through
/// [`DomainPlacementManifest::resolve_domain`] at `config.epoch()` with one
/// bounded access — the same activation-epoch-checked path the authenticated
/// write path uses — rather than reading `placement.domain()`
/// unconditionally, so an inactive placement classifies identically across
/// every query route, including `/v1/context`, instead of only where storage
/// I/O happens to run.
fn resolve_query_domain(
    placement: &DomainPlacementManifest,
    config: &NodeConfig,
) -> Result<AtomicityDomainId, QueryInvocationError> {
    placement
        .resolve_domain(config.epoch(), 1)
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)
}

fn invoke_query_context(
    config: &NodeConfig,
    protocol_config: &ProtocolConfig,
) -> Result<Vec<u8>, QueryInvocationError> {
    let placement = protocol_config
        .domain_placement
        .as_ref()
        .ok_or(ProtocolConfigError::MissingDomainPlacement)
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)?;
    let domain = resolve_query_domain(placement, config)?;
    let profile = resolve_transaction_auth_profile(protocol_config)
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)?;
    let protocol_config_bytes = protocol_config
        .canonical_bytes()
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)?;
    let result = HttpContextQueryResult::new(
        config.chain_id().clone(),
        config.protocol_version(),
        config.epoch(),
        protocol_config.hash_suite_id,
        profile.profile_id(),
        profile.signature_scheme_id().as_u16(),
        profile.address_binding().as_u16(),
        domain,
        protocol_config_bytes,
    )
    .map_err(|_| QueryInvocationError::ResultEncoding)?;
    result
        .encode()
        .map_err(|_| QueryInvocationError::ResultEncoding)
}

/// Allocates the trusted storage authority shared by queries and publication
/// writes: a resolved logical domain, a fresh restart-safe correlation
/// identity, and a bounded deadline, all from trusted composition rather
/// than the HTTP request.
///
/// The domain is resolved through [`resolve_query_domain`], so an inactive
/// placement rejects before identity allocation, clock access, or storage
/// I/O. The deadline is freshly derived from the current trusted clock and
/// operation timeout; callers do not reuse a prior query's authority.
fn prepare_storage_context<S, B, T, C, I>(
    components: &StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: &ProtocolConfig,
    authority: &StructuredDurableRequestAuthority,
    config: &NodeConfig,
) -> Result<(AtomicityDomainId, DurableOperationContext), QueryInvocationError>
where
    I: IndexedOutboxIdentitySource,
    C: Clock,
{
    let placement = protocol_config
        .domain_placement
        .as_ref()
        .ok_or(ProtocolConfigError::MissingDomainPlacement)
        .map_err(NodeCoreError::from)
        .map_err(QueryInvocationError::Node)?;
    let domain = resolve_query_domain(placement, config)?;
    let identity = components
        .identities
        .next_attempt_identity()
        .map_err(|error| match error {
            IndexedOutboxIdentitySourceError::Unavailable => {
                QueryInvocationError::IdentityUnavailable
            }
            IndexedOutboxIdentitySourceError::Exhausted => QueryInvocationError::IdentityExhausted,
        })?;
    let now_unix_millis = components
        .clock
        .now_unix_millis()
        .map_err(|error| QueryInvocationError::Node(NodeCoreError::Runtime(error)))?;
    let deadline_unix_millis = now_unix_millis
        .checked_add(authority.operation_timeout_millis.get())
        .ok_or(QueryInvocationError::Node(
            NodeCoreError::PersistenceInvariant("storage deadline arithmetic overflowed"),
        ))?;
    let deadline = StorageDeadline::new(deadline_unix_millis).ok_or(QueryInvocationError::Node(
        NodeCoreError::PersistenceInvariant("storage deadline arithmetic overflowed"),
    ))?;
    let context =
        DurableOperationContext::new(authority.writer_fence, deadline, identity.correlation_id);
    Ok((domain, context))
}

fn invoke_query_object<S, B, T, C, I>(
    components: &StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: &ProtocolConfig,
    authority: &StructuredDurableRequestAuthority,
    config: &NodeConfig,
    object_id: ObjectId,
) -> Result<Vec<u8>, QueryInvocationError>
where
    S: StructuredDurableDomainStateStore,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let (domain, context) =
        prepare_storage_context(components, protocol_config, authority, config)?;
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let result = query_object(
        components.store.as_ref(),
        &context,
        domain,
        config.chain_id(),
        object_id,
    )
    .map_err(QueryInvocationError::Node)?;
    // Defense in depth: never bind the answer to a different selector than
    // was requested, even under a future node-core regression.
    if result.object_id() != object_id {
        return Err(QueryInvocationError::Node(
            NodeCoreError::PersistenceInvariant(
                "query result object id disagreed with the requested selector",
            ),
        ));
    }
    HttpObjectQueryResult::from(result)
        .encode()
        .map_err(|_| QueryInvocationError::ResultEncoding)
}

fn invoke_query_receipt<S, B, T, C, I>(
    components: &StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: &ProtocolConfig,
    authority: &StructuredDurableRequestAuthority,
    config: &NodeConfig,
    request_id: RequestId,
) -> Result<Vec<u8>, QueryInvocationError>
where
    S: StructuredDurableDomainStateStore,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let (domain, context) =
        prepare_storage_context(components, protocol_config, authority, config)?;
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let result = query_request_receipt(components.store.as_ref(), &context, domain, request_id)
        .map_err(QueryInvocationError::Node)?;
    // Defense in depth: never bind the answer to a different selector than
    // was requested, even under a future node-core regression.
    if result.request_id() != request_id {
        return Err(QueryInvocationError::Node(
            NodeCoreError::PersistenceInvariant(
                "query result request id disagreed with the requested selector",
            ),
        ));
    }
    let wire = http_receipt_query_result(result).map_err(QueryInvocationError::Node)?;
    wire.encode()
        .map_err(|_| QueryInvocationError::ResultEncoding)
}

fn invoke_query_next_nonce<S, B, T, C, I>(
    components: &StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: &ProtocolConfig,
    authority: &StructuredDurableRequestAuthority,
    config: &NodeConfig,
    sender: [u8; 32],
) -> Result<Vec<u8>, QueryInvocationError>
where
    S: StructuredDurableDomainStateStore,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let (domain, context) =
        prepare_storage_context(components, protocol_config, authority, config)?;
    if components.is_cancelled() {
        return Err(QueryInvocationError::CancelledBeforeStorage);
    }
    let epoch = config.epoch();
    let next_nonce = query_sender_next_nonce(
        components.store.as_ref(),
        &context,
        domain,
        config.chain_id().clone(),
        config.protocol_version(),
        epoch,
        sender,
    )
    .map_err(QueryInvocationError::Node)?;
    HttpNextNonceQueryResult::new(Address::new(sender), epoch, next_nonce)
        .encode()
        .map_err(|_| QueryInvocationError::ResultEncoding)
}

async fn get_structured_durable_context<S, B, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_context(&state.config, &state.protocol_config)
    })
    .await
}

async fn get_structured_durable_object<S, B, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(object_id_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let object_id = match decode_hex64_selector(&object_id_hex) {
        Some(bytes) => ObjectId::new(bytes),
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-object-id"),
    };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_object(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            object_id,
        )
    })
    .await
}

async fn get_structured_durable_receipt<S, B, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(request_id_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let request_id =
        match decode_hex64_selector(&request_id_hex).and_then(|bytes| RequestId::new(bytes).ok()) {
            Some(request_id) => request_id,
            None => return error_response(StatusCode::BAD_REQUEST, "invalid-request-id"),
        };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_receipt(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            request_id,
        )
    })
    .await
}

async fn get_structured_durable_next_nonce<S, B, M, T, C, I>(
    State(state): State<SharedStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(sender_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let sender = match decode_hex64_selector(&sender_hex) {
        Some(sender) => sender,
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-sender"),
    };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_next_nonce(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            sender,
        )
    })
    .await
}

async fn get_preinstalled_wasm_structured_durable_context<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_context(&state.config, &state.protocol_config)
    })
    .await
}

async fn get_preinstalled_wasm_structured_durable_object<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(object_id_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let object_id = match decode_hex64_selector(&object_id_hex) {
        Some(bytes) => ObjectId::new(bytes),
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-object-id"),
    };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_object(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            object_id,
        )
    })
    .await
}

async fn get_preinstalled_wasm_structured_durable_receipt<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(request_id_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let request_id =
        match decode_hex64_selector(&request_id_hex).and_then(|bytes| RequestId::new(bytes).ok()) {
            Some(request_id) => request_id,
            None => return error_response(StatusCode::BAD_REQUEST, "invalid-request-id"),
        };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_receipt(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            request_id,
        )
    })
    .await
}

async fn get_preinstalled_wasm_structured_durable_next_nonce<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(sender_hex): Path<String>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let sender = match decode_hex64_selector(&sender_hex) {
        Some(sender) => sender,
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-sender"),
    };
    let initial_cancelled = state.components.is_cancelled();
    let blocking_executor = state.blocking_executor.clone();
    query_structured_durable_common(initial_cancelled, blocking_executor, move || {
        invoke_query_next_nonce(
            &state.components,
            &state.protocol_config,
            &state.authority,
            &state.config,
            sender,
        )
    })
    .await
}

enum InvocationError {
    CancelledBeforeStorage,
    Node(NodeCoreError),
    Delivery(OutboxDeliveryError),
    Indexed(IndexedOutboxRecoveryError),
    ResultEncoding,
    /// A known [`NodeEventKind`] whose family requires per-family
    /// authentication and authorization that no native route implements yet
    /// (DR-0099). `SubmitTransaction` is the only kind any native route
    /// authenticates; every other kind must fail closed here, before any
    /// identity allocation, clock read, storage I/O, machine access-plan or
    /// transition, outbox work, or transport send. The error deliberately
    /// carries no event-kind detail so every family maps to the same opaque
    /// response.
    EventFamilyRequiresAuthenticatedRoute,
}

/// Rejects a `SubmitTransaction` event before any machine or storage work.
///
/// `router` and `resolved_domain_router` never authenticate a transaction:
/// only [`structured_durable_router`] does. Calling either of those legacy
/// routes with a `SubmitTransaction` event must fail closed here rather than
/// let it reach [`TransactionalNodeStateMachine::access_plan`] or storage
/// under the appearance of having been authenticated.
fn reject_unauthenticated_submit_transaction(event: &NodeEvent) -> Result<(), InvocationError> {
    if event.kind() == NodeEventKind::SubmitTransaction {
        return Err(InvocationError::Node(
            NodeCoreError::UnauthenticatedTransactionSubmission,
        ));
    }
    Ok(())
}

/// Rejects every known `NodeEventKind` other than `SubmitTransaction` before
/// any identity allocation, clock read, storage I/O, machine access-plan or
/// transition, outbox work, or transport send (DR-0099).
///
/// This is an external-boundary policy, not a node-core change: node-core's
/// generic [`TransactionalNodeStateMachine`] path remains fully implemented
/// and reusable, and this function only decides which event kinds native-http
/// is currently willing to hand to it. `ReceiveVote`, `ReceiveCertificate`,
/// `ReceiveConsensusMessage`, `ApplyGovernanceCertificate`,
/// `ApplyProtocolUpgrade`, `ApplyValidatorSetChange`, and `Tick` each need
/// their own authentication and authorization the native adapter does not
/// implement yet, so every one of them maps to the same opaque
/// `501 event-family-requires-authenticated-route` response on every native
/// route, including the two legacy routes that never authenticate
/// `SubmitTransaction` either. The match is exhaustive over
/// [`NodeEventKind`] so a future kind must be classified here explicitly
/// rather than silently falling through to acceptance.
fn reject_unauthenticated_event_family(event: &NodeEvent) -> Result<(), InvocationError> {
    match event.kind() {
        NodeEventKind::SubmitTransaction => Ok(()),
        NodeEventKind::ReceiveVote
        | NodeEventKind::ReceiveCertificate
        | NodeEventKind::ReceiveConsensusMessage
        | NodeEventKind::ApplyGovernanceCertificate
        | NodeEventKind::ApplyProtocolUpgrade
        | NodeEventKind::ApplyValidatorSetChange
        | NodeEventKind::Tick => Err(InvocationError::EventFamilyRequiresAuthenticatedRoute),
    }
}

fn invoke_event<R, M, L>(
    state: &NativeHttpState<R, M, L>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    R: Runtime,
    R::State: TransactionalStateStore,
    M: TransactionalNodeStateMachine,
    L: OutboxLeaseIdSource,
{
    let event = NodeEvent::decode(body).map_err(InvocationError::Node)?;
    reject_unauthenticated_event_family(&event)?;
    reject_unauthenticated_submit_transaction(&event)?;
    let request_id = event.request_id();
    let output = handle_idempotent_event(
        state.runtime.as_ref(),
        &state.config,
        &state.resolver,
        event,
        state.machine.as_ref(),
    )
    .map_err(InvocationError::Node)?;
    let _delivered_messages = deliver_request_outbox(
        state.runtime.as_ref(),
        &state.config,
        state.lease_ids.as_ref(),
        request_id,
    )
    .map_err(InvocationError::Delivery)?;
    HttpNodeResult::new(request_id, output.responses().to_vec())
        .and_then(|result| result.encode())
        .map_err(|_| InvocationError::ResultEncoding)
}

fn invoke_resolved_domain_event<R, M, L>(
    state: &ResolvedDomainNativeHttpState<R, M, L>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    M: TransactionalNodeStateMachine,
    L: OutboxLeaseIdSource,
{
    let event = NodeEvent::decode(body).map_err(InvocationError::Node)?;
    reject_unauthenticated_event_family(&event)?;
    reject_unauthenticated_submit_transaction(&event)?;
    let request_id = event.request_id();
    let resolved = handle_resolved_idempotent_event(
        state.runtime.as_ref(),
        &state.placement,
        &state.config,
        &state.resolver,
        event,
        state.machine.as_ref(),
    )
    .map_err(InvocationError::Node)?;
    let _delivered_messages = deliver_request_outbox_in_domain(
        state.runtime.as_ref(),
        resolved.domain(),
        &state.config,
        state.lease_ids.as_ref(),
        request_id,
    )
    .map_err(InvocationError::Delivery)?;
    HttpNodeResult::new(request_id, resolved.output().responses().to_vec())
        .and_then(|result| result.encode())
        .map_err(|_| InvocationError::ResultEncoding)
}

/// Distinguishes how one authenticated `SubmitTransaction` is executed by
/// [`invoke_structured_durable_event_with_execution`], the shared core behind
/// both [`invoke_structured_durable_event`] and
/// [`invoke_preinstalled_wasm_structured_durable_event`]. Every other stage
/// of the request path (authenticated preparation, storage context, exact
/// request-scoped outbox claim/send/ack) is identical for every variant.
enum StructuredDurableAuthenticatedExecution<'a> {
    /// [`handle_authenticated_resolved_durable_submit_transaction`]: read-only.
    ReadOnly,
    /// [`handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`].
    PreinstalledWasm {
        catalog: &'a PreinstalledModuleCatalog,
        engine: WasmExecutionEngine,
        created_checkpoint: u64,
        fee_composition: Option<PreinstalledFeeComposition<'a>>,
    },
}

fn invoke_structured_durable_event<S, B, M, T, C, I>(
    state: &StructuredDurableNativeHttpState<S, B, M, T, C, I>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    S: IndexedOutboxRepository,
    B: BlobStore,
    M: TransactionalNodeStateMachine,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    invoke_structured_durable_event_with_execution(
        &state.components,
        &state.protocol_config,
        &state.authority,
        &state.config,
        &state.resolver,
        state.machine.as_ref(),
        StructuredDurableAuthenticatedExecution::ReadOnly,
        body,
    )
}

fn invoke_preinstalled_wasm_structured_durable_event<S, B, M, T, C, I>(
    state: &PreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    S: IndexedOutboxRepository,
    B: BlobStore,
    M: TransactionalNodeStateMachine,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    invoke_structured_durable_event_with_execution(
        &state.components,
        &state.protocol_config,
        &state.authority,
        &state.config,
        &state.resolver,
        state.machine.as_ref(),
        StructuredDurableAuthenticatedExecution::PreinstalledWasm {
            catalog: state.preinstalled_wasm.catalog.as_ref(),
            engine: state.preinstalled_wasm.engine,
            created_checkpoint: state.preinstalled_wasm.created_checkpoint,
            fee_composition: state.preinstalled_wasm.fee.as_ref().map(|fee| {
                PreinstalledFeeComposition::new(fee.treasury_object_id, fee.composer.as_ref())
            }),
        },
        body,
    )
}

#[allow(clippy::too_many_arguments)]
fn invoke_structured_durable_event_with_execution<S, B, M, T, C, I>(
    components: &StructuredDurableNativeComponents<S, B, T, C, I>,
    protocol_config: &ProtocolConfig,
    authority: &StructuredDurableRequestAuthority,
    config: &NodeConfig,
    resolver: &HashSuiteResolver,
    machine: &M,
    execution: StructuredDurableAuthenticatedExecution<'_>,
    body: &[u8],
) -> Result<Vec<u8>, InvocationError>
where
    S: IndexedOutboxRepository,
    B: BlobStore,
    M: TransactionalNodeStateMachine,
    T: Transport,
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    if components.is_cancelled() {
        return Err(InvocationError::CancelledBeforeStorage);
    }
    let event = NodeEvent::decode(body).map_err(InvocationError::Node)?;
    reject_unauthenticated_event_family(&event)?;
    validate_native_event_context(&event, config).map_err(InvocationError::Node)?;
    let request_id = event.request_id();
    let submission = Box::new(
        authenticate_submit_transaction_event(event, config, protocol_config)
            .map_err(InvocationError::Node)?,
    );
    let identity = components
        .identities
        .next_attempt_identity()
        .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Identity(error)))?;
    let now_unix_millis = components
        .clock
        .now_unix_millis()
        .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Runtime(error)))?;
    let deadline_unix_millis = now_unix_millis
        .checked_add(authority.operation_timeout_millis.get())
        .ok_or(InvocationError::Indexed(
            IndexedOutboxRecoveryError::TimeOverflow,
        ))?;
    let lease_expires_at_unix_millis = now_unix_millis
        .checked_add(authority.lease_duration_millis.get())
        .ok_or(InvocationError::Indexed(
            IndexedOutboxRecoveryError::TimeOverflow,
        ))?;
    let deadline = StorageDeadline::new(deadline_unix_millis).ok_or(InvocationError::Indexed(
        IndexedOutboxRecoveryError::TimeOverflow,
    ))?;
    let context =
        DurableOperationContext::new(authority.writer_fence, deadline, identity.correlation_id);
    if components.is_cancelled() {
        return Err(InvocationError::CancelledBeforeStorage);
    }
    let resolved = match execution {
        StructuredDurableAuthenticatedExecution::ReadOnly => {
            handle_authenticated_resolved_durable_submit_transaction(
                components.blob_store.as_ref(),
                components.store.as_ref(),
                &context,
                resolver,
                *submission,
                machine,
            )
        }
        StructuredDurableAuthenticatedExecution::PreinstalledWasm {
            catalog,
            engine,
            created_checkpoint,
            fee_composition,
        } => handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution(
            components.blob_store.as_ref(),
            components.store.as_ref(),
            &context,
            resolver,
            catalog,
            &engine,
            *submission,
            created_checkpoint,
            fee_composition,
        ),
    }
    .map_err(InvocationError::Node)?;

    let outbox_request_id = OutboxRequestId::new(*request_id.as_bytes())
        .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Contract(error)))?;
    let claim_request = RequestOutboxClaimRequest::new(
        resolved.domain(),
        outbox_request_id,
        now_unix_millis,
        identity.lease_id,
        lease_expires_at_unix_millis,
    )
    .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Contract(error)))?;
    let claim = reconcile_request_outbox_claim(components.store.as_ref(), &context, claim_request)
        .map_err(InvocationError::Indexed)?;
    if let Some(claim) = claim {
        if claim.request_id() != outbox_request_id
            || claim.lease_id() != identity.lease_id
            || claim.lease_expires_at_unix_millis() != lease_expires_at_unix_millis
        {
            return Err(InvocationError::Indexed(
                IndexedOutboxRecoveryError::ClaimIdentityMismatch,
            ));
        }
        let outbound = NodeEvent::decode(claim.canonical_payload())
            .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Node(error)))?;
        validate_native_event_context(&outbound, config)
            .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Node(error)))?;
        let canonical_payload = outbound
            .encode()
            .map_err(|error| InvocationError::Indexed(IndexedOutboxRecoveryError::Node(error)))?;
        if canonical_payload != claim.canonical_payload() {
            return Err(InvocationError::Indexed(IndexedOutboxRecoveryError::Node(
                NodeCoreError::PersistenceInvariant("request outbox payload is not canonical"),
            )));
        }
        components
            .transport
            .send(canonical_payload)
            .map_err(|_| InvocationError::Indexed(IndexedOutboxRecoveryError::Send))?;
        let acknowledgement = DurableOutboxAcknowledgement::new(
            resolved.domain(),
            claim.request_id(),
            claim.message_index(),
            claim.lease_id(),
        );
        reconcile_indexed_acknowledgement(components.store.as_ref(), &context, acknowledgement)
            .map_err(InvocationError::Indexed)?;
    }

    HttpNodeResult::new(request_id, resolved.output().responses().to_vec())
        .and_then(|result| result.encode())
        .map_err(|_| InvocationError::ResultEncoding)
}

fn validate_native_event_context(
    event: &NodeEvent,
    config: &NodeConfig,
) -> Result<(), NodeCoreError> {
    if event.chain_id() != config.chain_id() {
        return Err(NodeCoreError::ChainMismatch {
            expected: config.chain_id().clone(),
            actual: event.chain_id().clone(),
        });
    }
    if event.protocol_version() != config.protocol_version() {
        return Err(NodeCoreError::ProtocolVersionMismatch {
            expected: config.protocol_version(),
            actual: event.protocol_version(),
        });
    }
    if event.epoch() != config.epoch() {
        return Err(NodeCoreError::EpochMismatch {
            expected: config.epoch(),
            actual: event.epoch(),
        });
    }
    Ok(())
}

fn reconcile_request_outbox_claim<S>(
    store: &S,
    context: &DurableOperationContext,
    request: RequestOutboxClaimRequest,
) -> Result<Option<runtime::DurableOutboxClaim>, IndexedOutboxRecoveryError>
where
    S: IndexedOutboxRepository,
{
    match store.claim_request_outbox(context, request) {
        DurableOutboxClaimOutcome::Claimed(claim) => Ok(Some(claim)),
        DurableOutboxClaimOutcome::NoDueWork => Ok(None),
        DurableOutboxClaimOutcome::Rejected(reason) => {
            Err(IndexedOutboxRecoveryError::ClaimRejected(reason))
        }
        DurableOutboxClaimOutcome::Indeterminate(first_reason) => {
            match store.claim_request_outbox(context, request) {
                DurableOutboxClaimOutcome::Claimed(claim) => Ok(Some(claim)),
                _ => Err(IndexedOutboxRecoveryError::ClaimIndeterminate(first_reason)),
            }
        }
    }
}

fn invocation_error_response(error: &InvocationError) -> Response {
    match error {
        InvocationError::CancelledBeforeStorage => cancelled_before_storage_response(),
        InvocationError::Node(error) => node_error_response(error),
        InvocationError::Delivery(OutboxDeliveryError::Node(error)) => node_error_response(error),
        InvocationError::Delivery(OutboxDeliveryError::Send) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "outbound-send-failed")
        }
        InvocationError::Delivery(OutboxDeliveryError::LeaseId(
            OutboxLeaseIdSourceError::Unavailable,
        )) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "lease-id-source-unavailable",
        ),
        InvocationError::Delivery(OutboxDeliveryError::LeaseId(
            OutboxLeaseIdSourceError::Exhausted,
        )) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "lease-id-source-exhausted",
        ),
        InvocationError::Indexed(error) => indexed_invocation_error_response(error),
        InvocationError::ResultEncoding => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "result-encoding-failed")
        }
        InvocationError::EventFamilyRequiresAuthenticatedRoute => error_response(
            StatusCode::NOT_IMPLEMENTED,
            "event-family-requires-authenticated-route",
        ),
    }
}

fn indexed_invocation_error_response(error: &IndexedOutboxRecoveryError) -> Response {
    match error {
        IndexedOutboxRecoveryError::Runtime(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "runtime-unavailable")
        }
        IndexedOutboxRecoveryError::Identity(IndexedOutboxIdentitySourceError::Unavailable) => {
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "indexed-identity-source-unavailable",
            )
        }
        IndexedOutboxRecoveryError::Identity(IndexedOutboxIdentitySourceError::Exhausted) => {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "indexed-identity-source-exhausted",
            )
        }
        IndexedOutboxRecoveryError::ClaimRejected(
            DurableOutboxClaimRejection::WriterFenced { .. }
            | DurableOutboxClaimRejection::DeadlineExceededBeforeCommit
            | DurableOutboxClaimRejection::SerializationFailure
            | DurableOutboxClaimRejection::UnavailableBeforeCommit,
        ) => error_response(StatusCode::SERVICE_UNAVAILABLE, "outbox-claim-unavailable"),
        IndexedOutboxRecoveryError::ClaimIndeterminate(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "outbox-claim-indeterminate",
        ),
        IndexedOutboxRecoveryError::Send => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "outbound-send-failed")
        }
        IndexedOutboxRecoveryError::AcknowledgementRejected(
            DurableOutboxAcknowledgementRejection::WriterFenced { .. }
            | DurableOutboxAcknowledgementRejection::DeadlineExceededBeforeCommit
            | DurableOutboxAcknowledgementRejection::SerializationFailure
            | DurableOutboxAcknowledgementRejection::UnavailableBeforeCommit,
        ) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "outbox-acknowledgement-unavailable",
        ),
        IndexedOutboxRecoveryError::AcknowledgementIndeterminate(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "outbox-acknowledgement-indeterminate",
        ),
        IndexedOutboxRecoveryError::Node(error) => node_error_response(error),
        IndexedOutboxRecoveryError::TimeOverflow
        | IndexedOutboxRecoveryError::Contract(_)
        | IndexedOutboxRecoveryError::ClaimIdentityMismatch
        | IndexedOutboxRecoveryError::ClaimRejected(_)
        | IndexedOutboxRecoveryError::AcknowledgementRejected(_) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "invalid-durable-outbox")
        }
        IndexedOutboxRecoveryError::CapacityExhausted
        | IndexedOutboxRecoveryError::AdmissionClosed
        | IndexedOutboxRecoveryError::BlockingTaskFailed => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid-indexed-invocation-state",
        ),
    }
}

enum OutboxDeliveryError {
    Node(NodeCoreError),
    Send,
    LeaseId(OutboxLeaseIdSourceError),
}

impl From<NodeCoreError> for OutboxDeliveryError {
    fn from(value: NodeCoreError) -> Self {
        Self::Node(value)
    }
}

impl From<RuntimeError> for OutboxDeliveryError {
    fn from(value: RuntimeError) -> Self {
        Self::Node(NodeCoreError::Runtime(value))
    }
}

impl From<OutboxLeaseIdSourceError> for OutboxDeliveryError {
    fn from(value: OutboxLeaseIdSourceError) -> Self {
        Self::LeaseId(value)
    }
}

fn recovery_delivery_error(error: OutboxDeliveryError) -> NativeOutboxRecoveryError {
    match error {
        OutboxDeliveryError::Node(error) => NativeOutboxRecoveryError::Node(error),
        OutboxDeliveryError::Send => NativeOutboxRecoveryError::Send,
        OutboxDeliveryError::LeaseId(error) => NativeOutboxRecoveryError::LeaseId(error),
    }
}

fn deliver_request_outbox<R, L>(
    runtime: &R,
    config: &NodeConfig,
    lease_ids: &L,
    request_id: RequestId,
) -> Result<usize, OutboxDeliveryError>
where
    R: Runtime,
    R::State: TransactionalStateStore,
    L: OutboxLeaseIdSource,
{
    deliver_request_outbox_inner(
        runtime,
        config,
        lease_ids,
        request_id,
        |layout, request_id, lease_id, now_unix_millis| {
            claim_next_outbox_message(
                runtime.state_store(),
                layout,
                request_id,
                lease_id,
                now_unix_millis,
                NATIVE_OUTBOX_LEASE_MILLIS,
            )
        },
        |layout, request_id, index, lease_id| {
            acknowledge_outbox_message(runtime.state_store(), layout, request_id, index, lease_id)
        },
    )
}

fn deliver_request_outbox_in_domain<R, L>(
    runtime: &R,
    domain: AtomicityDomainId,
    config: &NodeConfig,
    lease_ids: &L,
    request_id: RequestId,
) -> Result<usize, OutboxDeliveryError>
where
    R: Runtime,
    R::State: DomainTransactionalStateStore,
    L: OutboxLeaseIdSource,
{
    deliver_request_outbox_inner(
        runtime,
        config,
        lease_ids,
        request_id,
        |layout, request_id, lease_id, now_unix_millis| {
            claim_next_outbox_message_in_domain(
                runtime.state_store(),
                domain,
                layout,
                request_id,
                lease_id,
                now_unix_millis,
                NATIVE_OUTBOX_LEASE_MILLIS,
            )
        },
        |layout, request_id, index, lease_id| {
            acknowledge_outbox_message_in_domain(
                runtime.state_store(),
                domain,
                layout,
                request_id,
                index,
                lease_id,
            )
        },
    )
}

fn deliver_request_outbox_inner<R, L, C, A>(
    runtime: &R,
    config: &NodeConfig,
    lease_ids: &L,
    request_id: RequestId,
    mut claim_next: C,
    mut acknowledge: A,
) -> Result<usize, OutboxDeliveryError>
where
    R: Runtime,
    L: OutboxLeaseIdSource,
    C: FnMut(
        &PersistenceLayout,
        RequestId,
        OutboxLeaseId,
        u64,
    ) -> Result<Option<OutboxClaim>, NodeCoreError>,
    A: FnMut(&PersistenceLayout, RequestId, u32, OutboxLeaseId) -> Result<(), NodeCoreError>,
{
    let layout = PersistenceLayout::new(config.chain_id().clone(), config.protocol_version());
    let mut delivered_messages = 0_usize;
    for _ in 0..MAX_NODE_OUTPUT_ITEMS {
        let lease_id = lease_ids.next_lease_id(request_id)?;
        let now_unix_millis = runtime.clock().now_unix_millis()?;
        let Some(claim) = claim_next(&layout, request_id, lease_id, now_unix_millis)? else {
            return Ok(delivered_messages);
        };
        let encoded = claim.message().event().encode()?;
        runtime
            .transport()
            .send(encoded)
            .map_err(|_| OutboxDeliveryError::Send)?;
        acknowledge(&layout, claim.request_id(), claim.index(), claim.lease_id())?;
        delivered_messages = delivered_messages
            .checked_add(1)
            .ok_or(NodeCoreError::OutboxArithmeticOverflow)?;
    }
    Ok(delivered_messages)
}

fn has_supported_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let supported = values
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case(NODE_EVENT_MEDIA_TYPE)
        });
    supported && values.next().is_none()
}

fn has_unsupported_content_encoding(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
    match values.next() {
        None => false,
        Some(value) => {
            value
                .to_str()
                .map_or(true, |value| !value.trim().eq_ignore_ascii_case("identity"))
                || values.next().is_some()
        }
    }
}

fn node_error_response(error: &NodeCoreError) -> Response {
    if let NodeCoreError::TransactionAuth(error) = error {
        return transaction_auth_error_response(error);
    }
    let (status, code) = match error {
        NodeCoreError::UnauthenticatedTransactionSubmission => (
            StatusCode::NOT_IMPLEMENTED,
            "submit-transaction-requires-authenticated-route",
        ),
        NodeCoreError::ProtocolConfigVersionMismatch { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            "protocol-config-authority-mismatch",
        ),
        NodeCoreError::PayloadTooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, "payload-too-large"),
        NodeCoreError::SenderNonceMismatch { .. } => {
            (StatusCode::CONFLICT, "sender-nonce-mismatch")
        }
        NodeCoreError::SenderNonceOverflow { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "sender-nonce-overflow")
        }
        NodeCoreError::ChainMismatch { .. }
        | NodeCoreError::ProtocolVersionMismatch { .. }
        | NodeCoreError::EpochMismatch { .. }
        | NodeCoreError::StateConflict
        | NodeCoreError::RequestIdReuse
        | NodeCoreError::DurableCommitRejected(runtime::DurableCommitRejection::Conflict {
            ..
        }) => (StatusCode::CONFLICT, "state-or-context-conflict"),
        NodeCoreError::OutboxLeaseActive { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "outbox-lease-active")
        }
        NodeCoreError::TransitionRejected(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "transition-rejected")
        }
        NodeCoreError::Runtime(_) => (StatusCode::SERVICE_UNAVAILABLE, "runtime-unavailable"),
        NodeCoreError::DurableRead(
            runtime::DurableReadError::WriterFenced { .. }
            | runtime::DurableReadError::DeadlineExceeded
            | runtime::DurableReadError::Unavailable,
        )
        | NodeCoreError::DurableCommitRejected(
            runtime::DurableCommitRejection::WriterFenced { .. }
            | runtime::DurableCommitRejection::DeadlineExceededBeforeCommit
            | runtime::DurableCommitRejection::SerializationFailure
            | runtime::DurableCommitRejection::UnavailableBeforeCommit,
        )
        | NodeCoreError::DurableCommitIndeterminate(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "durable-storage-unavailable",
        ),
        NodeCoreError::ProtocolConfig(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "protocol-config-unavailable",
        ),
        NodeCoreError::DurableRead(runtime::DurableReadError::InvalidRequest(
            runtime::RuntimeError::UnsupportedObjectStorage,
        )) => (StatusCode::NOT_IMPLEMENTED, "object-storage-unsupported"),
        NodeCoreError::ObjectNotFound { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "object-not-found")
        }
        NodeCoreError::ObjectVersionMismatch { .. } => {
            (StatusCode::CONFLICT, "object-version-mismatch")
        }
        NodeCoreError::ObjectDigestMismatch { .. } => {
            (StatusCode::CONFLICT, "object-digest-mismatch")
        }
        NodeCoreError::ObjectOwnerMismatch { .. } => {
            (StatusCode::FORBIDDEN, "object-owner-mismatch")
        }
        NodeCoreError::ObjectAccessModeUnsupported { .. } => (
            StatusCode::NOT_IMPLEMENTED,
            "object-mutating-access-unsupported",
        ),
        NodeCoreError::ObjectOwnerKindUnsupported { .. } => {
            (StatusCode::NOT_IMPLEMENTED, "object-owner-kind-unsupported")
        }
        // A blob absent from the supplied `BlobStore`, or a store `RuntimeError`
        // (mapped generically below), is host/storage unavailability, not a
        // caller fault: it never exposes blob bytes or storage details.
        NodeCoreError::ObjectBlobMissing { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "object-blob-unavailable")
        }
        // Fetched bytes that do not hash to their own claimed content digest
        // are storage corruption, not a caller fault: opaque like every other
        // digest/record-corruption variant below.
        NodeCoreError::ObjectBlobDigestMismatch { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid-node-output")
        }
        // A `BlobStore::put_blob` failure while publishing a new version is
        // host/storage unavailability, distinct from a caller fault or from
        // corruption discovered on read: it never exposes blob bytes or
        // storage details.
        NodeCoreError::ObjectBlobPublishFailed { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "object-blob-publish-failed")
        }
        NodeCoreError::ObjectManifestTooLarge { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "object-manifest-too-large",
        ),
        NodeCoreError::DuplicateObjectAccess { .. } => {
            (StatusCode::BAD_REQUEST, "object-manifest-duplicate")
        }
        NodeCoreError::InvalidObjectVersion { .. } => {
            (StatusCode::BAD_REQUEST, "object-version-invalid")
        }
        NodeCoreError::ObjectConflict { .. } => (StatusCode::CONFLICT, "object-head-conflict"),
        // An object at its maximum immutable version can never be mutated
        // again: a real conflict, not a malformed request.
        NodeCoreError::ObjectVersionOverflow { .. } => {
            (StatusCode::CONFLICT, "object-version-overflow")
        }
        // Object-creating effects are outside this MVP slice; consistent
        // with every other `*Unsupported` object variant below.
        NodeCoreError::ObjectCreationUnsupported { .. } => {
            (StatusCode::NOT_IMPLEMENTED, "object-creation-unsupported")
        }
        // A declared signed access and its deterministic execution effect
        // disagreed: deterministic given the same signed transaction and
        // trusted module, so a client/request fault, not a server fault.
        NodeCoreError::ObjectEffectMismatch { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "object-effect-mismatch")
        }
        NodeCoreError::ObjectRecordMissing { .. }
        | NodeCoreError::ObjectRecordMismatch { .. }
        | NodeCoreError::ObjectBodyDigestMismatch { .. }
        | NodeCoreError::ObjectProvenanceMismatch { .. }
        // These can only mean deterministic execution (over a trusted
        // catalog module) or the owned-effects translator produced output
        // that disagrees with its own documented invariants: impossible in
        // practice, never a caller-supplied fault.
        | NodeCoreError::DuplicateObjectEffect { .. }
        | NodeCoreError::TooManyObjectEffects { .. }
        | NodeCoreError::UndeclaredObjectEffect { .. }
        | NodeCoreError::ObjectMutationContextMissing { .. }
        | NodeCoreError::InadmissibleObjectOutputOwnerAddress { .. }
        | NodeCoreError::SystemModules(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid-node-output")
        }
        NodeCoreError::ObjectDigestUnverifiable { .. } => (
            StatusCode::NOT_IMPLEMENTED,
            "object-digest-algorithm-unsupported",
        ),
        NodeCoreError::ObjectBodyTooLarge { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "object-body-too-large")
        }
        NodeCoreError::Execution(execution_error) => execution_error_response(execution_error),
        // Malformed/inactive/unknown module reference: deterministic,
        // request-dependent client faults.
        NodeCoreError::PreinstalledModuleUnknown { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-unknown",
        ),
        NodeCoreError::PreinstalledModuleInactive { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-inactive",
        ),
        NodeCoreError::PreinstalledModuleNotYetActive { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-not-yet-active",
        ),
        NodeCoreError::PreinstalledModuleReferenceDigestMismatch { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-reference-invalid",
        ),
        // Args/gas/zero-object request faults: deterministic client errors.
        NodeCoreError::PreinstalledModuleArgsTooLarge { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-args-too-large",
        ),
        NodeCoreError::PreinstalledModuleGasLimitExceedsCeiling { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-gas-limit-exceeded",
        ),
        NodeCoreError::PreinstalledModuleZeroObjectAccess => (
            StatusCode::BAD_REQUEST,
            "preinstalled-module-zero-object-access",
        ),
        NodeCoreError::FeePaymentRequired => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-required",
        ),
        NodeCoreError::FeePaymentNotRequired => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-not-required",
        ),
        NodeCoreError::FeePaymentUnsupportedOnPath => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-unsupported-on-path",
        ),
        NodeCoreError::FeePaymentRejected(
            fees::FeeError::UnknownAsset(_)
            | fees::FeeError::AssetDisabled(_)
            | fees::FeeError::MaxFeeExceeded { .. },
        ) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-payment-rejected",
        ),
        NodeCoreError::FeePaymentRejected(fees::FeeError::ArithmeticOverflow) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-settlement-overflow",
        ),
        NodeCoreError::FeePaymentRejected(
            fees::FeeError::StandardAsset(_)
            | fees::FeeError::ZeroFeeUnitsPerAssetUnit
            | fees::FeeError::RegistryTooLarge(_)
            | fees::FeeError::TooManySigners(_)
            | fees::FeeError::DuplicateAsset(_)
            | fees::FeeError::EmptySignerSet
            | fees::FeeError::DuplicateSigner(_)
            | fees::FeeError::CanonicalEncoding(_)
            | fees::FeeError::CanonicalDecoding(_)
            | fees::FeeError::Object(_),
        ) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-policy-invalid",
        ),
        NodeCoreError::FeeObjectNotDeclaredWrite => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-object-not-declared-write",
        ),
        NodeCoreError::FeeObjectNotOwnedBySender => (
            StatusCode::FORBIDDEN,
            "fee-object-owner-mismatch",
        ),
        NodeCoreError::FeeObjectIsTreasury => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-object-is-treasury",
        ),
        NodeCoreError::FeeTreasuryAccessMisdeclared => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-treasury-access-misdeclared",
        ),
        NodeCoreError::FeeCompositionFailed(node_core::FeeCompositionError::InsufficientBalance) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "fee-balance-insufficient",
        ),
        NodeCoreError::FeeCompositionFailed(
            node_core::FeeCompositionError::MalformedBody
            | node_core::FeeCompositionError::AssetMismatch
            | node_core::FeeCompositionError::Overflow,
        ) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-composition-invalid",
        ),
        NodeCoreError::FeeCompositionUnavailable => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-composition-unavailable",
        ),
        NodeCoreError::FeeCompositionNoOp => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-composition-no-op",
        ),
        NodeCoreError::FeeAmountZero => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-settlement-zero",
        ),
        // The committed `GasSchedule` itself is malformed for this path
        // (see `node_core::GasScheduleShapeFault`): trusted configuration,
        // never anything the caller controls, so it is opaque to the caller
        // beyond a generic server-fault code.
        NodeCoreError::UnsupportedGasScheduleShape(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "fee-schedule-unsupported",
        ),
        // Catalog/commitment mismatch: the composition-trusted catalog
        // disagrees with the governance-committed registry, which is a host
        // misconfiguration rather than anything the caller controls.
        NodeCoreError::PreinstalledModuleNotCataloged { .. }
        | NodeCoreError::PreinstalledModuleCodeHashMismatch { .. }
        | NodeCoreError::PreinstalledModuleManifestHashMismatch { .. }
        | NodeCoreError::PreinstalledModuleSemanticsHashMismatch { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "preinstalled-module-catalog-mismatch",
        ),
        // `created_checkpoint` is trusted node composition, never request
        // input; a regression here is a host/operator failure.
        NodeCoreError::ObjectCreatedCheckpointRegression { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "object-created-checkpoint-regression",
        ),
        NodeCoreError::ResponseRequestMismatch { .. }
        | NodeCoreError::StateTooLarge(_)
        | NodeCoreError::TooManyOutputItems { .. }
        | NodeCoreError::OutputTooLarge(_)
        | NodeCoreError::ZeroOutboxLeaseId
        | NodeCoreError::InvalidOutboxLeaseDuration(_)
        | NodeCoreError::PersistenceInvariant(_)
        | NodeCoreError::OutboxNotFound
        | NodeCoreError::OutboxLeaseMismatch
        | NodeCoreError::OutboxIndexMismatch
        | NodeCoreError::OutboxArithmeticOverflow
        | NodeCoreError::DurableRead(_)
        | NodeCoreError::DurableInvocation(_)
        | NodeCoreError::DurableCommitRejected(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid-node-output")
        }
        _ => (StatusCode::BAD_REQUEST, "invalid-node-event"),
    };
    error_response(status, code)
}

/// Coarse HTTP classification for every [`ExecutionError`] variant reachable
/// from the preinstalled-WASM route, matched exhaustively (no wildcard) so a
/// future variant forces an explicit classification decision here.
///
/// By the time [`node_core::handle_authenticated_resolved_durable_submit_transaction_with_preinstalled_wasm_execution`]'s
/// machine ever runs, [`node_core::authenticate_submit_transaction_event`]
/// has already decoded and re-encoded the exact same transaction once
/// (`transaction_auth::authenticate_transaction_bytes` calls
/// `execution::encode_transaction_signable`), so `EmptyEntrypoint`,
/// `TransactionFieldTooLarge`, `NonCanonicalTransactionEncoding`, and every
/// other canonical-encoding-shaped variant can only recur here as a
/// host/composition invariant violation, never a fresh caller-supplied
/// fault; the same is true of `HashChainMismatch`/`HashProtocolVersionMismatch`,
/// since this route's `resolver` is the same trusted value already used to
/// authenticate the event's chain/protocol version.
fn execution_error_response(error: &ExecutionError) -> (StatusCode, &'static str) {
    match error {
        // The transaction's client-chosen entrypoint name does not exist in
        // an otherwise trusted, catalog-verified module: deterministic and
        // request-dependent, so a client fault.
        ExecutionError::MissingEntrypoint(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-entrypoint-unknown",
        ),
        // Deterministic execution resource bounds (args/input-object/
        // input-data size) exceeded; scales with the caller's own manifest
        // and args, so a client fault. Malformed trusted catalog WASM bytes
        // cannot reach this arm: `PreinstalledModuleCatalogEntry::new`
        // already enforces the same module-byte bound at composition time.
        ExecutionError::ResourceLimitExceeded(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "preinstalled-module-resource-limit-exceeded",
        ),
        // The trusted catalog module itself failed fuel setup, compilation,
        // host-function linking, instantiation, or start: a host/catalog
        // defect (malformed trusted catalog WASM), never something the
        // caller can control. A wrong-signature entrypoint does not reach
        // this arm; it normalizes as a deterministic execution
        // failure/trap instead. Bounded only by this route's
        // admission/pre-activation limits, not production fee accounting.
        ExecutionError::WasmEngine(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "preinstalled-module-engine-failure",
        ),
        // Mirrors `NodeCoreError::ObjectVersionOverflow`'s classification:
        // the object can no longer be mutated, a real conflict rather than a
        // malformed request.
        ExecutionError::ObjectVersionOverflow(_) => {
            (StatusCode::CONFLICT, "object-version-overflow")
        }
        // Every remaining variant is internal encoding/hashing/context
        // machinery over an already-authenticated, already-bounded
        // transaction; see this function's doc comment for why reaching one
        // here is a host/composition invariant violation.
        ExecutionError::CanonicalEncoding(_)
        | ExecutionError::CanonicalDecoding(_)
        | ExecutionError::Abi(_)
        | ExecutionError::Object(_)
        | ExecutionError::Hashing(_)
        | ExecutionError::Fee(_)
        | ExecutionError::ProtocolType(_)
        | ExecutionError::EmptyEntrypoint
        | ExecutionError::EmptySignature
        | ExecutionError::TransactionFieldTooLarge { .. }
        | ExecutionError::NonCanonicalTransactionEncoding
        | ExecutionError::UnknownExecutionStatusTag(_)
        | ExecutionError::UnknownObjectEffectTag(_)
        | ExecutionError::TooManyObjectEffects(_)
        | ExecutionError::TooManyEvents(_)
        | ExecutionError::ExecutionEffectsListCountMismatch { .. }
        | ExecutionError::NonCanonicalExecutionEffectsEncoding
        | ExecutionError::HashChainMismatch
        | ExecutionError::HashProtocolVersionMismatch { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "invalid-node-output")
        }
    }
}

fn transaction_auth_error_response(error: &TransactionAuthError) -> Response {
    let (status, code) = match error {
        TransactionAuthError::Config(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "transaction-auth-config-unavailable",
        ),
        TransactionAuthError::Decode(_) | TransactionAuthError::SubmissionEnvelope(_) => {
            (StatusCode::BAD_REQUEST, "invalid-transaction-bytes")
        }
        TransactionAuthError::ChainMismatch { .. }
        | TransactionAuthError::ProtocolVersionMismatch { .. }
        | TransactionAuthError::EpochMismatch { .. } => {
            (StatusCode::BAD_REQUEST, "transaction-context-mismatch")
        }
        TransactionAuthError::SignableTransactionTooLarge { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "transaction-signable-too-large",
        ),
        TransactionAuthError::MissingSubmissionRequestId
        | TransactionAuthError::InadmissibleSenderAddress(_)
        | TransactionAuthError::Crypto(_)
        | TransactionAuthError::InvalidTransactionSignature => {
            (StatusCode::UNAUTHORIZED, "transaction-signature-invalid")
        }
    };
    error_response(status, code)
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        code,
    )
        .into_response()
}

fn cancelled_before_storage_response() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "invocation-cancelled-before-storage",
    )
}

fn overload_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        "blocking-capacity-exhausted",
    )
        .into_response()
}

#[cfg(test)]
mod tests;
