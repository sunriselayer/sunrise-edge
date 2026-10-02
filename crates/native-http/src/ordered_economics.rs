//! DR-0153 opt-in ordered network economics HTTP surface.
//!
//! [`certified_ordered_economics_router`] is a genuinely separate,
//! self-contained router constructor: its body only ever mounts the existing
//! paths in [`node_wire::ordered_economics`] and the read-only
//! [`node_wire::ordered_history`] family, never `NODE_EVENT_PATH` or any
//! `mutation_routes` from `publication`/`local_execution`/`paid_execution`.
//! It cannot expose a direct/legacy mutating economics route by
//! construction, not merely by a run-time flag happening to be false.
//! Callers (an operator binary) opt in explicitly by constructing an
//! [`OrderedEconomicsState`] and `.merge()`-ing the returned [`Router`] onto
//! whatever certified-only router they already serve; this module never
//! mounts itself.
//!
//! Every handler rejects an unsupported media type, an unsupported
//! `Content-Encoding`, and an oversized body on the async task itself
//! (cheap, non-blocking checks), then performs pure signature verification
//! (`verify_proposal`/`verify_certificate`, or `authenticate_candidate` for
//! `propose`) *before* any identity/clock/storage access -- exactly
//! mirroring `fastvote.rs`'s own authenticate-before-identity/clock/storage
//! ordering. Canonical decoding and cryptographic verification run inside
//! the shared blocking admission budget as well, not on the async executor.
//! Every synchronous store/core call (candidate
//! authentication that decodes/verifies a full intent, and the
//! `propose`/`process_proposal`/`process_certificate`/`observe_proposal`/
//! `query_status`/`process_tick` orchestration itself, which performs real
//! durable-store I/O) runs inside [`publication::admitted`], bounded by the
//! same [`NativeBlockingExecutor`] the host's certified FastVote router
//! uses -- one shared admission budget across both surfaces, never a
//! second, uncoordinated concurrency limit. `propose` signs proposals and
//! `proposal` may sign a vote; `observe` never signs.

use crate::{IndexedOutboxIdentitySource, IndexedOutboxIdentitySourceError, publication};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use consensus::ConsensusSigner;
use execution::local_execution::{LocalContractEngine, LocalExecutionPolicy};
use execution::paid_execution::PaidContractEngine;
use hashing::HashSuiteResolver;
use node_core::fast_path::FastPathEd25519Verifier;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{
    self, OrderedEconomicsEnvironment, OrderedEconomicsError, OrderedEconomicsPolicy,
    OrderedSealComposition,
};
use node_wire::ordered_economics::{
    MAX_ORDERED_CERTIFICATE_BYTES, MAX_ORDERED_PROPOSAL_BYTES, MAX_ORDERED_PROPOSE_REQUEST_BYTES,
    ORDERED_CERTIFICATE_MEDIA_TYPE, ORDERED_ECONOMICS_CERTIFICATE_PATH,
    ORDERED_ECONOMICS_OBSERVE_PATH, ORDERED_ECONOMICS_PROPOSAL_PATH,
    ORDERED_ECONOMICS_PROPOSE_PATH, ORDERED_ECONOMICS_STATUS_PATH, ORDERED_ECONOMICS_TICK_PATH,
    ORDERED_EVENT_OUTPUT_MEDIA_TYPE, ORDERED_PROPOSAL_MEDIA_TYPE,
    ORDERED_PROPOSE_REQUEST_MEDIA_TYPE, ORDERED_STATUS_MEDIA_TYPE, OrderedProposeRequest,
};
use runtime::portable::PortableBlobRepository;
use runtime::{
    AtomicityDomainId, BlobStore, Clock, DurableOperationContext, InvocationCancellation,
    StorageDeadline, StructuredDurableDomainStateStore, WriterFenceGeneration,
};
use std::{sync::Arc, time::Duration};

use crate::NativeBlockingExecutor;

mod ordered_history;

/// Real locally pinned reconstruction dependencies for the optional Seal
/// route. Capability support still comes only from this router's owning store;
/// these dependencies neither activate a successor nor grant serving authority.
pub struct OrderedSealHostComposition {
    pub genesis_root: VerifiedGenesisRoot,
    pub paid_base_policy: LocalExecutionPolicy,
    pub paid_engine: Arc<dyn PaidContractEngine + Send + Sync>,
    pub blobs: Arc<dyn PortableBlobRepository + Send + Sync>,
}

impl OrderedSealHostComposition {
    fn borrowed(&self) -> OrderedSealComposition<'_> {
        OrderedSealComposition {
            genesis_root: &self.genesis_root,
            paid_base_policy: &self.paid_base_policy,
            paid_engine: self.paid_engine.as_ref(),
            blobs: self.blobs.as_ref(),
        }
    }
}

/// State this router's handlers share. Never contains a signer capable of
/// authorizing a direct economics mutation outside the ordered routes.
pub struct OrderedEconomicsState<S, C, I, Sig> {
    pub store: Arc<S>,
    pub clock: Arc<C>,
    pub identities: Arc<I>,
    pub domain: AtomicityDomainId,
    pub writer_fence: WriterFenceGeneration,
    pub operation_timeout: Duration,
    pub policy: OrderedEconomicsPolicy,
    pub history: Vec<HashSuiteResolver>,
    pub leg_policy: LocalExecutionPolicy,
    pub engine: Arc<dyn LocalContractEngine + Send + Sync>,
    pub blobs: Arc<dyn BlobStore + Send + Sync>,
    /// Unsupported by default composition, never a decoded readiness claim.
    pub seal: Option<OrderedSealHostComposition>,
    /// This node's own leader-eligible signer. `observe`/`status`/
    /// `certificate` never use it; only `propose` and the vote it may emit
    /// from `proposal` do.
    pub signer: Sig,
    /// Shared blocking-admission budget. The caller (an operator binary)
    /// must pass the *same* [`NativeBlockingExecutor`] instance it hands to
    /// `certified_fastvote_router_with_executor`, so this router's own
    /// synchronous store/core work draws from one coordinated concurrency
    /// budget alongside FastVote's, never a second independent one.
    pub blocking_executor: NativeBlockingExecutor,
    /// Trusted cancellation signal, if the host has one. `None` never
    /// cancels, matching every existing composition that does not wire
    /// `StructuredDurableNativeComponents::with_cancellation`.
    pub cancellation: Option<Arc<dyn InvocationCancellation>>,
}

impl<S, C, I, Sig> OrderedEconomicsState<S, C, I, Sig> {
    fn seal_composition(&self) -> Option<OrderedSealComposition<'_>> {
        self.seal.as_ref().map(OrderedSealHostComposition::borrowed)
    }
    fn is_cancelled(&self) -> bool {
        match &self.cancellation {
            Some(cancellation) => cancellation.is_cancelled(),
            None => false,
        }
    }
}

type SharedOrderedEconomicsState<S, C, I, Sig> = Arc<OrderedEconomicsState<S, C, I, Sig>>;

fn error_response(status: StatusCode, code: &'static str) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], code).into_response()
}

fn ordered_economics_error_response(error: &OrderedEconomicsError) -> Response {
    if let Some(outcome) = error.completed_outcome() {
        return encode_event_output_response(&ordered_economics::OrderedEventOutput {
            messages: Vec::new(),
            committed: vec![outcome.clone()],
        });
    }
    // Structural/authentication failures are the caller's fault; storage
    // unavailability/fencing/ambiguity must never be reported as an ordinary
    // client error that a retry-with-different-bytes could paper over.
    match error {
        OrderedEconomicsError::Unauthenticated(_) | OrderedEconomicsError::Policy(_) => {
            error_response(StatusCode::BAD_REQUEST, "ordered-economics-rejected")
        }
        OrderedEconomicsError::RequestHeaderConflict
        | OrderedEconomicsError::Refused(_)
        | OrderedEconomicsError::Node(node_core::NodeCoreError::RequestIdReuse) => {
            error_response(StatusCode::CONFLICT, "ordered-economics-request-conflict")
        }
        OrderedEconomicsError::Node(node_core::NodeCoreError::EpochMismatch { .. }) => {
            error_response(
                StatusCode::CONFLICT,
                "ordered-economics-epoch-repin-required",
            )
        }
        _ => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "ordered-economics-unavailable",
        ),
    }
}

#[allow(clippy::result_large_err)]
fn build_context<S, C, I, Sig>(
    state: &OrderedEconomicsState<S, C, I, Sig>,
) -> Result<DurableOperationContext, Response>
where
    C: Clock,
    I: IndexedOutboxIdentitySource,
{
    let identity = state.identities.next_attempt_identity().map_err(|error| {
        let code = match error {
            IndexedOutboxIdentitySourceError::Unavailable => {
                "ordered-economics-identity-unavailable"
            }
            IndexedOutboxIdentitySourceError::Exhausted => "ordered-economics-identity-exhausted",
        };
        error_response(StatusCode::SERVICE_UNAVAILABLE, code)
    })?;
    let now_unix_millis = state.clock.now_unix_millis().map_err(|_| {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "ordered-economics-clock-unavailable",
        )
    })?;
    let deadline_unix_millis = now_unix_millis
        .checked_add(state.operation_timeout.as_millis() as u64)
        .ok_or_else(|| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ordered-economics-deadline-overflow",
            )
        })?;
    let deadline = StorageDeadline::new(deadline_unix_millis).ok_or_else(|| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ordered-economics-deadline-overflow",
        )
    })?;
    Ok(DurableOperationContext::new(
        state.writer_fence,
        deadline,
        identity.correlation_id,
    ))
}

fn has_media_type(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        == Some(expected)
}

/// Shared preflight: unsupported media type, unsupported `Content-Encoding`,
/// or an oversized body, all rejected on the async task with zero identity/
/// clock/storage access and zero admission-slot use.
fn reject_unsupported_request(
    headers: &HeaderMap,
    body: &Bytes,
    expected_media_type: &str,
    max_bytes: usize,
) -> Option<Response> {
    if !has_media_type(headers, expected_media_type) {
        return Some(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-ordered-content",
        ));
    }
    if crate::has_unsupported_content_encoding(headers) {
        return Some(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-ordered-content-encoding",
        ));
    }
    if body.len() > max_bytes {
        return Some(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "ordered-body-too-large",
        ));
    }
    None
}

async fn propose_handler<S, C, I, Sig>(
    State(state): State<SharedOrderedEconomicsState<S, C, I, Sig>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    if let Some(response) = reject_unsupported_request(
        &headers,
        &body,
        ORDERED_PROPOSE_REQUEST_MEDIA_TYPE,
        MAX_ORDERED_PROPOSE_REQUEST_BYTES,
    ) {
        return response;
    }
    let cancelled = state.is_cancelled();
    let executor = state.blocking_executor.clone();
    publication::admitted(cancelled, executor, move || {
        let request = match OrderedProposeRequest::decode(&body) {
            Ok(value) => value,
            Err(_) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-propose-request");
            }
        };
        let candidate = match request.candidate {
            Some(bytes) => match ordered_economics::decode_ordered_candidate(&bytes) {
                Ok(value) => Some(value),
                Err(_) => {
                    return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-candidate");
                }
            },
            None => None,
        };
        let env = OrderedEconomicsEnvironment {
            policy: &state.policy,
            history: &state.history,
            leg_policy: &state.leg_policy,
            engine: state.engine.as_ref(),
            blobs: state.blobs.as_ref(),
            seal: state.seal_composition(),
        };
        // Pure authentication before any identity/clock/storage access.
        if let Some(candidate) = &candidate
            && let Err(error) = ordered_economics::authenticate_candidate(&env, candidate)
        {
            return ordered_economics_error_response(&error);
        }
        let context = match build_context(&state) {
            Ok(value) => value,
            Err(response) => return response,
        };
        match ordered_economics::propose(
            state.store.as_ref(),
            &context,
            &env,
            candidate.as_ref(),
            &state.signer,
        ) {
            Ok(proposal) => match ordered_economics::encode_ordered_proposal(&proposal) {
                Ok(bytes) => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, ORDERED_PROPOSAL_MEDIA_TYPE),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response(),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ordered-proposal-encoding",
                ),
            },
            Err(error) => ordered_economics_error_response(&error),
        }
    })
    .await
}

async fn proposal_handler<S, C, I, Sig>(
    State(state): State<SharedOrderedEconomicsState<S, C, I, Sig>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    if let Some(response) = reject_unsupported_request(
        &headers,
        &body,
        ORDERED_PROPOSAL_MEDIA_TYPE,
        MAX_ORDERED_PROPOSAL_BYTES,
    ) {
        return response;
    }
    let cancelled = state.is_cancelled();
    let executor = state.blocking_executor.clone();
    publication::admitted(cancelled, executor, move || {
        let proposal = match ordered_economics::decode_ordered_proposal(&body) {
            Ok(value) => value,
            Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-proposal"),
        };
        // Pure envelope authentication remains before identity/clock/I/O,
        // but bounded cryptographic work must not occupy an async worker.
        if state
            .policy
            .engine()
            .verify_proposal(&proposal.proposal, &FastPathEd25519Verifier)
            .is_err()
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid-ordered-proposal-signature",
            );
        }
        let env = OrderedEconomicsEnvironment {
            policy: &state.policy,
            history: &state.history,
            leg_policy: &state.leg_policy,
            engine: state.engine.as_ref(),
            blobs: state.blobs.as_ref(),
            seal: state.seal_composition(),
        };
        if let Some(candidate) = &proposal.candidate
            && let Err(error) = ordered_economics::authenticate_candidate(&env, candidate)
        {
            return ordered_economics_error_response(&error);
        }
        let context = match build_context(&state) {
            Ok(value) => value,
            Err(response) => return response,
        };
        match ordered_economics::process_proposal(
            state.store.as_ref(),
            &context,
            &env,
            &proposal,
            &state.signer,
        ) {
            Ok(output) => encode_event_output_response(&output),
            Err(error) => ordered_economics_error_response(&error),
        }
    })
    .await
}

async fn certificate_handler<S, C, I, Sig>(
    State(state): State<SharedOrderedEconomicsState<S, C, I, Sig>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    if let Some(response) = reject_unsupported_request(
        &headers,
        &body,
        ORDERED_CERTIFICATE_MEDIA_TYPE,
        MAX_ORDERED_CERTIFICATE_BYTES,
    ) {
        return response;
    }
    let cancelled = state.is_cancelled();
    let executor = state.blocking_executor.clone();
    publication::admitted(cancelled, executor, move || {
        let certificate = match consensus::decode_quorum_certificate(&body) {
            Ok(value) => value,
            Err(_) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-certificate");
            }
        };
        // Verification is admitted CPU work, still before identity/clock/I/O.
        if state
            .policy
            .engine()
            .verify_certificate(&certificate, &FastPathEd25519Verifier)
            .is_err()
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid-ordered-certificate-signature",
            );
        }
        let env = OrderedEconomicsEnvironment {
            policy: &state.policy,
            history: &state.history,
            leg_policy: &state.leg_policy,
            engine: state.engine.as_ref(),
            blobs: state.blobs.as_ref(),
            seal: state.seal_composition(),
        };
        let context = match build_context(&state) {
            Ok(value) => value,
            Err(response) => return response,
        };
        match ordered_economics::process_certificate(
            state.store.as_ref(),
            &context,
            &env,
            &certificate,
        ) {
            Ok(output) => encode_event_output_response(&output),
            Err(error) => ordered_economics_error_response(&error),
        }
    })
    .await
}

async fn observe_handler<S, C, I, Sig>(
    State(state): State<SharedOrderedEconomicsState<S, C, I, Sig>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    if let Some(response) = reject_unsupported_request(
        &headers,
        &body,
        ORDERED_PROPOSAL_MEDIA_TYPE,
        MAX_ORDERED_PROPOSAL_BYTES,
    ) {
        return response;
    }
    let cancelled = state.is_cancelled();
    let executor = state.blocking_executor.clone();
    publication::admitted(cancelled, executor, move || {
        let proposal = match ordered_economics::decode_ordered_proposal(&body) {
            Ok(value) => value,
            Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-proposal"),
        };
        // Signerless does not mean unauthenticated. Verify before any I/O.
        if state
            .policy
            .engine()
            .verify_proposal(&proposal.proposal, &FastPathEd25519Verifier)
            .is_err()
        {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid-ordered-proposal-signature",
            );
        }
        let env = OrderedEconomicsEnvironment {
            policy: &state.policy,
            history: &state.history,
            leg_policy: &state.leg_policy,
            engine: state.engine.as_ref(),
            blobs: state.blobs.as_ref(),
            seal: state.seal_composition(),
        };
        if let Some(candidate) = &proposal.candidate
            && let Err(error) = ordered_economics::authenticate_candidate(&env, candidate)
        {
            return ordered_economics_error_response(&error);
        }
        let context = match build_context(&state) {
            Ok(value) => value,
            Err(response) => return response,
        };
        // Signerless: never emits a vote, never mutates a reservation.
        match ordered_economics::observe_proposal(state.store.as_ref(), &context, &env, &proposal) {
            Ok(output) => encode_event_output_response(&output),
            Err(error) => ordered_economics_error_response(&error),
        }
    })
    .await
}

async fn status_handler<S, C, I, Sig>(
    State(state): State<SharedOrderedEconomicsState<S, C, I, Sig>>,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    let cancelled = state.is_cancelled();
    let executor = state.blocking_executor.clone();
    publication::admitted(cancelled, executor, move || {
        let env = OrderedEconomicsEnvironment {
            policy: &state.policy,
            history: &state.history,
            leg_policy: &state.leg_policy,
            engine: state.engine.as_ref(),
            blobs: state.blobs.as_ref(),
            seal: state.seal_composition(),
        };
        let context = match build_context(&state) {
            Ok(value) => value,
            Err(response) => return response,
        };
        match ordered_economics::query_status(state.store.as_ref(), &context, &env) {
            Ok(status) => match ordered_economics::encode_ordered_status(&status) {
                Ok(bytes) => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, ORDERED_STATUS_MEDIA_TYPE),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response(),
                Err(_) => {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "ordered-status-encoding")
                }
            },
            Err(error) => ordered_economics_error_response(&error),
        }
    })
    .await
}

async fn outcome_handler<S, C, I, Sig>(
    State(state): State<SharedOrderedEconomicsState<S, C, I, Sig>>,
    Path(selector): Path<String>,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    let Some(request_id) =
        crate::decode_hex64_selector(&selector).filter(|bytes| *bytes != [0; 32])
    else {
        return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-request-id");
    };
    let executor = state.blocking_executor.clone();
    publication::admitted(state.is_cancelled(), executor, move || {
        let env = OrderedEconomicsEnvironment {
            policy: &state.policy,
            history: &state.history,
            leg_policy: &state.leg_policy,
            engine: state.engine.as_ref(),
            blobs: state.blobs.as_ref(),
            seal: state.seal_composition(),
        };
        let context = match build_context(&state) {
            Ok(value) => value,
            Err(response) => return response,
        };
        match ordered_economics::query_ordered_outcome(
            state.store.as_ref(),
            &context,
            &env,
            &request_id,
        ) {
            Ok(None) => (
                StatusCode::NO_CONTENT,
                [(header::CACHE_CONTROL, "no-store")],
            )
                .into_response(),
            Ok(Some(outcome)) => match ordered_economics::encode_ordered_outcome(&outcome) {
                Ok(bytes) => (
                    StatusCode::OK,
                    [
                        (
                            header::CONTENT_TYPE,
                            node_wire::ordered_economics::ORDERED_OUTCOME_MEDIA_TYPE,
                        ),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response(),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ordered-outcome-encoding",
                ),
            },
            Err(error) => ordered_economics_error_response(&error),
        }
    })
    .await
}

fn encode_event_output_response(output: &ordered_economics::OrderedEventOutput) -> Response {
    match ordered_economics::encode_ordered_event_output(output) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, ORDERED_EVENT_OUTPUT_MEDIA_TYPE),
                (header::CACHE_CONTROL, "no-store"),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ordered-event-output-encoding",
        ),
    }
}

/// Trusted-local-clock-only pacemaker handler
/// (`node_core::ordered_economics::process_tick`). Requires a strictly
/// empty body and rejects any `Content-Encoding` *before* identity, clock,
/// or storage access; `now` comes only from `state.clock`, never a caller-
/// supplied timestamp. Never selects a substitute leader: it only asks the
/// pinned engine whether *this* node is the deterministically selected
/// leader for a view whose deadline the trusted clock shows has elapsed.
async fn tick_handler<S, C, I, Sig>(
    State(state): State<SharedOrderedEconomicsState<S, C, I, Sig>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    if crate::has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-ordered-content-encoding",
        );
    }
    if !body.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "ordered-tick-body-must-be-empty");
    }
    let cancelled = state.is_cancelled();
    let executor = state.blocking_executor.clone();
    publication::admitted(cancelled, executor, move || {
        let now_unix_millis = match state.clock.now_unix_millis() {
            Ok(value) => value,
            Err(_) => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ordered-economics-clock-unavailable",
                );
            }
        };
        let env = OrderedEconomicsEnvironment {
            policy: &state.policy,
            history: &state.history,
            leg_policy: &state.leg_policy,
            engine: state.engine.as_ref(),
            blobs: state.blobs.as_ref(),
            seal: state.seal_composition(),
        };
        let context = match build_context(&state) {
            Ok(value) => value,
            Err(response) => return response,
        };
        match ordered_economics::process_tick(
            state.store.as_ref(),
            &context,
            &env,
            now_unix_millis,
            &state.signer,
        ) {
            Ok(output) => encode_event_output_response(&output),
            Err(error) => ordered_economics_error_response(&error),
        }
    })
    .await
}

/// Builds the opt-in ordered-economics router. The caller merges the result
/// onto whatever certified-only router it already serves; this constructor
/// never merges anything else in, so the returned router can never carry a
/// direct/legacy mutating route regardless of caller mistake.
pub fn certified_ordered_economics_router<S, C, I, Sig>(
    state: OrderedEconomicsState<S, C, I, Sig>,
) -> Router
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    let shared: SharedOrderedEconomicsState<S, C, I, Sig> = Arc::new(state);
    Router::new()
        .route(
            ORDERED_ECONOMICS_PROPOSE_PATH,
            post(propose_handler::<S, C, I, Sig>),
        )
        .route(
            ORDERED_ECONOMICS_PROPOSAL_PATH,
            post(proposal_handler::<S, C, I, Sig>),
        )
        .route(
            ORDERED_ECONOMICS_CERTIFICATE_PATH,
            post(certificate_handler::<S, C, I, Sig>),
        )
        .route(
            ORDERED_ECONOMICS_OBSERVE_PATH,
            post(observe_handler::<S, C, I, Sig>),
        )
        .route(
            ORDERED_ECONOMICS_STATUS_PATH,
            get(status_handler::<S, C, I, Sig>),
        )
        .route(
            node_wire::ordered_economics::ORDERED_ECONOMICS_OUTCOME_ROUTE,
            get(outcome_handler::<S, C, I, Sig>),
        )
        .route(
            ORDERED_ECONOMICS_TICK_PATH,
            post(tick_handler::<S, C, I, Sig>),
        )
        .merge(ordered_history::routes::<S, C, I, Sig>())
        .layer(DefaultBodyLimit::max(MAX_ORDERED_PROPOSAL_BYTES))
        .with_state(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_unsupported_request_rejects_the_wrong_media_type_with_zero_admission() {
        let headers = HeaderMap::new();
        let body = Bytes::from_static(b"");
        let response =
            reject_unsupported_request(&headers, &body, "application/expected", 1024).unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn reject_unsupported_request_rejects_an_unsupported_content_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/expected".parse().unwrap(),
        );
        headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        let body = Bytes::from_static(b"");
        let response =
            reject_unsupported_request(&headers, &body, "application/expected", 1024).unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn reject_unsupported_request_rejects_an_oversized_body_before_decoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/expected".parse().unwrap(),
        );
        let body = Bytes::from(vec![0u8; 16]);
        let response =
            reject_unsupported_request(&headers, &body, "application/expected", 8).unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn reject_unsupported_request_accepts_a_well_formed_request() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/expected".parse().unwrap(),
        );
        let body = Bytes::from_static(b"ok");
        assert!(
            reject_unsupported_request(&headers, &body, "application/expected", 1024).is_none()
        );
    }
}
