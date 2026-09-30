//! Certified-only FastVote HTTP transport (DR-0148).
//!
//! [`certified_fastvote_router`] is a genuinely separate router constructor,
//! not a flag threaded through [`super::preinstalled_wasm_structured_durable_router`]:
//! its body never references [`publication::mutation_routes`],
//! [`local_execution::mutation_routes`], [`paid_execution::mutation_routes`],
//! or `NODE_EVENT_PATH`, so it cannot expose a direct/legacy mutating route
//! by construction, not merely by a run-time flag happening to be false.
//! [`PreinstalledWasmComposition::with_fastvote`] is crate-private, so no
//! other constructor in this crate can ever be handed a FastVote composition
//! either.
//!
//! Dedicated, opt-in routes wrap the existing
//! `node_core::fast_path::{prepare, apply}` entry points -- the exact same
//! authenticated admission/execution pipeline the direct paid-execution
//! route uses -- with no new canonical protocol type. `POST
//! `[`FASTVOTE_PREPARE_PATH`]`` accepts exactly one canonical
//! `SignedPaidIntent` and returns exactly one canonical `FastVote`. `POST
//! `[`FASTVOTE_CERTIFICATES_PATH`]`` accepts a [`FastVoteApplyRequest`] (the
//! same signed intent bytes plus a canonical `FastCertificate`) and returns
//! the same `HttpNodeResult` shape the direct paid-execution route returns.
//!
//! The prepare and apply handlers authenticate the exact signed bytes against the caller's
//! own declared chain/protocol/epoch *before* allocating a restart-safe
//! identity, reading the clock, or resolving domain/context -- exactly the
//! ordering `node_core::paid_execution::authenticate_paid_execution`'s own
//! doc comment requires ("without consulting runtime identity, clock,
//! storage, policy, code, object, or blob state"). The caller's own declared
//! epoch, not a freshly storage-read current epoch, is what gets
//! authenticated: `fast_path::prepare`/`apply` re-authenticate internally
//! against that same declared context and only *then* CAS-fence it against
//! the durable current epoch, so a stale-but-genuinely-signed intent still
//! fails closed, just after authentication rather than before it. Neither
//! handler ever calls `node_core::paid_execution::reconcile_authenticated_paid_execution`:
//! that function rejects on a declared/current epoch mismatch *before*
//! checking for an existing exact receipt, which would break `fast_path::apply`'s
//! own receipt-first historical exact-replay guarantee for a request whose
//! epoch has since advanced.

use super::*;
use consensus::{ConsensusSigner, bundle::MAX_ENCODED_BUNDLE_BYTES};
use execution::paid_execution::{MAX_SIGNED_PAID_INTENT_BYTES, decode_signed_paid_intent};
use node_core::fast_path::publication::PublicationRetentionError;
use node_core::fast_path::{self, FastPathError};
use node_core::ordered_economics::{
    FrozenFrontierError, FrozenFrontierStep, advance_frozen_frontier, read_frozen_frontier_page,
};
use node_core::paid_execution::authenticate_paid_execution;
use protocol_types::{SignatureSchemeId, ValidatorId};
use runtime::{outbox_guard::StructuredOutboxExclusionGuard, portable::DurablePortableRepository};
use std::num::NonZeroUsize;

mod drain;

/// Production mutation-route inventory excluded by certified-only hosting.
/// Derived from the actual handler constants so route renames remain covered.
pub const CERTIFIED_FASTVOTE_EXCLUDED_MUTATION_PATHS: &[&str] = &[
    NODE_EVENT_PATH,
    publication::PUBLICATION_PATH,
    local_execution::EXECUTION_PATH,
    paid_execution::PAID_EXECUTION_PATH,
];

/// Adapts a boxed [`FastVoteComposition`] signer into a concrete, `Sized`
/// [`ConsensusSigner`] implementation: `node_core::fast_path::prepare`'s own
/// `C: ConsensusSigner` bound requires a `Sized` type, which `dyn
/// ConsensusSigner` itself is not, and this crate cannot implement the
/// foreign `ConsensusSigner` trait directly on `Arc<dyn ConsensusSigner>`
/// under Rust's orphan rules.
struct DynConsensusSigner<'a>(&'a (dyn ConsensusSigner + Send + Sync));

impl ConsensusSigner for DynConsensusSigner<'_> {
    fn validator_id(&self) -> ValidatorId {
        self.0.validator_id()
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        self.0.signature_scheme()
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        self.0.sign_framed(framed)
    }
}

pub(super) fn routes<S, B, M, T, C, I>(
    enabled: bool,
) -> Router<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>
where
    S: IndexedOutboxRepository
        + DurablePortableRepository
        + StructuredOutboxExclusionGuard
        + Send
        + Sync
        + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    if !enabled {
        return Router::new();
    }
    Router::new()
        .route(
            FASTVOTE_PREPARE_PATH,
            post(submit_prepare::<S, B, M, T, C, I>)
                .layer(DefaultBodyLimit::max(MAX_SIGNED_PAID_INTENT_BYTES)),
        )
        .route(
            FASTVOTE_CERTIFICATES_PATH,
            post(submit_apply::<S, B, M, T, C, I>).layer(DefaultBodyLimit::max(
                node_wire::MAX_FASTVOTE_APPLY_REQUEST_BYTES,
            )),
        )
        .route(
            FASTVOTE_PUBLICATION_RETAIN_PATH,
            post(submit_publication_retain::<S, B, M, T, C, I>)
                .layer(DefaultBodyLimit::max(MAX_ENCODED_BUNDLE_BYTES)),
        )
        .route(
            FASTVOTE_PUBLICATION_SOURCE_PATH,
            post(submit_publication_source::<S, B, M, T, C, I>).layer(DefaultBodyLimit::max(
                node_wire::MAX_FASTVOTE_APPLY_REQUEST_BYTES,
            )),
        )
        .route(
            FASTVOTE_PUBLISHED_APPLY_PATH,
            post(submit_published_apply::<S, B, M, T, C, I>).layer(DefaultBodyLimit::max(
                node_wire::MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES,
            )),
        )
        .route(
            FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
            post(advance_frontier::<S, B, M, T, C, I>).layer(DefaultBodyLimit::max(1)),
        )
        .route(
            FASTVOTE_FROZEN_FRONTIER_PAGE_PATH,
            post(get_frontier_page::<S, B, M, T, C, I>).layer(DefaultBodyLimit::max(
                node_wire::MAX_FRONTIER_PAGE_REQUEST_BYTES,
            )),
        )
        .merge(drain::routes::<S, B, M, T, C, I>())
}

pub(super) fn frontier_error_response(error: &FrozenFrontierError) -> Response {
    match error {
        FrozenFrontierError::NotReady(_) => {
            error_response(StatusCode::CONFLICT, "frontier-not-ready")
        }
        FrozenFrontierError::InvalidCursor(_) => {
            error_response(StatusCode::BAD_REQUEST, "invalid-frontier-page-cursor")
        }
        FrozenFrontierError::Node(NodeCoreError::EpochMismatch { .. }) => {
            error_response(StatusCode::CONFLICT, "frontier-epoch-mismatch")
        }
        _ => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "frontier-verification-failed",
        ),
    }
}

/// Advances at most one verified retained publication after a committed
/// ordered Freeze. A retry after finalization returns the exact saved vote;
/// a failed or ambiguous store commit cannot expose a fresh signature.
async fn advance_frontier<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: IndexedOutboxRepository
        + DurablePortableRepository
        + StructuredOutboxExclusionGuard
        + Send
        + Sync
        + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    if !has_supported_content_type(&headers) || has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-fastvote-content",
        );
    }
    let body: Bytes = match body {
        Ok(value) => value,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if !body.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "frontier-advance-body-not-empty");
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let Some(fastvote) = state.preinstalled_wasm.fastvote.as_ref() else {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            };
            let expected = match execution::publication::PublicationContext::new(
                state.config.chain_id().clone(),
                state.config.protocol_version(),
                state.config.epoch(),
            ) {
                Ok(value) => value,
                Err(_) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "frontier-host-context",
                    );
                }
            };
            let (domain, context) = match prepare_storage_context(
                &state.components,
                &state.protocol_config,
                &state.authority,
                &state.config,
            ) {
                Ok(value) => value,
                Err(error) => return query_invocation_error_response(&error),
            };
            if state.components.is_cancelled() {
                return cancelled_before_storage_response();
            }
            match advance_frozen_frontier(
                state.components.store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &state.history,
                &expected,
                &DynConsensusSigner(fastvote.signer.as_ref()),
            ) {
                Ok(FrozenFrontierStep::Advanced { .. }) => StatusCode::NO_CONTENT.into_response(),
                Ok(FrozenFrontierStep::Finalized(vote)) => {
                    match consensus::encode_frozen_frontier_vote(&vote) {
                        Ok(bytes) => (
                            StatusCode::OK,
                            [
                                (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
                                (header::CACHE_CONTROL, "no-store"),
                            ],
                            bytes,
                        )
                            .into_response(),
                        Err(_) => error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "frontier-vote-encoding",
                        ),
                    }
                }
                Err(error) => frontier_error_response(&error),
            }
        },
    )
    .await
}

/// Returns a page only from this replica's durably finalized, signed
/// frontier. Neither an HTTP 200 nor a single page proves the complete log.
async fn get_frontier_page<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: IndexedOutboxRepository
        + DurablePortableRepository
        + StructuredOutboxExclusionGuard
        + Send
        + Sync
        + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    if !has_supported_content_type(&headers) || has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-fastvote-content",
        );
    }
    let body: Bytes = match body {
        Ok(value) => value,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if body.len() > node_wire::MAX_FRONTIER_PAGE_REQUEST_BYTES {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "frontier-page-request-too-large",
        );
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let Some(fastvote) = state.preinstalled_wasm.fastvote.as_ref() else {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            };
            let request: node_wire::FrozenFrontierPageRequest =
                match node_wire::FrozenFrontierPageRequest::decode(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid-frontier-page-request",
                        );
                    }
                };
            if request.epoch != state.config.epoch() {
                return error_response(StatusCode::CONFLICT, "frontier-epoch-repin-required");
            }
            let expected = match execution::publication::PublicationContext::new(
                state.config.chain_id().clone(),
                state.config.protocol_version(),
                state.config.epoch(),
            ) {
                Ok(value) => value,
                Err(_) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "frontier-host-context",
                    );
                }
            };
            let (domain, context) = match prepare_storage_context(
                &state.components,
                &state.protocol_config,
                &state.authority,
                &state.config,
            ) {
                Ok(value) => value,
                Err(error) => return query_invocation_error_response(&error),
            };
            if state.components.is_cancelled() {
                return cancelled_before_storage_response();
            }
            let limit: NonZeroUsize = match NonZeroUsize::new(usize::from(request.limit)) {
                Some(value) => value,
                None => {
                    return error_response(StatusCode::BAD_REQUEST, "invalid-frontier-page-limit");
                }
            };
            let (vote, page) = match read_frozen_frontier_page(
                state.components.store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &state.history,
                &expected,
                fastvote.signer.validator_id(),
                request.after_request_id,
                limit,
            ) {
                Ok(value) => value,
                Err(error) => return frontier_error_response(&error),
            };
            let response = match (
                consensus::encode_frozen_frontier_vote(&vote),
                consensus::encode_frozen_frontier_page(&page),
            ) {
                (Ok(vote), Ok(page)) => node_wire::FrozenFrontierPageResponse { vote, page },
                _ => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "frontier-page-encoding",
                    );
                }
            };
            match response.encode() {
                Ok(bytes) => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response(),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "frontier-page-envelope-encoding",
                ),
            }
        },
    )
    .await
}

/// Returns only the canonical bundle already backed by this replica's
/// committed prepare-side witness and artifacts. The supplied certificate is
/// verified by the core; this handler never executes or applies the request.
async fn submit_publication_source<S, B, M, T, C, I>(
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
    if !has_supported_content_type(&headers) || has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-fastvote-content",
        );
    }
    let body: Bytes = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if body.len() > node_wire::MAX_FASTVOTE_APPLY_REQUEST_BYTES {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "fastvote-source-too-large");
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            if state.preinstalled_wasm.fastvote.is_none() {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            }
            let request: node_wire::FastVoteApplyRequest =
                match node_wire::FastVoteApplyRequest::decode(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid-fastvote-source-request",
                        );
                    }
                };
            let declared_context =
                match declared_paid_context(&state.config, &request.signed_paid_intent) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
            if let Err(error) = authenticate_paid_execution(
                &state.resolver,
                &declared_context,
                &request.signed_paid_intent,
            ) {
                return paid_execution::admission_error(&error);
            }
            if declared_context.epoch() != state.config.epoch() {
                return error_response(StatusCode::CONFLICT, "fastvote-epoch-repin-required");
            }
            let (domain, context) = match prepare_storage_context(
                &state.components,
                &state.protocol_config,
                &state.authority,
                &state.config,
            ) {
                Ok(value) => value,
                Err(error) => return query_invocation_error_response(&error),
            };
            if state.components.is_cancelled() {
                return cancelled_before_storage_response();
            }
            let bundle: consensus::bundle::PublicationBundle =
                match fast_path::publication::assemble_publication_bundle(
                    state.components.store.as_ref(),
                    &context,
                    domain,
                    &state.resolver,
                    &state.history,
                    &declared_context,
                    &request.signed_paid_intent,
                    &request.certificate,
                ) {
                    Ok(value) => value,
                    Err(error) => return publication_retention_error_response(&error),
                };
            match consensus::bundle::encode_publication_bundle(&bundle) {
                Ok(bytes) => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response(),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "fastvote-source-bundle-encoding",
                ),
            }
        },
    )
    .await
}

/// Accepts one canonical publication bundle only on the certified router.
/// Authentication precedes runtime identity, clock, storage and expensive
/// artifact verification; the core performs the same authentication again
/// before exposing its durably retained availability vote.
async fn submit_publication_retain<S, B, M, T, C, I>(
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
    if !has_supported_content_type(&headers) || has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-fastvote-content",
        );
    }
    let body: Bytes = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if body.len() > MAX_ENCODED_BUNDLE_BYTES {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "fastvote-bundle-too-large");
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let Some(fastvote) = state.preinstalled_wasm.fastvote.as_ref() else {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            };
            let bundle: consensus::bundle::PublicationBundle =
                match consensus::bundle::decode_publication_bundle(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid-fastvote-publication-bundle",
                        );
                    }
                };
            let declared_context =
                match declared_paid_context(&state.config, &bundle.signed_intent) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
            if let Err(error) = authenticate_paid_execution(
                &state.resolver,
                &declared_context,
                &bundle.signed_intent,
            ) {
                return paid_execution::admission_error(&error);
            }
            if declared_context.epoch() != state.config.epoch() {
                return error_response(StatusCode::CONFLICT, "fastvote-epoch-repin-required");
            }
            let (domain, context) = match prepare_storage_context(
                &state.components,
                &state.protocol_config,
                &state.authority,
                &state.config,
            ) {
                Ok(value) => value,
                Err(error) => return query_invocation_error_response(&error),
            };
            if state.components.is_cancelled() {
                return cancelled_before_storage_response();
            }
            let vote: consensus::AvailabilityVote = match fast_path::publication::retain_publication(
                state.components.store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &state.history,
                &declared_context,
                &body,
                &DynConsensusSigner(fastvote.signer.as_ref()),
            ) {
                Ok(value) => value,
                Err(error) => return publication_retention_error_response(&error),
            };
            match consensus::encode_availability_vote(&vote) {
                Ok(bytes) => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response(),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "fastvote-availability-vote-encoding",
                ),
            }
        },
    )
    .await
}

fn publication_retention_error_response(error: &PublicationRetentionError) -> Response {
    match error {
        PublicationRetentionError::Admission(error) => paid_execution::admission_error(error),
        PublicationRetentionError::Node(NodeCoreError::EpochMismatch { .. }) => {
            error_response(StatusCode::CONFLICT, "fastvote-epoch-repin-required")
        }
        PublicationRetentionError::Node(error) => node_error_response(error),
        PublicationRetentionError::ConflictingRetainedIdentity => {
            error_response(StatusCode::CONFLICT, "fastvote-publication-conflict")
        }
        PublicationRetentionError::ClosureTooLarge { .. } => error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "fastvote-publication-closure-too-large",
        ),
        PublicationRetentionError::InconsistentRetainedRecord(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "fastvote-retained-publication-inconsistent",
        ),
        _ => error_response(StatusCode::BAD_REQUEST, "fastvote-publication-rejected"),
    }
}

async fn submit_prepare<S, B, M, T, C, I>(
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
    if !has_supported_content_type(&headers) || has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-fastvote-content",
        );
    }
    let body: Bytes = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if body.len() > MAX_SIGNED_PAID_INTENT_BYTES {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "fastvote-prepare-too-large");
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let Some(fastvote) = state.preinstalled_wasm.fastvote.as_ref() else {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            };
            let declared_context = match declared_paid_context(&state.config, &body) {
                Ok(value) => value,
                Err(response) => return response,
            };
            // Authenticate the exact signed bytes against the caller's own
            // declared chain/protocol/epoch before any identity, clock, or
            // storage access. `fast_path::prepare` re-authenticates
            // internally (and only then reads storage), so this pre-check's
            // sole purpose is to reject a malformed, unsigned, or
            // wrong-context request before any of that work -- never to
            // replace prepare's own authentication or epoch fencing.
            if let Err(error) =
                authenticate_paid_execution(&state.resolver, &declared_context, &body)
            {
                return paid_execution::admission_error(&error);
            }
            // A cached prepared vote must not bypass this host's fixed pin.
            // Authenticate first, then reject before identity/clock/state I/O.
            if declared_context.epoch() != state.config.epoch() {
                return error_response(StatusCode::CONFLICT, "fastvote-epoch-repin-required");
            }
            let (domain, context) = match prepare_storage_context(
                &state.components,
                &state.protocol_config,
                &state.authority,
                &state.config,
            ) {
                Ok(value) => value,
                Err(error) => return query_invocation_error_response(&error),
            };
            if state.components.is_cancelled() {
                return cancelled_before_storage_response();
            }
            let vote = match fast_path::prepare(
                state.components.store.as_ref(),
                state.components.blob_store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &state.history,
                &declared_context,
                &fastvote.execution.base_policy,
                &fastvote.execution.fee_policy,
                &fastvote.execution.engine,
                &DynConsensusSigner(fastvote.signer.as_ref()),
                &body,
                fastvote.created_checkpoint,
            ) {
                Ok(value) => value,
                Err(error) => return fastpath_error_response(&error),
            };
            match consensus::encode_fast_vote(&vote) {
                Ok(bytes) => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response(),
                Err(_) => {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "fastvote-vote-encoding")
                }
            }
        },
    )
    .await
}

/// Structurally decodes `signed_bytes` (no cryptographic verification) to
/// build the [`execution::publication::PublicationContext`] the caller's
/// own signed intent declares, purely so authentication can proceed against
/// exactly that context before any identity/clock/storage access. Never
/// used as a trust decision on its own: [`authenticate_paid_execution`] (and
/// later `fast_path::prepare`/`apply` again, internally) still
/// cryptographically verifies the signature against this same context.
/// Mirrors the existing `clippy::result_large_err` precedent in
/// `node_core::fast_path`: this error variant legitimately carries a full
/// `Response`.
#[allow(clippy::result_large_err)]
fn declared_paid_context(
    config: &NodeConfig,
    signed_bytes: &[u8],
) -> Result<execution::publication::PublicationContext, Response> {
    let signed = decode_signed_paid_intent(signed_bytes)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, "invalid-fastvote-signed-intent"))?;
    execution::publication::PublicationContext::new(
        config.chain_id().clone(),
        config.protocol_version(),
        signed.intent.context.epoch(),
    )
    .map_err(|_| error_response(StatusCode::BAD_REQUEST, "invalid-fastvote-signed-intent"))
}

async fn submit_apply<S, B, M, T, C, I>(
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
    if !has_supported_content_type(&headers) || has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-fastvote-content",
        );
    }
    let body: Bytes = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if body.len() > node_wire::MAX_FASTVOTE_APPLY_REQUEST_BYTES {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "fastvote-apply-too-large");
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let Some(fastvote) = state.preinstalled_wasm.fastvote.as_ref() else {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            };
            let request: node_wire::FastVoteApplyRequest =
                match node_wire::FastVoteApplyRequest::decode(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid-fastvote-apply-request",
                        );
                    }
                };
            let declared_context =
                match declared_paid_context(&state.config, &request.signed_paid_intent) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
            // Same authenticate-before-identity/clock/storage ordering as
            // `submit_prepare`. `fast_path::apply` itself never calls
            // `node_core::paid_execution::reconcile_authenticated_paid_execution`
            // (which would reject a declared/current epoch mismatch *before*
            // an exact-receipt lookup): it reconciles the exact receipt
            // first, so a historical, already-applied request replays
            // correctly even after the epoch has since advanced.
            if let Err(error) = authenticate_paid_execution(
                &state.resolver,
                &declared_context,
                &request.signed_paid_intent,
            ) {
                return paid_execution::admission_error(&error);
            }
            let (domain, context) = match prepare_storage_context(
                &state.components,
                &state.protocol_config,
                &state.authority,
                &state.config,
            ) {
                Ok(value) => value,
                Err(error) => return query_invocation_error_response(&error),
            };
            if state.components.is_cancelled() {
                return cancelled_before_storage_response();
            }
            let output = match fast_path::apply_with_recovery(
                state.components.store.as_ref(),
                state.components.blob_store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &state.history,
                &declared_context,
                &fastvote.execution.base_policy,
                &fastvote.execution.fee_policy,
                &fastvote.execution.engine,
                &request.signed_paid_intent,
                &request.certificate,
                fastvote.created_checkpoint,
            ) {
                Ok(value) => value,
                Err(error) => return fastpath_error_response(&error),
            };
            let request_id = match decode_signed_paid_intent(&request.signed_paid_intent) {
                Ok(signed) => match RequestId::new(signed.intent.request_id) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "fastvote-apply-request-id-invalid",
                        );
                    }
                },
                Err(_) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid-fastvote-apply-request",
                    );
                }
            };
            match HttpNodeResult::new(request_id, output.responses().to_vec())
                .and_then(|result| result.encode())
            {
                Ok(bytes) => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response(),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "fastvote-apply-result-encoding",
                ),
            }
        },
    )
    .await
}

/// Publication-gated apply for a handoff-capable genesis. The core selects
/// the required availability proof from the signed, installed profile, not
/// this route: the historical route cannot downgrade a v2 operation.
async fn submit_published_apply<S, B, M, T, C, I>(
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
    if !has_supported_content_type(&headers) || has_unsupported_content_encoding(&headers) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-fastvote-content",
        );
    }
    let body: Bytes = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if body.len() > node_wire::MAX_FASTVOTE_PUBLISHED_APPLY_REQUEST_BYTES {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "fastvote-published-apply-too-large",
        );
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let Some(fastvote) = state.preinstalled_wasm.fastvote.as_ref() else {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            };
            let request: node_wire::FastVotePublishedApplyRequest =
                match node_wire::FastVotePublishedApplyRequest::decode(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid-fastvote-published-apply-request",
                        );
                    }
                };
            let declared_context =
                match declared_paid_context(&state.config, &request.signed_paid_intent) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
            // Keep the historical exact-replay path alive across an epoch
            // change: authenticate first, then let the core reconcile its
            // existing receipt before reading current policy or objects.
            if let Err(error) = authenticate_paid_execution(
                &state.resolver,
                &declared_context,
                &request.signed_paid_intent,
            ) {
                return paid_execution::admission_error(&error);
            }
            let (domain, context) = match prepare_storage_context(
                &state.components,
                &state.protocol_config,
                &state.authority,
                &state.config,
            ) {
                Ok(value) => value,
                Err(error) => return query_invocation_error_response(&error),
            };
            if state.components.is_cancelled() {
                return cancelled_before_storage_response();
            }
            let output: node_core::NodeOutput =
                match fast_path::apply_with_recovery_after_publication(
                    state.components.store.as_ref(),
                    state.components.blob_store.as_ref(),
                    &context,
                    domain,
                    &state.resolver,
                    &state.history,
                    &declared_context,
                    &fastvote.execution.base_policy,
                    &fastvote.execution.fee_policy,
                    &fastvote.execution.engine,
                    &request.signed_paid_intent,
                    &request.certificate,
                    fastvote.created_checkpoint,
                    &request.availability_certificate,
                ) {
                    Ok(value) => value,
                    Err(error) => return fastpath_error_response(&error),
                };
            let request_id: RequestId = match decode_signed_paid_intent(&request.signed_paid_intent)
                .ok()
                .and_then(|signed| RequestId::new(signed.intent.request_id).ok())
            {
                Some(value) => value,
                None => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "fastvote-published-apply-request-id-invalid",
                    );
                }
            };
            match HttpNodeResult::new(request_id, output.responses().to_vec())
                .and_then(|result| result.encode())
            {
                Ok(bytes) => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response(),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "fastvote-published-apply-result-encoding",
                ),
            }
        },
    )
    .await
}

fn fastpath_error_response(error: &FastPathError) -> Response {
    match error {
        FastPathError::Admission(error) => paid_execution::admission_error(error),
        FastPathError::Node(NodeCoreError::EpochMismatch { .. }) => {
            error_response(StatusCode::CONFLICT, "fastvote-epoch-repin-required")
        }
        FastPathError::Node(error) => node_error_response(error),
        FastPathError::Consensus(_) => {
            error_response(StatusCode::BAD_REQUEST, "fastvote-consensus-rejected")
        }
        FastPathError::Invalid(_) => error_response(StatusCode::BAD_REQUEST, "fastvote-rejected"),
        FastPathError::Publication(error) => publication_retention_error_response(error),
    }
}

/// A [`TransactionalNodeStateMachine`] that is never invoked: the certified
/// router this module builds never mounts `NODE_EVENT_PATH`, so neither
/// method here is reachable from any request. It exists only to satisfy
/// `PreinstalledWasmStructuredDurableNativeHttpState`'s generic `M` bound,
/// which every construction of that state type must supply regardless of
/// which routes actually get merged.
pub(super) struct DisabledNodeStateMachine;

impl TransactionalNodeStateMachine for DisabledNodeStateMachine {
    fn access_plan(
        &self,
        _event: &NodeEvent,
    ) -> Result<node_core::NodeStateAccessPlan, NodeCoreError> {
        Err(NodeCoreError::PersistenceInvariant(
            "certified-only FastVote hosting never processes SubmitTransaction",
        ))
    }

    fn transition(
        &self,
        _state: &node_core::NodeStateSnapshot,
        _event: &NodeEvent,
    ) -> Result<node_core::TransactionalNodeTransition, NodeCoreError> {
        Err(NodeCoreError::PersistenceInvariant(
            "certified-only FastVote hosting never processes SubmitTransaction",
        ))
    }
}

/// Builds the certified-only FastVote router (DR-0148) with the default
/// bounded blocking-admission policy.
#[allow(clippy::too_many_arguments)]
pub fn certified_fastvote_router<S, B, T, C, I>(
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    fastvote: FastVoteComposition,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    history: Vec<HashSuiteResolver>,
    blocking_policy: NativeBlockingPolicy,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository
        + DurablePortableRepository
        + StructuredOutboxExclusionGuard
        + Send
        + Sync
        + 'static,
    B: BlobStore + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    certified_fastvote_router_with_executor(
        components,
        fastvote,
        protocol_config,
        authority,
        config,
        resolver,
        history,
        NativeBlockingExecutor::new(blocking_policy),
    )
}

/// Builds the certified-only FastVote router (DR-0148) with shared blocking
/// admission.
///
/// This merges only [`liveness`], the four bounded structured-durable
/// queries, [`paid_execution::read_routes`] (the fee-policy query),
/// [`local_execution::read_routes`] (the instance query),
/// [`publication::read_routes`] (the code/publication query), and this
/// module's own [`routes`] (the FastVote endpoints). It never references
/// `paid_execution::mutation_routes`, `local_execution::mutation_routes`,
/// `publication::mutation_routes`, or `NODE_EVENT_PATH`: a direct/legacy
/// mutating route cannot reach this router's request path no matter how
/// `fastvote` or any other argument is configured.
#[allow(clippy::too_many_arguments)]
pub fn certified_fastvote_router_with_executor<S, B, T, C, I>(
    components: StructuredDurableNativeComponents<S, B, T, C, I>,
    fastvote: FastVoteComposition,
    protocol_config: ProtocolConfig,
    authority: StructuredDurableRequestAuthority,
    config: NodeConfig,
    resolver: HashSuiteResolver,
    history: Vec<HashSuiteResolver>,
    blocking_executor: NativeBlockingExecutor,
) -> Result<Router, StructuredDurableRouterError>
where
    S: IndexedOutboxRepository
        + DurablePortableRepository
        + StructuredOutboxExclusionGuard
        + Send
        + Sync
        + 'static,
    B: BlobStore + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    validate_structured_durable_router_authority(&protocol_config, &config)?;
    let expected_context = execution::publication::PublicationContext::new(
        config.chain_id().clone(),
        config.protocol_version(),
        config.epoch(),
    )
    .map_err(|_| StructuredDurableRouterError::FastVotePolicyContextMismatch)?;
    let base_digest = fastvote
        .execution
        .base_policy
        .digest(&resolver)
        .map_err(|_| StructuredDurableRouterError::FastVotePolicyContextMismatch)?;
    if fastvote.execution.base_policy.profile()
        != execution::GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION
        || fastvote.execution.base_policy.context() != &expected_context
        || fastvote.execution.fee_policy.context != expected_context
        || fastvote.execution.fee_policy.base_policy_digest != base_digest
    {
        return Err(StructuredDurableRouterError::FastVotePolicyContextMismatch);
    }
    let created_checkpoint: u64 = fastvote.created_checkpoint;
    let catalog: PreinstalledModuleCatalog = PreinstalledModuleCatalog::new(Vec::new())
        .map_err(|_| StructuredDurableRouterError::FastVotePolicyContextMismatch)?;
    let preinstalled_wasm: PreinstalledWasmComposition = PreinstalledWasmComposition::new(
        Arc::new(catalog),
        execution::WasmExecutionEngine,
        created_checkpoint,
    )
    .with_fastvote(fastvote);
    let state = Arc::new(PreinstalledWasmStructuredDurableNativeHttpState {
        components,
        preinstalled_wasm,
        protocol_config,
        authority,
        config,
        resolver,
        history,
        machine: Arc::new(DisabledNodeStateMachine),
        blocking_executor,
    });
    Ok(Router::new()
        .route(LIVENESS_PATH, get(liveness))
        .route(
            QUERY_CONTEXT_PATH,
            get(get_preinstalled_wasm_structured_durable_context::<
                S,
                B,
                DisabledNodeStateMachine,
                T,
                C,
                I,
            >),
        )
        .route(
            QUERY_OBJECT_PATH,
            get(get_preinstalled_wasm_structured_durable_object::<
                S,
                B,
                DisabledNodeStateMachine,
                T,
                C,
                I,
            >),
        )
        .route(
            QUERY_RECEIPT_PATH,
            get(get_preinstalled_wasm_structured_durable_receipt::<
                S,
                B,
                DisabledNodeStateMachine,
                T,
                C,
                I,
            >),
        )
        .route(
            QUERY_NEXT_NONCE_PATH,
            get(get_preinstalled_wasm_structured_durable_next_nonce::<
                S,
                B,
                DisabledNodeStateMachine,
                T,
                C,
                I,
            >),
        )
        .layer(DefaultBodyLimit::max(MAX_HTTP_EVENT_BODY_BYTES))
        .merge(paid_execution::read_routes::<
            S,
            B,
            DisabledNodeStateMachine,
            T,
            C,
            I,
        >(true))
        .merge(local_execution::read_routes::<
            S,
            B,
            DisabledNodeStateMachine,
            T,
            C,
            I,
        >(true))
        .merge(publication::read_routes::<
            S,
            B,
            DisabledNodeStateMachine,
            T,
            C,
            I,
        >(true))
        .merge(routes::<S, B, DisabledNodeStateMachine, T, C, I>(true))
        .with_state(state))
}
