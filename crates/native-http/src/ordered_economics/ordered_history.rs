//! Read-only fixed-target DR-0169 history source. Transport locators never
//! select domain, genesis or membership authority. Every store call receives
//! the host's fresh writer-fenced context and runs under shared admission.

use super::*;
use axum::extract::rejection::BytesRejection;
use node_core::ordered_economics::{
    OrderedHistoryHeightDescriptor, OrderedHistoryIdentity, OrderedHistorySummary,
    OrderedHistoryVerifier, encode_ordered_history_height_descriptor,
    encode_ordered_history_summary, ordered_history_descriptor_digest,
    query_ordered_history_summary, read_ordered_history_component_chunk,
    read_ordered_history_height_descriptor,
};
use node_wire::ordered_history::{
    MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES, MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES,
    ORDERED_HISTORY_COMPONENT_PATH, ORDERED_HISTORY_HEIGHT_PATH, ORDERED_HISTORY_SUMMARY_PATH,
    OrderedHistoryChunkResponse, OrderedHistoryComponentRequest, OrderedHistoryHeightRequest,
};
use node_wire::{NODE_EVENT_MEDIA_TYPE, NODE_RESULT_MEDIA_TYPE};

pub(super) fn routes<S, C, I, Sig>() -> Router<SharedOrderedEconomicsState<S, C, I, Sig>>
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    Router::new()
        .route(
            ORDERED_HISTORY_SUMMARY_PATH,
            get(summary::<S, C, I, Sig>).layer(DefaultBodyLimit::max(1)),
        )
        .route(
            ORDERED_HISTORY_HEIGHT_PATH,
            post(height::<S, C, I, Sig>).layer(DefaultBodyLimit::max(
                MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES,
            )),
        )
        .route(
            ORDERED_HISTORY_COMPONENT_PATH,
            post(component::<S, C, I, Sig>).layer(DefaultBodyLimit::max(
                MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES,
            )),
        )
}

fn unavailable() -> Response {
    // Even pure failure of archived candidate authentication is a source
    // refusal, never an ordinary business rejection or synthesized receipt.
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "ordered-history-unavailable",
    )
}

fn canonical_response(bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, NODE_RESULT_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    )
        .into_response()
}

#[allow(clippy::result_large_err)]
fn require_host_profile<S, C, I, Sig>(
    state: &OrderedEconomicsState<S, C, I, Sig>,
) -> Result<(), Response> {
    if state.domain != state.policy.domain()
        || state.policy.minimum_freeze_block_height() == 0
        || u64::try_from(state.operation_timeout.as_millis()).is_err()
    {
        return Err(unavailable());
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn require_pinned_identity<S, C, I, Sig>(
    state: &OrderedEconomicsState<S, C, I, Sig>,
    identity: &OrderedHistoryIdentity,
) -> Result<(), Response> {
    require_host_profile(state)?;
    if identity.context.epoch() != state.policy.context().epoch() {
        return Err(error_response(
            StatusCode::CONFLICT,
            "ordered-history-epoch-repin-required",
        ));
    }
    // Constructor is pure: validates the entire signed-genesis identity and
    // target shape before identity allocation, trusted clock or storage I/O.
    if OrderedHistoryVerifier::new(state.policy.clone(), identity.clone()).is_err() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid-ordered-history-identity",
        ));
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn post_body(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
    max_bytes: usize,
) -> Result<Bytes, Response> {
    if !has_media_type(headers, NODE_EVENT_MEDIA_TYPE)
        || crate::has_unsupported_content_encoding(headers)
    {
        return Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-ordered-history-content",
        ));
    }
    let body: Bytes = body.map_err(|error| error_response(error.status(), "body-rejected"))?;
    if body.len() > max_bytes {
        return Err(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "ordered-history-body-too-large",
        ));
    }
    Ok(body)
}

async fn summary<S, C, I, Sig>(
    State(state): State<SharedOrderedEconomicsState<S, C, I, Sig>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
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
            "unsupported-ordered-history-content",
        );
    }
    let body: Bytes = match body {
        Ok(value) => value,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if !body.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "ordered-history-summary-body-not-empty",
        );
    }
    publication::admitted(
        state.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            if let Err(response) = require_host_profile(&state) {
                return response;
            }
            let context: DurableOperationContext = match build_context(&state) {
                Ok(value) => value,
                Err(response) => return response,
            };
            if state.is_cancelled() {
                return crate::cancelled_before_storage_response();
            }
            let env: OrderedEconomicsEnvironment<'_> = environment(&state);
            let value: OrderedHistorySummary =
                match query_ordered_history_summary(state.store.as_ref(), &context, &env) {
                    Ok(value) => value,
                    Err(_) => return unavailable(),
                };
            match encode_ordered_history_summary(&value) {
                Ok(bytes) => canonical_response(bytes),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ordered-history-encoding",
                ),
            }
        },
    )
    .await
}

fn environment<S, C, I, Sig>(
    state: &OrderedEconomicsState<S, C, I, Sig>,
) -> OrderedEconomicsEnvironment<'_> {
    OrderedEconomicsEnvironment {
        policy: &state.policy,
        resolver: state.policy.resolver(),
        history: &state.history,
        leg_policy: &state.leg_policy,
        engine: state.engine.as_ref(),
        blobs: state.blobs.as_ref(),
    }
}

async fn height<S, C, I, Sig>(
    State(state): State<SharedOrderedEconomicsState<S, C, I, Sig>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    let body: Bytes = match post_body(&headers, body, MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES) {
        Ok(value) => value,
        Err(response) => return response,
    };
    publication::admitted(
        state.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let request: OrderedHistoryHeightRequest =
                match OrderedHistoryHeightRequest::decode(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid-ordered-history-height",
                        );
                    }
                };
            if let Err(response) = require_pinned_identity(&state, &request.identity) {
                return response;
            }
            let context: DurableOperationContext = match build_context(&state) {
                Ok(value) => value,
                Err(response) => return response,
            };
            if state.is_cancelled() {
                return crate::cancelled_before_storage_response();
            }
            let env: OrderedEconomicsEnvironment<'_> = environment(&state);
            let descriptor: OrderedHistoryHeightDescriptor =
                match read_ordered_history_height_descriptor(
                    state.store.as_ref(),
                    &context,
                    &env,
                    &request.identity,
                    request.height,
                ) {
                    Ok(value) => value,
                    Err(_) => return unavailable(),
                };
            match encode_ordered_history_height_descriptor(&descriptor) {
                Ok(bytes) => canonical_response(bytes),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ordered-history-encoding",
                ),
            }
        },
    )
    .await
}

async fn component<S, C, I, Sig>(
    State(state): State<SharedOrderedEconomicsState<S, C, I, Sig>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
    Sig: ConsensusSigner + Send + Sync + 'static,
{
    let body: Bytes = match post_body(&headers, body, MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES) {
        Ok(value) => value,
        Err(response) => return response,
    };
    publication::admitted(
        state.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let request: OrderedHistoryComponentRequest =
                match OrderedHistoryComponentRequest::decode(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid-ordered-history-component",
                        );
                    }
                };
            if let Err(response) = require_pinned_identity(&state, &request.identity) {
                return response;
            }
            let context: DurableOperationContext = match build_context(&state) {
                Ok(value) => value,
                Err(response) => return response,
            };
            if state.is_cancelled() {
                return crate::cancelled_before_storage_response();
            }
            let env: OrderedEconomicsEnvironment<'_> = environment(&state);
            let descriptor: OrderedHistoryHeightDescriptor =
                match read_ordered_history_height_descriptor(
                    state.store.as_ref(),
                    &context,
                    &env,
                    &request.identity,
                    request.height,
                ) {
                    Ok(value) => value,
                    Err(_) => return unavailable(),
                };
            if ordered_history_descriptor_digest(&state.policy, &descriptor).ok()
                != Some(request.descriptor_digest)
            {
                return error_response(StatusCode::CONFLICT, "ordered-history-descriptor-changed");
            }
            let Some(reference) = descriptor
                .components
                .iter()
                .find(|reference| reference.kind == request.kind)
            else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "ordered-history-component-not-present",
                );
            };
            if request.offset >= reference.length {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "ordered-history-offset-outside-component",
                );
            }
            if state.is_cancelled() {
                return crate::cancelled_before_storage_response();
            }
            let bytes: Vec<u8> = match read_ordered_history_component_chunk(
                state.store.as_ref(),
                &context,
                &env,
                &request.identity,
                request.height,
                request.descriptor_digest,
                request.kind,
                request.offset,
                request.limit,
            ) {
                Ok(value) => value,
                Err(_) => return unavailable(),
            };
            let response: OrderedHistoryChunkResponse = OrderedHistoryChunkResponse {
                offset: request.offset,
                total_length: reference.length,
                chunk_bytes: bytes,
            };
            match response.encode() {
                Ok(bytes) => canonical_response(bytes),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ordered-history-encoding",
                ),
            }
        },
    )
    .await
}
