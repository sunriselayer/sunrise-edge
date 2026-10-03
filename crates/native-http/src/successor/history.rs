//! Successor-scoped read-only DR-0169 ordered history source for verified
//! peer catch-up. Each request resolves a fresh warrant, builds the e+1
//! successor policy from it and reads only through the owning core history
//! readers under that policy key scope. Transport locators never select
//! domain, genesis, epoch or membership authority; an identity for another
//! epoch or anchor is refused, never served from another scope. Nothing is
//! signed or written.

use super::*;
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

pub(super) fn routes<S: SuccessorStore>() -> Router<SharedSuccessorHost<S>> {
    Router::new()
        .route(
            ORDERED_HISTORY_SUMMARY_PATH,
            get(summary::<S>).layer(DefaultBodyLimit::max(1)),
        )
        .route(
            ORDERED_HISTORY_HEIGHT_PATH,
            post(height::<S>).layer(DefaultBodyLimit::max(MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES)),
        )
        .route(
            ORDERED_HISTORY_COMPONENT_PATH,
            post(component::<S>)
                .layer(DefaultBodyLimit::max(MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES)),
        )
}

fn unavailable() -> Response {
    error_response(StatusCode::SERVICE_UNAVAILABLE, "ordered-history-unavailable")
}

fn canonical(bytes: Result<Vec<u8>, impl Sized>) -> Response {
    match bytes {
        Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "ordered-history-encoding"),
    }
}

fn preflight(headers: &HeaderMap, body: &Bytes, maximum: usize) -> Option<Response> {
    if !has_supported_content_type(headers) || has_unsupported_content_encoding(headers) {
        return Some(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-ordered-history-content",
        ));
    }
    if body.len() > maximum {
        return Some(error_response(StatusCode::PAYLOAD_TOO_LARGE, "ordered-history-body-too-large"));
    }
    None
}

/// Pure scope check under the fresh successor policy: the identity must be
/// the e+1 epoch and a valid identity for exactly this policy.
#[allow(clippy::result_large_err)]
fn require_scoped_identity(
    policy: &OrderedEconomicsPolicy,
    identity: &OrderedHistoryIdentity,
) -> Result<(), Response> {
    if policy.minimum_freeze_block_height() == 0 {
        return Err(unavailable());
    }
    if identity.context.epoch() != policy.context().epoch() {
        return Err(error_response(StatusCode::CONFLICT, "ordered-history-epoch-repin-required"));
    }
    if OrderedHistoryVerifier::new(policy.clone(), identity.clone()).is_err() {
        return Err(error_response(StatusCode::BAD_REQUEST, "invalid-ordered-history-identity"));
    }
    Ok(())
}

async fn summary<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if has_unsupported_content_encoding(&headers) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported-ordered-history-content");
    }
    if !body.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "ordered-history-summary-body-not-empty");
    }
    blocking(host, |host: &SuccessorHostComposition<S>| {
        serve(host, |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
            let scope: OrderedScope = match OrderedScope::from_warrant(host, warrant) {
                Ok(value) => value,
                Err(response) => return response,
            };
            if scope.policy.minimum_freeze_block_height() == 0 {
                return unavailable();
            }
            let env: OrderedEconomicsEnvironment<'_> = scope.env(host);
            let value: OrderedHistorySummary =
                match query_ordered_history_summary(host.store.as_ref(), context, &env) {
                    Ok(value) => value,
                    Err(_) => return unavailable(),
                };
            canonical(encode_ordered_history_summary(&value))
        })
    })
    .await
}

async fn height<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = preflight(&headers, &body, MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES) {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let Ok(request) = OrderedHistoryHeightRequest::decode(&body) else {
            return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-history-height");
        };
        serve(host, |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
            let scope: OrderedScope = match OrderedScope::from_warrant(host, warrant) {
                Ok(value) => value,
                Err(response) => return response,
            };
            if let Err(response) = require_scoped_identity(&scope.policy, &request.identity) {
                return response;
            }
            let env: OrderedEconomicsEnvironment<'_> = scope.env(host);
            match read_ordered_history_height_descriptor(
                host.store.as_ref(),
                context,
                &env,
                &request.identity,
                request.height,
            ) {
                Ok(descriptor) => canonical(encode_ordered_history_height_descriptor(&descriptor)),
                Err(_) => unavailable(),
            }
        })
    })
    .await
}

async fn component<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(response) = preflight(&headers, &body, MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES)
    {
        return response;
    }
    blocking(host, move |host: &SuccessorHostComposition<S>| {
        let Ok(request) = OrderedHistoryComponentRequest::decode(&body) else {
            return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-history-component");
        };
        serve(host, |warrant: &LiveWarrant<'_>, context: &DurableOperationContext| {
            let scope: OrderedScope = match OrderedScope::from_warrant(host, warrant) {
                Ok(value) => value,
                Err(response) => return response,
            };
            if let Err(response) = require_scoped_identity(&scope.policy, &request.identity) {
                return response;
            }
            let env: OrderedEconomicsEnvironment<'_> = scope.env(host);
            let descriptor: OrderedHistoryHeightDescriptor =
                match read_ordered_history_height_descriptor(
                    host.store.as_ref(),
                    context,
                    &env,
                    &request.identity,
                    request.height,
                ) {
                    Ok(value) => value,
                    Err(_) => return unavailable(),
                };
            if ordered_history_descriptor_digest(&scope.policy, &descriptor).ok()
                != Some(request.descriptor_digest)
            {
                return error_response(StatusCode::CONFLICT, "ordered-history-descriptor-changed");
            }
            let Some(reference) = descriptor
                .components
                .iter()
                .find(|reference| reference.kind == request.kind)
            else {
                return error_response(StatusCode::BAD_REQUEST, "ordered-history-component-not-present");
            };
            if request.offset >= reference.length {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "ordered-history-offset-outside-component",
                );
            }
            let chunk_bytes: Vec<u8> = match read_ordered_history_component_chunk(
                host.store.as_ref(),
                context,
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
            canonical(
                OrderedHistoryChunkResponse {
                    offset: request.offset,
                    total_length: reference.length,
                    chunk_bytes,
                }
                .encode(),
            )
        })
    })
    .await
}
