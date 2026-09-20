//! Public paid Call/Instantiate/Publish HTTP surface (DR-0126).

use super::*;
use execution::paid_execution::{
    MAX_SIGNED_PAID_INTENT_BYTES, decode_signed_paid_intent, encode_paid_fee_policy,
};

pub const PAID_EXECUTION_PATH: &str = "/v1/contracts/paid-executions";
pub const PAID_FEE_POLICY_PATH: &str = "/v1/contracts/paid-fee-policy";

pub(super) fn routes<S, B, M, T, C, I>(
    enabled: bool,
) -> Router<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
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
        .route(PAID_EXECUTION_PATH, post(submit::<S, B, M, T, C, I>))
        .route(PAID_FEE_POLICY_PATH, get(query_policy::<S, B, M, T, C, I>))
        .layer(DefaultBodyLimit::max(MAX_SIGNED_PAID_INTENT_BYTES))
}

async fn submit<S, B, M, T, C, I>(
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
            "unsupported-paid-content",
        );
    }
    let body: Bytes = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let signed = match decode_signed_paid_intent(&body) {
                Ok(signed) => signed,
                Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-paid-execution"),
            };
            let Some(paid) = state.preinstalled_wasm.paid_execution.as_ref() else {
                return error_response(StatusCode::NOT_FOUND, "paid-execution-disabled");
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
            let request_id: RequestId = match RequestId::new(signed.intent.request_id) {
                Ok(value) => value,
                Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-request-id"),
            };
            let output = match node_core::paid_execution::handle_paid_execution(
                state.components.store.as_ref(),
                state.components.blob_store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &state.history,
                &paid.fee_policy.context,
                &paid.base_policy,
                &paid.fee_policy,
                &paid.engine,
                &body,
                state.preinstalled_wasm.created_checkpoint,
            ) {
                Ok(value) => value,
                Err(error) => return admission_error(&error),
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
                    "paid-execution-result-encoding",
                ),
            }
        },
    )
    .await
}

async fn query_policy<S, B, M, T, C, I>(
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
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let Some(paid) = state.preinstalled_wasm.paid_execution.as_ref() else {
                return error_response(StatusCode::NOT_FOUND, "paid-execution-disabled");
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
            let key: Vec<u8> = match node_core::local_instance_state::paid_fee_policy_key(
                &paid.fee_policy.context,
            ) {
                Ok(value) => value,
                Err(error) => return node_error_response(&error),
            };
            let expected: Vec<u8> = match encode_paid_fee_policy(&paid.fee_policy) {
                Ok(value) => value,
                Err(_) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "paid-fee-policy-invalid",
                    );
                }
            };
            match state
                .components
                .store
                .get_versioned_durable(&context, domain, &key)
            {
                Ok(observed) if observed.value() == Some(expected.as_slice()) => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, QUERY_RESULT_MEDIA_TYPE),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    expected,
                )
                    .into_response(),
                Ok(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "paid-fee-policy-not-installed",
                ),
                Err(error) => query_invocation_error_response(&QueryInvocationError::Node(
                    NodeCoreError::from(error),
                )),
            }
        },
    )
    .await
}

fn admission_error(error: &node_core::paid_execution::PaidExecutionAdmissionError) -> Response {
    use node_core::paid_execution::PaidExecutionAdmissionError as E;
    match error {
        E::Node(error) => node_error_response(error),
        E::Publication(error) => publication::admission_error(error),
        E::Execution(_) | E::Paid(_) | E::Invalid(_) => {
            error_response(StatusCode::BAD_REQUEST, "paid-execution-rejected")
        }
    }
}
