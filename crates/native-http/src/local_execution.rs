//! Explicit local instance routes sharing bounded/fenced native admission.
use super::*;
use execution::local_execution::{
    MAX_LOCAL_EXECUTION_INTENT_BYTES, decode_signed_local_execution, encode_instance_record,
};

pub(super) const EXECUTION_PATH: &str = "/v1/contracts/executions";
const INSTANCE_PATH: &str = "/v1/contracts/instances/{creator}/{seed}";

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
        .route(EXECUTION_PATH, post(submit::<S, B, M, T, C, I>))
        .route(INSTANCE_PATH, get(query::<S, B, M, T, C, I>))
        .layer(DefaultBodyLimit::max(MAX_LOCAL_EXECUTION_INTENT_BYTES))
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
            "unsupported-execution-content",
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
            let signed = match decode_signed_local_execution(&body) {
                Ok(signed) => signed,
                Err(_) => {
                    return error_response(StatusCode::BAD_REQUEST, "invalid-local-execution");
                }
            };
            let Some(local) = state.preinstalled_wasm.local_execution.as_ref() else {
                return error_response(StatusCode::NOT_FOUND, "local-execution-disabled");
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
            let id: RequestId = match RequestId::new(signed.intent.call.request_id) {
                Ok(id) => id,
                Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-request-id"),
            };
            let output = match node_core::local_execution::handle_local_execution(
                state.components.store.as_ref(),
                state.components.blob_store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &[],
                &local.policy,
                &local.engine,
                &body,
                state.preinstalled_wasm.created_checkpoint,
            ) {
                Ok(output) => output,
                Err(error) => return admission_error(&error),
            };
            match HttpNodeResult::new(id, output.responses().to_vec())
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
                    "local-execution-result-encoding",
                ),
            }
        },
    )
    .await
}

async fn query<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path((creator, seed)): Path<(String, String)>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let (Some(creator), Some(seed)) = (
        decode_hex64_selector(&creator),
        decode_hex64_selector(&seed),
    ) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid-instance-selector");
    };
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
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
            match node_core::local_execution::query_local_instance(
                state.components.store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &[],
                state.config.chain_id(),
                creator,
                seed,
            ) {
                Ok(Some(record)) => match encode_instance_record(&record) {
                    Ok(bytes) => (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, QUERY_RESULT_MEDIA_TYPE),
                            (header::CACHE_CONTROL, "no-store"),
                        ],
                        bytes,
                    )
                        .into_response(),
                    Err(_) => error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "instance-result-encoding",
                    ),
                },
                Ok(None) => error_response(StatusCode::NOT_FOUND, "instance-not-found"),
                Err(node_core::local_execution::LocalExecutionAdmissionError::Node(error)) => {
                    query_invocation_error_response(&QueryInvocationError::Node(error))
                }
                Err(_) => {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "instance-query-failed")
                }
            }
        },
    )
    .await
}

fn admission_error(error: &node_core::local_execution::LocalExecutionAdmissionError) -> Response {
    use node_core::local_execution::LocalExecutionAdmissionError as E;
    match error {
        E::Node(error) => node_error_response(error),
        E::Publication(error) => publication::admission_error(error),
        E::Invalid("instance already reserved") => {
            error_response(StatusCode::CONFLICT, "instance-already-reserved")
        }
        E::Invalid("execution policy absent or different") => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "local-execution-policy-invalid",
        ),
        E::Execution(_) | E::Invalid(_) => {
            error_response(StatusCode::BAD_REQUEST, "local-execution-rejected")
        }
    }
}
