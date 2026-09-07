//! Explicit local-development immutable publication routes.

use super::*;
use abi::package_types::PackageOrigin;
use execution::publication::{
    MAX_PUBLICATION_SUBMISSION_BYTES, decode_publication_submission, encode_publication_submission,
};

pub(super) const PUBLICATION_PATH: &str = "/v1/contracts/publications";
const QUERY_PATH: &str = "/v1/contracts/publications/{publisher}/{origin_seed}";

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
        .route(PUBLICATION_PATH, post(submit::<S, B, M, T, C, I>))
        .route(QUERY_PATH, get(query::<S, B, M, T, C, I>))
        .layer(DefaultBodyLimit::max(MAX_PUBLICATION_SUBMISSION_BYTES))
}

async fn admitted<F>(cancelled: bool, executor: NativeBlockingExecutor, work: F) -> Response
where
    F: FnOnce() -> Response + Send + 'static,
{
    if cancelled {
        return cancelled_before_storage_response();
    }
    let permit = match executor.try_acquire() {
        Ok(permit) => permit,
        Err(TryAcquireError::NoPermits) => return overload_response(),
        Err(TryAcquireError::Closed) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "blocking-admission-closed");
        }
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    {
        Ok(response) => response,
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "blocking-task-failed"),
    }
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
            "unsupported-publication-content",
        );
    }
    let body: Bytes = match body {
        Ok(body) => body,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            let submission = match decode_publication_submission(&body) {
                Ok(value) => value,
                Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-publication"),
            };
            let Some(policy) = state.preinstalled_wasm.publication.as_ref() else {
                return error_response(StatusCode::NOT_FOUND, "publication-disabled");
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
            let request_id: RequestId = match RequestId::new(*submission.request_id()) {
                Ok(value) => value,
                Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-request-id"),
            };
            let output = match node_core::publication::handle_local_publication(
                state.components.store.as_ref(),
                &context,
                domain,
                &state.resolver,
                policy,
                submission,
            ) {
                Ok(output) => output,
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
                    "publication-result-encoding",
                ),
            }
        },
    )
    .await
}

async fn query<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path((publisher, seed)): Path<(String, String)>,
) -> Response
where
    S: IndexedOutboxRepository + Send + Sync + 'static,
    B: BlobStore + Send + Sync + 'static,
    M: TransactionalNodeStateMachine + Send + Sync + 'static,
    T: Transport + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let (Some(publisher), Some(seed)) = (
        decode_hex64_selector(&publisher),
        decode_hex64_selector(&seed),
    ) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid-publication-selector");
    };
    let origin: PackageOrigin =
        match PackageOrigin::unverified(state.config.chain_id().clone(), publisher, seed) {
            Ok(origin) => origin,
            Err(_) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid-publication-selector");
            }
        };
    admitted(
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
            match node_core::publication::query_publication(
                state.components.store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &origin,
            ) {
                Ok(Some(submission)) => match encode_publication_submission(&submission) {
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
                        "publication-result-encoding",
                    ),
                },
                Ok(None) => error_response(StatusCode::NOT_FOUND, "publication-not-found"),
                Err(error) => match error {
                    node_core::publication::PublicationAdmissionError::Node(error) => {
                        query_invocation_error_response(&QueryInvocationError::Node(error))
                    }
                    _ => error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "publication-query-failed",
                    ),
                },
            }
        },
    )
    .await
}

fn admission_error(error: &node_core::publication::PublicationAdmissionError) -> Response {
    use node_core::publication::PublicationAdmissionError as E;
    match error {
        E::Node(error) => node_error_response(error),
        E::OriginExists => error_response(StatusCode::CONFLICT, "publication-origin-exists"),
        E::Publication(_) | E::Interface(_) | E::MissingDependency | E::Limit => {
            error_response(StatusCode::BAD_REQUEST, "publication-rejected")
        }
        E::PolicyMismatch | E::CorruptRecord | E::HistoricalContextUnavailable => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "publication-policy-or-state-invalid",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use node_core::publication::PublicationAdmissionError as E;

    #[test]
    fn publication_errors_keep_conflict_and_uncertain_storage_distinct() {
        assert_eq!(
            admission_error(&E::OriginExists).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            admission_error(&E::MissingDependency).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            admission_error(&E::CorruptRecord).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let error = E::Node(NodeCoreError::DurableCommitIndeterminate(
            IndeterminateCommitReason::ConnectionLost,
        ));
        assert_eq!(
            admission_error(&error).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
