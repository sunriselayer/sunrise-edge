//! Certified-only, bounded transport for local frozen-frontier drain progress.
//!
//! The HTTP caller chooses a schedule and supplies bytes, never authority.
//! Node-core fences the installed epoch/Freeze and re-verifies every vote,
//! page, complete publication and CAS read set. No handler signs, ACKs,
//! executes, or claims an ordered DrainSet decision.

use super::*;
use node_core::ordered_economics::{
    DrainSignerError, DrainUnionStep, advance_drain_union, confirm_drain_signer_entry,
    import_staged_drain_publication, ingest_drain_signer_page,
};

pub(super) fn routes<S, B, M, T, C, I>()
-> Router<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>
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
    Router::new()
        .route(
            node_wire::FASTVOTE_DRAIN_SIGNER_PAGE_PATH,
            post(ingest_signer_page::<S, B, M, T, C, I>).layer(DefaultBodyLimit::max(
                node_wire::MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES,
            )),
        )
        .route(
            node_wire::FASTVOTE_DRAIN_IMPORT_PATH,
            post(import_publication::<S, B, M, T, C, I>)
                .layer(DefaultBodyLimit::max(MAX_ENCODED_BUNDLE_BYTES)),
        )
        .route(
            node_wire::FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH,
            post(confirm_member::<S, B, M, T, C, I>).layer(DefaultBodyLimit::max(
                node_wire::MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES,
            )),
        )
        .route(
            node_wire::FASTVOTE_DRAIN_UNION_ADVANCE_PATH,
            post(advance_union::<S, B, M, T, C, I>).layer(DefaultBodyLimit::max(
                node_wire::MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES,
            )),
        )
}

/// The retry outcomes a caller must be able to tell apart:
/// [`PermanentlyInvalid`](Self::PermanentlyInvalid) never becomes success no
/// matter how many times it is retried unmodified (a forged/malformed vote,
/// tombstoned proof or artifact, or a profile/context mismatch);
/// [`NotReadyOrCas`](Self::NotReadyOrCas) is an ordinary local-state race a
/// caller should resync and retry (a stale expected identity, an
/// unconfirmed prerequisite, or an optimistic-concurrency conflict on an
/// exact CAS revision); [`StorageUnavailable`](Self::StorageUnavailable)
/// is a failed read or a definitely uncommitted backend failure;
/// [`StorageIndeterminate`](Self::StorageIndeterminate) means the commit
/// outcome is unknown. Both require an exact-byte retry or reconciliation,
/// never a modified replacement request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainErrorClass {
    PermanentlyInvalid,
    NotReadyOrCas,
    StorageUnavailable,
    StorageIndeterminate,
}

fn node_core_error_class(error: &NodeCoreError) -> DrainErrorClass {
    match error {
        NodeCoreError::DurableCommitIndeterminate(_) => DrainErrorClass::StorageIndeterminate,
        NodeCoreError::DurableRead(runtime::DurableReadError::WriterFenced { .. })
        | NodeCoreError::DurableCommitRejected(
            runtime::DurableCommitRejection::Conflict { .. }
            | runtime::DurableCommitRejection::ObjectConflict { .. }
            | runtime::DurableCommitRejection::RequestAlreadyCommitted
            | runtime::DurableCommitRejection::WriterFenced { .. }
            | runtime::DurableCommitRejection::SerializationFailure,
        )
        | NodeCoreError::StateConflict
        | NodeCoreError::EpochMismatch { .. } => DrainErrorClass::NotReadyOrCas,
        NodeCoreError::DurableRead(_)
        | NodeCoreError::DurableCommitRejected(_)
        | NodeCoreError::PersistenceInvariant(_) => DrainErrorClass::StorageUnavailable,
        NodeCoreError::ChainMismatch { .. } | NodeCoreError::ProtocolVersionMismatch { .. } => {
            DrainErrorClass::PermanentlyInvalid
        }
        // Other node-core errors can arise from already-persisted local data
        // or an invariant failure; do not blame a caller with a permanent
        // 4xx when storage or the deployment may need repair.
        _ => DrainErrorClass::StorageUnavailable,
    }
}

fn publication_error_class(error: &PublicationRetentionError) -> DrainErrorClass {
    match error {
        PublicationRetentionError::Node(inner) => node_core_error_class(inner),
        _ => DrainErrorClass::PermanentlyInvalid,
    }
}

fn drain_error_class(error: &DrainSignerError) -> DrainErrorClass {
    match error {
        DrainSignerError::NotReady(_) => DrainErrorClass::NotReadyOrCas,
        DrainSignerError::Invalid(_) => DrainErrorClass::PermanentlyInvalid,
        DrainSignerError::Node(inner) => node_core_error_class(inner),
        // `consensus::FrontierError` has no storage/indeterminate variant: it
        // is always a forged signature, mixed-Freeze vote, gap, reorder or
        // other permanently invalid page/vote.
        DrainSignerError::Frontier(_) => DrainErrorClass::PermanentlyInvalid,
        DrainSignerError::Publication(inner) => publication_error_class(inner),
    }
}

fn drain_error_response(error: &DrainSignerError) -> Response {
    if let DrainSignerError::Node(NodeCoreError::EpochMismatch { .. }) = error {
        return error_response(StatusCode::CONFLICT, "drain-epoch-repin-required");
    }
    match drain_error_class(error) {
        DrainErrorClass::PermanentlyInvalid => {
            error_response(StatusCode::BAD_REQUEST, "drain-invalid")
        }
        DrainErrorClass::NotReadyOrCas => error_response(StatusCode::CONFLICT, "drain-not-ready"),
        DrainErrorClass::StorageUnavailable => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "drain-storage-unavailable")
        }
        DrainErrorClass::StorageIndeterminate => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "drain-storage-indeterminate",
        ),
    }
}

fn expected_context(config: &NodeConfig) -> Option<execution::publication::PublicationContext> {
    execution::publication::PublicationContext::new(
        config.chain_id().clone(),
        config.protocol_version(),
        config.epoch(),
    )
    .ok()
}

async fn ingest_signer_page<S, B, M, T, C, I>(
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
        Ok(value) => value,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if body.len() > node_wire::MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "drain-page-too-large");
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            if state.preinstalled_wasm.fastvote.is_none() {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            }
            let request: node_wire::DrainSignerPageRequest =
                match node_wire::DrainSignerPageRequest::decode(&body) {
                    Ok(value) => value,
                    Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-page"),
                };
            if request.epoch != state.config.epoch() {
                return error_response(StatusCode::CONFLICT, "drain-epoch-repin-required");
            }
            let vote: consensus::FrozenFrontierVote =
                match consensus::decode_frozen_frontier_vote(&request.vote) {
                    Ok(value) => value,
                    Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-vote"),
                };
            let page: consensus::FrozenFrontierPage =
                match consensus::decode_frozen_frontier_page(&request.page) {
                    Ok(value) => value,
                    Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-page"),
                };
            let expected: execution::publication::PublicationContext =
                match expected_context(&state.config) {
                    Some(value) => value,
                    None => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "drain-host-context",
                        );
                    }
                };
            let (domain, context): (AtomicityDomainId, DurableOperationContext) =
                match prepare_storage_context(
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
            match ingest_drain_signer_page(
                state.components.store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &expected,
                vote.validator,
                vote,
                page,
            ) {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => drain_error_response(&error),
            }
        },
    )
    .await
}

async fn import_publication<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    Path(validator_hex): Path<String>,
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
    let validator_bytes: [u8; 32] = match decode_hex64_selector(&validator_hex) {
        Some(value) => value,
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-validator"),
    };
    let body: Bytes = match body {
        Ok(value) => value,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if body.len() > MAX_ENCODED_BUNDLE_BYTES {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "drain-bundle-too-large");
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            if state.preinstalled_wasm.fastvote.is_none() {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            }
            let bundle: consensus::bundle::PublicationBundle =
                match consensus::bundle::decode_publication_bundle(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(StatusCode::BAD_REQUEST, "invalid-drain-bundle");
                    }
                };
            let declared: execution::publication::PublicationContext =
                match declared_paid_context(&state.config, &bundle.signed_intent) {
                    Ok(value) => value,
                    Err(response) => return response,
                };
            if let Err(error) =
                authenticate_paid_execution(&state.resolver, &declared, &bundle.signed_intent)
            {
                return paid_execution::admission_error(&error);
            }
            if declared.epoch() != state.config.epoch() {
                return error_response(StatusCode::CONFLICT, "drain-epoch-repin-required");
            }
            let (domain, context): (AtomicityDomainId, DurableOperationContext) =
                match prepare_storage_context(
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
            match import_staged_drain_publication(
                state.components.store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &state.history,
                &declared,
                ValidatorId::new(validator_bytes),
                &body,
            ) {
                Ok(identity) => match consensus::encode_availability_identity(&identity) {
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
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "drain-identity-encoding")
                    }
                },
                Err(error) => drain_error_response(&error),
            }
        },
    )
    .await
}

async fn confirm_member<S, B, M, T, C, I>(
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
        Ok(value) => value,
        Err(error) => return error_response(error.status(), "body-rejected"),
    };
    if body.len() > node_wire::MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "drain-confirm-too-large");
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            if state.preinstalled_wasm.fastvote.is_none() {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            }
            let request: node_wire::DrainMemberConfirmRequest =
                match node_wire::DrainMemberConfirmRequest::decode(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(StatusCode::BAD_REQUEST, "invalid-drain-confirm");
                    }
                };
            if request.epoch != state.config.epoch() {
                return error_response(StatusCode::CONFLICT, "drain-epoch-repin-required");
            }
            let expected: execution::publication::PublicationContext =
                match expected_context(&state.config) {
                    Some(value) => value,
                    None => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "drain-host-context",
                        );
                    }
                };
            let (domain, context): (AtomicityDomainId, DurableOperationContext) =
                match prepare_storage_context(
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
            match confirm_drain_signer_entry(
                state.components.store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &state.history,
                &expected,
                request.validator,
                request.request_id,
            ) {
                Ok(_) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => drain_error_response(&error),
            }
        },
    )
    .await
}

async fn advance_union<S, B, M, T, C, I>(
    State(state): State<SharedPreinstalledWasmStructuredDurableNativeHttpState<S, B, M, T, C, I>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: IndexedOutboxRepository + DurablePortableRepository + Send + Sync + 'static,
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
    if body.len() > node_wire::MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "drain-union-too-large");
    }
    publication::admitted(
        state.components.is_cancelled(),
        state.blocking_executor.clone(),
        move || {
            if state.preinstalled_wasm.fastvote.is_none() {
                return error_response(StatusCode::NOT_FOUND, "fastvote-disabled");
            }
            let request: node_wire::DrainUnionAdvanceRequest =
                match node_wire::DrainUnionAdvanceRequest::decode(&body) {
                    Ok(value) => value,
                    Err(_) => {
                        return error_response(StatusCode::BAD_REQUEST, "invalid-drain-union");
                    }
                };
            if request.epoch != state.config.epoch() {
                return error_response(StatusCode::CONFLICT, "drain-epoch-repin-required");
            }
            let expected: execution::publication::PublicationContext =
                match expected_context(&state.config) {
                    Some(value) => value,
                    None => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "drain-host-context",
                        );
                    }
                };
            let (domain, context): (AtomicityDomainId, DurableOperationContext) =
                match prepare_storage_context(
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
            match advance_drain_union(
                state.components.store.as_ref(),
                &context,
                domain,
                &state.resolver,
                &state.history,
                &expected,
                &request.votes,
            ) {
                Ok(DrainUnionStep::Advanced { .. }) => StatusCode::NO_CONTENT.into_response(),
                Ok(DrainUnionStep::Ready(identity)) => {
                    match consensus::encode_drain_union_identity(&identity) {
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
                            "drain-union-encoding",
                        ),
                    }
                }
                Err(error) => drain_error_response(&error),
            }
        },
    )
    .await
}

#[cfg(test)]
mod error_taxonomy_tests {
    use super::*;
    use node_core::fast_path::publication::PublicationRetentionError;

    fn status_of(error: DrainSignerError) -> StatusCode {
        drain_error_response(&error).status()
    }

    /// A permanently invalid vote, page, proof or context can never become
    /// success by retrying the exact same bytes: it must surface as a 4xx,
    /// never the 503 a caller would otherwise read as "try again".
    #[test]
    fn permanently_invalid_errors_map_to_4xx() {
        assert_eq!(
            status_of(DrainSignerError::Invalid("bad")),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(DrainSignerError::Frontier(
                consensus::FrontierError::Invalid("bad frontier")
            )),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(DrainSignerError::Publication(Box::new(
                PublicationRetentionError::ForeignDomain
            ))),
            StatusCode::BAD_REQUEST
        );
    }

    /// A not-ready or optimistic-concurrency (CAS) condition is an ordinary
    /// local-state race: the caller should resync and retry, so it must
    /// surface as 409, distinct from both a permanent 4xx and a 503.
    #[test]
    fn not_ready_and_cas_errors_map_to_409() {
        assert_eq!(
            status_of(DrainSignerError::NotReady("not yet")),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status_of(DrainSignerError::Node(NodeCoreError::StateConflict)),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status_of(DrainSignerError::Node(
                NodeCoreError::DurableCommitRejected(runtime::DurableCommitRejection::Conflict {
                    key: vec![0x01],
                    current_revision: runtime::StateRevision::INITIAL,
                })
            )),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status_of(DrainSignerError::Node(NodeCoreError::EpochMismatch {
                expected: protocol_types::Epoch::new(1),
                actual: protocol_types::Epoch::new(2),
            })),
            StatusCode::CONFLICT
        );
    }

    /// Unknown commit outcomes surface as 503 for exact-byte reconciliation.
    #[test]
    fn storage_indeterminate_errors_map_to_503() {
        assert_eq!(
            status_of(DrainSignerError::Node(
                NodeCoreError::DurableCommitIndeterminate(
                    IndeterminateCommitReason::ConnectionLost
                )
            )),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_of(DrainSignerError::Publication(Box::new(
                PublicationRetentionError::Node(NodeCoreError::DurableCommitIndeterminate(
                    IndeterminateCommitReason::DeadlineExceeded
                ))
            ))),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn storage_read_and_definite_backend_failures_map_to_503() {
        assert_eq!(
            status_of(DrainSignerError::Node(NodeCoreError::DurableRead(
                runtime::DurableReadError::Unavailable
            ))),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_of(DrainSignerError::Node(
                NodeCoreError::DurableCommitRejected(
                    runtime::DurableCommitRejection::UnavailableBeforeCommit
                )
            )),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
