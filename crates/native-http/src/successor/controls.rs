//! Existing frontier and drain frames over fresh successor warrants. Every
//! control enters the same core owner as the original route; decoding and
//! transport bounds precede identity, clock and artifact access.

use super::*;
use axum::extract::rejection::BytesRejection;
use node_core::ordered_economics::{
    DrainSignerError, DrainSignerProgress, DrainUnionStep, FrozenFrontierStep,
    advance_drain_union_successor, advance_frozen_frontier_successor,
    confirm_drain_signer_entry_successor, import_staged_drain_publication_successor,
    ingest_drain_signer_page_successor, read_drain_signer_progress_successor,
    read_frozen_frontier_page_successor,
};
use protocol_types::ValidatorId;
use std::num::NonZeroUsize;

pub(super) fn routes<S: SuccessorStore>() -> Router<SharedSuccessorHost<S>> {
    Router::new()
        .route(
            FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
            post(advance_frontier::<S>).layer(DefaultBodyLimit::max(1)),
        )
        .route(
            FASTVOTE_FROZEN_FRONTIER_PAGE_PATH,
            post(frontier_page::<S>).layer(DefaultBodyLimit::max(
                node_wire::MAX_FRONTIER_PAGE_REQUEST_BYTES,
            )),
        )
        .route(
            node_wire::FASTVOTE_DRAIN_SIGNER_PAGE_PATH,
            post(ingest_page::<S>).layer(DefaultBodyLimit::max(
                node_wire::MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES,
            )),
        )
        .route(
            node_wire::FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH,
            post(confirm_member::<S>).layer(DefaultBodyLimit::max(
                node_wire::MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES,
            )),
        )
        .route(
            node_wire::FASTVOTE_DRAIN_IMPORT_PATH,
            post(import_publication::<S>).layer(DefaultBodyLimit::max(
                consensus::bundle::MAX_ENCODED_BUNDLE_BYTES,
            )),
        )
        .route(
            node_wire::FASTVOTE_DRAIN_UNION_ADVANCE_PATH,
            post(advance_union::<S>).layer(DefaultBodyLimit::max(
                node_wire::MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES,
            )),
        )
        .route(
            node_wire::FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH,
            post(retained_source::<S>).layer(DefaultBodyLimit::max(
                node_wire::MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES,
            )),
        )
        .route(
            node_wire::FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH,
            post(signer_progress::<S>).layer(DefaultBodyLimit::max(
                node_wire::MAX_DRAIN_SIGNER_PROGRESS_REQUEST_BYTES,
            )),
        )
        .route(
            node_wire::FASTVOTE_DRAIN_APPLY_PATH,
            post(apply_member::<S>).layer(DefaultBodyLimit::max(
                node_wire::MAX_DRAIN_MEMBER_APPLY_REQUEST_BYTES,
            )),
        )
}

#[allow(clippy::result_large_err)]
fn control_body(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
    maximum: usize,
) -> Result<Bytes, Response> {
    if !has_supported_content_type(headers) || has_unsupported_content_encoding(headers) {
        return Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-fastvote-content",
        ));
    }
    let body: Bytes = body.map_err(|error| error_response(error.status(), "body-rejected"))?;
    if body.len() > maximum {
        return Err(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "fastvote-control-too-large",
        ));
    }
    Ok(body)
}

fn wrong_epoch() -> Response {
    error_response(StatusCode::CONFLICT, "drain-epoch-repin-required")
}

async fn advance_frontier<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: Bytes = match control_body(&headers, body, 1) {
        Ok(body) => body,
        Err(response) => return response,
    };
    if !body.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "frontier-advance-body-not-empty");
    }
    blocking(host, |host| {
        serve(
            host,
            |warrant, context| match advance_frozen_frontier_successor(
                warrant,
                host.store.as_ref(),
                context,
                warrant.policy_inputs().domain(),
                &host.resolver,
                &host.history,
                warrant.policy_inputs().context(),
                &signer(host),
            ) {
                Ok(FrozenFrontierStep::Advanced { .. }) => StatusCode::NO_CONTENT.into_response(),
                Ok(FrozenFrontierStep::Finalized(vote)) => {
                    match consensus::encode_frozen_frontier_vote(&vote) {
                        Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                        Err(_) => error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "frontier-vote-encoding",
                        ),
                    }
                }
                Err(error) => fastvote::frontier_error_response(&error),
            },
        )
    })
    .await
}

async fn frontier_page<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: Bytes = match control_body(&headers, body, node_wire::MAX_FRONTIER_PAGE_REQUEST_BYTES)
    {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: node_wire::FrozenFrontierPageRequest =
        match node_wire::FrozenFrontierPageRequest::decode(&body) {
            Ok(request) => request,
            Err(_) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid-frontier-page-request");
            }
        };
    let limit: NonZeroUsize = match NonZeroUsize::new(usize::from(request.limit)) {
        Some(limit) => limit,
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-frontier-page-limit"),
    };
    blocking(host, move |host| {
        serve(host, |warrant, context| {
            if request.epoch != warrant.policy_inputs().context().epoch() {
                return wrong_epoch();
            }
            let (vote, page) = match read_frozen_frontier_page_successor(
                warrant,
                host.store.as_ref(),
                context,
                warrant.policy_inputs().domain(),
                &host.resolver,
                &host.history,
                warrant.policy_inputs().context(),
                host.signer.validator_id(),
                request.after_request_id,
                limit,
            ) {
                Ok(material) => material,
                Err(error) => return fastvote::frontier_error_response(&error),
            };
            let response: node_wire::FrozenFrontierPageResponse = match (
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
                Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                Err(_) => {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "frontier-page-encoding")
                }
            }
        })
    })
    .await
}

async fn ingest_page<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: Bytes = match control_body(
        &headers,
        body,
        node_wire::MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES,
    ) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: node_wire::DrainSignerPageRequest =
        match node_wire::DrainSignerPageRequest::decode(&body) {
            Ok(request) => request,
            Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-page"),
        };
    let vote: consensus::FrozenFrontierVote =
        match consensus::decode_frozen_frontier_vote(&request.vote) {
            Ok(vote) => vote,
            Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-vote"),
        };
    let page: consensus::FrozenFrontierPage =
        match consensus::decode_frozen_frontier_page(&request.page) {
            Ok(page) => page,
            Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-page"),
        };
    blocking(host, move |host| {
        serve(host, |warrant, context| {
            if request.epoch != warrant.policy_inputs().context().epoch() {
                return wrong_epoch();
            }
            match ingest_drain_signer_page_successor(
                warrant,
                host.store.as_ref(),
                context,
                warrant.policy_inputs().domain(),
                &host.resolver,
                warrant.policy_inputs().context(),
                vote.validator,
                vote,
                page,
            ) {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => fastvote::drain::drain_error_response(&error),
            }
        })
    })
    .await
}

async fn confirm_member<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: Bytes = match control_body(
        &headers,
        body,
        node_wire::MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES,
    ) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: node_wire::DrainMemberConfirmRequest =
        match node_wire::DrainMemberConfirmRequest::decode(&body) {
            Ok(request) => request,
            Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-confirm"),
        };
    blocking(host, move |host| {
        serve(host, |warrant, context| {
            if request.epoch != warrant.policy_inputs().context().epoch() {
                return wrong_epoch();
            }
            match confirm_drain_signer_entry_successor(
                warrant,
                host.store.as_ref(),
                context,
                warrant.policy_inputs().domain(),
                &host.resolver,
                &host.history,
                warrant.policy_inputs().context(),
                request.validator,
                request.request_id,
            ) {
                Ok(_) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => fastvote::drain::drain_error_response(&error),
            }
        })
    })
    .await
}

async fn import_publication<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    Path(validator_hex): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: Bytes =
        match control_body(&headers, body, consensus::bundle::MAX_ENCODED_BUNDLE_BYTES) {
            Ok(body) => body,
            Err(response) => return response,
        };
    let validator: ValidatorId = match decode_hex64_selector(&validator_hex) {
        Some(bytes) => ValidatorId::new(bytes),
        None => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-validator"),
    };
    blocking(host, move |host| {
        let bundle: consensus::bundle::PublicationBundle =
            match consensus::bundle::decode_publication_bundle(&body) {
                Ok(bundle) => bundle,
                Err(_) => {
                    return error_response(StatusCode::BAD_REQUEST, "invalid-drain-import-bundle");
                }
            };
        let declared: PublicationContext =
            match authenticate_declared_intent(&host.resolver, &bundle.signed_intent) {
                Ok(context) => context,
                Err(response) => return response,
            };
        serve(host, |warrant, context| {
            if let Err(response) = require_warrant_context(&declared, warrant) {
                return response;
            }
            match import_staged_drain_publication_successor(
                warrant,
                host.store.as_ref(),
                context,
                warrant.policy_inputs().domain(),
                &host.resolver,
                &host.history,
                &declared,
                validator,
                &body,
            ) {
                Ok(identity) => match consensus::encode_availability_identity(&identity) {
                    Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                    Err(_) => {
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "drain-identity-encoding")
                    }
                },
                Err(error) => fastvote::drain::drain_error_response(&error),
            }
        })
    })
    .await
}

async fn advance_union<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: Bytes = match control_body(
        &headers,
        body,
        node_wire::MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES,
    ) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: node_wire::DrainUnionAdvanceRequest =
        match node_wire::DrainUnionAdvanceRequest::decode(&body) {
            Ok(request) => request,
            Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-union"),
        };
    blocking(host, move |host| {
        serve(host, |warrant, context| {
            if request.epoch != warrant.policy_inputs().context().epoch() {
                return wrong_epoch();
            }
            match advance_drain_union_successor(
                warrant,
                host.store.as_ref(),
                context,
                warrant.policy_inputs().domain(),
                &host.resolver,
                &host.history,
                warrant.policy_inputs().context(),
                &request.votes,
            ) {
                Ok(DrainUnionStep::Advanced { .. }) => StatusCode::NO_CONTENT.into_response(),
                Ok(DrainUnionStep::Ready(identity)) => {
                    match consensus::encode_drain_union_identity(&identity) {
                        Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                        Err(_) => error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "drain-union-encoding",
                        ),
                    }
                }
                Err(error) => fastvote::drain::drain_error_response(&error),
            }
        })
    })
    .await
}

async fn retained_source<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: Bytes = match control_body(
        &headers,
        body,
        node_wire::MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES,
    ) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: node_wire::RetainedPublicationSourceRequest =
        match node_wire::RetainedPublicationSourceRequest::decode(&body) {
            Ok(request) => request,
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid-fastvote-retained-source-request",
                );
            }
        };
    blocking(host, move |host| serve(host, |warrant, context| {
        if request.epoch != warrant.policy_inputs().context().epoch() { return wrong_epoch(); }
        let bundle: consensus::bundle::PublicationBundle = match node_core::fast_path::drain_publication::load_retained_publication_bundle_successor(
            warrant, host.store.as_ref(), context, warrant.policy_inputs().domain(), &host.resolver, &host.history,
            warrant.policy_inputs().context(), request.request_id,
        ) { Ok(bundle) => bundle, Err(error) => return publication_retention_error_response(&error) };
        match consensus::bundle::encode_publication_bundle(&bundle) {
            Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes), Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "fastvote-retained-source-bundle-encoding"),
        }
    })).await
}

async fn signer_progress<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: Bytes = match control_body(
        &headers,
        body,
        node_wire::MAX_DRAIN_SIGNER_PROGRESS_REQUEST_BYTES,
    ) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: node_wire::DrainSignerProgressRequest =
        match node_wire::DrainSignerProgressRequest::decode(&body) {
            Ok(request) => request,
            Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-progress"),
        };
    blocking(host, move |host| {
        serve(host, |warrant, context| {
            let expected: &PublicationContext = warrant.policy_inputs().context();
            if request.epoch != expected.epoch() {
                return wrong_epoch();
            }
            let progress: DrainSignerProgress = match read_drain_signer_progress_successor(
                warrant,
                host.store.as_ref(),
                context,
                warrant.policy_inputs().domain(),
                &host.resolver,
                expected,
                request.signer,
            ) {
                Ok(progress) => progress,
                Err(DrainSignerError::NotReady("no signer progress")) => {
                    return error_response(StatusCode::CONFLICT, "drain-progress-pristine");
                }
                Err(DrainSignerError::Invalid("signer not in outgoing set")) => {
                    return error_response(StatusCode::BAD_REQUEST, "drain-invalid");
                }
                Err(DrainSignerError::Invalid(_) | DrainSignerError::Frontier(_)) => {
                    return error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "drain-storage-unavailable",
                    );
                }
                Err(error) => return fastvote::drain::drain_error_response(&error),
            };
            let (vote, confirmed_identity): (Vec<u8>, Vec<u8>) = match (
                consensus::encode_frozen_frontier_vote(&progress.vote),
                consensus::encode_frozen_frontier_identity(&progress.confirmed_identity),
            ) {
                (Ok(vote), Ok(identity)) => (vote, identity),
                _ => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "drain-progress-encoding",
                    );
                }
            };
            let staged_page: Option<Vec<u8>> = match progress
                .staged_page
                .as_ref()
                .map(consensus::encode_frozen_frontier_page)
                .transpose()
            {
                Ok(page) => page,
                Err(_) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "drain-progress-page-encoding",
                    );
                }
            };
            let response: node_wire::DrainSignerProgressResponse =
                node_wire::DrainSignerProgressResponse {
                    chain_id: expected.chain_id().as_str().to_owned(),
                    epoch: expected.epoch(),
                    signer: progress.signer,
                    vote,
                    confirmed_identity,
                    cursor: progress.confirmed_last_request_id,
                    staged_page,
                    complete: progress.complete,
                };
            match response.encode() {
                Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                Err(_) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "drain-progress-envelope-encoding",
                ),
            }
        })
    })
    .await
}

async fn apply_member<S: SuccessorStore>(
    State(host): State<SharedSuccessorHost<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: Bytes = match control_body(
        &headers,
        body,
        node_wire::MAX_DRAIN_MEMBER_APPLY_REQUEST_BYTES,
    ) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: node_wire::DrainMemberApplyRequest =
        match node_wire::DrainMemberApplyRequest::decode(&body) {
            Ok(request) => request,
            Err(_) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid-drain-apply-request");
            }
        };
    let expected: PublicationContext = match PublicationContext::new(
        host.resolver.chain_id().clone(),
        host.resolver.protocol_version(),
        request.epoch,
    ) {
        Ok(context) => context,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-drain-apply-context"),
    };
    blocking(host, move |host| {
        serve(host, |warrant, context| {
            // The unchanged core handler authenticates retained signed bytes and
            // reconciles their exact receipt before checking fresh drain readiness.
            // A later current epoch must not hide that already committed result.
            let fee_policy: PaidFeePolicy = match successor_fee_policy(host, warrant, context) {
                Ok(policy) => policy,
                Err(response) => return response,
            };
            let base_policy: LocalExecutionPolicy = LocalExecutionPolicy::generic_object_results(
                warrant.policy_inputs().context().clone(),
            );
            let output: node_core::NodeOutput =
                match node_core::fast_path::drain_apply::apply_drain_member_successor(
                    warrant,
                    host.store.as_ref(),
                    host.blobs.as_ref(),
                    context,
                    warrant.policy_inputs().domain(),
                    &host.resolver,
                    &host.history,
                    &expected,
                    &base_policy,
                    &fee_policy,
                    host.engine.as_ref(),
                    request.member_request_id,
                    host.created_checkpoint,
                ) {
                    Ok(output) => output,
                    Err(node_core::fast_path::FastPathError::Invalid(_)) => {
                        return error_response(StatusCode::CONFLICT, "drain-member-not-ready");
                    }
                    Err(error) => return fastpath_error_response(&error),
                };
            node_result_response(RequestId::new(request.member_request_id).ok(), &output)
        })
    })
    .await
}
