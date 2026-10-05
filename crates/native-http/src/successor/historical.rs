//! Material-only post-Seal history transport. This never creates a live
//! warrant or mounts a signing/commit/query-context route. The host freshly
//! verifies the complete predecessor chain and exact completed import on
//! every request; the existing history owners authenticate the material.

use super::*;
use node_core::ordered_economics::{
    OrderedHistoryComponentKind, OrderedHistoryHeightDescriptor, OrderedHistoryIdentity,
    OrderedHistorySummary, OrderedHistoryVerifier, OrderedOperationKind, decode_ordered_candidate,
    encode_ordered_history_height_descriptor, encode_ordered_history_summary,
    ordered_history_descriptor_digest, query_ordered_history_summary,
    read_ordered_history_component_chunk, read_ordered_history_height_descriptor,
};
use node_wire::ordered_history::{
    MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES, MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES,
    ORDERED_HISTORY_COMPONENT_PATH, ORDERED_HISTORY_HEIGHT_PATH, ORDERED_HISTORY_SUMMARY_PATH,
    OrderedHistoryChunkResponse, OrderedHistoryComponentRequest, OrderedHistoryHeightRequest,
};
use protocol_types::Digest32;
use runtime::SealBarrier;

/// Supplies only a fresh verified current policy for material consumption.
/// Implementations independently reverify every pinned predecessor link and
/// check the exact physical namespace, current member/epoch/domain and
/// completed import binding/progress. This is not serving authority.
pub trait SuccessorHistoricalPolicySource<S>: Send + Sync {
    /// No policy or verified chain is memoized across requests.
    fn ordered_policy(
        &self,
        store: &S,
        context: &DurableOperationContext,
    ) -> Result<OrderedEconomicsPolicy, ServingAuthorityError>;
}

/// Existing read dependencies, without a signer or mutation capability.
pub struct SuccessorHistoricalComposition<S> {
    pub store: Arc<S>,
    pub policy_source: Arc<dyn SuccessorHistoricalPolicySource<S>>,
    pub blobs: Arc<dyn BlobStore + Send + Sync>,
    pub clock: Arc<dyn Clock + Send + Sync>,
    pub identities: Arc<dyn IndexedOutboxIdentitySource + Send + Sync>,
    pub writer_fence: WriterFenceGeneration,
    pub operation_timeout: Duration,
    pub domain: AtomicityDomainId,
    pub blocking_executor: NativeBlockingExecutor,
}

type Shared<S> = Arc<SuccessorHistoricalComposition<S>>;

/// Mounts exactly the three existing read-only ordered-history paths.
/// It does not expose receipts, paid/control/admission or signing routes.
pub fn successor_history_router<S>(
    host: SuccessorHistoricalComposition<S>,
) -> Result<Router, SuccessorRouterError>
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
{
    if host.operation_timeout.is_zero() {
        return Err(SuccessorRouterError::ZeroOperationTimeout);
    }
    Ok(Router::new()
        .route(
            ORDERED_HISTORY_SUMMARY_PATH,
            get(summary::<S>).layer(DefaultBodyLimit::max(1)),
        )
        .route(
            ORDERED_HISTORY_HEIGHT_PATH,
            post(height::<S>).layer(DefaultBodyLimit::max(
                MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES,
            )),
        )
        .route(
            ORDERED_HISTORY_COMPONENT_PATH,
            post(component::<S>).layer(DefaultBodyLimit::max(
                MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES,
            )),
        )
        .with_state(Arc::new(host)))
}

fn unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "ordered-history-unavailable",
    )
}

#[allow(clippy::result_large_err)]
fn preflight(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
    maximum: usize,
    summary: bool,
) -> Result<Bytes, Response> {
    if has_unsupported_content_encoding(headers)
        || (!summary && !has_supported_content_type(headers))
    {
        return Err(error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-ordered-history-content",
        ));
    }
    let body: Bytes = body.map_err(|error| error_response(error.status(), "body-rejected"))?;
    if body.len() > maximum {
        return Err(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "ordered-history-body-too-large",
        ));
    }
    if summary && !body.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "ordered-history-summary-body-not-empty",
        ));
    }
    Ok(body)
}

async fn admitted<S, F>(host: Shared<S>, work: F) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
    F: FnOnce(&SuccessorHistoricalComposition<S>) -> Response + Send + 'static,
{
    publication::admitted(false, host.blocking_executor.clone(), move || work(&host)).await
}

/// Rechecks the protected barrier and terminal material under the fresh
/// policy. The full source-free exported prefix remains a consumer-verifier
/// obligation; these checks grant no activation or signing permission.
fn read<S>(
    host: &SuccessorHistoricalComposition<S>,
    work: impl FnOnce(
        &DurableOperationContext,
        &OrderedEconomicsEnvironment<'_>,
        &OrderedHistoryIdentity,
    ) -> Response,
) -> Response
where
    S: StructuredDurableDomainStateStore,
{
    let identity: IndexedOutboxAttemptIdentity = match host.identities.next_attempt_identity() {
        Ok(identity) => identity,
        Err(_) => return unavailable(),
    };
    let now: u64 = match host.clock.now_unix_millis() {
        Ok(now) => now,
        Err(_) => return unavailable(),
    };
    let deadline: StorageDeadline = match u64::try_from(host.operation_timeout.as_millis())
        .ok()
        .and_then(|timeout| now.checked_add(timeout))
        .and_then(StorageDeadline::new)
    {
        Some(deadline) => deadline,
        None => return unavailable(),
    };
    let context: DurableOperationContext =
        DurableOperationContext::new(host.writer_fence, deadline, identity.correlation_id);
    let policy: OrderedEconomicsPolicy = match host
        .policy_source
        .ordered_policy(host.store.as_ref(), &context)
    {
        Ok(policy) => policy,
        Err(_) => return unavailable(),
    };
    if policy.domain() != host.domain || policy.minimum_freeze_block_height() == 0 {
        return unavailable();
    }
    let sealed: SealBarrier = match host.store.get_outgoing_barrier(&context, host.domain) {
        Ok(runtime::OutgoingBarrier::Sealed(sealed))
            if sealed.outgoing_epoch == policy.context().epoch() =>
        {
            sealed
        }
        _ => return unavailable(),
    };
    let leg_policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(policy.context().clone());
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: &policy,
        history: &[],
        leg_policy: &leg_policy,
        engine: &engine,
        blobs: host.blobs.as_ref(),
        seal: None,
    };
    let summary: OrderedHistorySummary =
        match query_ordered_history_summary(host.store.as_ref(), &context, &env) {
            Ok(summary) => summary,
            Err(_) => return unavailable(),
        };
    if summary.identity.through_height != sealed.height
        || summary.identity.through_digest != sealed.block_digest
        || OrderedHistoryVerifier::new(policy.clone(), summary.identity.clone()).is_err()
    {
        return unavailable();
    }
    let descriptor: OrderedHistoryHeightDescriptor = match read_ordered_history_height_descriptor(
        host.store.as_ref(),
        &context,
        &env,
        &summary.identity,
        sealed.height,
    ) {
        Ok(descriptor) => descriptor,
        Err(_) => return unavailable(),
    };
    let candidate_length: u64 = match descriptor
        .components
        .iter()
        .find(|reference| reference.kind == OrderedHistoryComponentKind::Candidate)
    {
        Some(reference) => reference.length,
        None => return unavailable(),
    };
    let descriptor_digest: Digest32 = match ordered_history_descriptor_digest(&policy, &descriptor)
    {
        Ok(digest) => digest,
        Err(_) => return unavailable(),
    };
    let terminal_limit: u32 =
        match u32::try_from(node_core::ordered_economics::MAX_ORDERED_HISTORY_CHUNK_BYTES) {
            Ok(limit) => limit,
            Err(_) => return unavailable(),
        };
    let candidate_bytes: Vec<u8> = match read_ordered_history_component_chunk(
        host.store.as_ref(),
        &context,
        &env,
        &summary.identity,
        sealed.height,
        descriptor_digest,
        OrderedHistoryComponentKind::Candidate,
        0,
        terminal_limit,
    ) {
        Ok(bytes) if u64::try_from(bytes.len()).ok() == Some(candidate_length) => bytes,
        _ => return unavailable(),
    };
    let candidate: core_ordered::OrderedCandidate = match decode_ordered_candidate(&candidate_bytes)
    {
        Ok(candidate) => candidate,
        Err(_) => return unavailable(),
    };
    if candidate.kind != OrderedOperationKind::Seal
        || candidate.context != *policy.context()
        || candidate.request_id != sealed.request
    {
        return unavailable();
    }
    let intent: core_ordered::SealIntent = match core_ordered::decode_seal_intent(&candidate.intent)
    {
        Ok(intent) => intent,
        Err(_) => return unavailable(),
    };
    if intent.predecessor_tag != core_ordered::SEAL_PREDECESSOR_TAG_SUCCESSOR {
        return unavailable();
    }
    let subject_digest: Digest32 = match intent.readiness_subject.identity(policy.resolver()) {
        Ok(digest) => digest,
        Err(_) => return unavailable(),
    };
    if core_ordered::seal_target_digest(
        policy.resolver(),
        policy.context(),
        subject_digest,
        intent.predecessor_tag,
        intent.predecessor_digest,
    )
    .ok()
        != Some(sealed.target_digest)
    {
        return unavailable();
    }
    work(&context, &env, &summary.identity)
}

async fn summary<S>(
    State(host): State<Shared<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
{
    if let Err(response) = preflight(&headers, body, 1, true) {
        return response;
    }
    admitted(host, |host| {
        read(
            host,
            |_, _, identity| match encode_ordered_history_summary(&OrderedHistorySummary {
                identity: identity.clone(),
            }) {
                Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                Err(_) => unavailable(),
            },
        )
    })
    .await
}

async fn height<S>(
    State(host): State<Shared<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
{
    let body: Bytes = match preflight(
        &headers,
        body,
        MAX_ORDERED_HISTORY_HEIGHT_REQUEST_BYTES,
        false,
    ) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: OrderedHistoryHeightRequest = match OrderedHistoryHeightRequest::decode(&body) {
        Ok(request) => request,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid-ordered-history-height"),
    };
    admitted(host, move |host| {
        read(host, |context, env, terminal| {
            if request.identity != *terminal {
                return error_response(StatusCode::CONFLICT, "ordered-history-terminal-changed");
            }
            match read_ordered_history_height_descriptor(
                host.store.as_ref(),
                context,
                env,
                &request.identity,
                request.height,
            )
            .and_then(|descriptor| encode_ordered_history_height_descriptor(&descriptor))
            {
                Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                Err(_) => unavailable(),
            }
        })
    })
    .await
}

async fn component<S>(
    State(host): State<Shared<S>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response
where
    S: StructuredDurableDomainStateStore + Send + Sync + 'static,
{
    let body: Bytes = match preflight(
        &headers,
        body,
        MAX_ORDERED_HISTORY_COMPONENT_REQUEST_BYTES,
        false,
    ) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: OrderedHistoryComponentRequest =
        match OrderedHistoryComponentRequest::decode(&body) {
            Ok(request) => request,
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid-ordered-history-component",
                );
            }
        };
    admitted(host, move |host| {
        read(host, |context, env, terminal| {
            if request.identity != *terminal {
                return error_response(StatusCode::CONFLICT, "ordered-history-terminal-changed");
            }
            let descriptor: OrderedHistoryHeightDescriptor =
                match read_ordered_history_height_descriptor(
                    host.store.as_ref(),
                    context,
                    env,
                    &request.identity,
                    request.height,
                ) {
                    Ok(descriptor) => descriptor,
                    Err(_) => return unavailable(),
                };
            if ordered_history_descriptor_digest(env.policy, &descriptor).ok()
                != Some(request.descriptor_digest)
            {
                return error_response(StatusCode::CONFLICT, "ordered-history-descriptor-changed");
            }
            let length: u64 = match descriptor
                .components
                .iter()
                .find(|reference| reference.kind == request.kind)
            {
                Some(reference) => reference.length,
                None => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "ordered-history-component-not-present",
                    );
                }
            };
            let chunk_bytes: Vec<u8> = match read_ordered_history_component_chunk(
                host.store.as_ref(),
                context,
                env,
                &request.identity,
                request.height,
                request.descriptor_digest,
                request.kind,
                request.offset,
                request.limit,
            ) {
                Ok(bytes) => bytes,
                Err(_) => return unavailable(),
            };
            match (OrderedHistoryChunkResponse {
                offset: request.offset,
                total_length: length,
                chunk_bytes,
            })
            .encode()
            {
                Ok(bytes) => bytes_response(NODE_RESULT_MEDIA_TYPE, bytes),
                Err(_) => unavailable(),
            }
        })
    })
    .await
}
