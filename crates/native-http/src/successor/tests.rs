//! Focused successor router tests: refusal classification before any I/O,
//! loopback-only listening, and OriginalGenesis as a refusal, never a
//! fallback. Genuine successor serving is covered by the operator
//! four-host acceptance, which owns the activated SQLite fixtures.

use super::*;
use protocol_types::{
    ChainId, Epoch, HashAlgorithmId, HashSuite, HashSuiteId, HashSuiteSchedule, SignatureSchemeId,
    ValidatorId,
};
use runtime::{MemoryBlobStore, MemoryDurableStateStore, SystemClock};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Clone, Copy)]
enum Decision {
    Original,
    Refused,
}

struct StubAuthority {
    decision: Decision,
    calls: AtomicUsize,
}

impl SuccessorAuthoritySource<MemoryDurableStateStore> for StubAuthority {
    fn genesis_root(&self) -> &VerifiedGenesisRoot {
        unreachable!("every refusal precedes successor policy construction")
    }

    fn resolve<'inv>(
        &self,
        _store: &'inv MemoryDurableStateStore,
        _context: &'inv DurableOperationContext,
    ) -> Result<LiveAuthority<'inv>, ServingAuthorityError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.decision {
            Decision::Original => Ok(LiveAuthority::OriginalGenesis),
            Decision::Refused => Err(ServingAuthorityError::Refused("test refusal")),
        }
    }
}

struct RefusingSigner;

impl ConsensusSigner for RefusingSigner {
    fn validator_id(&self) -> ValidatorId {
        ValidatorId::new([7; 32])
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, _framed: &[u8]) -> Result<Vec<u8>, String> {
        panic!("a refused successor invocation never signs")
    }
}

struct Identities(AtomicU64);

impl IndexedOutboxIdentitySource for Identities {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        let sequence: u64 = self.0.fetch_add(1, Ordering::SeqCst);
        let mut lease: [u8; 32] = [0; 32];
        lease[..8].copy_from_slice(&sequence.to_be_bytes());
        let mut correlation: [u8; 16] = [0; 16];
        correlation[..8].copy_from_slice(&sequence.to_be_bytes());
        Ok(IndexedOutboxAttemptIdentity::new(
            DurableOutboxLeaseId::new(lease)
                .map_err(|_| IndexedOutboxIdentitySourceError::Unavailable)?,
            StorageCorrelationId::new(correlation)
                .ok_or(IndexedOutboxIdentitySourceError::Unavailable)?,
        ))
    }
}

/// Closes the given executor as a side effect of reading the clock, so a
/// test can model the host's shared admission pool closing while the
/// request's own blocking job has already entered its admitted closure.
struct ClosingClock(NativeBlockingExecutor);

impl Clock for ClosingClock {
    fn now_unix_millis(&self) -> Result<u64, RuntimeError> {
        self.0.close();
        SystemClock.now_unix_millis()
    }
}

struct FailingIdentities(NativeBlockingExecutor);

impl IndexedOutboxIdentitySource for FailingIdentities {
    fn next_attempt_identity(
        &self,
    ) -> Result<IndexedOutboxAttemptIdentity, IndexedOutboxIdentitySourceError> {
        self.0.close();
        Err(IndexedOutboxIdentitySourceError::Unavailable)
    }
}

struct FailingClock(NativeBlockingExecutor);

impl Clock for FailingClock {
    fn now_unix_millis(&self) -> Result<u64, RuntimeError> {
        self.0.close();
        Err(RuntimeError::ClockBeforeUnixEpoch)
    }
}

struct OverflowingClock(NativeBlockingExecutor);

impl Clock for OverflowingClock {
    fn now_unix_millis(&self) -> Result<u64, RuntimeError> {
        self.0.close();
        Ok(u64::MAX)
    }
}

fn resolver() -> HashSuiteResolver {
    HashSuiteResolver::new(
        ChainId::new("successor-http-test").unwrap(),
        ProtocolVersion::new(1),
        vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite {
                id: HashSuiteId::new(1),
                transaction_hash: HashAlgorithmId::Sha2_256,
                object_digest: HashAlgorithmId::Sha2_256,
                effects_hash: HashAlgorithmId::Sha2_256,
                code_hash: HashAlgorithmId::Sha2_256,
                config_hash: HashAlgorithmId::Sha2_256,
                certificate_hash: HashAlgorithmId::Sha2_256,
            },
        }],
    )
    .unwrap()
}

fn router(decision: Decision) -> (Router, Arc<StubAuthority>) {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let authority: Arc<StubAuthority> = Arc::new(StubAuthority {
        decision,
        calls: AtomicUsize::new(0),
    });
    let mut protocol_config: ProtocolConfig = ProtocolConfig::genesis();
    protocol_config.protocol_version = ProtocolVersion::new(1);
    let host: SuccessorHostComposition<MemoryDurableStateStore> = SuccessorHostComposition {
        store: Arc::new(MemoryDurableStateStore::new(fence)),
        blobs: Arc::new(MemoryBlobStore::default()),
        authority: authority.clone(),
        signer: Arc::new(RefusingSigner),
        clock: Arc::new(SystemClock),
        identities: Arc::new(Identities(AtomicU64::new(1))),
        resolver: resolver(),
        history: Vec::new(),
        engine: Arc::new(LocalWasmExecutionEngine::new()),
        protocol_config,
        writer_fence: fence,
        operation_timeout: Duration::from_secs(5),
        created_checkpoint: 1,
        blocking_executor: NativeBlockingExecutor::new(NativeBlockingPolicy::new(
            NonZeroUsize::new(4).unwrap(),
        )),
    };
    (successor_router(host).unwrap(), authority)
}

/// Same composition as [`router`], but with an explicit clock, identity
/// source and blocking executor so a test can arrange the host's own
/// `operation_context` stop check deterministically.
fn host_with<C, I>(
    decision: Decision,
    clock: Arc<C>,
    identities: Arc<I>,
    blocking_executor: NativeBlockingExecutor,
) -> (
    SuccessorHostComposition<MemoryDurableStateStore>,
    Arc<StubAuthority>,
)
where
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let authority: Arc<StubAuthority> = Arc::new(StubAuthority {
        decision,
        calls: AtomicUsize::new(0),
    });
    let mut protocol_config: ProtocolConfig = ProtocolConfig::genesis();
    protocol_config.protocol_version = ProtocolVersion::new(1);
    let host: SuccessorHostComposition<MemoryDurableStateStore> = SuccessorHostComposition {
        store: Arc::new(MemoryDurableStateStore::new(fence)),
        blobs: Arc::new(MemoryBlobStore::default()),
        authority: authority.clone(),
        signer: Arc::new(RefusingSigner),
        clock,
        identities,
        resolver: resolver(),
        history: Vec::new(),
        engine: Arc::new(LocalWasmExecutionEngine::new()),
        protocol_config,
        writer_fence: fence,
        operation_timeout: Duration::from_secs(5),
        created_checkpoint: 1,
        blocking_executor,
    };
    (host, authority)
}

async fn send(
    router: &Router,
    method: &str,
    path: &str,
    media: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(media) = media {
        request = request.header(header::CONTENT_TYPE, media);
    }
    let response: Response = router
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status: StatusCode = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes: Bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    (status, bytes.to_vec())
}

#[test]
fn loopback_listener_accepts_only_exact_ipv4_or_ipv6_loopback() {
    for accepted in ["127.0.0.1:0", "127.0.0.1:8080", "[::1]:0", "[::1]:9443"] {
        assert!(require_loopback_listen(accepted).is_ok(), "{accepted}");
    }
    for refused in [
        "0.0.0.0:80",
        "127.0.0.2:80",
        "127.1.2.3:80",
        "10.0.0.1:80",
        "[::]:80",
        "[::ffff:127.0.0.1]:80",
        "[fe80::1]:80",
    ] {
        assert_eq!(
            require_loopback_listen(refused),
            Err(SuccessorListenError::NotLoopback),
            "{refused}"
        );
    }
    for malformed in ["localhost:80", "127.0.0.1", "", "127.0.0.1:99999"] {
        assert_eq!(
            require_loopback_listen(malformed),
            Err(SuccessorListenError::Invalid),
            "{malformed}"
        );
    }
}

#[tokio::test]
async fn binding_refuses_a_nonloopback_address_before_any_socket() {
    let address: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let error: io::Error = bind_successor_loopback(address).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let bound: tokio::net::TcpListener = bind_successor_loopback("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    assert!(bound.local_addr().unwrap().ip().is_loopback());
}

#[tokio::test]
async fn permanent_controls_and_unserved_routes_refuse_before_authority() {
    let (router, authority): (Router, Arc<StubAuthority>) = router(Decision::Original);
    for path in SUCCESSOR_REFUSED_CONTROL_PATHS {
        let concrete: String = path.replace("{validator_id}", &"ab".repeat(32));
        for method in ["POST", "GET"] {
            let (status, body): (StatusCode, Vec<u8>) = send(
                &router,
                method,
                &concrete,
                Some(NODE_EVENT_MEDIA_TYPE),
                b"x".to_vec(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{method} {concrete}"
            );
            assert_eq!(body, b"successor-control-unsupported");
        }
    }
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_requests_refuse_before_identity_clock_or_authority() {
    let (router, authority): (Router, Arc<StubAuthority>) = router(Decision::Original);
    let cases: [(&str, Option<&str>, Vec<u8>, StatusCode); 11] = [
        (
            node_wire::FEE_CLAIM_PREPARE_PATH,
            Some(node_wire::FEE_CLAIM_PREPARE_REQUEST_MEDIA_TYPE),
            b"junk".to_vec(),
            StatusCode::BAD_REQUEST,
        ),
        (
            node_wire::FEE_CLAIM_PREPARE_PATH,
            Some(NODE_EVENT_MEDIA_TYPE),
            b"junk".to_vec(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            node_wire::ordered_history::ORDERED_HISTORY_HEIGHT_PATH,
            Some(NODE_EVENT_MEDIA_TYPE),
            b"junk".to_vec(),
            StatusCode::BAD_REQUEST,
        ),
        (
            node_wire::ordered_history::ORDERED_HISTORY_COMPONENT_PATH,
            Some("text/plain"),
            b"junk".to_vec(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            FASTVOTE_PREPARE_PATH,
            Some(NODE_EVENT_MEDIA_TYPE),
            b"junk".to_vec(),
            StatusCode::BAD_REQUEST,
        ),
        (
            FASTVOTE_PREPARE_PATH,
            Some("text/plain"),
            b"junk".to_vec(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            FASTVOTE_CERTIFICATES_PATH,
            Some(NODE_EVENT_MEDIA_TYPE),
            b"junk".to_vec(),
            StatusCode::BAD_REQUEST,
        ),
        (
            FASTVOTE_PUBLICATION_RETAIN_PATH,
            Some(NODE_EVENT_MEDIA_TYPE),
            b"junk".to_vec(),
            StatusCode::BAD_REQUEST,
        ),
        (
            ORDERED_ECONOMICS_PROPOSAL_PATH,
            Some(ORDERED_PROPOSAL_MEDIA_TYPE),
            b"junk".to_vec(),
            StatusCode::BAD_REQUEST,
        ),
        (
            ORDERED_ECONOMICS_PROPOSE_PATH,
            Some(ORDERED_PROPOSAL_MEDIA_TYPE),
            b"junk".to_vec(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            ORDERED_ECONOMICS_TICK_PATH,
            None,
            b"x".to_vec(),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (path, media, body, expected) in cases {
        let (status, _): (StatusCode, Vec<u8>) = send(&router, "POST", path, media, body).await;
        assert_eq!(status, expected, "{path}");
    }
    let (status, _): (StatusCode, Vec<u8>) =
        send(&router, "GET", "/v1/receipts/not-hex", None, Vec::new()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn recurring_controls_keep_exact_body_bounds_and_decode_before_authority() {
    let (router, authority): (Router, Arc<StubAuthority>) = router(Decision::Original);
    let controls: [(&str, usize); 9] = [
        (FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH, 1),
        (
            FASTVOTE_FROZEN_FRONTIER_PAGE_PATH,
            node_wire::MAX_FRONTIER_PAGE_REQUEST_BYTES,
        ),
        (
            node_wire::FASTVOTE_DRAIN_SIGNER_PAGE_PATH,
            node_wire::MAX_DRAIN_SIGNER_PAGE_REQUEST_BYTES,
        ),
        (
            node_wire::FASTVOTE_DRAIN_MEMBER_CONFIRM_PATH,
            node_wire::MAX_DRAIN_MEMBER_CONFIRM_REQUEST_BYTES,
        ),
        (
            node_wire::FASTVOTE_DRAIN_IMPORT_PATH,
            consensus::bundle::MAX_ENCODED_BUNDLE_BYTES,
        ),
        (
            node_wire::FASTVOTE_DRAIN_UNION_ADVANCE_PATH,
            node_wire::MAX_DRAIN_UNION_ADVANCE_REQUEST_BYTES,
        ),
        (
            node_wire::FASTVOTE_RETAINED_PUBLICATION_SOURCE_PATH,
            node_wire::MAX_RETAINED_PUBLICATION_SOURCE_REQUEST_BYTES,
        ),
        (
            node_wire::FASTVOTE_DRAIN_SIGNER_PROGRESS_PATH,
            node_wire::MAX_DRAIN_SIGNER_PROGRESS_REQUEST_BYTES,
        ),
        (
            node_wire::FASTVOTE_DRAIN_APPLY_PATH,
            node_wire::MAX_DRAIN_MEMBER_APPLY_REQUEST_BYTES,
        ),
    ];
    for (path, maximum) in controls {
        let path: String = path.replace("{validator_id}", &"ab".repeat(32));
        let (status, _): (StatusCode, Vec<u8>) =
            send(&router, "POST", &path, Some(NODE_EVENT_MEDIA_TYPE), vec![1]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        let (status, _): (StatusCode, Vec<u8>) =
            send(&router, "POST", &path, Some("text/plain"), vec![1]).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{path}");
        let (status, _): (StatusCode, Vec<u8>) = send(
            &router,
            "POST",
            &path,
            Some(NODE_EVENT_MEDIA_TYPE),
            vec![1; maximum + 1],
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
    }
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    for _ in 0..2 {
        let (status, body): (StatusCode, Vec<u8>) = send(
            &router,
            "POST",
            FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
            Some(NODE_EVENT_MEDIA_TYPE),
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, b"successor-original-genesis-refused");
    }
    assert_eq!(
        authority.calls.load(Ordering::SeqCst),
        2,
        "fresh authority on every valid control invocation"
    );
}

struct RefusingHistoricalPolicy(AtomicUsize);

impl SuccessorHistoricalPolicySource<MemoryDurableStateStore> for RefusingHistoricalPolicy {
    fn ordered_policy(
        &self,
        _store: &MemoryDurableStateStore,
        _context: &DurableOperationContext,
    ) -> Result<OrderedEconomicsPolicy, ServingAuthorityError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ServingAuthorityError::Refused("test history refusal"))
    }
}

/// Same read-only composition as the mounting test below, but with an
/// explicit clock, identity source and blocking executor so a test can
/// arrange the historical `read` boundary's own stop check deterministically.
fn historical_host_with<C, I>(
    policy_source: Arc<RefusingHistoricalPolicy>,
    clock: Arc<C>,
    identities: Arc<I>,
    blocking_executor: NativeBlockingExecutor,
) -> SuccessorHistoricalComposition<MemoryDurableStateStore>
where
    C: Clock + Send + Sync + 'static,
    I: IndexedOutboxIdentitySource + Send + Sync + 'static,
{
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    SuccessorHistoricalComposition {
        store: Arc::new(MemoryDurableStateStore::new(fence)),
        policy_source,
        blobs: Arc::new(MemoryBlobStore::default()),
        clock,
        identities,
        writer_fence: fence,
        operation_timeout: Duration::from_secs(5),
        domain: AtomicityDomainId::new([1; 32]).unwrap(),
        blocking_executor,
    }
}

/// DR-0251: the historical read boundary's own `blocking_executor` stop
/// check is rechecked after identity/clock/deadline preparation but before
/// `policy_source.ordered_policy`, matching `successor::operation_context`'s
/// boundary. The generic `publication::admitted` entry guard cannot observe
/// a close that lands during this function's own clock read, so the summary
/// route must still refuse before ever reaching the policy source once the
/// shared executor is closed inside the clock call.
#[tokio::test]
async fn closed_blocking_executor_refuses_historical_summary_before_policy() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(2).unwrap()));
    let policy_source: Arc<RefusingHistoricalPolicy> =
        Arc::new(RefusingHistoricalPolicy(AtomicUsize::new(0)));
    let host: SuccessorHistoricalComposition<MemoryDurableStateStore> = historical_host_with(
        policy_source.clone(),
        Arc::new(ClosingClock(executor.clone())),
        Arc::new(Identities(AtomicU64::new(1))),
        executor,
    );
    let router: Router = successor_history_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) = send(
        &router,
        "GET",
        node_wire::ordered_history::ORDERED_HISTORY_SUMMARY_PATH,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"invocation-cancelled-before-storage");
    assert_eq!(policy_source.0.load(Ordering::SeqCst), 0);
}

/// Counterpart to the closed case above on the exact same route: with no
/// stop signal, the fresh policy source is still reached exactly once and
/// the preexisting `ordered-history-unavailable` refusal is unchanged.
#[tokio::test]
async fn open_blocking_executor_historical_summary_counterpart_reaches_policy_once() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(2).unwrap()));
    let policy_source: Arc<RefusingHistoricalPolicy> =
        Arc::new(RefusingHistoricalPolicy(AtomicUsize::new(0)));
    let host: SuccessorHistoricalComposition<MemoryDurableStateStore> = historical_host_with(
        policy_source.clone(),
        Arc::new(SystemClock),
        Arc::new(Identities(AtomicU64::new(1))),
        executor,
    );
    let router: Router = successor_history_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) = send(
        &router,
        "GET",
        node_wire::ordered_history::ORDERED_HISTORY_SUMMARY_PATH,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"ordered-history-unavailable");
    assert_eq!(policy_source.0.load(Ordering::SeqCst), 1);
}

/// Closing admission during identity preparation does not mask its own
/// failure: the historical `read` boundary returns the identity-sourced
/// `ordered-history-unavailable` refusal before its new cancellation
/// checkpoint, and the policy source is never reached either way.
#[tokio::test]
async fn historical_identity_error_outranks_a_closed_blocking_executor() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(2).unwrap()));
    let policy_source: Arc<RefusingHistoricalPolicy> =
        Arc::new(RefusingHistoricalPolicy(AtomicUsize::new(0)));
    let host: SuccessorHistoricalComposition<MemoryDurableStateStore> = historical_host_with(
        policy_source.clone(),
        Arc::new(SystemClock),
        Arc::new(FailingIdentities(executor.clone())),
        executor.clone(),
    );
    let router: Router = successor_history_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) = send(
        &router,
        "GET",
        node_wire::ordered_history::ORDERED_HISTORY_SUMMARY_PATH,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"ordered-history-unavailable");
    assert_eq!(policy_source.0.load(Ordering::SeqCst), 0);
    assert!(executor.stop_cancellation().is_cancelled());
}

/// Closing admission during a failing clock read keeps the same
/// `ordered-history-unavailable` refusal and never reaches the policy source.
#[tokio::test]
async fn historical_clock_error_outranks_a_closed_blocking_executor() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(2).unwrap()));
    let policy_source: Arc<RefusingHistoricalPolicy> =
        Arc::new(RefusingHistoricalPolicy(AtomicUsize::new(0)));
    let host: SuccessorHistoricalComposition<MemoryDurableStateStore> = historical_host_with(
        policy_source.clone(),
        Arc::new(FailingClock(executor.clone())),
        Arc::new(Identities(AtomicU64::new(1))),
        executor.clone(),
    );
    let router: Router = successor_history_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) = send(
        &router,
        "GET",
        node_wire::ordered_history::ORDERED_HISTORY_SUMMARY_PATH,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"ordered-history-unavailable");
    assert_eq!(policy_source.0.load(Ordering::SeqCst), 0);
    assert!(executor.stop_cancellation().is_cancelled());
}

/// Closing admission during the clock read retains deadline-overflow
/// priority over the new cancellation checkpoint.
#[tokio::test]
async fn historical_deadline_overflow_outranks_a_closed_blocking_executor() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(2).unwrap()));
    let policy_source: Arc<RefusingHistoricalPolicy> =
        Arc::new(RefusingHistoricalPolicy(AtomicUsize::new(0)));
    let host: SuccessorHistoricalComposition<MemoryDurableStateStore> = historical_host_with(
        policy_source.clone(),
        Arc::new(OverflowingClock(executor.clone())),
        Arc::new(Identities(AtomicU64::new(1))),
        executor.clone(),
    );
    let router: Router = successor_history_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) = send(
        &router,
        "GET",
        node_wire::ordered_history::ORDERED_HISTORY_SUMMARY_PATH,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"ordered-history-unavailable");
    assert_eq!(policy_source.0.load(Ordering::SeqCst), 0);
    assert!(executor.stop_cancellation().is_cancelled());
}

#[tokio::test]
async fn historical_material_router_mounts_only_three_read_routes_and_reverifies() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let policy_source: Arc<RefusingHistoricalPolicy> =
        Arc::new(RefusingHistoricalPolicy(AtomicUsize::new(0)));
    let router: Router = successor_history_router(SuccessorHistoricalComposition {
        store: Arc::new(MemoryDurableStateStore::new(fence)),
        policy_source: policy_source.clone(),
        blobs: Arc::new(MemoryBlobStore::default()),
        clock: Arc::new(SystemClock),
        identities: Arc::new(Identities(AtomicU64::new(1))),
        writer_fence: fence,
        operation_timeout: Duration::from_secs(5),
        domain: AtomicityDomainId::new([1; 32]).unwrap(),
        blocking_executor: NativeBlockingExecutor::new(NativeBlockingPolicy::new(
            NonZeroUsize::new(2).unwrap(),
        )),
    })
    .unwrap();
    for path in [
        node_wire::ordered_history::ORDERED_HISTORY_HEIGHT_PATH,
        node_wire::ordered_history::ORDERED_HISTORY_COMPONENT_PATH,
    ] {
        let (status, _): (StatusCode, Vec<u8>) =
            send(&router, "POST", path, Some(NODE_EVENT_MEDIA_TYPE), vec![1]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(policy_source.0.load(Ordering::SeqCst), 0);
    for _ in 0..2 {
        let (status, _): (StatusCode, Vec<u8>) = send(
            &router,
            "GET",
            node_wire::ordered_history::ORDERED_HISTORY_SUMMARY_PATH,
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }
    assert_eq!(policy_source.0.load(Ordering::SeqCst), 2);
    for path in [
        NODE_EVENT_PATH,
        QUERY_CONTEXT_PATH,
        FASTVOTE_PREPARE_PATH,
        FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
        ORDERED_ECONOMICS_PROPOSE_PATH,
        node_wire::FEE_CLAIM_PREPARE_PATH,
        "/v1/receipts/1111111111111111111111111111111111111111111111111111111111111111",
    ] {
        for method in ["GET", "POST"] {
            let response: Response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        }
    }
    assert_eq!(policy_source.0.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn original_genesis_is_an_explicit_refusal_never_a_serving_fallback() {
    let (router, authority): (Router, Arc<StubAuthority>) = router(Decision::Original);
    let selector: String = "11".repeat(32);
    let reads: [String; 7] = [
        QUERY_CONTEXT_PATH.to_string(),
        node_wire::ordered_history::ORDERED_HISTORY_SUMMARY_PATH.to_string(),
        format!("/v1/objects/{selector}"),
        format!("/v1/receipts/{selector}"),
        format!("/v1/senders/{selector}/next-nonce"),
        paid_execution::PAID_FEE_POLICY_PATH.to_string(),
        ORDERED_ECONOMICS_STATUS_PATH.to_string(),
    ];
    for path in &reads {
        let (status, body): (StatusCode, Vec<u8>) =
            send(&router, "GET", path, None, Vec::new()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}");
        assert_eq!(body, b"successor-original-genesis-refused");
    }
    let (status, body): (StatusCode, Vec<u8>) = send(
        &router,
        "POST",
        ORDERED_ECONOMICS_TICK_PATH,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, b"successor-original-genesis-refused");
    assert_eq!(authority.calls.load(Ordering::SeqCst), reads.len() + 1);
}

#[tokio::test]
async fn refused_authority_is_an_explicit_conflict_without_signing() {
    let (router, authority): (Router, Arc<StubAuthority>) = router(Decision::Refused);
    for (method, path) in [
        ("GET", ORDERED_ECONOMICS_STATUS_PATH),
        ("POST", ORDERED_ECONOMICS_TICK_PATH),
    ] {
        let (status, body): (StatusCode, Vec<u8>) =
            send(&router, method, path, None, Vec::new()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{path}");
        assert_eq!(body, b"successor-authority-refused");
    }
    assert_eq!(authority.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn router_refuses_a_protocol_config_that_differs_from_the_pinned_resolver() {
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let mut protocol_config: ProtocolConfig = ProtocolConfig::genesis();
    protocol_config.protocol_version = ProtocolVersion::new(2);
    let host: SuccessorHostComposition<MemoryDurableStateStore> = SuccessorHostComposition {
        store: Arc::new(MemoryDurableStateStore::new(fence)),
        blobs: Arc::new(MemoryBlobStore::default()),
        authority: Arc::new(StubAuthority {
            decision: Decision::Original,
            calls: AtomicUsize::new(0),
        }),
        signer: Arc::new(RefusingSigner),
        clock: Arc::new(SystemClock),
        identities: Arc::new(Identities(AtomicU64::new(1))),
        resolver: resolver(),
        history: Vec::new(),
        engine: Arc::new(LocalWasmExecutionEngine::new()),
        protocol_config,
        writer_fence: fence,
        operation_timeout: Duration::from_secs(5),
        created_checkpoint: 1,
        blocking_executor: NativeBlockingExecutor::new(NativeBlockingPolicy::new(
            NonZeroUsize::new(1).unwrap(),
        )),
    };
    assert!(matches!(
        successor_router(host),
        Err(SuccessorRouterError::ProtocolVersionMismatch)
    ));
}

/// DR-0250: `operation_context` derives its cancellation signal from the same
/// `blocking_executor` the router's own admission already shares, and checks
/// it after identity/clock/deadline preparation but before the context used
/// for authority resolution is returned. A representative read/query route
/// never reaches the authority double once that executor is closed.
#[tokio::test]
async fn closed_blocking_executor_refuses_a_context_query_before_authority() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()));
    let (host, authority): (
        SuccessorHostComposition<MemoryDurableStateStore>,
        Arc<StubAuthority>,
    ) = host_with(
        Decision::Original,
        Arc::new(ClosingClock(executor.clone())),
        Arc::new(Identities(AtomicU64::new(1))),
        executor,
    );
    let router: Router = successor_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) =
        send(&router, "GET", QUERY_CONTEXT_PATH, None, Vec::new()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"invocation-cancelled-before-storage");
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
}

/// Counterpart to the closed case above on the exact same route: with no
/// stop signal, the fresh authority is reached exactly once and the
/// preexisting `OriginalGenesis` refusal is unchanged.
#[tokio::test]
async fn open_blocking_executor_context_query_counterpart_reaches_authority_once() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()));
    let (host, authority): (
        SuccessorHostComposition<MemoryDurableStateStore>,
        Arc<StubAuthority>,
    ) = host_with(
        Decision::Original,
        Arc::new(SystemClock),
        Arc::new(Identities(AtomicU64::new(1))),
        executor,
    );
    let router: Router = successor_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) =
        send(&router, "GET", QUERY_CONTEXT_PATH, None, Vec::new()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, b"successor-original-genesis-refused");
    assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
}

/// Same guard on a representative mutation route sharing `with_authority`.
#[tokio::test]
async fn closed_blocking_executor_refuses_an_ordered_tick_before_authority() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()));
    let (host, authority): (
        SuccessorHostComposition<MemoryDurableStateStore>,
        Arc<StubAuthority>,
    ) = host_with(
        Decision::Original,
        Arc::new(ClosingClock(executor.clone())),
        Arc::new(Identities(AtomicU64::new(1))),
        executor,
    );
    let router: Router = successor_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) = send(
        &router,
        "POST",
        ORDERED_ECONOMICS_TICK_PATH,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"invocation-cancelled-before-storage");
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
}

/// Counterpart to the closed mutation case above: no stop signal still
/// reaches the fresh authority exactly once with the unchanged refusal.
#[tokio::test]
async fn open_blocking_executor_ordered_tick_counterpart_reaches_authority_once() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()));
    let (host, authority): (
        SuccessorHostComposition<MemoryDurableStateStore>,
        Arc<StubAuthority>,
    ) = host_with(
        Decision::Original,
        Arc::new(SystemClock),
        Arc::new(Identities(AtomicU64::new(1))),
        executor,
    );
    let router: Router = successor_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) = send(
        &router,
        "POST",
        ORDERED_ECONOMICS_TICK_PATH,
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, b"successor-original-genesis-refused");
    assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
}

/// Closing admission during identity preparation does not mask its failure.
/// The router entered through an open executor; `operation_context` returns
/// the identity error before its new cancellation checkpoint.
#[tokio::test]
async fn identity_error_outranks_a_closed_blocking_executor() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()));
    let (host, authority): (
        SuccessorHostComposition<MemoryDurableStateStore>,
        Arc<StubAuthority>,
    ) = host_with(
        Decision::Original,
        Arc::new(SystemClock),
        Arc::new(FailingIdentities(executor.clone())),
        executor.clone(),
    );
    let router: Router = successor_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) =
        send(&router, "GET", QUERY_CONTEXT_PATH, None, Vec::new()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"successor-host-unavailable");
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert!(executor.stop_cancellation().is_cancelled());
}

/// Closing admission during a failing clock read retains the clock error.
#[tokio::test]
async fn clock_error_outranks_a_closed_blocking_executor() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()));
    let (host, authority): (
        SuccessorHostComposition<MemoryDurableStateStore>,
        Arc<StubAuthority>,
    ) = host_with(
        Decision::Original,
        Arc::new(FailingClock(executor.clone())),
        Arc::new(Identities(AtomicU64::new(1))),
        executor.clone(),
    );
    let router: Router = successor_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) =
        send(&router, "GET", QUERY_CONTEXT_PATH, None, Vec::new()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"successor-host-unavailable");
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert!(executor.stop_cancellation().is_cancelled());
}

/// Closing admission during the clock read retains deadline-overflow priority.
#[tokio::test]
async fn deadline_overflow_outranks_a_closed_blocking_executor() {
    let executor: NativeBlockingExecutor =
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()));
    let (host, authority): (
        SuccessorHostComposition<MemoryDurableStateStore>,
        Arc<StubAuthority>,
    ) = host_with(
        Decision::Original,
        Arc::new(OverflowingClock(executor.clone())),
        Arc::new(Identities(AtomicU64::new(1))),
        executor.clone(),
    );
    let router: Router = successor_router(host).unwrap();
    let (status, body): (StatusCode, Vec<u8>) =
        send(&router, "GET", QUERY_CONTEXT_PATH, None, Vec::new()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, b"successor-host-state-invalid");
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert!(executor.stop_cancellation().is_cancelled());
}
