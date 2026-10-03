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
