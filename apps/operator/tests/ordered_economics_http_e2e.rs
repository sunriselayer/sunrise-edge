//! Actual production ordered router over TCP, with counters at the real
//! identity/clock/state/object/blob boundaries. Pure helper tests alone cannot
//! establish authentication-before-I/O or which routes a host exposes.
mod support;

use consensus::ConsensusSigner;
use ed25519_zebra::SigningKey;
use execution::local_execution::LocalExecutionPolicy;
use native_http::ordered_economics::{OrderedEconomicsState, certified_ordered_economics_router};
use native_http::{NativeBlockingExecutor, NativeBlockingPolicy};
use node_core::bond_lifecycle::{
    BondLifecycleIntent, BondLifecycleOperation, SignedBondLifecycleIntent,
    encode_signed_bond_lifecycle_intent,
};
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{self, OrderedCandidate, OrderedOperationKind};
use node_wire::ordered_economics::*;
use objects::Address;
use protocol_types::{Digest32, HashAlgorithmId, SignatureSchemeId, ValidatorId};
use runtime::{
    DurableOperationContext, MemoryBlobStore, MemoryDurableStateStore, StorageCorrelationId,
    StorageDeadline, SystemClock, WriterFenceGeneration,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::observed_io::{IoCounters, Observed};

struct Signer {
    id: ValidatorId,
    key: SigningKey,
}
impl ConsensusSigner for Signer {
    fn validator_id(&self) -> ValidatorId {
        self.id
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.key.sign(bytes).into();
        Ok(signature.to_vec())
    }
}

fn request(addr: SocketAddr, method: &str, path: &str, headers: &str, body: &[u8]) -> u16 {
    let mut stream: TcpStream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let head: String = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut response: Vec<u8> = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8_lossy(&response)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordered_router_authenticates_before_actual_io_and_has_no_direct_mutations() {
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let fixture = support::genesis_fixture::build_economics_fixture(&format!(
        "ordered-http-{}-{now}",
        std::process::id()
    ));
    let manifest = node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let fence: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    let context = DurableOperationContext::new(
        fence,
        StorageDeadline::new(now + 120_000).unwrap(),
        StorageCorrelationId::new([0x61; 16]).unwrap(),
    );
    let store = Arc::new(MemoryDurableStateStore::new(fence));
    let blobs = Arc::new(MemoryBlobStore::default());
    node_core::install_genesis_with_history(
        store.as_ref(),
        &context,
        fixture.domain,
        &fixture.resolver,
        &[],
        &manifest,
        1,
    )
    .unwrap();
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &fixture.resolver,
        &fixture.manifest_bytes,
        fixture.manifest_digest,
        &fixture.context,
    )
    .unwrap();
    let policy =
        ordered_economics::OrderedEconomicsPolicy::from_genesis_root(&root, fixture.domain)
            .unwrap();
    let leader: ValidatorId = policy.engine().validator_set().leader(1).unwrap();
    let entry = fixture
        .validators
        .iter()
        .find(|entry| entry.validator_id == leader)
        .unwrap();
    let signer = Signer {
        id: leader,
        key: SigningKey::from(entry.seed),
    };
    let leg_policy = LocalExecutionPolicy::generic_object_results(fixture.context.clone());
    let engine = execution::LocalWasmExecutionEngine::new();
    let env = ordered_economics::OrderedEconomicsEnvironment {
        policy: &policy,
        history: &[],
        leg_policy: &leg_policy,
        engine: &engine,
        blobs: blobs.as_ref(),
    };
    ordered_economics::install_ordered_genesis(store.as_ref(), &context, &env, now).unwrap();
    let proposal =
        ordered_economics::propose(store.as_ref(), &context, &env, None, &signer).unwrap();
    let mut forged_proposal = proposal.clone();
    forged_proposal.proposal.signature[0] ^= 1;
    let forged_proposal_bytes =
        ordered_economics::encode_ordered_proposal(&forged_proposal).unwrap();
    let mut forged_qc = policy.engine().genesis_state(now).high_qc;
    forged_qc.proposal_digest = Digest32::new(HashAlgorithmId::Sha2_256, [0x99; 32]);
    let forged_qc_bytes = consensus::encode_quorum_certificate(&forged_qc).unwrap();
    // Structurally valid closed-profile candidate, but signed by a key that is
    // not the registered validator. Invalid outer auth must precede bond I/O.
    let resource = manifest.economics_policy.resources[0].resource_id;
    let candidate = OrderedCandidate {
        context: fixture.context.clone(),
        request_id: [0x72; 32],
        kind: OrderedOperationKind::BondLifecycle,
        created_checkpoint: 1,
        intent: encode_signed_bond_lifecycle_intent(&SignedBondLifecycleIntent {
            intent: BondLifecycleIntent {
                context: fixture.context.clone(),
                request_id: [0x72; 32],
                validator_id: leader,
                resource_id: resource,
                expected_generation: 1,
                expected_previous_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x73; 32]),
                expected_next_row_digest: Digest32::new(HashAlgorithmId::Sha2_256, [0x74; 32]),
                operation: BondLifecycleOperation::Unbond {
                    recipient: Address::new([0x75; 32]),
                },
            },
            signature: SigningKey::from([0xFF; 32]).sign(b"forged").into(),
        })
        .unwrap(),
    };
    let candidate_bytes = ordered_economics::encode_ordered_candidate(&candidate).unwrap();
    let forged_request = OrderedProposeRequest {
        candidate: Some(candidate_bytes),
    }
    .encode()
    .unwrap();
    let counters = IoCounters::default();
    let router = certified_ordered_economics_router(OrderedEconomicsState {
        store: Arc::new(Observed::new(store, &counters)),
        clock: Arc::new(Observed::new(Arc::new(SystemClock), &counters)),
        identities: Arc::new(Observed::new(
            Arc::new(sunrise_edge_devnet::DevnetOutboxIdentitySource::new(fence)),
            &counters,
        )),
        domain: fixture.domain,
        writer_fence: fence,
        operation_timeout: Duration::from_secs(30),
        policy,
        history: Vec::new(),
        leg_policy,
        engine: Arc::new(engine),
        blobs: Arc::new(Observed::new(blobs, &counters)),
        signer,
        blocking_executor: NativeBlockingExecutor::new(NativeBlockingPolicy::new(
            NonZeroUsize::new(2).unwrap(),
        )),
        cancellation: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(native_http::serve(listener, router, async {
        let _ = shutdown.await;
    }));

    for (path, media) in [
        (
            ORDERED_ECONOMICS_PROPOSE_PATH,
            ORDERED_PROPOSE_REQUEST_MEDIA_TYPE,
        ),
        (ORDERED_ECONOMICS_PROPOSAL_PATH, ORDERED_PROPOSAL_MEDIA_TYPE),
        (ORDERED_ECONOMICS_OBSERVE_PATH, ORDERED_PROPOSAL_MEDIA_TYPE),
        (
            ORDERED_ECONOMICS_CERTIFICATE_PATH,
            ORDERED_CERTIFICATE_MEDIA_TYPE,
        ),
    ] {
        for (headers, expected) in [
            (String::new(), 415),
            (
                format!("Content-Type: {media}\r\nContent-Encoding: gzip\r\n"),
                415,
            ),
            (format!("Content-Type: {media}\r\n"), 400),
        ] {
            counters.reset();
            assert_eq!(
                request(addr, "POST", path, &headers, b"malformed"),
                expected,
                "{path}"
            );
            assert_eq!(counters.snapshot(), [0; 5], "{path}");
        }
    }
    for (path, media, body) in [
        (
            ORDERED_ECONOMICS_PROPOSE_PATH,
            ORDERED_PROPOSE_REQUEST_MEDIA_TYPE,
            &forged_request,
        ),
        (
            ORDERED_ECONOMICS_PROPOSAL_PATH,
            ORDERED_PROPOSAL_MEDIA_TYPE,
            &forged_proposal_bytes,
        ),
        (
            ORDERED_ECONOMICS_OBSERVE_PATH,
            ORDERED_PROPOSAL_MEDIA_TYPE,
            &forged_proposal_bytes,
        ),
        (
            ORDERED_ECONOMICS_CERTIFICATE_PATH,
            ORDERED_CERTIFICATE_MEDIA_TYPE,
            &forged_qc_bytes,
        ),
    ] {
        counters.reset();
        assert_eq!(
            request(
                addr,
                "POST",
                path,
                &format!("Content-Type: {media}\r\n"),
                body
            ),
            400,
            "{path}"
        );
        assert_eq!(counters.snapshot(), [0; 5], "{path}");
    }
    for (headers, body, expected) in [
        ("", b"caller-timestamp=999999".as_slice(), 400),
        ("Content-Encoding: gzip\r\n", b"".as_slice(), 415),
    ] {
        counters.reset();
        assert_eq!(
            request(addr, "POST", ORDERED_ECONOMICS_TICK_PATH, headers, body),
            expected
        );
        assert_eq!(counters.snapshot(), [0; 5]);
    }
    counters.reset();
    assert_eq!(
        request(
            addr,
            "POST",
            ORDERED_ECONOMICS_PROPOSE_PATH,
            &format!("Content-Type: {ORDERED_PROPOSE_REQUEST_MEDIA_TYPE}\r\n"),
            &vec![0; MAX_ORDERED_PROPOSE_REQUEST_BYTES + 1]
        ),
        413
    );
    assert_eq!(counters.snapshot(), [0; 5]);
    for path in [
        native_http::NODE_EVENT_PATH,
        "/v1/economics/fee-claims",
        "/v1/economics/bonds",
    ] {
        counters.reset();
        assert_eq!(request(addr, "POST", path, "", b""), 404);
        assert_eq!(counters.snapshot(), [0; 5]);
    }
    // Positive controls ensure the counters are attached to actual handlers.
    for selector in ["not-a-request-id".to_owned(), "00".repeat(32)] {
        counters.reset();
        assert_eq!(
            request(
                addr,
                "GET",
                &format!("{ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX}{selector}"),
                "",
                b""
            ),
            400
        );
        assert_eq!(counters.snapshot(), [0; 5]);
    }
    counters.reset();
    assert_eq!(
        request(
            addr,
            "GET",
            &format!("{ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX}{}", "61".repeat(32)),
            "",
            b""
        ),
        204
    );
    let outcome_reads = counters.snapshot();
    assert!(outcome_reads[0] > 0 && outcome_reads[1] > 0 && outcome_reads[2] > 0);
    assert_eq!(&outcome_reads[3..], &[0, 0]);
    counters.reset();
    assert_eq!(
        request(addr, "GET", ORDERED_ECONOMICS_STATUS_PATH, "", b""),
        200
    );
    let snapshot = counters.snapshot();
    assert!(snapshot[0] > 0 && snapshot[1] > 0 && snapshot[2] > 0);
    counters.reset();
    let bytes = ordered_economics::encode_ordered_proposal(&proposal).unwrap();
    assert_eq!(
        request(
            addr,
            "POST",
            ORDERED_ECONOMICS_PROPOSAL_PATH,
            &format!("Content-Type: {ORDERED_PROPOSAL_MEDIA_TYPE}\r\n"),
            &bytes
        ),
        200
    );
    assert!(counters.snapshot()[3] > 0);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
