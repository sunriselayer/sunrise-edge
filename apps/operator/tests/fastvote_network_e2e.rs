//! Real, multi-process-equivalent, four-validator FastVote network E2E
//! (DR-0148): actual `native_http::certified_fastvote_router` HTTP servers
//! over real loopback TCP and real SQLite durable storage, driven by the
//! actual `sunrise_edge_client::fastvote_client` network client -- prepare,
//! quorum certificate formation from the local genesis pin, and apply.
//!
//! Reuses `support::genesis_fixture` (the same real four-validator genesis
//! manifest and real sender-signed paid `transfer` intent the live
//! PostgreSQL `fastvote_pg` E2E drives) so this test exercises the identical
//! signed bytes and validator identities, just over the certified-only HTTP
//! router and SQLite instead of the PostgreSQL operator CLI.

mod support;

use execution::local_execution::LocalExecutionPolicy;
use execution::paid_execution::{PaidExecutionStatus, SignedPaidIntent, decode_signed_paid_intent};
use hashing::HashSuiteResolver;
use native_http::{
    FastVoteComposition, NativeBlockingPolicy, PaidExecutionComposition,
    StructuredDurableNativeComponents, StructuredDurableRequestAuthority,
    certified_fastvote_router,
};
use node_core::{GenesisManifest, NodeConfig, decode_genesis_manifest};
use protocol_config::TransactionAuthProfile;
use protocol_config::{DomainPlacementManifest, ProtocolConfig};
use protocol_types::{Epoch, ValidatorId};
use runtime::{
    DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    fs,
    num::NonZeroUsize,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sunrise_edge_client::{
    Client, FastVoteEndpoint, LoopbackHttpTransport, Transport, apply_fastvote_to_all,
    collect_fastvote_certificate, load_trusted_fastvote_genesis,
};
use support::genesis_fixture::{self, FastVoteGenesisFixture};

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A real, non-mocked Ed25519 `ConsensusSigner` backed by one fixture
/// validator's exact signing key.
struct FixtureSigner {
    validator_id: ValidatorId,
    signing_key: ed25519_zebra::SigningKey,
}
impl consensus::ConsensusSigner for FixtureSigner {
    fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
    fn signature_scheme(&self) -> protocol_types::SignatureSchemeId {
        protocol_types::SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
        let signature: [u8; 64] = self.signing_key.sign(framed).into();
        Ok(signature.to_vec())
    }
}

fn protocol_config(fixture: &FastVoteGenesisFixture) -> ProtocolConfig {
    let mut config = ProtocolConfig::genesis();
    config.protocol_version = fixture.protocol_version;
    config.domain_placement =
        Some(DomainPlacementManifest::single_domain(1, fixture.domain, Epoch::new(0)).unwrap());
    config.transaction_auth_profile = Some(TransactionAuthProfile::ed25519_address_is_public_key());
    config
}

/// Builds and serves one real, SQLite-backed certified FastVote HTTP host
/// for `validator_id`, returning its bound loopback socket address and a
/// shutdown handle. The server runs on a real spawned Tokio task, accepting
/// real TCP connections -- not an in-process fake responder.
struct ObservedHost {
    addr: std::net::SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    store: Arc<SqliteDurableStore>,
    blob_store: Arc<SqliteBlobStore>,
    context: DurableOperationContext,
    counters: support::observed_io::IoCounters,
}

async fn spawn_validator_host(
    fixture: &FastVoteGenesisFixture,
    manifest: &GenesisManifest,
    resolver: &HashSuiteResolver,
    validator_id: ValidatorId,
    signing_key: ed25519_zebra::SigningKey,
    data_dir: &std::path::Path,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let host = spawn_observed_host(
        fixture,
        manifest,
        resolver,
        validator_id,
        signing_key,
        data_dir,
        fixture.epoch,
        false,
    )
    .await;
    (host.addr, host.stop)
}

#[allow(clippy::too_many_arguments)]
async fn spawn_observed_host(
    fixture: &FastVoteGenesisFixture,
    manifest: &GenesisManifest,
    resolver: &HashSuiteResolver,
    validator_id: ValidatorId,
    signing_key: ed25519_zebra::SigningKey,
    data_dir: &std::path::Path,
    pinned_epoch: Epoch,
    prepare_cached: bool,
) -> ObservedHost {
    let database_path = data_dir.join(format!("{validator_id}-state.sqlite3"));
    let blob_path = data_dir.join(format!("{validator_id}-blob.sqlite3"));
    let namespace = SqliteNamespace::new(fixture.chain_id.clone(), validator_id, fixture.domain);
    let writer_fence = WriterFenceGeneration::new(1).unwrap();
    let store =
        Arc::new(SqliteDurableStore::open(&database_path, namespace, writer_fence).unwrap());
    let blob_store = Arc::new(SqliteBlobStore::open(&blob_path).unwrap());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let context = DurableOperationContext::new(
        writer_fence,
        StorageDeadline::new(now + 60_000).unwrap(),
        StorageCorrelationId::new([validator_id.as_bytes()[0]; 16]).unwrap(),
    );
    node_core::install_genesis_with_history(
        store.as_ref(),
        &context,
        fixture.domain,
        resolver,
        &[],
        manifest,
        1,
    )
    .unwrap();

    if prepare_cached {
        node_core::fast_path::prepare(
            store.as_ref(),
            blob_store.as_ref(),
            &context,
            fixture.domain,
            resolver,
            &[],
            &fixture.context,
            &LocalExecutionPolicy::generic_object_results(fixture.context.clone()),
            &manifest.fee_policy,
            &execution::LocalWasmExecutionEngine::new(),
            &FixtureSigner {
                validator_id,
                signing_key,
            },
            &fixture.paid_intent_bytes,
            1,
        )
        .unwrap();
    }
    let pinned_context = execution::publication::PublicationContext::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        pinned_epoch,
    )
    .unwrap();
    let base_policy = LocalExecutionPolicy::generic_object_results(pinned_context.clone());
    let mut fee_policy = manifest.fee_policy.clone();
    fee_policy.context = pinned_context;
    fee_policy.base_policy_digest = base_policy.digest(resolver).unwrap();
    let execution = PaidExecutionComposition::new(base_policy, fee_policy);
    let counters = support::observed_io::IoCounters::default();
    let signer: Arc<dyn consensus::ConsensusSigner + Send + Sync> = Arc::new(FixtureSigner {
        validator_id,
        signing_key,
    });
    let fastvote = FastVoteComposition::new(execution, signer, 1);

    let components = StructuredDurableNativeComponents::new(
        Arc::new(support::observed_io::Observed::new(
            store.clone(),
            &counters,
        )),
        Arc::new(support::observed_io::Observed::new(
            blob_store.clone(),
            &counters,
        )),
        Arc::new(sunrise_edge_devnet::DevnetTransport::new(
            NonZeroUsize::new(4).unwrap(),
        )),
        Arc::new(support::observed_io::Observed::new(
            Arc::new(SystemClock),
            &counters,
        )),
        Arc::new(support::observed_io::Observed::new(
            Arc::new(sunrise_edge_devnet::DevnetOutboxIdentitySource::new(
                writer_fence,
            )),
            &counters,
        )),
    );
    let authority = StructuredDurableRequestAuthority::new(writer_fence, 30_000, 300_000).unwrap();
    let router = certified_fastvote_router(
        components,
        fastvote,
        protocol_config(fixture),
        authority,
        NodeConfig::new(
            fixture.chain_id.clone(),
            fixture.protocol_version,
            pinned_epoch,
            b"fastvote-network-e2e/node-state".to_vec(),
        )
        .unwrap(),
        resolver.clone(),
        Vec::new(),
        NativeBlockingPolicy::new(NonZeroUsize::new(4).unwrap()),
    )
    .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(native_http::serve(listener, router, async {
        let _ = shutdown.await;
    }));
    ObservedHost {
        addr,
        stop,
        store,
        blob_store,
        context,
        counters,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fastvote_network_prepares_certifies_and_applies_a_real_transfer_over_real_http() {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let fixture = genesis_fixture::build_network_fixture(&unique);
    let manifest: GenesisManifest = decode_genesis_manifest(&fixture.manifest_bytes).unwrap();

    let data_dir = std::env::temp_dir().join(format!("sunrise-fastvote-net-e2e-{unique}"));
    fs::create_dir(&data_dir).unwrap();
    let _owned = TempDir(data_dir.clone());

    let mut addrs = Vec::with_capacity(4);
    let mut stops = Vec::with_capacity(4);
    for validator in &fixture.validators {
        let (addr, stop) = spawn_validator_host(
            &fixture,
            &manifest,
            &fixture.resolver,
            validator.validator_id,
            validator.signing_key,
            &data_dir,
        )
        .await;
        addrs.push(addr);
        stops.push(stop);
    }

    let endpoints: Vec<FastVoteEndpoint<LoopbackHttpTransport>> = addrs
        .iter()
        .zip(&fixture.validators)
        .enumerate()
        .map(|(index, (addr, validator))| FastVoteEndpoint {
            validator_id: validator.validator_id,
            endpoint_label: format!("127.0.0.1:{index}"),
            client: Client::new(
                LoopbackHttpTransport::new(
                    *addr,
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                    NonZeroUsize::new(64 * 1024).unwrap(),
                    NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
                )
                .unwrap(),
            ),
        })
        .collect();

    let (manifest_path, _guard) = {
        let path = std::env::temp_dir().join(format!("sunrise-fastvote-net-e2e-manifest-{unique}"));
        fs::write(&path, &fixture.manifest_bytes).unwrap();
        (path.clone(), scopeguard(path))
    };
    let certifier = load_trusted_fastvote_genesis(
        &manifest_path,
        &fixture.resolver,
        fixture.manifest_digest,
        &fixture.context,
    )
    .unwrap();

    let signed: SignedPaidIntent = decode_signed_paid_intent(&fixture.paid_intent_bytes).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let per_request_cap = Duration::from_secs(10);
    let (certificate, attempts) = collect_fastvote_certificate(
        &endpoints,
        &certifier,
        &fixture.resolver,
        &signed,
        deadline,
        per_request_cap,
    )
    .unwrap();
    assert_eq!(attempts.len(), 4);
    assert!(attempts.iter().all(|attempt| attempt.result.is_ok()));
    // `try_form_certificate` is minimal: it stops accumulating as soon as
    // quorum (3 of 4 equal-power validators) is reached, independent of how
    // many of the 4 endpoints actually answered.
    assert_eq!(certificate.votes.len(), 3);

    let apply_attempts = apply_fastvote_to_all(
        &endpoints,
        &certifier,
        &signed,
        &fixture.resolver,
        &certificate,
        deadline,
        per_request_cap,
    )
    .unwrap();
    assert_eq!(apply_attempts.len(), 4);
    for attempt in &apply_attempts {
        let result = attempt.result.as_ref().unwrap_or_else(|error| {
            panic!("validator {} apply failed: {error}", attempt.validator_id)
        });
        assert_eq!(result.status, PaidExecutionStatus::Success);
        assert_eq!(result.request_id, signed.intent.request_id);
    }

    // Exact replay: the identical signed bytes and certificate, resubmitted
    // to every endpoint, must return the identical committed result rather
    // than re-executing or rejecting as a fresh request.
    let replay_attempts = apply_fastvote_to_all(
        &endpoints,
        &certifier,
        &signed,
        &fixture.resolver,
        &certificate,
        deadline,
        per_request_cap,
    )
    .unwrap();
    assert_eq!(replay_attempts.len(), 4);
    for (first, replay) in apply_attempts.iter().zip(&replay_attempts) {
        let first_result = first.result.as_ref().unwrap();
        let replay_result = replay.result.as_ref().unwrap_or_else(|error| {
            panic!(
                "validator {} exact replay failed: {error}",
                replay.validator_id
            )
        });
        assert_eq!(first_result.status, replay_result.status);
        assert_eq!(first_result.request_id, replay_result.request_id);
        assert_eq!(first_result.charged, replay_result.charged);
    }

    // Certified-only hosting: the direct/legacy mutating routes never exist
    // on the real running server, checked over a genuine HTTP round trip
    // (not merely at router-construction time in a unit test).
    for path in native_http::CERTIFIED_FASTVOTE_EXCLUDED_MUTATION_PATHS {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            assert_eq!(
                raw_http_status(addrs[0], method, path),
                404,
                "{method} {path}"
            );
        }
    }
    assert_eq!(
        raw_http_status(addrs[0], "GET", node_wire::QUERY_CONTEXT_PATH),
        200
    );
    assert_eq!(
        raw_http_status(addrs[0], "GET", "/v1/contracts/paid-fee-policy"),
        200
    );

    for stop in stops {
        let _ = stop.send(());
    }
}

/// Minimal RAII temp-file guard so the manifest file used only to exercise
/// [`load_trusted_fastvote_genesis`] is removed even on an early panic.
struct FileGuard(PathBuf);
impl Drop for FileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn scopeguard(path: PathBuf) -> FileGuard {
    FileGuard(path)
}

fn raw_http_status(addr: std::net::SocketAddr, method: &str, path: &str) -> u16 {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response: Vec<u8> = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8_lossy(&response)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn unique(label: &str) -> String {
    format!(
        "{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn owned_directory(unique: &str) -> TempDir {
    let path = std::env::temp_dir().join(format!("sunrise-fastvote-{unique}"));
    fs::create_dir(&path).unwrap();
    TempDir(path)
}

fn transport(addr: std::net::SocketAddr) -> LoopbackHttpTransport {
    LoopbackHttpTransport::new(
        addr,
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        NonZeroUsize::new(64 * 1024).unwrap(),
        NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
    )
    .unwrap()
}

fn post(
    transport: &LoopbackHttpTransport,
    path: &str,
    media: &'static str,
    body: Vec<u8>,
) -> sunrise_edge_client::WireResponse {
    transport
        .send(&sunrise_edge_client::WireRequest {
            method: sunrise_edge_client::Method::Post,
            path: path.to_owned(),
            content_type: Some(media),
            body,
            deadline: None,
        })
        .unwrap()
}

fn apply_body(signed_paid_intent: Vec<u8>, certificate: Vec<u8>) -> Vec<u8> {
    node_wire::FastVoteApplyRequest {
        signed_paid_intent,
        certificate,
    }
    .encode()
    .unwrap()
}

fn with_context(
    fixture: &FastVoteGenesisFixture,
    context: execution::publication::PublicationContext,
    request_id: [u8; 32],
) -> Vec<u8> {
    let mut intent = decode_signed_paid_intent(&fixture.paid_intent_bytes)
        .unwrap()
        .intent;
    intent.context = context.clone();
    intent.request_id = request_id;
    if let execution::paid_execution::PaidApplication::Call(call) = &mut intent.application {
        call.context = context;
        call.request_id = request_id;
    }
    fixture.sign_intent(intent)
}

/// Both real production handlers use these observed runtime components.
/// Counting all code/object/store/blob prerequisites proves that execution
/// cannot be reached on an unauthenticated rejection; the concrete WASM engine
/// has no synthetic test counter and cannot execute without those reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_handlers_authenticate_before_actual_identity_clock_store_and_blob_io() {
    let unique = unique("auth");
    let fixture = genesis_fixture::build_network_fixture(&unique);
    let manifest = decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let owned = owned_directory(&unique);
    let validator = &fixture.validators[0];
    let host = spawn_observed_host(
        &fixture,
        &manifest,
        &fixture.resolver,
        validator.validator_id,
        validator.signing_key,
        &owned.0,
        fixture.epoch,
        false,
    )
    .await;
    let transport = transport(host.addr);
    let mut corrupt = decode_signed_paid_intent(&fixture.paid_intent_bytes).unwrap();
    corrupt.signature[0] ^= 1;
    let corrupt_bytes = execution::paid_execution::encode_signed_paid_intent(&corrupt).unwrap();
    // Canonically well formed, so this negative reaches signature verification.
    assert!(decode_signed_paid_intent(&corrupt_bytes).is_ok());
    let wrong_chain =
        genesis_fixture::build_network_fixture(&format!("{unique}-foreign")).paid_intent_bytes;
    let wrong_protocol = genesis_fixture::build_fixture_with_protocol(
        &unique,
        protocol_types::ProtocolVersion::new(4),
        fixture.epoch,
    )
    .paid_intent_bytes;

    for path in [
        node_wire::FASTVOTE_PREPARE_PATH,
        node_wire::FASTVOTE_CERTIFICATES_PATH,
    ] {
        let wrap = |signed: Vec<u8>| {
            if path == node_wire::FASTVOTE_CERTIFICATES_PATH {
                // Apply envelope decoding is independent of certificate verification;
                // authentication must reject first even with these certificate bytes.
                apply_body(signed, vec![0xAA])
            } else {
                signed
            }
        };
        let oversized = if path == node_wire::FASTVOTE_PREPARE_PATH {
            sunrise_edge_client::MAX_SIGNED_PAID_INTENT_BYTES + 1
        } else {
            node_wire::MAX_FASTVOTE_APPLY_REQUEST_BYTES + 1
        };
        let cases = [
            ("text/plain", vec![0xAA], 415),
            (node_wire::NODE_EVENT_MEDIA_TYPE, vec![0; oversized], 413),
            (node_wire::NODE_EVENT_MEDIA_TYPE, vec![0xAA; 64], 400),
            (
                node_wire::NODE_EVENT_MEDIA_TYPE,
                wrap(corrupt_bytes.clone()),
                400,
            ),
            (
                node_wire::NODE_EVENT_MEDIA_TYPE,
                wrap(wrong_chain.clone()),
                400,
            ),
            (
                node_wire::NODE_EVENT_MEDIA_TYPE,
                wrap(wrong_protocol.clone()),
                400,
            ),
        ];
        for (media, body, status) in cases {
            host.counters.reset();
            let response = post(&transport, path, media, body);
            assert_eq!(
                response.status,
                status,
                "{path}: {}",
                String::from_utf8_lossy(&response.body)
            );
            assert_eq!(
                host.counters.snapshot(),
                [0; 5],
                "{path}: actual runtime I/O before authentication"
            );
        }
    }
    // Positive control: these exact wrappers are used by the live handler,
    // rather than being disconnected counters.
    host.counters.reset();
    assert_eq!(
        post(
            &transport,
            node_wire::FASTVOTE_PREPARE_PATH,
            node_wire::NODE_EVENT_MEDIA_TYPE,
            fixture.paid_intent_bytes.clone()
        )
        .status,
        200
    );
    let counts = host.counters.snapshot();
    assert!(
        counts[0] > 0 && counts[1] > 0 && counts[2] > 0 && counts[3] > 0,
        "{counts:?}"
    );
    host.counters.reset();
    let response = post(
        &transport,
        node_wire::FASTVOTE_CERTIFICATES_PATH,
        node_wire::NODE_EVENT_MEDIA_TYPE,
        apply_body(fixture.paid_intent_bytes.clone(), vec![0xAA]),
    );
    assert_eq!(response.status, 400);
    let counts = host.counters.snapshot();
    assert!(
        counts[0] > 0 && counts[1] > 0 && counts[2] > 0,
        "apply counters are connected: {counts:?}"
    );
    let _ = host.stop.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn declared_previous_and_future_epochs_refuse_both_handlers_without_durable_changes() {
    let unique = unique("declared");
    let fixture = genesis_fixture::build_network_fixture_at_epoch(&unique, Epoch::new(1));
    let manifest = decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let owned = owned_directory(&unique);
    let validator = &fixture.validators[0];
    let host = spawn_observed_host(
        &fixture,
        &manifest,
        &fixture.resolver,
        validator.validator_id,
        validator.signing_key,
        &owned.0,
        fixture.epoch,
        false,
    )
    .await;
    let transport = transport(host.addr);
    let before = support::durable_state::snapshot(&host.store, &host.context, &fixture);
    for epoch in [Epoch::new(0), Epoch::new(2)] {
        let context = execution::publication::PublicationContext::new(
            fixture.chain_id.clone(),
            fixture.protocol_version,
            epoch,
        )
        .unwrap();
        let signed = with_context(&fixture, context, [0xE0 + epoch.get() as u8; 32]);
        for path in [
            node_wire::FASTVOTE_PREPARE_PATH,
            node_wire::FASTVOTE_CERTIFICATES_PATH,
        ] {
            host.counters.reset();
            let body = if path == node_wire::FASTVOTE_CERTIFICATES_PATH {
                apply_body(signed.clone(), vec![0xAA])
            } else {
                signed.clone()
            };
            let response = post(&transport, path, node_wire::NODE_EVENT_MEDIA_TYPE, body);
            assert_eq!(response.status, 409);
            assert_eq!(response.body, b"fastvote-epoch-repin-required");
            assert_eq!(host.counters.snapshot()[3], 0, "no commit on epoch refusal");
            assert_eq!(
                support::durable_state::snapshot(&host.store, &host.context, &fixture),
                before
            );
            for key in [
                node_core::local_instance_state::fastpath_prepared_record_key(
                    &fixture.chain_id,
                    &[0xE0 + epoch.get() as u8; 32],
                )
                .unwrap(),
                node_core::local_instance_state::fastpath_nonce_lock_key(
                    &fixture.chain_id,
                    &fixture.sender,
                    epoch,
                )
                .unwrap(),
                node_core::local_instance_state::fastpath_lock_key(
                    &fixture.chain_id,
                    fixture.fee_coin,
                )
                .unwrap(),
            ] {
                assert!(
                    runtime::DurableDomainStateStore::get_versioned_durable(
                        host.store.as_ref(),
                        &host.context,
                        fixture.domain,
                        &key
                    )
                    .unwrap()
                    .value()
                    .is_none()
                );
            }
        }
    }
    let _ = host.stop.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_host_refuses_a_genuine_cached_future_vote_and_fresh_future_apply() {
    let unique = unique("cached");
    let fixture = genesis_fixture::build_network_fixture_at_epoch(&unique, Epoch::new(1));
    let manifest = decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let owned = owned_directory(&unique);
    let validator = &fixture.validators[0];
    let host = spawn_observed_host(
        &fixture,
        &manifest,
        &fixture.resolver,
        validator.validator_id,
        validator.signing_key,
        &owned.0,
        Epoch::new(0),
        true,
    )
    .await;
    let key = node_core::local_instance_state::fastpath_prepared_record_key(
        &fixture.chain_id,
        &fixture.request_id,
    )
    .unwrap();
    let observed = runtime::DurableDomainStateStore::get_versioned_durable(
        host.store.as_ref(),
        &host.context,
        fixture.domain,
        &key,
    )
    .unwrap();
    let prepared =
        node_core::fast_path::records::decode_fastpath_prepared_record(observed.value().unwrap())
            .unwrap();
    assert_eq!(prepared.context.epoch(), Epoch::new(1));
    let fixed_context = execution::publication::PublicationContext::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        Epoch::new(0),
    )
    .unwrap();
    let fixed_policy = LocalExecutionPolicy::generic_object_results(fixed_context.clone());
    let mut fixed_fee = manifest.fee_policy.clone();
    fixed_fee.context = fixed_context;
    fixed_fee.base_policy_digest = fixed_policy.digest(&fixture.resolver).unwrap();
    // Prove this is the real valid cached branch, which intentionally does
    // not re-run fresh admission against a changed execution policy.
    let cached_vote = node_core::fast_path::prepare(
        host.store.as_ref(),
        host.blob_store.as_ref(),
        &host.context,
        fixture.domain,
        &fixture.resolver,
        &[],
        &fixture.context,
        &fixed_policy,
        &fixed_fee,
        &execution::LocalWasmExecutionEngine::new(),
        &FixtureSigner {
            validator_id: validator.validator_id,
            signing_key: validator.signing_key,
        },
        &fixture.paid_intent_bytes,
        1,
    )
    .unwrap();
    assert_eq!(
        consensus::encode_fast_vote(&cached_vote).unwrap(),
        prepared.vote
    );
    let before = support::durable_state::snapshot(&host.store, &host.context, &fixture);
    let transport = transport(host.addr);
    host.counters.reset();
    let response = post(
        &transport,
        node_wire::FASTVOTE_PREPARE_PATH,
        node_wire::NODE_EVENT_MEDIA_TYPE,
        fixture.paid_intent_bytes.clone(),
    );
    assert_eq!(response.status, 409);
    assert_eq!(response.body, b"fastvote-epoch-repin-required");
    assert_eq!(host.counters.snapshot(), [0; 5]);
    // This authenticated e+1 apply reaches receipt reconciliation, then the
    // trusted policy pin check, even though its epoch equals the live epoch.
    let response = post(
        &transport,
        node_wire::FASTVOTE_CERTIFICATES_PATH,
        node_wire::NODE_EVENT_MEDIA_TYPE,
        apply_body(fixture.paid_intent_bytes.clone(), vec![0xAA]),
    );
    assert_eq!(response.status, 409);
    assert_eq!(response.body, b"fastvote-epoch-repin-required");
    assert_eq!(host.counters.snapshot()[3], 0);
    assert_eq!(
        support::durable_state::snapshot(&host.store, &host.context, &fixture),
        before
    );
    let _ = host.stop.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changed_live_epoch_refuses_fixed_host_new_work_but_replays_exact_committed_receipt() {
    let unique = unique("historical");
    let fixture = genesis_fixture::build_network_fixture(&unique);
    let manifest = decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let owned = owned_directory(&unique);
    let mut hosts = Vec::new();
    for validator in &fixture.validators {
        hosts.push(
            spawn_observed_host(
                &fixture,
                &manifest,
                &fixture.resolver,
                validator.validator_id,
                validator.signing_key,
                &owned.0,
                fixture.epoch,
                false,
            )
            .await,
        );
    }
    let endpoints: Vec<FastVoteEndpoint<LoopbackHttpTransport>> = hosts
        .iter()
        .zip(&fixture.validators)
        .map(|(host, validator)| FastVoteEndpoint {
            validator_id: validator.validator_id,
            endpoint_label: host.addr.to_string(),
            client: Client::new(transport(host.addr)),
        })
        .collect();
    let infos: Vec<validator_set::ValidatorInfo> = manifest
        .validator_set
        .validators
        .iter()
        .map(|entry| validator_set::ValidatorInfo {
            id: entry.id,
            voting_power: entry.voting_power,
            signature_scheme: entry.signature_scheme,
            public_key: entry.public_key.clone(),
        })
        .collect();
    let certifier = consensus::FastPathCertifier::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        validator_set::ValidatorSet::new(fixture.epoch, infos).unwrap(),
    )
    .unwrap();
    let signed = decode_signed_paid_intent(&fixture.paid_intent_bytes).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let (certificate, _) = collect_fastvote_certificate(
        &endpoints,
        &certifier,
        &fixture.resolver,
        &signed,
        deadline,
        Duration::from_secs(5),
    )
    .unwrap();
    let certificate_bytes = consensus::encode_fast_certificate(&certificate).unwrap();
    let original_body = apply_body(fixture.paid_intent_bytes.clone(), certificate_bytes.clone());
    let first = post(
        endpoints[0].client.transport(),
        node_wire::FASTVOTE_CERTIFICATES_PATH,
        node_wire::NODE_EVENT_MEDIA_TYPE,
        original_body.clone(),
    );
    assert_eq!(first.status, 200);
    let host = &hosts[0];
    let key =
        node_core::local_instance_state::fastpath_epoch_record_key(&fixture.chain_id).unwrap();
    let observed = runtime::DurableDomainStateStore::get_versioned_durable(
        host.store.as_ref(),
        &host.context,
        fixture.domain,
        &key,
    )
    .unwrap();
    let mut live =
        node_core::local_instance_state::decode_fastpath_epoch_record(observed.value().unwrap())
            .unwrap();
    live.previous_epoch = Some(fixture.epoch);
    live.current_epoch = Epoch::new(1);
    // Controlled fixture change of the local live record only; no lifecycle
    // ingress, validator handoff, or global owned-state safety claim.
    support::durable_state::set_epoch(
        &host.store,
        &host.context,
        fixture.domain,
        &fixture.chain_id,
        &live,
    );
    let before = support::durable_state::snapshot(&host.store, &host.context, &fixture);
    let old_fresh = fixture.sign_transfer([0xF1; 32], 1, [0x31; 32]);
    let future_context = execution::publication::PublicationContext::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        Epoch::new(1),
    )
    .unwrap();
    let future_fresh = with_context(&fixture, future_context, [0xF2; 32]);
    for bytes in [old_fresh, future_fresh] {
        for path in [
            node_wire::FASTVOTE_PREPARE_PATH,
            node_wire::FASTVOTE_CERTIFICATES_PATH,
        ] {
            let body = if path == node_wire::FASTVOTE_PREPARE_PATH {
                bytes.clone()
            } else {
                apply_body(bytes.clone(), certificate_bytes.clone())
            };
            host.counters.reset();
            let response = post(
                endpoints[0].client.transport(),
                path,
                node_wire::NODE_EVENT_MEDIA_TYPE,
                body,
            );
            assert_eq!(response.status, 409);
            assert_eq!(response.body, b"fastvote-epoch-repin-required");
            assert_eq!(host.counters.snapshot()[3], 0);
            assert_eq!(
                support::durable_state::snapshot(&host.store, &host.context, &fixture),
                before
            );
        }
    }
    host.counters.reset();
    let replay = post(
        endpoints[0].client.transport(),
        node_wire::FASTVOTE_CERTIFICATES_PATH,
        node_wire::NODE_EVENT_MEDIA_TYPE,
        original_body,
    );
    assert_eq!(replay.status, 200);
    assert_eq!(
        replay.body, first.body,
        "exact historical committed result, including fee charge"
    );
    assert_eq!(
        host.counters.snapshot()[3],
        0,
        "no receipt or fee reapplication"
    );
    assert_eq!(
        support::durable_state::snapshot(&host.store, &host.context, &fixture),
        before
    );
    for host in hosts {
        let _ = host.stop.send(());
    }
}
