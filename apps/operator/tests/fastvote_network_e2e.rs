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

fn node_config(fixture: &FastVoteGenesisFixture) -> NodeConfig {
    NodeConfig::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        b"fastvote-network-e2e/node-state".to_vec(),
    )
    .unwrap()
}

/// Builds and serves one real, SQLite-backed certified FastVote HTTP host
/// for `validator_id`, returning its bound loopback socket address and a
/// shutdown handle. The server runs on a real spawned Tokio task, accepting
/// real TCP connections -- not an in-process fake responder.
async fn spawn_validator_host(
    fixture: &FastVoteGenesisFixture,
    manifest: &GenesisManifest,
    resolver: &HashSuiteResolver,
    validator_id: ValidatorId,
    signing_key: ed25519_zebra::SigningKey,
    data_dir: &std::path::Path,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let database_path = data_dir.join(format!("{validator_id}-state.sqlite3"));
    let blob_path = data_dir.join(format!("{validator_id}-blob.sqlite3"));
    let namespace = SqliteNamespace::new(fixture.chain_id.clone(), validator_id, fixture.domain);
    let writer_fence = WriterFenceGeneration::new(1).unwrap();
    let store = SqliteDurableStore::open(&database_path, namespace, writer_fence).unwrap();
    let blob_store = SqliteBlobStore::open(&blob_path).unwrap();

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
        &store,
        &context,
        fixture.domain,
        resolver,
        &[],
        manifest,
        1,
    )
    .unwrap();

    let base_policy = LocalExecutionPolicy::generic_object_results(fixture.context.clone());
    let execution = PaidExecutionComposition::new(base_policy, manifest.fee_policy.clone());
    let signer: Arc<dyn consensus::ConsensusSigner + Send + Sync> = Arc::new(FixtureSigner {
        validator_id,
        signing_key,
    });
    let fastvote = FastVoteComposition::new(execution, signer, 1);

    let components = StructuredDurableNativeComponents::new(
        Arc::new(store),
        Arc::new(blob_store),
        Arc::new(sunrise_edge_devnet::DevnetTransport::new(
            NonZeroUsize::new(4).unwrap(),
        )),
        Arc::new(SystemClock),
        Arc::new(sunrise_edge_devnet::DevnetOutboxIdentitySource::new(
            writer_fence,
        )),
    );
    let authority = StructuredDurableRequestAuthority::new(writer_fence, 30_000, 300_000).unwrap();
    let router = certified_fastvote_router(
        components,
        fastvote,
        protocol_config(fixture),
        authority,
        node_config(fixture),
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
    (addr, stop)
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
    let fixture = genesis_fixture::build_fixture(&unique);
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
        .map(|(addr, validator)| FastVoteEndpoint {
            validator_id: validator.validator_id,
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
    let (certificate, attempts) =
        collect_fastvote_certificate(&endpoints, &certifier, &signed, deadline).unwrap();
    assert_eq!(attempts.len(), 4);
    assert!(attempts.iter().all(|attempt| attempt.result.is_ok()));
    // `try_form_certificate` is minimal: it stops accumulating as soon as
    // quorum (3 of 4 equal-power validators) is reached, independent of how
    // many of the 4 endpoints actually answered.
    assert_eq!(certificate.votes.len(), 3);

    let apply_attempts = apply_fastvote_to_all(
        &endpoints,
        &signed,
        &fixture.resolver,
        &certificate,
        deadline,
    );
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
        &signed,
        &fixture.resolver,
        &certificate,
        deadline,
    );
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
    for path in [
        node_wire::NODE_EVENT_PATH,
        "/v1/contracts/paid-executions",
        "/v1/contracts/publications",
        "/v1/contracts/executions",
    ] {
        let request = sunrise_edge_client::WireRequest {
            method: sunrise_edge_client::Method::Post,
            path: path.to_owned(),
            content_type: Some(node_wire::NODE_EVENT_MEDIA_TYPE),
            body: vec![0xAA],
            deadline: None,
        };
        let response = endpoints[0].client.transport().send(&request).unwrap();
        assert_eq!(
            response.status, 404,
            "expected {path} to be unmounted on the certified-only host, got {}",
            response.status
        );
    }

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
