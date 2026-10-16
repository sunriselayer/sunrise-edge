//! Real compiled `sqlite_source_host` process acceptance.
//!
//! Four actual `env!("CARGO_BIN_EXE_sqlite_source_host")` child processes,
//! each opening its own already frozen/drained SQLite source file under the
//! real signed causal genesis fixture (original trusted manifest/digest,
//! four distinct real local validator keys), serve one genuine EMPTY
//! ordered round plus a pause/reopen/signerless-replay cycle over real
//! loopback HTTP. Every host owns its own persisted state-db and signing-
//! key file; the shared blob-db is the same genuine immutable public blob
//! repository convention used by the rest of this suite.
//!
//! Boundary: this file never drives a Seal or a paid FastVote call through
//! the compiled binary. Freeze closes ordinary paid admission, so a fresh
//! post-Freeze paid transfer is not a safe positive case here; driving a
//! real Seal needs the readiness-certificate pipeline owned by
//! conditional_readiness_sqlite.rs, which this exclusively-owned new file
//! must not duplicate or edit. ordered_seal_sqlite_acceptance.rs keeps its
//! existing in-process four-validator network, including SealWarrantFault,
//! which wraps DurableDomainStateStore from inside the test process with no
//! compiled-binary equivalent hook; that coverage is left unchanged.
//!
//! DR-0256 adds one additional selected real-SIGTERM oracle against the
//! certified FastVote router's own unsigned, no-payload frontier-maintenance
//! `advance` route. That route carries no signed intent, candidate or
//! certificate, so this remains within the existing boundary above: this
//! file still never drives a paid FastVote prepare/apply/publication call or
//! a Seal through the compiled binary.

#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[allow(dead_code)]
#[path = "business_cut/fixture.rs"]
mod fixture;
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;

use canonical_encoding::{decode_canonical_frame, decode_digest32};
use consensus::{
    ConsensusProposal, QuorumCertificate, decode_availability_identity,
    decode_frozen_frontier_identity, decode_proposal,
};
use fixture::Fixture;
use node_core::business_reconstruction::{SourceBusinessSnapshot, SourceSnapshotRecord};
use node_core::ordered_economics::{
    OrderedEconomicsEnvironment, OrderedProposal, OrderedStatus, decode_ordered_proposal,
    decode_ordered_status, query_status,
};
use node_wire::ordered_economics::{
    ORDERED_ECONOMICS_PROPOSE_PATH, ORDERED_PROPOSE_REQUEST_MEDIA_TYPE, OrderedProposeRequest,
};
use node_wire::{FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH, NODE_EVENT_MEDIA_TYPE};
use protocol_types::{Digest32, ValidatorId};
use runtime::{
    Clock, DurableDomainStateStore, DurableOperationContext, OutgoingBarrier, StorageCorrelationId,
    StorageDeadline, SystemClock, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
use sunrise_edge_client::ordered_economics_client::{
    ArtifactSink, OrderedEconomicsEndpoint, RoundOutcome, drive_empty_ordered_round,
    replay_declared_prefix_with_sink,
};
use sunrise_edge_client::{
    Client, LoopbackHttpTransport, Method, Transport, WireRequest, WireResponse,
};
use sunrise_edge_operator::business_snapshot::capture_source_business_snapshot;

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

struct HostProcess {
    child: Child,
    address: SocketAddr,
    generation: u64,
}

impl Drop for HostProcess {
    fn drop(&mut self) {
        let _ignored = self.child.kill();
        let _ignored = self.child.wait();
    }
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace()
        .find_map(|token: &str| token.strip_prefix(key))
        .unwrap_or_else(|| panic!("host line lacks {key}: {line}"))
        .to_owned()
}

#[allow(clippy::too_many_arguments)]
fn start_host(
    fixture: &Fixture,
    genesis: &Path,
    blob_db: &Path,
    state_db: &Path,
    key_file: &Path,
    validator_id: ValidatorId,
) -> HostProcess {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_source_host"));
    command.args([
        "--chain-id",
        fixture.network.chain_id.as_str(),
        "--validator-id",
        &hex(validator_id.as_bytes()),
        "--domain",
        &hex(fixture.network.domain.as_bytes()),
        "--protocol-version",
        &fixture.network.protocol_version.get().to_string(),
        "--epoch",
        &fixture.network.epoch.get().to_string(),
        "--suite",
        "0:1:1:1:1:1:1:1",
        "--genesis-manifest",
        genesis.to_str().unwrap(),
        "--expected-genesis-digest",
        &hex(&fixture.network.manifest_digest),
        "--signing-key-file",
        key_file.to_str().unwrap(),
        "--state-db",
        state_db.to_str().unwrap(),
        "--blob-db",
        blob_db.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--created-checkpoint",
        "1000",
        "--timeout-seconds",
        "30",
        "--max-concurrent",
        "4",
        "--confirm-offline-fence-advance",
    ]);
    let startup_deadline: Duration = Duration::from_secs(30);
    let startup_byte_cap: std::num::NonZeroUsize =
        compiled_source_host_process::compiled_host_startup_line_limit(
            fixture.network.chain_id.as_str(),
        );
    let (mut guard, line) = compiled_source_host_process::spawn_bounded_status_line(
        command,
        startup_deadline,
        startup_byte_cap,
    );
    if line.is_empty() {
        panic!(
            "sqlite-source-host exited before serving: {:?}",
            guard.try_wait()
        );
    }
    assert!(line.contains("complete=true mode=serving"), "{line}");
    HostProcess {
        address: field(&line, "listen=").parse().unwrap(),
        generation: field(&line, "writer_generation=").parse().unwrap(),
        child: guard.into_inner(),
    }
}

fn transport(address: SocketAddr) -> LoopbackHttpTransport {
    LoopbackHttpTransport::new(
        address,
        Duration::from_secs(10),
        Duration::from_secs(600),
        Duration::from_secs(60),
        NonZeroUsize::new(64 * 1024).unwrap(),
        NonZeroUsize::new(64 * 1024 * 1024).unwrap(),
    )
    .unwrap()
}

fn raw_status(address: SocketAddr) -> WireResponse {
    transport(address)
        .send(&WireRequest {
            method: Method::Get,
            path: node_wire::ordered_economics::ORDERED_ECONOMICS_STATUS_PATH.to_owned(),
            content_type: None,
            body: Vec::new(),
            deadline: None,
        })
        .unwrap()
}

fn status(address: SocketAddr) -> OrderedStatus {
    let response: WireResponse = raw_status(address);
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    decode_ordered_status(&response.body).unwrap()
}

struct Sink;
impl ArtifactSink for Sink {
    fn persist(&mut self, _name: &str, _bytes: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
}

fn ordered_endpoints(
    fixture: &Fixture,
    hosts: &[Option<&HostProcess>],
) -> Vec<OrderedEconomicsEndpoint<LoopbackHttpTransport>> {
    hosts
        .iter()
        .zip(&fixture.network.validators)
        .filter_map(|(host, validator)| {
            host.map(|host: &HostProcess| OrderedEconomicsEndpoint {
                validator_id: validator.validator_id,
                endpoint_label: host.address.to_string(),
                client: Client::new(transport(host.address)),
            })
        })
        .collect()
}

fn round(
    endpoints: &[OrderedEconomicsEndpoint<LoopbackHttpTransport>],
    policy: &node_core::ordered_economics::OrderedEconomicsPolicy,
    parent: Option<&QuorumCertificate>,
) -> RoundOutcome {
    let deadline: Instant = Instant::now() + Duration::from_secs(600);
    drive_empty_ordered_round(
        endpoints,
        policy,
        parent,
        deadline,
        Duration::from_secs(60),
        &mut Sink,
    )
    .unwrap()
}

#[test]
fn compiled_sqlite_source_host_processes_serve_real_rounds_and_reconnect_with_a_fresh_fence() {
    let mut fixture: Fixture = Fixture::new();
    fixture.freeze_and_complete();

    let genesis: PathBuf = fixture.directory.0.join("genesis.bin");
    std::fs::write(&genesis, &fixture.network.manifest_bytes).unwrap();
    let blob_db: PathBuf = fixture.directory.0.join("blobs.sqlite");
    let mut key_files: Vec<PathBuf> = Vec::new();
    for (index, validator) in fixture.network.validators.iter().enumerate() {
        let key_path: PathBuf = fixture.directory.0.join(format!("source-host-{index}.key"));
        std::fs::write(&key_path, validator.seed).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        key_files.push(key_path);
    }
    // Close every in-process handle before any compiled host claims the
    // writer fence against the exact same files.
    fixture.stores.clear();

    let state_db = |index: usize| fixture.directory.0.join(format!("state-{index}.sqlite"));
    let mut hosts: Vec<HostProcess> = (0..4)
        .map(|index: usize| {
            start_host(
                &fixture,
                &genesis,
                &blob_db,
                &state_db(index),
                &key_files[index],
                fixture.network.validators[index].validator_id,
            )
        })
        .collect();
    for host in &hosts {
        assert_eq!(
            host.generation, 2,
            "the fixture's stores close at writer fence 1, so each first real compiled claim is exactly generation 2, not merely a higher one"
        );
    }

    // The genuine post-Drain source has QC8 and committed_height 6, exactly
    // as the in-process ordered_seal_sqlite_acceptance network observes on
    // the same fixture construction, now reported by a real compiled
    // process rather than queried liveness alone.
    let initial: OrderedStatus = status(hosts[0].address);
    assert_eq!(initial.high_qc.height, 8);
    assert_eq!(initial.committed_height, 6);

    // One genuine EMPTY ordered round, quorum-formed over real loopback
    // HTTP against all four real compiled processes.
    let all_endpoints = ordered_endpoints(
        &fixture,
        &[
            Some(&hosts[0]),
            Some(&hosts[1]),
            Some(&hosts[2]),
            Some(&hosts[3]),
        ],
    );
    let outcome: RoundOutcome = round(&all_endpoints, &fixture.policy, None);
    assert!(outcome.qc_formed_from.len() >= 3);
    let advanced: OrderedStatus = status(hosts[0].address);
    assert!(advanced.committed_height > initial.committed_height);

    // Same-boot replay: resubmitting the already-certified round to the
    // same running process is a genuine no-op, not a fresh commit.
    replay_declared_prefix_with_sink(
        &ordered_endpoints(&fixture, &[Some(&hosts[0]), None, None, None]),
        &fixture.policy,
        &[(
            outcome.proposal_bytes.clone(),
            outcome.certificate_bytes.clone(),
        )],
        Instant::now() + Duration::from_secs(600),
        Duration::from_secs(60),
        &mut Sink,
    )
    .unwrap();
    assert_eq!(
        status(hosts[0].address),
        advanced,
        "same-boot replay of an already-certified round changes nothing"
    );

    // Pause the fourth real process, certify one more EMPTY round without
    // it, then reopen it as a fresh real process and catch it up through
    // real signerless replay.
    let paused: HostProcess = hosts.remove(3);
    let paused_generation: u64 = paused.generation;
    drop(paused);
    let alive = ordered_endpoints(
        &fixture,
        &[Some(&hosts[0]), Some(&hosts[1]), Some(&hosts[2]), None],
    );
    let missed: RoundOutcome = round(&alive, &fixture.policy, None);
    let reopened: HostProcess = start_host(
        &fixture,
        &genesis,
        &blob_db,
        &state_db(3),
        &key_files[3],
        fixture.network.validators[3].validator_id,
    );
    assert_eq!(
        reopened.generation,
        paused_generation.checked_add(1).unwrap(),
        "reopening a real process claims exactly the next writer fence, not merely a higher one"
    );
    replay_declared_prefix_with_sink(
        &ordered_endpoints(&fixture, &[None, None, None, Some(&reopened)]),
        &fixture.policy,
        &[(
            missed.proposal_bytes.clone(),
            missed.certificate_bytes.clone(),
        )],
        Instant::now() + Duration::from_secs(600),
        Duration::from_secs(60),
        &mut Sink,
    )
    .unwrap();
    let caught_up: OrderedStatus = status(reopened.address);
    assert_eq!(
        caught_up.high_qc,
        status(hosts[0].address).high_qc,
        "the paused real process caught up through verified signerless replay"
    );
    hosts.push(reopened);

    for host in hosts {
        drop(host);
    }

    // Final direct, in-process re-check of what the compiled processes
    // actually persisted. The writer fence has moved past the original
    // fixture-construction context, so each check reads the current real
    // fence first and builds a genuinely current observation context from
    // it, instead of reusing the now-stale original context.
    for index in 0..4 {
        let namespace: SqliteNamespace = SqliteNamespace::new(
            fixture.network.chain_id.clone(),
            fixture.network.validators[index].validator_id,
            fixture.network.domain,
        );
        let reopened_store: SqliteDurableStore =
            SqliteDurableStore::open_existing(state_db(index), namespace).unwrap();
        let current_fence = reopened_store.writer_fence().unwrap();
        assert_eq!(
            current_fence.get(),
            if index == 3 { 3 } else { 2 },
            "only the paused-and-reopened host advanced past its first real claim"
        );
        let now_millis: u64 = SystemClock.now_unix_millis().unwrap();
        let current_operation: DurableOperationContext = DurableOperationContext::new(
            current_fence,
            StorageDeadline::new(now_millis.checked_add(60_000).unwrap()).unwrap(),
            StorageCorrelationId::new([0x62; 16]).unwrap(),
        );
        let env = OrderedEconomicsEnvironment {
            policy: &fixture.policy,
            history: &[],
            leg_policy: &fixture.local_policy,
            engine: &fixture.engine,
            blobs: &fixture.blobs,
            seal: None,
        };
        let final_status = query_status(&reopened_store, &current_operation, &env).unwrap();
        assert_eq!(final_status.high_qc, caught_up.high_qc);
        assert_eq!(
            reopened_store
                .get_outgoing_barrier(&current_operation, fixture.network.domain)
                .unwrap(),
            OutgoingBarrier::Unsealed,
            "no Seal was attempted through the compiled binary in this acceptance"
        );
    }
}

/// A second real compiled claim against the exact same already-served
/// state file is not a race: DR-0192 says each open claims one fresh
/// writer generation and never reclaims it mid-request, so the first
/// process's own baked-in generation becomes genuinely stale the instant a
/// second real process claims the next one, even while the first process
/// is still alive and listening. This drives that exact fencing contract
/// through two real compiled processes and one real HTTP read each, not a
/// raw storage-layer assertion.
#[test]
fn compiled_sqlite_source_host_second_claim_fences_the_first_live_process() {
    let mut fixture: Fixture = Fixture::new();
    fixture.freeze_and_complete();

    let genesis: PathBuf = fixture.directory.0.join("genesis.bin");
    std::fs::write(&genesis, &fixture.network.manifest_bytes).unwrap();
    let blob_db: PathBuf = fixture.directory.0.join("blobs.sqlite");
    let validator = &fixture.network.validators[0];
    let key_path: PathBuf = fixture.directory.0.join("stale-writer.key");
    std::fs::write(&key_path, validator.seed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let state_db: PathBuf = fixture.directory.0.join("state-0.sqlite");
    // Close every in-process handle before any compiled host claims the
    // writer fence against this exact file.
    fixture.stores.clear();

    let first: HostProcess = start_host(
        &fixture,
        &genesis,
        &blob_db,
        &state_db,
        &key_path,
        validator.validator_id,
    );
    assert_eq!(
        first.generation, 2,
        "the cloned file closes at writer fence 1, so the first real claim is exactly generation 2"
    );
    let first_status: OrderedStatus = status(first.address);
    assert_eq!(first_status.committed_height, 6);

    // Second real compiled process, same exact state file, while the first
    // is still alive and listening: a genuinely valid, exact next claim.
    let second: HostProcess = start_host(
        &fixture,
        &genesis,
        &blob_db,
        &state_db,
        &key_path,
        validator.validator_id,
    );
    assert_eq!(
        second.generation, 3,
        "a second real claim against the same file is exactly the next writer generation"
    );

    // Valid current positive: the second, genuinely current process still
    // serves ordinary reads over real loopback HTTP.
    let second_status: OrderedStatus = status(second.address);
    assert_eq!(second_status.high_qc, first_status.high_qc);
    assert_eq!(
        second_status.committed_height,
        first_status.committed_height
    );

    // Stale-writer negative: the first process's baked-in generation 2 no
    // longer matches the persisted fence (now 3), so its own real HTTP
    // read is refused with the ordered route's persistence-unavailable response,
    // never a stale 200.
    let stale_response: WireResponse = raw_status(first.address);
    assert_eq!(
        stale_response.status,
        503,
        "{}",
        String::from_utf8_lossy(&stale_response.body)
    );
    assert_eq!(stale_response.body, b"ordered-economics-unavailable");

    drop(first);
    drop(second);
}

/// DR-0254: deterministic real-factory + real-SIGTERM wiring oracle. See
/// `docs/architecture/native-source-host-sigterm-wiring-oracle.md` for the
/// exact, limited claim. This isolates the compiled host's own SIGTERM ->
/// `NativeBlockingExecutor::close()` -> ordered-economics `admitted()`/
/// `build_context()` cancellation wiring; it is not a real-binary late-
/// pre-storage window isolation, a FastVote/successor/historical/TLS
/// qualification, or a D05/M5 closure.
struct LeaderPick {
    index: usize,
    validator_id: ValidatorId,
    view: u64,
}

/// Reads the current leader directly from the already-frozen fixture,
/// before any compiled process claims the writer fence. Every replica's
/// state file is byte-identical at this point, so replica 0 is
/// representative; this never opens a network connection.
fn pick_leader(fixture: &Fixture) -> LeaderPick {
    let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
        policy: &fixture.policy,
        history: &[],
        leg_policy: &fixture.local_policy,
        engine: &fixture.engine,
        blobs: &fixture.blobs,
        seal: None,
    };
    let status: OrderedStatus = query_status(&fixture.stores[0], &fixture.operation, &env).unwrap();
    let validator_id: ValidatorId = fixture
        .policy
        .engine()
        .validator_set()
        .leader(status.current_view)
        .expect("a view always has a deterministic leader");
    let index: usize = fixture
        .network
        .validators
        .iter()
        .position(|validator| validator.validator_id == validator_id)
        .expect("the leader is one of this fixture's own validators");
    LeaderPick {
        index,
        validator_id,
        view: status.current_view,
    }
}

fn durable_operation(fence: WriterFenceGeneration, tag: u8) -> DurableOperationContext {
    let now_millis: u64 = SystemClock.now_unix_millis().unwrap();
    DurableOperationContext::new(
        fence,
        StorageDeadline::new(now_millis.checked_add(60_000).unwrap()).unwrap(),
        StorageCorrelationId::new([tag; 16]).unwrap(),
    )
}

/// Captures only `records`/`referenced_blobs`; the snapshot's own `token`
/// differs on every call by construction and is never a sensitivity signal.
fn business_records(
    store: &SqliteDurableStore,
    fixture: &Fixture,
    fence: WriterFenceGeneration,
    tag: u8,
) -> SourceBusinessSnapshot {
    capture_source_business_snapshot(
        store,
        &fixture.blobs,
        &durable_operation(fence, tag),
        fixture.network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap()
}

/// Spawns the leader's own compiled host with its stderr piped (so this
/// oracle can read its one termination-summary line), otherwise identical
/// to `start_host`'s own argument set.
fn start_leader_host(
    fixture: &Fixture,
    genesis: &Path,
    blob_db: &Path,
    state_db: &Path,
    key_file: &Path,
    validator_id: ValidatorId,
) -> (compiled_source_host_process::ChildGuard, SocketAddr, u64) {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_source_host"));
    command
        .args([
            "--chain-id",
            fixture.network.chain_id.as_str(),
            "--validator-id",
            &hex(validator_id.as_bytes()),
            "--domain",
            &hex(fixture.network.domain.as_bytes()),
            "--protocol-version",
            &fixture.network.protocol_version.get().to_string(),
            "--epoch",
            &fixture.network.epoch.get().to_string(),
            "--suite",
            "0:1:1:1:1:1:1:1",
            "--genesis-manifest",
            genesis.to_str().unwrap(),
            "--expected-genesis-digest",
            &hex(&fixture.network.manifest_digest),
            "--signing-key-file",
            key_file.to_str().unwrap(),
            "--state-db",
            state_db.to_str().unwrap(),
            "--blob-db",
            blob_db.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--created-checkpoint",
            "1000",
            "--timeout-seconds",
            "30",
            "--max-concurrent",
            "4",
            "--confirm-offline-fence-advance",
        ])
        .stderr(Stdio::piped());
    let startup_deadline: Duration = Duration::from_secs(30);
    let startup_byte_cap: NonZeroUsize =
        compiled_source_host_process::compiled_host_startup_line_limit(
            fixture.network.chain_id.as_str(),
        );
    let (mut guard, line) = compiled_source_host_process::spawn_bounded_status_line(
        command,
        startup_deadline,
        startup_byte_cap,
    );
    if line.is_empty() {
        panic!(
            "sqlite-source-host exited before serving: {:?}",
            guard.try_wait()
        );
    }
    assert!(line.contains("complete=true mode=serving"), "{line}");
    let address: SocketAddr = field(&line, "listen=").parse().unwrap();
    let generation: u64 = field(&line, "writer_generation=").parse().unwrap();
    (guard, address, generation)
}

fn raw_propose(address: SocketAddr, body: Vec<u8>) -> WireResponse {
    transport(address)
        .send(&WireRequest {
            method: Method::Post,
            path: ORDERED_ECONOMICS_PROPOSE_PATH.to_owned(),
            content_type: Some(ORDERED_PROPOSE_REQUEST_MEDIA_TYPE),
            body,
            deadline: None,
        })
        .unwrap()
}

/// Blocks on `stream` until `needle` has been observed in the accumulated
/// bytes, a real read error occurs, or `deadline` elapses. Never a fixed
/// sleep: the wait is the socket's own bounded blocking read.
fn read_until(
    stream: &mut TcpStream,
    deadline: Instant,
    needle: &[u8],
    cap: usize,
    label: &str,
) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut collected: Vec<u8> = Vec::new();
    let mut buffer: [u8; 256] = [0; 256];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => panic!("{label}: connection closed before the expected bytes arrived"),
            Ok(count) => {
                collected.extend_from_slice(&buffer[..count]);
                assert!(
                    collected.len() <= cap,
                    "{label}: exceeded its bounded byte cap"
                );
                if collected
                    .windows(needle.len())
                    .any(|window| window == needle)
                {
                    return collected;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("{label}: read error: {error}"),
        }
        assert!(Instant::now() < deadline, "{label}: deadline elapsed");
    }
}

/// Blocks until idle connection `stream` observes EOF or a reset, or panics
/// at `deadline`. A real read-timeout retry on an otherwise-untouched
/// socket, never a fixed sleep standing in for the condition itself.
fn wait_for_eof_or_reset(stream: &TcpStream, deadline: Instant) {
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut buffer: [u8; 16] = [0; 16];
    loop {
        match (&*stream).read(&mut buffer) {
            Ok(0) => return,
            Ok(_) => panic!("idle connection C unexpectedly received bytes"),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            // A reset/closed read also satisfies the barrier: either is a
            // real, observable effect of the listener/connection closing.
            Err(_error) => return,
        }
        assert!(
            Instant::now() < deadline,
            "connection C did not observe EOF/reset within its deadline"
        );
    }
}

/// Reads connection `stream` to actual EOF (the server always closes after
/// one response: `keep_alive(false)` plus this request's own
/// `Connection: close`), then splits its exact status code and body bytes.
fn read_http_response(stream: &mut TcpStream, deadline: Instant) -> (u16, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut raw: Vec<u8> = Vec::new();
    let mut buffer: [u8; 4096] = [0; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => raw.extend_from_slice(&buffer[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("connection A: read error collecting its response: {error}"),
        }
        assert!(
            raw.len() <= 64 * 1024,
            "connection A: response exceeded its bounded cap"
        );
        assert!(
            Instant::now() < deadline,
            "connection A: deadline elapsed collecting its response"
        );
    }
    let header_end: usize = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("connection A: response has a header terminator");
    let status_line: &str = std::str::from_utf8(&raw[..header_end])
        .expect("connection A: response head is ASCII")
        .lines()
        .next()
        .expect("connection A: response has a status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("connection A: status line has a code token")
        .parse()
        .expect("connection A: status code is numeric");
    (status, raw[header_end + 4..].to_vec())
}

/// Sends `signal_name` to `pid` and requires the signal helper itself to
/// succeed quickly. This never waits for `pid`'s own exit: that remains a
/// separate, explicit bounded wait so this call cannot block on in-flight
/// work this oracle still needs to drive concurrently.
fn send_signal(pid: u32, signal_name: &str) {
    assert!(pid > 0 && pid <= i32::MAX as u32, "positive owned host PID");
    let mut command: Command = Command::new("kill");
    command.args(["-s", signal_name, "--"]).arg(pid.to_string());
    let output =
        compiled_source_host_process::spawn_bounded_output(command, Duration::from_secs(5));
    assert!(
        output.status.success(),
        "owned-host {signal_name} helper failed: {:?}",
        output.stderr
    );
}

/// `node_core::ordered_economics::identity::LeaderProposalRecord`'s own
/// frame type id (`crates/node-core/src/ordered_economics/identity.rs`,
/// `ORDERED_LEADER_RECORD_TYPE`). That module is crate-private, so this
/// oracle cannot import or decode its Rust type directly; it instead reads
/// the exact same canonical frame through only public `canonical-encoding`
/// APIs, citing this already-allocated identifier rather than allocating a
/// new one.
const LEADER_PROPOSAL_RECORD_TYPE_ID: u16 = 0x644B;

/// `node_core::ordered_economics::frontier`'s own frame type ids
/// (`crates/node-core/src/ordered_economics/frontier.rs`,
/// `FRONTIER_CURSOR_TYPE`/`FRONTIER_ENTRY_TYPE`/`FRONTIER_FINAL_TYPE`). That
/// module is crate-private, so this oracle cites these already-allocated
/// identifiers rather than importing or re-deriving them, following the
/// same pattern as `LEADER_PROPOSAL_RECORD_TYPE_ID` above.
const FRONTIER_CURSOR_RECORD_TYPE_ID: u16 = 0x6459;
const FRONTIER_ENTRY_RECORD_TYPE_ID: u16 = 0x6452;
const FRONTIER_FINAL_RECORD_TYPE_ID: u16 = 0x645A;
const FRONTIER_CURSOR_INDEXED_VERSION: u16 = 2;
const FRONTIER_ENTRY_RECORD_VERSION: u16 = 1;

/// True once any record's value decodes to a frontier cursor, entry or
/// final frame. Used only to confirm a fresh validator's own frontier state
/// starts genuinely absent before this oracle's compiled host ever opens
/// its file.
fn has_any_frontier_record(records: &[SourceSnapshotRecord]) -> bool {
    for record in records {
        let Some(value) = record.value.as_ref() else {
            continue;
        };
        let Ok(frame) = decode_canonical_frame(value) else {
            continue;
        };
        if frame.require_type(FRONTIER_CURSOR_RECORD_TYPE_ID).is_ok()
            || frame.require_type(FRONTIER_ENTRY_RECORD_TYPE_ID).is_ok()
            || frame.require_type(FRONTIER_FINAL_RECORD_TYPE_ID).is_ok()
        {
            return true;
        }
    }
    false
}

#[test]
fn compiled_sqlite_source_host_sigterm_cancels_withheld_propose_not_a_delivered_one() {
    // ---- Negative half: a real SIGTERM, a real withheld body, zero writes. ----
    let mut fixture: Fixture = Fixture::new();
    fixture.freeze_and_complete();
    let leader: LeaderPick = pick_leader(&fixture);

    let genesis: PathBuf = fixture.directory.0.join("genesis.bin");
    std::fs::write(&genesis, &fixture.network.manifest_bytes).unwrap();
    let blob_db: PathBuf = fixture.directory.0.join("blobs.sqlite");
    let key_path: PathBuf = fixture.directory.0.join("leader.key");
    std::fs::write(&key_path, fixture.network.validators[leader.index].seed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    // Matches `Fixture::build`'s own naming (`business_cut/fixture.rs`:
    // `directory.0.join(format!("state-{index}.sqlite"))`), so this is the
    // exact same file `fixture.stores[leader.index]` already opened, not a
    // fresh, nonexistent one.
    let state_db: PathBuf = fixture
        .directory
        .0
        .join(format!("state-{}.sqlite", leader.index));

    let before: SourceBusinessSnapshot = business_records(
        &fixture.stores[leader.index],
        &fixture,
        fixture.stores[leader.index].writer_fence().unwrap(),
        0xA0,
    );
    // Close every in-process handle before the compiled host claims the
    // writer fence against the exact same files.
    fixture.stores.clear();

    let (mut guard, address, generation) = start_leader_host(
        &fixture,
        &genesis,
        &blob_db,
        &state_db,
        &key_path,
        leader.validator_id,
    );
    assert_eq!(
        generation, 2,
        "the fixture's stores close at writer fence 1, so the first real compiled claim is exactly generation 2"
    );
    let stderr_pipe = guard
        .child_mut()
        .stderr
        .take()
        .expect("owned host stderr must be piped for this oracle");

    let body: Vec<u8> = OrderedProposeRequest { candidate: None }.encode().unwrap();
    assert!(
        !body.is_empty(),
        "an encoded empty ordered-propose request is still a nonempty canonical frame"
    );

    // Connection A: send only the request head with `Expect: 100-continue`,
    // deliberately withholding the body.
    let mut connection_a: TcpStream = TcpStream::connect(address).unwrap();
    connection_a.set_nodelay(true).unwrap();
    let head: String = format!(
        "POST {ORDERED_ECONOMICS_PROPOSE_PATH} HTTP/1.1\r\nHost: {address}\r\nContent-Type: {ORDERED_PROPOSE_REQUEST_MEDIA_TYPE}\r\nContent-Length: {}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
        body.len(),
    );
    connection_a.write_all(head.as_bytes()).unwrap();

    // Local hyper proof, against the real source of the exact
    // `Cargo.lock`-pinned `hyper 1.11.0`
    // (checksum `d22053281f852e11534f5198498373cbb59295120a20771d90f7ed1897490a72`,
    // `Cargo.lock:1154-1157`). The gate is the body's own "want" channel, not
    // merely `poll_loop`'s read/write/flush order:
    // `dispatch.rs:304-311`'s `poll_read_head` creates this request's body
    // channel with `wanter = wants.contains(Wants::EXPECT)` (true here), so
    // `body/incoming.rs:114-122`'s `new_channel` starts it at `WANT_PENDING`.
    // `dispatch.rs:222-229`'s `poll_read` calls `Sender::poll_ready`
    // (`incoming.rs:362-368`), which calls `poll_want`
    // (`incoming.rs:370-377`): `Poll::Pending` while `WANT_PENDING`, parking
    // before `conn.rs:409-415`'s `poll_read_body` (the arm that actually
    // buffers `b"HTTP/1.1 100 Continue\r\n\r\n"`) is ever reached. Only
    // `Incoming::poll_frame` (`incoming.rs:193-234`) sends `WANT_READY`
    // (`incoming.rs:220`), and that is called only by `to_bytes(body, limit)`
    // inside this crate's own `dispatch_bounded_request`
    // (`crates/native-http/src/lib.rs:1604-1608`) -- itself only reached by a
    // connection task that already passed every per-connection shutdown
    // check (`crates/native-http/src/lib.rs:1481`, `:1486`, `:1550`).
    let continue_deadline: Instant = Instant::now() + Duration::from_secs(5);
    let continue_bytes: Vec<u8> = read_until(
        &mut connection_a,
        continue_deadline,
        b"\r\n\r\n",
        256,
        "connection A's 100-continue handshake",
    );
    assert_eq!(continue_bytes, b"HTTP/1.1 100 Continue\r\n\r\n");

    // Connection C: a second, otherwise-untouched idle connection.
    let connection_c: TcpStream = TcpStream::connect(address).unwrap();
    connection_c.set_nodelay(true).unwrap();

    // A real SIGTERM against the owned PID. Its effect is observed only
    // through the deterministic barrier below, never a sleep.
    send_signal(guard.child_mut().id(), "TERM");

    // Deterministic listener-drop barrier. `drop(listener)` and
    // `shutdown_sender.send(true)` (`crates/native-http/src/lib.rs:1512-1513`)
    // -- the only two things that can make idle connection C observe
    // EOF/reset and make a fresh connect observe `ConnectionRefused` -- run
    // only after the `shutdown` future handed to `serve_with_stream_upgrade_observed`
    // already resolved; and that exact future's own body
    // (`apps/operator/src/native_operations.rs:272-276`) calls
    // `stop_executor.close()` strictly before it resolves. So observing both
    // effects below proves the executor is already closed.
    //
    // A third, unrelated way C could see EOF/reset is its own 5-second
    // header-read timeout firing while the listener is still open. That
    // case still fails closed here: the fresh connect right after would
    // then succeed instead of being refused, and the `match` below panics.
    let barrier_deadline: Instant = Instant::now() + Duration::from_secs(5);
    wait_for_eof_or_reset(&connection_c, barrier_deadline);
    drop(connection_c);
    match TcpStream::connect(address) {
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        other => panic!(
            "expected exactly one fresh ConnectionRefused once the listener dropped: {other:?}"
        ),
    }

    // Now release connection A's withheld body.
    connection_a.write_all(&body).unwrap();
    let response_deadline: Instant = Instant::now() + Duration::from_secs(5);
    let (status, response_body): (u16, Vec<u8>) =
        read_http_response(&mut connection_a, response_deadline);
    drop(connection_a);

    // Reap the owned host: a bounded poll, exactly this suite's existing
    // convention, with an explicit SIGKILL-then-panic fallback so a stuck
    // process on failure is still reaped rather than leaked.
    let exit_deadline: Instant = Instant::now() + Duration::from_secs(10);
    let exit_status: ExitStatus = loop {
        if let Some(status) = guard.try_wait().expect("poll owned host after SIGTERM") {
            break status;
        }
        if Instant::now() >= exit_deadline {
            send_signal(guard.child_mut().id(), "KILL");
            let _ = guard.child_mut().wait();
            panic!("owned host did not exit within the bounded post-SIGTERM deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        exit_status.code(),
        Some(0),
        "SIGTERM must still produce an ordinary successful host exit"
    );
    // The host has already exited, so its stderr write end is already
    // closed: this is a bounded, already-terminated read, not an open wait.
    // Bounded the same way as this suite's existing stderr capture
    // (`support/compiled_source_host_process.rs`'s `stop_with_signal`): one
    // extra byte over the cap turns a silent truncation into a failure.
    const STDERR_CAP: usize = 2 * 1024;
    let mut stderr_bytes: Vec<u8> = Vec::new();
    stderr_pipe
        .take(STDERR_CAP as u64 + 1)
        .read_to_end(&mut stderr_bytes)
        .expect("read owned host termination summary");
    assert!(
        stderr_bytes.len() <= STDERR_CAP,
        "owned host termination summary exceeded its bounded cap"
    );
    let stderr_text: String = String::from_utf8(stderr_bytes).unwrap();
    drop(guard);

    // Exact business records/referenced blobs unchanged FIRST.
    let namespace: SqliteNamespace = SqliteNamespace::new(
        fixture.network.chain_id.clone(),
        leader.validator_id,
        fixture.network.domain,
    );
    let reopened_store: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_db, namespace).unwrap();
    let current_fence: WriterFenceGeneration = reopened_store.writer_fence().unwrap();
    assert_eq!(
        current_fence.get(),
        2,
        "no second claim happened; only the one owned host ever opened this file"
    );
    let after: SourceBusinessSnapshot =
        business_records(&reopened_store, &fixture, current_fence, 0xA1);
    assert_eq!(
        after.records, before.records,
        "a withheld-body propose cancelled before storage must leave every business record unchanged"
    );
    assert_eq!(
        after.referenced_blobs, before.referenced_blobs,
        "a withheld-body propose cancelled before storage must leave every referenced blob unchanged"
    );

    // Then the exact response and the exact actual metrics.
    assert_eq!(status, 503, "{}", String::from_utf8_lossy(&response_body));
    assert_eq!(response_body, b"invocation-cancelled-before-storage");
    assert!(stderr_text.contains("stop=sigterm"), "{stderr_text}");
    assert!(
        stderr_text.contains(" blocking_admitted=0 "),
        "{stderr_text}"
    );
    assert!(stderr_text.contains(" blocking_closed=0 "), "{stderr_text}");

    // ---- Positive sensitivity control: a fresh fixture, body delivered before SIGTERM. ----
    let mut positive_fixture: Fixture = Fixture::new();
    positive_fixture.freeze_and_complete();
    let positive_leader: LeaderPick = pick_leader(&positive_fixture);

    let positive_genesis: PathBuf = positive_fixture.directory.0.join("genesis.bin");
    std::fs::write(&positive_genesis, &positive_fixture.network.manifest_bytes).unwrap();
    let positive_blob_db: PathBuf = positive_fixture.directory.0.join("blobs.sqlite");
    let positive_key_path: PathBuf = positive_fixture.directory.0.join("leader.key");
    std::fs::write(
        &positive_key_path,
        positive_fixture.network.validators[positive_leader.index].seed,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&positive_key_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    let positive_state_db: PathBuf = positive_fixture
        .directory
        .0
        .join(format!("state-{}.sqlite", positive_leader.index));

    let positive_before: SourceBusinessSnapshot = business_records(
        &positive_fixture.stores[positive_leader.index],
        &positive_fixture,
        positive_fixture.stores[positive_leader.index]
            .writer_fence()
            .unwrap(),
        0xB0,
    );
    positive_fixture.stores.clear();

    let (positive_guard, positive_address, positive_generation) = start_leader_host(
        &positive_fixture,
        &positive_genesis,
        &positive_blob_db,
        &positive_state_db,
        &positive_key_path,
        positive_leader.validator_id,
    );
    assert_eq!(positive_generation, 2);

    let positive_body: Vec<u8> = OrderedProposeRequest { candidate: None }.encode().unwrap();
    let response: WireResponse = raw_propose(positive_address, positive_body);
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let response_proposal: OrderedProposal = decode_ordered_proposal(&response.body).unwrap();
    assert_eq!(response_proposal.proposal.view, positive_leader.view);
    assert_eq!(
        response_proposal.proposal.leader,
        positive_leader.validator_id
    );

    // Reuses this suite's own existing signal+wait+capture helper: there is
    // no withheld body here, so nothing else needs to run concurrently with
    // the stop.
    let positive_stderr: Vec<u8> = positive_guard.stop_orderly_terminate(Duration::from_secs(10));
    let positive_stderr_text: String = String::from_utf8(positive_stderr).unwrap();
    assert!(
        positive_stderr_text.contains("stop=sigterm"),
        "{positive_stderr_text}"
    );
    assert!(
        positive_stderr_text.contains(" blocking_admitted=1 "),
        "{positive_stderr_text}"
    );

    let positive_namespace: SqliteNamespace = SqliteNamespace::new(
        positive_fixture.network.chain_id.clone(),
        positive_leader.validator_id,
        positive_fixture.network.domain,
    );
    let positive_reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(&positive_state_db, positive_namespace).unwrap();
    let positive_fence: WriterFenceGeneration = positive_reopened.writer_fence().unwrap();
    let positive_after: SourceBusinessSnapshot =
        business_records(&positive_reopened, &positive_fixture, positive_fence, 0xB1);

    let added: Vec<&SourceSnapshotRecord> = positive_after
        .records
        .iter()
        .filter(|record| !positive_before.records.contains(record))
        .collect();
    assert!(
        !added.is_empty(),
        "an admitted propose call must add at least one durable record, not merely a writer-fence metadata change"
    );

    let mut saw_leader_proposal_record: bool = false;
    for record in added {
        let Some(value) = record.value.as_ref() else {
            continue;
        };
        let Ok(frame) = decode_canonical_frame(value) else {
            continue;
        };
        if frame.require_type(LEADER_PROPOSAL_RECORD_TYPE_ID).is_err() {
            continue;
        }
        frame.require_version(1).unwrap();
        let view: u64 = frame.required_u64(1).unwrap();
        let leader_bytes: [u8; 32] = frame.required_field(2).unwrap().try_into().unwrap();
        let recorded_leader: ValidatorId = ValidatorId::new(leader_bytes);
        let digest: Digest32 = decode_digest32(frame.required_field(3).unwrap()).unwrap();
        let recorded_proposal: ConsensusProposal =
            decode_proposal(frame.required_field(4).unwrap()).unwrap();
        assert_eq!(view, response_proposal.proposal.view);
        assert_eq!(recorded_leader, positive_leader.validator_id);
        assert_eq!(
            recorded_proposal, response_proposal.proposal,
            "the retained record must carry the exact signed proposal returned over HTTP, not a re-derived one"
        );
        let recomputed_digest: Digest32 = positive_fixture
            .policy
            .engine()
            .proposal_digest(&recorded_proposal)
            .unwrap();
        assert_eq!(digest, recomputed_digest);
        saw_leader_proposal_record = true;
    }
    assert!(
        saw_leader_proposal_record,
        "capture_source_business_snapshot must see the durable LeaderProposalRecord (type 0x644B); a writer-fence-only metadata change is not sensitivity"
    );
}

/// DR-0256: selected frozen-frontier-maintenance real SIGTERM wiring oracle.
/// See `docs/architecture/native-frontier-sigterm-wiring-oracle.md` for the
/// exact, limited claim. This isolates the compiled host's own SIGTERM ->
/// `NativeBlockingExecutor::close()` -> certified FastVote router's
/// `advance_frontier` route's own `publication::admitted()` cancellation
/// wiring, a genuinely separate wiring path from the ordered-economics
/// `propose` route the sibling oracle above isolates. It is not a
/// real-binary late-pre-storage window isolation, a paid FastVote
/// prepare/apply/publication call, a Seal, a successor/historical/TLS
/// qualification, or a D05/M5 closure.
#[test]
fn compiled_sqlite_source_host_sigterm_cancels_withheld_frontier_advance_not_a_delivered_one() {
    // ---- Negative half: a real SIGTERM, a real withheld empty chunked body, zero writes. ----
    let mut fixture: Fixture = Fixture::new();
    fixture.freeze_and_complete();
    // `Fixture::freeze_and_complete`'s own `.take(3)` finalize loop
    // (`business_cut/fixture.rs:424-460`) only finalizes the frontier for
    // the first three stores, so index 3 starts with no cursor, entry or
    // final record and one retained publication still available to advance.
    let idx: usize = 3;
    let validator_id: ValidatorId = fixture.network.validators[idx].validator_id;

    let genesis: PathBuf = fixture.directory.0.join("genesis.bin");
    std::fs::write(&genesis, &fixture.network.manifest_bytes).unwrap();
    let blob_db: PathBuf = fixture.directory.0.join("blobs.sqlite");
    let key_path: PathBuf = fixture.directory.0.join("frontier.key");
    std::fs::write(&key_path, fixture.network.validators[idx].seed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let state_db: PathBuf = fixture.directory.0.join(format!("state-{idx}.sqlite"));

    let before: SourceBusinessSnapshot = business_records(
        &fixture.stores[idx],
        &fixture,
        fixture.stores[idx].writer_fence().unwrap(),
        0xF0,
    );
    assert!(
        !has_any_frontier_record(&before.records),
        "validator index 3's own frontier state must start absent before this oracle's one owned host ever opens its file"
    );
    // Close every in-process handle before the compiled host claims the
    // writer fence against the exact same files.
    fixture.stores.clear();

    let (mut guard, address, generation) = start_leader_host(
        &fixture,
        &genesis,
        &blob_db,
        &state_db,
        &key_path,
        validator_id,
    );
    assert_eq!(
        generation, 2,
        "the fixture's stores close at writer fence 1, so the first real compiled claim is exactly generation 2"
    );
    let stderr_pipe = guard
        .child_mut()
        .stderr
        .take()
        .expect("owned host stderr must be piped for this oracle");

    // Connection A: send only the request head with `Expect: 100-continue`
    // and `Transfer-Encoding: chunked`, deliberately withholding even the
    // empty terminating chunk. `advance_frontier` only requires an empty
    // body (`fastvote.rs:194`) and never inspects `Content-Length`, so
    // chunked framing with the terminator withheld is the only way to keep
    // this exact route's own request in flight without ever sending a
    // nonempty payload.
    let mut connection_a: TcpStream = TcpStream::connect(address).unwrap();
    connection_a.set_nodelay(true).unwrap();
    let head: String = format!(
        "POST {FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH} HTTP/1.1\r\nHost: {address}\r\nContent-Type: {NODE_EVENT_MEDIA_TYPE}\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
    );
    connection_a.write_all(head.as_bytes()).unwrap();

    // Same local hyper proof DR-0254 already establishes for a
    // `Content-Length`-bearing `Expect`-continue request, independent of
    // framing: see `docs/architecture/native-frontier-sigterm-wiring-oracle.md`.
    let continue_deadline: Instant = Instant::now() + Duration::from_secs(5);
    let continue_bytes: Vec<u8> = read_until(
        &mut connection_a,
        continue_deadline,
        b"\r\n\r\n",
        256,
        "connection A's 100-continue handshake",
    );
    assert_eq!(continue_bytes, b"HTTP/1.1 100 Continue\r\n\r\n");

    // Connection C: a second, otherwise-untouched idle connection.
    let connection_c: TcpStream = TcpStream::connect(address).unwrap();
    connection_c.set_nodelay(true).unwrap();

    // A real SIGTERM against the owned PID. Its effect is observed only
    // through the deterministic barrier below, never a sleep.
    send_signal(guard.child_mut().id(), "TERM");

    // Deterministic listener-drop barrier, identical to the sibling oracle
    // above: both effects below can only follow the already-closed
    // executor's own `shutdown` future resolving.
    let barrier_deadline: Instant = Instant::now() + Duration::from_secs(5);
    wait_for_eof_or_reset(&connection_c, barrier_deadline);
    drop(connection_c);
    match TcpStream::connect(address) {
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        other => panic!(
            "expected exactly one fresh ConnectionRefused once the listener dropped: {other:?}"
        ),
    }

    // Now release connection A's withheld zero-length chunk terminator.
    connection_a.write_all(b"0\r\n\r\n").unwrap();
    let response_deadline: Instant = Instant::now() + Duration::from_secs(5);
    let (status, response_body): (u16, Vec<u8>) =
        read_http_response(&mut connection_a, response_deadline);
    drop(connection_a);

    // Reap the owned host: a bounded poll, this suite's existing
    // convention, with an explicit SIGKILL-then-panic fallback.
    let exit_deadline: Instant = Instant::now() + Duration::from_secs(10);
    let exit_status: ExitStatus = loop {
        if let Some(status) = guard.try_wait().expect("poll owned host after SIGTERM") {
            break status;
        }
        if Instant::now() >= exit_deadline {
            send_signal(guard.child_mut().id(), "KILL");
            let _ = guard.child_mut().wait();
            panic!("owned host did not exit within the bounded post-SIGTERM deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        exit_status.code(),
        Some(0),
        "SIGTERM must still produce an ordinary successful host exit"
    );
    const STDERR_CAP: usize = 2 * 1024;
    let mut stderr_bytes: Vec<u8> = Vec::new();
    stderr_pipe
        .take(STDERR_CAP as u64 + 1)
        .read_to_end(&mut stderr_bytes)
        .expect("read owned host termination summary");
    assert!(
        stderr_bytes.len() <= STDERR_CAP,
        "owned host termination summary exceeded its bounded cap"
    );
    let stderr_text: String = String::from_utf8(stderr_bytes).unwrap();
    drop(guard);

    // Exact business records/referenced blobs unchanged FIRST.
    let namespace: SqliteNamespace = SqliteNamespace::new(
        fixture.network.chain_id.clone(),
        validator_id,
        fixture.network.domain,
    );
    let reopened_store: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_db, namespace).unwrap();
    let current_fence: WriterFenceGeneration = reopened_store.writer_fence().unwrap();
    assert_eq!(
        current_fence.get(),
        2,
        "no second claim happened; only the one owned host ever opened this file"
    );
    let after: SourceBusinessSnapshot =
        business_records(&reopened_store, &fixture, current_fence, 0xF1);
    assert_eq!(
        after.records, before.records,
        "a withheld-chunked-body frontier advance cancelled before storage must leave every business record unchanged"
    );
    assert_eq!(
        after.referenced_blobs, before.referenced_blobs,
        "a withheld-chunked-body frontier advance cancelled before storage must leave every referenced blob unchanged"
    );

    // Then the exact response and the exact actual metrics.
    assert_eq!(status, 503, "{}", String::from_utf8_lossy(&response_body));
    assert_eq!(response_body, b"invocation-cancelled-before-storage");
    assert!(stderr_text.contains("stop=sigterm"), "{stderr_text}");
    assert!(
        stderr_text.contains(" blocking_admitted=0 "),
        "{stderr_text}"
    );
    assert!(stderr_text.contains(" blocking_closed=0 "), "{stderr_text}");

    // ---- Positive sensitivity control: a fresh fixture, zero-chunk sent before SIGTERM. ----
    let mut positive_fixture: Fixture = Fixture::new();
    positive_fixture.freeze_and_complete();
    let positive_validator_id: ValidatorId = positive_fixture.network.validators[idx].validator_id;

    let positive_genesis: PathBuf = positive_fixture.directory.0.join("genesis.bin");
    std::fs::write(&positive_genesis, &positive_fixture.network.manifest_bytes).unwrap();
    let positive_blob_db: PathBuf = positive_fixture.directory.0.join("blobs.sqlite");
    let positive_key_path: PathBuf = positive_fixture.directory.0.join("frontier.key");
    std::fs::write(
        &positive_key_path,
        positive_fixture.network.validators[idx].seed,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&positive_key_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    let positive_state_db: PathBuf = positive_fixture
        .directory
        .0
        .join(format!("state-{idx}.sqlite"));

    let positive_before: SourceBusinessSnapshot = business_records(
        &positive_fixture.stores[idx],
        &positive_fixture,
        positive_fixture.stores[idx].writer_fence().unwrap(),
        0xF2,
    );
    assert!(!has_any_frontier_record(&positive_before.records));
    positive_fixture.stores.clear();

    let (positive_guard, positive_address, positive_generation) = start_leader_host(
        &positive_fixture,
        &positive_genesis,
        &positive_blob_db,
        &positive_state_db,
        &positive_key_path,
        positive_validator_id,
    );
    assert_eq!(positive_generation, 2);

    let mut positive_connection: TcpStream = TcpStream::connect(positive_address).unwrap();
    positive_connection.set_nodelay(true).unwrap();
    let positive_head: String = format!(
        "POST {FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH} HTTP/1.1\r\nHost: {positive_address}\r\nContent-Type: {NODE_EVENT_MEDIA_TYPE}\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
    );
    positive_connection
        .write_all(positive_head.as_bytes())
        .unwrap();
    let positive_continue_deadline: Instant = Instant::now() + Duration::from_secs(5);
    let positive_continue_bytes: Vec<u8> = read_until(
        &mut positive_connection,
        positive_continue_deadline,
        b"\r\n\r\n",
        256,
        "positive connection's 100-continue handshake",
    );
    assert_eq!(positive_continue_bytes, b"HTTP/1.1 100 Continue\r\n\r\n");
    // The zero-length chunk terminator is sent before any signal here.
    positive_connection.write_all(b"0\r\n\r\n").unwrap();
    let positive_response_deadline: Instant = Instant::now() + Duration::from_secs(5);
    let (positive_status, positive_response_body): (u16, Vec<u8>) =
        read_http_response(&mut positive_connection, positive_response_deadline);
    drop(positive_connection);
    assert_eq!(
        positive_status,
        204,
        "{}",
        String::from_utf8_lossy(&positive_response_body)
    );
    assert!(
        positive_response_body.is_empty(),
        "a FrozenFrontierStep::Advanced step returns an empty 204 body"
    );

    // Reuses this suite's own existing signal+wait+capture helper: there is
    // no withheld body here, so nothing else needs to run concurrently with
    // the stop. No second advance call is made, so no final vote exists.
    let positive_stderr: Vec<u8> = positive_guard.stop_orderly_terminate(Duration::from_secs(10));
    let positive_stderr_text: String = String::from_utf8(positive_stderr).unwrap();
    assert!(
        positive_stderr_text.contains("stop=sigterm"),
        "{positive_stderr_text}"
    );
    assert!(
        positive_stderr_text.contains(" blocking_admitted=1 "),
        "{positive_stderr_text}"
    );

    let positive_namespace: SqliteNamespace = SqliteNamespace::new(
        positive_fixture.network.chain_id.clone(),
        positive_validator_id,
        positive_fixture.network.domain,
    );
    let positive_reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(&positive_state_db, positive_namespace).unwrap();
    let positive_fence: WriterFenceGeneration = positive_reopened.writer_fence().unwrap();
    let positive_after: SourceBusinessSnapshot =
        business_records(&positive_reopened, &positive_fixture, positive_fence, 0xF3);

    let added: Vec<&SourceSnapshotRecord> = positive_after
        .records
        .iter()
        .filter(|record| !positive_before.records.contains(record))
        .collect();
    let removed_count: usize = positive_before
        .records
        .iter()
        .filter(|record| !positive_after.records.contains(record))
        .count();
    assert_eq!(
        removed_count, 0,
        "an admitted frontier advance must never remove an existing business record"
    );
    assert_eq!(
        added.len(),
        2,
        "an admitted frontier advance must add exactly the new cursor and entry records, nothing else"
    );
    assert_eq!(
        positive_after.referenced_blobs, positive_before.referenced_blobs,
        "an admitted frontier advance must not change any referenced blob"
    );

    let mut saw_cursor_record: bool = false;
    let mut saw_entry_record: bool = false;
    for record in added {
        let Some(value) = record.value.as_ref() else {
            continue;
        };
        let Ok(frame) = decode_canonical_frame(value) else {
            continue;
        };
        assert!(
            frame.require_type(FRONTIER_FINAL_RECORD_TYPE_ID).is_err(),
            "a single Advanced step must never also retain a final frontier record (type 0x645A)"
        );
        if frame.require_type(FRONTIER_CURSOR_RECORD_TYPE_ID).is_ok() {
            frame
                .require_version(FRONTIER_CURSOR_INDEXED_VERSION)
                .unwrap();
            let identity: consensus::FrozenFrontierIdentity =
                decode_frozen_frontier_identity(frame.required_field(1).unwrap()).unwrap();
            let last_request_id: [u8; 32] = frame.required_field(2).unwrap().try_into().unwrap();
            let physical_last_request_id: [u8; 32] =
                frame.required_field(3).unwrap().try_into().unwrap();
            assert_eq!(identity.entry_count, 1);
            assert_eq!(identity.closure_request_id, [0xCB; 32]);
            assert_eq!(last_request_id, positive_fixture.network.request_id);
            assert_eq!(
                physical_last_request_id,
                positive_fixture.network.request_id
            );
            saw_cursor_record = true;
            continue;
        }
        if frame.require_type(FRONTIER_ENTRY_RECORD_TYPE_ID).is_ok() {
            frame
                .require_version(FRONTIER_ENTRY_RECORD_VERSION)
                .unwrap();
            let closure_request_id: [u8; 32] = frame.required_field(1).unwrap().try_into().unwrap();
            let closure_height: u64 = frame.required_u64(2).unwrap();
            let ordinal: u64 = frame.required_u64(3).unwrap();
            let publication: consensus::AvailabilityIdentity =
                decode_availability_identity(frame.required_field(4).unwrap()).unwrap();
            assert_eq!(closure_request_id, [0xCB; 32]);
            assert!(closure_height > 0);
            assert_eq!(ordinal, 1);
            assert_eq!(publication.request_id, positive_fixture.network.request_id);
            saw_entry_record = true;
        }
    }
    assert!(
        saw_cursor_record,
        "capture_source_business_snapshot must see the durable frontier cursor record (type 0x6459)"
    );
    assert!(
        saw_entry_record,
        "capture_source_business_snapshot must see the durable frontier entry record (type 0x6452)"
    );
}
