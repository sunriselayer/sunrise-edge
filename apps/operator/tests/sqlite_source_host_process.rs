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

#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[allow(dead_code)]
#[path = "business_cut/fixture.rs"]
mod fixture;
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;

use consensus::QuorumCertificate;
use fixture::Fixture;
use node_core::ordered_economics::{
    OrderedEconomicsEnvironment, OrderedStatus, decode_ordered_status, query_status,
};
use protocol_types::ValidatorId;
use runtime::{
    Clock, DurableDomainStateStore, DurableOperationContext, OutgoingBarrier, StorageCorrelationId,
    StorageDeadline, SystemClock,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Child, Command},
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
    let (mut guard, line) =
        compiled_source_host_process::spawn_bounded_status_line(command, startup_deadline);
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
