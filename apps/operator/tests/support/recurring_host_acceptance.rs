//! Actual repeated compiled-process handoffs, starting from the independently
//! staged changed committee. Each step exports its own current history/cut,
//! obtains genuine successor readiness, commits its own Seal, then activates
//! from the entire ordered chain rooted in the original signed genesis.

use super::super::ordered_seal_sqlite_acceptance::{
    acknowledged_output, saved_configured_peer_results, saved_policy_submission_rounds,
};
use super::*;
use consensus::readiness::ReadinessCertificate;
use consensus::{ConsensusMessage, ConsensusVote};
use node_core::fast_path::FastPathEd25519Verifier;
use node_core::fast_path::records::{FastPathValidatorEntry, FastPathValidatorSetRecord};
use node_core::ordered_economics::{
    OrderedEventOutput, OrderedOutcome, OrderedProposal, decode_ordered_outcome,
};
use node_core::serving_authority::{
    LiveAuthority, SuccessorChainBudget, resolve_live_authority_chain,
};
use protocol_types::Epoch;
use runtime::{DurableDomainStateStore, StructuredDurableDomainStateStore};
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use sunrise_edge_client::load_successor_chain_workflow_from_directories;
use sunrise_edge_client::successor_artifacts::SuccessorChainArtifactFiles;

#[path = "recurring_lifecycle_acceptance.rs"]
mod lifecycle;

const MAXIMUM_LINKS: u32 = 8;

#[derive(Clone)]
struct Link {
    plan_history: PathBuf,
    cut: PathBuf,
    manifest_history: PathBuf,
    certificate: PathBuf,
}

impl Link {
    fn directories(&self) -> SuccessorArtifactDirectories<'_> {
        SuccessorArtifactDirectories {
            plan_history: &self.plan_history,
            cut: &self.cut,
            manifest_history: &self.manifest_history,
            certificate: &self.certificate,
        }
    }
}

struct CurrentTargets {
    paths: Vec<PathBuf>,
    members: Vec<SuccessorProcessMember>,
}

type SqlRows = Vec<Vec<Vec<rusqlite::types::Value>>>;

/// Every physical durable row, blob, source token, fence and permanent origin.
/// A refusal compares against the state captured AFTER the fault is injected.
#[derive(Debug, PartialEq)]
struct ProtectedState {
    business: Vec<node_core::business_reconstruction::SourceBusinessSnapshot>,
    metadata: Vec<(
        WriterFenceGeneration,
        runtime::NamespaceLifecycle,
        runtime::OutgoingBarrier,
        runtime::successor_serving::SuccessorServingSlot,
    )>,
    state_rows: Vec<SqlRows>,
    blob_rows: Vec<SqlRows>,
}

fn sql_rows(path: &Path, statements: &[&str]) -> SqlRows {
    let mut connection: rusqlite::Connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let transaction: rusqlite::Transaction<'_> = connection.transaction().unwrap();
    let mut tables: SqlRows = Vec::with_capacity(statements.len());
    for sql in statements {
        let mut statement: rusqlite::Statement<'_> = transaction.prepare(sql).unwrap();
        let columns: usize = statement.column_count();
        let rows: Vec<Vec<rusqlite::types::Value>> = statement
            .query_map([], |row: &rusqlite::Row<'_>| {
                (0..columns)
                    .map(|index: usize| row.get::<usize, rusqlite::types::Value>(index))
                    .collect::<Result<Vec<rusqlite::types::Value>, rusqlite::Error>>()
            })
            .unwrap()
            .collect::<Result<Vec<Vec<rusqlite::types::Value>>, rusqlite::Error>>()
            .unwrap();
        tables.push(rows);
    }
    tables
}

fn protected_state(fixture: &Fixture, targets: &CurrentTargets) -> ProtectedState {
    let mut metadata: Vec<(
        WriterFenceGeneration,
        runtime::NamespaceLifecycle,
        runtime::OutgoingBarrier,
        runtime::successor_serving::SuccessorServingSlot,
    )> = Vec::with_capacity(targets.paths.len());
    let mut state_rows: Vec<SqlRows> = Vec::with_capacity(targets.paths.len());
    let mut blob_rows: Vec<SqlRows> = Vec::with_capacity(targets.paths.len());
    for (index, path) in targets.paths.iter().enumerate() {
        let store: SqliteDurableStore = SqliteDurableStore::open_historical(
            path.join("state.db"),
            SqliteNamespace::new(
                fixture.network.chain_id.clone(),
                targets.members[index].validator_id,
                fixture.network.domain,
            ),
        )
        .unwrap();
        let fence: WriterFenceGeneration = store.writer_fence().unwrap();
        let operation: runtime::DurableOperationContext = runtime::DurableOperationContext::new(
            fence,
            runtime::StorageDeadline::new(u64::MAX / 2).unwrap(),
            runtime::StorageCorrelationId::new([0xcf; 16]).unwrap(),
        );
        metadata.push((
            fence,
            store
                .get_namespace_lifecycle(&operation, fixture.network.domain)
                .unwrap(),
            store
                .get_outgoing_barrier(&operation, fixture.network.domain)
                .unwrap(),
            store
                .get_successor_serving(&operation, fixture.network.domain)
                .unwrap(),
        ));
        state_rows.push(sql_rows(
            &path.join("state.db"),
            &[
                "SELECT * FROM durable_metadata ORDER BY id",
                "SELECT * FROM durable_import_progress ORDER BY id",
                "SELECT * FROM durable_outgoing_barrier ORDER BY id",
                "SELECT * FROM durable_successor_serving ORDER BY id",
                "SELECT * FROM durable_state ORDER BY key",
                "SELECT * FROM durable_conditional_readiness ORDER BY slot",
                "SELECT * FROM durable_object_heads ORDER BY object_id",
                "SELECT * FROM durable_object_versions ORDER BY object_id, object_version",
                "SELECT * FROM durable_receipts ORDER BY request_id",
                "SELECT * FROM durable_outbox_messages ORDER BY request_id, message_index",
                "SELECT * FROM durable_outbox_delivery ORDER BY request_id",
                "SELECT * FROM durable_outbox_attempts ORDER BY lease_id",
            ],
        ));
        blob_rows.push(sql_rows(
            &path.join("body.db"),
            &[
                "SELECT * FROM blob_metadata ORDER BY id",
                "SELECT * FROM blobs ORDER BY digest_algorithm, digest_bytes",
            ],
        ));
    }
    ProtectedState {
        business: lifecycle::physical_snapshots(fixture, targets),
        metadata,
        state_rows,
        blob_rows,
    }
}

fn budget() -> SuccessorChainBudget {
    SuccessorChainBudget::new(NonZeroU32::new(MAXIMUM_LINKS).unwrap())
}

fn workflow(fixture: &Fixture, links: &[Link]) -> SuccessorWorkflowAuthority {
    let directories: Vec<SuccessorArtifactDirectories<'_>> =
        links.iter().map(Link::directories).collect();
    load_successor_chain_workflow_from_directories(
        &fixture.directory.0.join("genesis.bin"),
        &fixture.network.resolver,
        fixture.network.manifest_digest,
        &fixture.network.context,
        fixture.network.domain,
        &directories,
        budget(),
    )
    .unwrap()
}

fn original_operator_pins(fixture: &Fixture) -> Vec<String> {
    vec![
        "--chain-id".into(),
        fixture.network.chain_id.as_str().into(),
        "--protocol-version".into(),
        fixture.network.protocol_version.get().to_string(),
        "--epoch".into(),
        fixture.network.epoch.get().to_string(),
        "--domain".into(),
        hex(fixture.network.domain.as_bytes()),
        "--suite".into(),
        "0:1:1:1:1:1:1:1".into(),
        "--genesis-manifest".into(),
        fixture
            .directory
            .0
            .join("genesis.bin")
            .to_str()
            .unwrap()
            .into(),
        "--expected-genesis-digest".into(),
        hex(&fixture.network.manifest_digest),
    ]
}

fn link_flags(links: &[Link], prefixed: bool) -> Vec<String> {
    let names: [&str; 4] = if prefixed {
        [
            "--successor-plan-history-dir",
            "--successor-cut-dir",
            "--successor-manifest-history-dir",
            "--successor-certificate-dir",
        ]
    } else {
        [
            "--ordered-history-dir",
            "--cut-dir",
            "--manifest-history-dir",
            "--certificate-dir",
        ]
    };
    let mut flags: Vec<String> = vec!["--successor-max-links".into(), MAXIMUM_LINKS.to_string()];
    for link in links {
        for (name, path) in names.iter().zip([
            &link.plan_history,
            &link.cut,
            &link.manifest_history,
            &link.certificate,
        ]) {
            flags.extend([(*name).into(), path.to_str().unwrap().into()]);
        }
    }
    flags
}

fn current_operator_pins(fixture: &Fixture, links: &[Link], history: &Path) -> Vec<String> {
    let mut flags: Vec<String> = original_operator_pins(fixture);
    flags.extend([
        "--ordered-history-dir".into(),
        history.to_str().unwrap().into(),
    ]);
    flags.extend(link_flags(links, true));
    flags
}

fn ordered_pins(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
) -> Vec<String> {
    vec![
        "--ordered-genesis-manifest".into(),
        fixture
            .directory
            .0
            .join("genesis.bin")
            .to_str()
            .unwrap()
            .into(),
        "--ordered-expected-genesis-digest".into(),
        hex(&fixture.network.manifest_digest),
        "--expected-chain-id".into(),
        fixture.network.chain_id.as_str().into(),
        "--expected-protocol-version".into(),
        fixture.network.protocol_version.get().to_string(),
        "--expected-epoch".into(),
        current.expected_context().epoch().get().to_string(),
        "--domain".into(),
        hex(fixture.network.domain.as_bytes()),
        "--successor-genesis-epoch".into(),
        fixture.network.epoch.get().to_string(),
        "--suite".into(),
        "0:1:1:1:1:1:1:1".into(),
    ]
    .into_iter()
    .chain(link_flags(links, true))
    .collect()
}

fn ordered_network_pins(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    network: &Path,
) -> Vec<String> {
    let mut flags: Vec<String> = ordered_pins(fixture, links, current);
    flags.extend([
        "--ordered-network".into(),
        network.to_str().unwrap().into(),
        "--deadline-seconds".into(),
        "1800".into(),
        "--per-request-cap-seconds".into(),
        "300".into(),
    ]);
    flags
}

fn fastvote_pins(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    network: &Path,
    frontier: bool,
) -> Vec<String> {
    let mut flags: Vec<String> = vec![
        "--fastvote-network".into(),
        network.to_str().unwrap().into(),
        "--fastvote-genesis-manifest".into(),
        fixture
            .directory
            .0
            .join("genesis.bin")
            .to_str()
            .unwrap()
            .into(),
        "--fastvote-expected-genesis-digest".into(),
        hex(&fixture.network.manifest_digest),
        "--expected-chain-id".into(),
        fixture.network.chain_id.as_str().into(),
        "--expected-protocol-version".into(),
        fixture.network.protocol_version.get().to_string(),
        "--expected-epoch".into(),
        current.expected_context().epoch().get().to_string(),
        "--expected-domain".into(),
        hex(fixture.network.domain.as_bytes()),
        "--successor-domain".into(),
        hex(fixture.network.domain.as_bytes()),
        "--successor-genesis-epoch".into(),
        fixture.network.epoch.get().to_string(),
        "--suite".into(),
        "0:1:1:1:1:1:1:1".into(),
        "--fastvote-deadline-seconds".into(),
        "1800".into(),
        "--fastvote-per-request-cap-seconds".into(),
        "300".into(),
    ];
    if !frontier {
        flags.extend(["--expected-hash-suite-id".into(), "1".into()]);
    }
    flags.extend(link_flags(links, true));
    flags
}

fn network_file(directory: &Path, hosts: &[HostProcess]) -> PathBuf {
    std::fs::create_dir_all(directory).unwrap();
    let path: PathBuf = directory.join("network.conf");
    let peers: String = hosts
        .iter()
        .map(|host: &HostProcess| {
            format!("{} {} - -\n", hex(host.validator.as_bytes()), host.address)
        })
        .collect();
    std::fs::write(&path, peers).unwrap();
    path
}

fn operator(binary: &str, mode: &str, flags: Vec<String>) -> String {
    let mut command: Command = Command::new(binary);
    command.arg(mode).args(flags);
    success(process::spawn_bounded_output(
        command,
        Duration::from_secs(600),
    ))
}

fn target_flags(targets: &CurrentTargets, index: usize, signer: bool) -> Vec<String> {
    let path: &Path = &targets.paths[index];
    let mut flags: Vec<String> = vec![
        "--state-db".into(),
        path.join("state.db").to_str().unwrap().into(),
        "--blob-db".into(),
        path.join("body.db").to_str().unwrap().into(),
        "--validator-id".into(),
        hex(targets.members[index].validator_id.as_bytes()),
    ];
    if signer {
        flags.extend([
            "--signer-key-file".into(),
            path.join("private.key").to_str().unwrap().into(),
        ]);
    }
    flags
}

fn host_flags(
    fixture: &Fixture,
    links: &[Link],
    targets: &CurrentTargets,
    index: usize,
    historical: bool,
    epoch: u64,
) -> Vec<String> {
    let path: &Path = &targets.paths[index];
    let mut flags: Vec<String> = original_operator_pins(fixture);
    flags.extend(link_flags(links, false));
    flags.extend([
        "--target-state-db".into(),
        path.join("state.db").to_str().unwrap().into(),
        "--target-blob-db".into(),
        path.join("body.db").to_str().unwrap().into(),
        "--validator-id".into(),
        hex(targets.members[index].validator_id.as_bytes()),
    ]);
    if historical {
        flags.extend(["--historical-epoch".into(), epoch.to_string()]);
    } else {
        flags.extend([
            "--signer-key-file".into(),
            path.join("private.key").to_str().unwrap().into(),
        ]);
    }
    flags
}

fn start(
    executables: &CompiledExecutableSnapshot,
    fixture: &Fixture,
    links: &[Link],
    targets: &CurrentTargets,
    index: usize,
    historical: bool,
    epoch: u64,
) -> HostProcess {
    let mut flags: Vec<String> = host_flags(fixture, links, targets, index, historical, epoch);
    flags.extend([
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--timeout-seconds".into(),
        "600".into(),
    ]);
    if !historical {
        flags.extend([
            "--created-checkpoint".into(),
            HOST_CHECKPOINT.to_string(),
            "--confirm-offline-fence-advance".into(),
        ]);
    }
    let mut command: Command = Command::new(&executables.successor_host);
    command
        .arg(if historical { "serve-history" } else { "serve" })
        .args(flags)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let (mut guard, line): (process::ChildGuard, String) =
        process::spawn_bounded_status_line(command, Duration::from_secs(600));
    assert!(
        !line.is_empty(),
        "recurring host failed: {:?}",
        guard.try_wait()
    );
    let mode: &str = if historical {
        "mode=successor-history-material-only"
    } else {
        "mode=successor-serving"
    };
    assert!(line.contains(mode), "{line}");
    assert_eq!(field(&line, "epoch="), epoch.to_string());
    let address: SocketAddr = field(&line, "listen=").parse().unwrap();
    let generation: u64 = field(&line, "writer_generation=").parse().unwrap();
    HostProcess {
        child: guard.into_inner(),
        address,
        generation,
        validator: targets.members[index].validator_id,
    }
}

fn historical_startup_flags(
    fixture: &Fixture,
    links: &[Link],
    targets: &CurrentTargets,
    epoch: u64,
) -> Vec<String> {
    let mut flags: Vec<String> = host_flags(fixture, links, targets, 0, true, epoch);
    flags.extend([
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--timeout-seconds".into(),
        "600".into(),
    ]);
    flags
}

fn assert_historical_startup_refused(
    executables: &CompiledExecutableSnapshot,
    fixture: &Fixture,
    targets: &CurrentTargets,
    flags: Vec<String>,
    reason: &str,
) {
    let after_injection: ProtectedState = protected_state(fixture, targets);
    let mut command: Command = Command::new(&executables.successor_host);
    command.arg("serve-history").args(flags);
    let output: Output = process::spawn_bounded_output(command, Duration::from_secs(600));
    assert!(!output.status.success(), "startup must refuse {reason}");
    assert!(
        output.stdout.is_empty(),
        "a refused startup never binds or prints serving status"
    );
    let error: String = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains(&format!("successor-host: {reason}")),
        "the actual startup reader must refuse the injected cause: {error}"
    );
    assert_eq!(protected_state(fixture, targets), after_injection);
}

/// Logical artifact-byte faults only. Missing files are held outside every
/// input archive, and Drop restores the original attachment or exact bytes.
struct ArtifactChange {
    path: PathBuf,
    original: Vec<u8>,
    held: Option<PathBuf>,
}

impl ArtifactChange {
    fn inject(path: &Path, held: &Path, missing: bool) -> Self {
        let original: Vec<u8> = std::fs::read(path).unwrap();
        let held: Option<PathBuf> = if missing {
            assert!(!held.exists());
            std::fs::rename(path, held).unwrap();
            Some(held.to_path_buf())
        } else {
            // None of these owning canonical codecs accepts a one-byte frame.
            std::fs::write(path, [0xff]).unwrap();
            None
        };
        Self {
            path: path.to_path_buf(),
            original,
            held,
        }
    }
}

impl Drop for ArtifactChange {
    fn drop(&mut self) {
        match &self.held {
            Some(held) => std::fs::rename(held, &self.path).unwrap(),
            None => std::fs::write(&self.path, &self.original).unwrap(),
        }
    }
}

/// Corrupts only the bytes of an observed real record. It never seeds rows,
/// rewrites revisions, advances a mutation sequence or repairs an origin.
struct HistoricalRowChange {
    path: PathBuf,
    key: Vec<u8>,
    original: Vec<u8>,
}

impl HistoricalRowChange {
    fn inject(path: &Path, key: Vec<u8>, original: Vec<u8>, corrupted: &[u8]) -> Self {
        let connection: rusqlite::Connection = rusqlite::Connection::open(path).unwrap();
        let actual: Vec<u8> = connection
            .query_row(
                "SELECT value FROM durable_state WHERE key = ?1",
                [&key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            actual, original,
            "the fault targets the observed live historical record"
        );
        assert_eq!(
            connection
                .execute(
                    "UPDATE durable_state SET value = ?1 WHERE key = ?2",
                    rusqlite::params![corrupted, &key],
                )
                .unwrap(),
            1
        );
        Self {
            path: path.to_path_buf(),
            key,
            original,
        }
    }
}

impl Drop for HistoricalRowChange {
    fn drop(&mut self) {
        let connection: rusqlite::Connection = rusqlite::Connection::open(&self.path).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE durable_state SET value = ?1 WHERE key = ?2",
                    rusqlite::params![&self.original, &self.key],
                )
                .unwrap(),
            1
        );
    }
}

fn historical_material(
    current: &SuccessorWorkflowAuthority,
    hosts: &[HostProcess],
) -> node_core::ordered_economics::OrderedHistoryIdentity {
    let mut agreed: Option<node_core::ordered_economics::OrderedHistoryIdentity> = None;
    for host in hosts {
        let summary: WireResponse = raw(
            host.address,
            Method::Get,
            node_wire::ORDERED_HISTORY_SUMMARY_PATH,
            None,
            Vec::new(),
        );
        assert_eq!(
            summary.status,
            200,
            "{}",
            String::from_utf8_lossy(&summary.body)
        );
        let identity: node_core::ordered_economics::OrderedHistoryIdentity =
            node_core::ordered_economics::decode_ordered_history_summary(&summary.body)
                .unwrap()
                .identity;
        assert_eq!(identity.context, *current.expected_context());
        let request: node_wire::ordered_history::OrderedHistoryHeightRequest =
            node_wire::ordered_history::OrderedHistoryHeightRequest {
                height: identity.through_height,
                identity: identity.clone(),
            };
        let material: WireResponse = raw(
            host.address,
            Method::Post,
            node_wire::ORDERED_HISTORY_HEIGHT_PATH,
            Some(node_wire::NODE_EVENT_MEDIA_TYPE),
            request.encode().unwrap(),
        );
        assert_eq!(
            material.status,
            200,
            "{}",
            String::from_utf8_lossy(&material.body)
        );
        let descriptor: node_core::ordered_economics::OrderedHistoryHeightDescriptor =
            node_core::ordered_economics::decode_ordered_history_height_descriptor(&material.body)
                .unwrap();
        assert_eq!(descriptor.identity, identity);
        assert_eq!(descriptor.height, identity.through_height);
        assert!(descriptor.components.iter().any(|reference| {
            reference.kind == node_core::ordered_economics::OrderedHistoryComponentKind::Candidate
        }));
        if let Some(previous) = &agreed {
            assert_eq!(&identity, previous);
        }
        agreed = Some(identity);
    }
    agreed.unwrap()
}

fn assert_historical_material_refused(hosts: &[HostProcess]) {
    for host in hosts {
        let response: WireResponse = raw(
            host.address,
            Method::Get,
            node_wire::ORDERED_HISTORY_SUMMARY_PATH,
            None,
            Vec::new(),
        );
        assert_eq!(response.status, 503);
        assert!(
            std::str::from_utf8(&response.body)
                .unwrap()
                .contains("ordered-history-unavailable"),
            "the existing history reader refuses unavailable authenticated material"
        );
    }
}

fn terminal_descriptor(
    fixture: &Fixture,
    current: &SuccessorWorkflowAuthority,
    targets: &CurrentTargets,
    identity: &node_core::ordered_economics::OrderedHistoryIdentity,
) -> Result<
    node_core::ordered_economics::OrderedHistoryHeightDescriptor,
    node_core::ordered_economics::OrderedEconomicsError,
> {
    let store: SqliteDurableStore = SqliteDurableStore::open_historical(
        targets.paths[0].join("state.db"),
        SqliteNamespace::new(
            fixture.network.chain_id.clone(),
            targets.members[0].validator_id,
            fixture.network.domain,
        ),
    )
    .unwrap();
    let operation: runtime::DurableOperationContext = runtime::DurableOperationContext::new(
        store.writer_fence().unwrap(),
        runtime::StorageDeadline::new(u64::MAX / 2).unwrap(),
        runtime::StorageCorrelationId::new([0xce; 16]).unwrap(),
    );
    let blobs: SqliteBlobStore =
        SqliteBlobStore::open_existing(targets.paths[0].join("body.db")).unwrap();
    let leg_policy: execution::local_execution::LocalExecutionPolicy =
        execution::local_execution::LocalExecutionPolicy::generic_object_results(
            current.expected_context().clone(),
        );
    let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
    let environment: node_core::ordered_economics::OrderedEconomicsEnvironment<'_> =
        node_core::ordered_economics::OrderedEconomicsEnvironment {
            policy: current.ordered_policy(),
            history: &[],
            leg_policy: &leg_policy,
            engine: &engine,
            blobs: &blobs,
            seal: None,
        };
    node_core::ordered_economics::read_ordered_history_height_descriptor(
        &store,
        &operation,
        &environment,
        identity,
        identity.through_height,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_historical_artifact_controls(
    executables: &CompiledExecutableSnapshot,
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    targets: &CurrentTargets,
    hosts: &[HostProcess],
    directory: &Path,
    seal: &OrderedCandidate,
) {
    assert_eq!(current.expected_context().epoch().get(), 1);
    let intact: ProtectedState = protected_state(fixture, targets);
    for (_, origin, barrier, slot) in &intact.metadata {
        assert!(matches!(
            origin,
            runtime::NamespaceLifecycle::CompleteInactive { .. }
        ));
        assert!(
            matches!(barrier, runtime::OutgoingBarrier::Sealed(sealed) if sealed.outgoing_epoch == current.expected_context().epoch() && sealed.request == seal.request_id)
        );
        assert!(
            slot.is_serving(),
            "permanent import origin and activation are retained after Seal"
        );
    }
    let identity: node_core::ordered_economics::OrderedHistoryIdentity =
        historical_material(current, hosts);
    let _: node_core::ordered_economics::OrderedHistoryHeightDescriptor =
        terminal_descriptor(fixture, current, targets, &identity).unwrap();
    let positive_host: HostProcess = start(executables, fixture, links, targets, 0, true, 1);
    assert_eq!(
        historical_material(current, std::slice::from_ref(&positive_host)),
        identity
    );
    drop(positive_host);
    assert_eq!(protected_state(fixture, targets), intact);
    let wrong_epoch: Vec<String> = historical_startup_flags(fixture, links, targets, 2);
    assert_historical_startup_refused(
        executables,
        fixture,
        targets,
        wrong_epoch,
        "historical current namespace pins differ from verified chain",
    );
    let mut foreign: Vec<String> = historical_startup_flags(fixture, links, targets, 1);
    let validator_flag: usize = foreign
        .iter()
        .position(|flag| flag == "--validator-id")
        .unwrap();
    foreign[validator_flag + 1] = hex(targets.members[1].validator_id.as_bytes());
    assert_historical_startup_refused(
        executables,
        fixture,
        targets,
        foreign,
        "SQLite database already has a different bound chain/validator/domain",
    );
    let link: &Link = links.last().unwrap();
    let cut_identity: PathBuf = link.cut.join("identity.bin");
    let certificate: PathBuf = link.certificate.join("certificate.bin");
    let history_pin: PathBuf = link.manifest_history.join("identity.bin");
    node_core::business_reconstruction::cut::decode_business_cut_identity(
        &std::fs::read(&cut_identity).unwrap(),
    )
    .unwrap();
    consensus::readiness::decode_readiness_certificate(&std::fs::read(&certificate).unwrap())
        .unwrap();
    node_core::ordered_economics::decode_ordered_history_identity(
        &std::fs::read(&history_pin).unwrap(),
    )
    .unwrap();
    for (label, file, missing_reason) in [
        ("cut", cut_identity, "successor artifact could not be read"),
        ("certificate", certificate, "successor artifact is missing"),
        (
            "history-pin",
            history_pin,
            "successor artifact could not be read",
        ),
    ] {
        for missing in [true, false] {
            assert_eq!(historical_material(current, hosts), identity);
            let held: PathBuf = directory.join(format!("{label}-{missing}.held"));
            let fault: ArtifactChange = ArtifactChange::inject(&file, &held, missing);
            let after_injection: ProtectedState = protected_state(fixture, targets);
            assert_historical_startup_refused(
                executables,
                fixture,
                targets,
                historical_startup_flags(fixture, links, targets, 1),
                if missing {
                    missing_reason
                } else {
                    "successor artifact is malformed"
                },
            );
            assert_historical_material_refused(hosts);
            assert_eq!(protected_state(fixture, targets), after_injection);
            drop(fault);
            assert_eq!(protected_state(fixture, targets), intact);
            assert_eq!(historical_material(current, hosts), identity);
        }
    }
    // Locate the actual current terminal proof and candidate by decoding
    // their observed source values; no private key builder or filename guess.
    let seal_bytes: Vec<u8> = node_core::ordered_economics::encode_ordered_candidate(seal).unwrap();
    let mut changed_seal: OrderedCandidate = seal.clone();
    // Pure Seal authentication bounds certificate_length, but the staged
    // certificate owner checks its actual length only under a live warrant.
    // Changing only this non-secret field preserves the cut checkpoint,
    // certificate digest and derived request id, so the genuine companions
    // remain readable and the history owner must reject the candidate digest.
    // This negative is policy-valid, not a verified certificate or Seal warrant.
    let mut changed_intent: node_core::ordered_economics::SealIntent =
        node_core::ordered_economics::decode_seal_intent(&seal.intent).unwrap();
    let original_length: u32 = changed_intent.certificate_length;
    let maximum_length: u32 =
        u32::try_from(consensus::readiness::MAX_READINESS_CERTIFICATE_BYTES).unwrap();
    assert!((1..=maximum_length).contains(&original_length));
    changed_intent.certificate_length = if original_length < maximum_length {
        original_length.checked_add(1).unwrap()
    } else {
        original_length.checked_sub(1).unwrap()
    };
    assert!((1..=maximum_length).contains(&changed_intent.certificate_length));
    assert_ne!(changed_intent.certificate_length, original_length);
    changed_seal.intent =
        node_core::ordered_economics::encode_seal_intent(&changed_intent).unwrap();
    assert_eq!(
        node_core::ordered_economics::decode_seal_intent(&changed_seal.intent).unwrap(),
        changed_intent
    );
    current
        .ordered_policy()
        .authenticate_candidate(&changed_seal)
        .unwrap();
    let changed_candidate: Vec<u8> =
        node_core::ordered_economics::encode_ordered_candidate(&changed_seal).unwrap();
    assert_eq!(
        node_core::ordered_economics::decode_ordered_candidate(&changed_candidate).unwrap(),
        changed_seal
    );
    assert_ne!(changed_candidate, seal_bytes);
    assert_ne!(
        current
            .ordered_policy()
            .candidate_digest(&changed_seal)
            .unwrap(),
        current.ordered_policy().candidate_digest(seal).unwrap()
    );
    for proof_fault in [true, false] {
        assert_eq!(historical_material(current, hosts), identity);
        let mut faults: Vec<HistoricalRowChange> = Vec::with_capacity(targets.paths.len());
        for (index, snapshot) in intact.business.iter().enumerate() {
            let matching: Vec<&node_core::business_reconstruction::SourceSnapshotRecord> = snapshot
                .records
                .iter()
                .filter(|record| {
                    if !matches!(
                        record.descriptor.key(),
                        runtime::portable::DurableRecordKey::State(_)
                    ) {
                        return false;
                    }
                    let Some(bytes) = &record.value else {
                        return false;
                    };
                    if proof_fault {
                        consensus::decode_committed_block_proof(bytes).is_ok_and(|proof| {
                            proof.committed.epoch == identity.context.epoch()
                                && proof.committed.height == identity.through_height
                        })
                    } else {
                        *bytes == seal_bytes
                    }
                })
                .collect();
            assert_eq!(
                matching.len(),
                1,
                "exactly one real current terminal record is targeted"
            );
            let record: &node_core::business_reconstruction::SourceSnapshotRecord = matching[0];
            let runtime::portable::DurableRecordKey::State(key) = record.descriptor.key() else {
                unreachable!();
            };
            let original: Vec<u8> = record.value.clone().unwrap();
            faults.push(HistoricalRowChange::inject(
                &targets.paths[index].join("state.db"),
                key.clone(),
                original,
                if proof_fault {
                    &[0xff]
                } else {
                    &changed_candidate
                },
            ));
        }
        let after_injection: ProtectedState = protected_state(fixture, targets);
        assert_eq!(
            after_injection.metadata, intact.metadata,
            "corruption changes neither fence nor permanent Seal origin"
        );
        let expected: &str = if proof_fault {
            "ordered history archived proof encoding"
        } else {
            "ordered history candidate digest mismatch"
        };
        let error: node_core::ordered_economics::OrderedEconomicsError =
            terminal_descriptor(fixture, current, targets, &identity).unwrap_err();
        assert!(
            matches!(&error, node_core::ordered_economics::OrderedEconomicsError::Prerequisite(reason) if *reason == expected),
            "actual terminal reader refusal: {error}"
        );
        assert_historical_material_refused(hosts);
        assert_eq!(protected_state(fixture, targets), after_injection);
        drop(faults);
        assert_eq!(protected_state(fixture, targets), intact);
        assert_eq!(historical_material(current, hosts), identity);
    }
    let positive_host: HostProcess = start(executables, fixture, links, targets, 0, true, 1);
    assert_eq!(
        historical_material(current, std::slice::from_ref(&positive_host)),
        identity
    );
    drop(positive_host);
    assert_eq!(protected_state(fixture, targets), intact);
}

fn committed_outcome(hosts: &[HostProcess], request: [u8; 32]) -> OrderedOutcome {
    agreed_outcome(hosts, request, node_core::NodeResponseStatus::Accepted)
}

fn agreed_outcome(
    hosts: &[HostProcess],
    request: [u8; 32],
    expected: node_core::NodeResponseStatus,
) -> OrderedOutcome {
    let mut agreed: Option<OrderedOutcome> = None;
    for host in hosts {
        let response: WireResponse = raw(
            host.address,
            Method::Get,
            &format!(
                "{}{}",
                node_wire::ordered_economics::ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX,
                hex(&request)
            ),
            None,
            Vec::new(),
        );
        assert_eq!(
            response.status,
            200,
            "{}",
            String::from_utf8_lossy(&response.body)
        );
        let outcome: OrderedOutcome = decode_ordered_outcome(&response.body).unwrap();
        assert_eq!(outcome.request_id, request);
        assert!(
            outcome
                .output
                .responses()
                .iter()
                .all(|response: &node_core::NodeResponse| response.status() == expected)
        );
        if let Some(previous) = &agreed {
            assert_eq!(previous, &outcome);
        }
        agreed = Some(outcome);
    }
    agreed.unwrap()
}

fn submit(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    network: &Path,
    candidate: &Path,
    output: &Path,
) {
    let mut flags: Vec<String> = ordered_network_pins(fixture, links, current, network);
    flags.extend([
        "--candidate".into(),
        candidate.to_str().unwrap().into(),
        "--out".into(),
        output.to_str().unwrap().into(),
    ]);
    cli(&["economics", "network-submit"], flags);
}

/// Proves actual signing and completion from the CLI's persisted canonical
/// re-encodings of HTTP acknowledgements, not membership in its trimmed QC.
/// The real four-peer submit, rotating leaders and delivery remain unchanged.
fn reopened_host_submission(
    fixture: &Fixture,
    current: &SuccessorWorkflowAuthority,
    targets: &CurrentTargets,
    hosts: &[HostProcess],
    candidate_path: &Path,
    prefix: &Path,
    initial_parent: &QuorumCertificate,
) -> OrderedOutcome {
    assert_eq!(current.expected_context().epoch(), Epoch::new(2));
    assert_eq!(hosts.len(), 4);
    assert_eq!(targets.members.len(), hosts.len());
    assert_eq!(targets.paths.len(), hosts.len());
    let set: &validator_set::ValidatorSet = current.ordered_policy().engine().validator_set();
    assert_eq!(set.validators().len(), hosts.len());
    assert_eq!(set.quorum_threshold(), 3);
    let validator_ids: Vec<ValidatorId> = hosts
        .iter()
        .enumerate()
        .map(|(index, host): (usize, &HostProcess)| {
            let member: &SuccessorProcessMember = &targets.members[index];
            let pinned: &validator_set::ValidatorInfo = set.get(host.validator).unwrap();
            assert_eq!(host.validator, member.validator_id);
            assert_eq!(pinned.voting_power, 1);
            let key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from(member.seed);
            let public: [u8; 32] = ed25519_zebra::VerificationKey::from(&key).into();
            assert_eq!(pinned.signature_scheme, SignatureSchemeId::Ed25519);
            assert_eq!(pinned.public_key.as_slice(), public.as_slice());
            host.validator
        })
        .collect();
    let endpoints: Vec<String> = hosts
        .iter()
        .map(|host: &HostProcess| host.address.to_string())
        .collect();
    let candidate: OrderedCandidate = node_core::ordered_economics::decode_ordered_candidate(
        &std::fs::read(candidate_path).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        candidate.kind,
        node_core::ordered_economics::OrderedOperationKind::Freeze
            | node_core::ordered_economics::OrderedOperationKind::Seal
    ));
    let rounds: Vec<(OrderedProposal, QuorumCertificate)> = saved_policy_submission_rounds(
        current.ordered_policy(),
        candidate_path,
        prefix,
        &candidate,
        initial_parent,
    );
    let candidate_round: usize = rounds
        .iter()
        .position(|(proposal, _): &(OrderedProposal, QuorumCertificate)| {
            proposal.candidate.as_ref() == Some(&candidate)
        })
        .unwrap();
    let candidate_digest: protocol_types::Digest32 = current
        .ordered_policy()
        .candidate_digest(&candidate)
        .unwrap();
    let results: BTreeMap<(usize, usize), (String, String)> =
        saved_configured_peer_results(&validator_ids, prefix, &endpoints, rounds.len());
    let mut completed: Option<OrderedOutcome> = None;
    for (round, (proposal, certificate)) in rounds.iter().enumerate() {
        let mut actual_votes: Vec<ConsensusVote> = Vec::with_capacity(hosts.len());
        for (index, host) in hosts.iter().enumerate() {
            let (vote_phase, certificate_phase): &(String, String) = &results[&(round, index)];
            let voted: OrderedEventOutput = acknowledged_output(vote_phase);
            let certified: OrderedEventOutput = acknowledged_output(certificate_phase);
            assert!(voted.committed.is_empty());
            assert!(certified.messages.is_empty());
            let votes: Vec<&ConsensusVote> = voted
                .messages
                .iter()
                .filter_map(|message: &ConsensusMessage| match message {
                    ConsensusMessage::Vote(vote) => Some(vote),
                    _ => None,
                })
                .collect();
            assert_eq!(
                votes.len(),
                1,
                "one real signed vote per attributed HTTP reply"
            );
            let vote: &ConsensusVote = votes[0];
            assert_eq!(vote.validator, host.validator);
            assert_eq!(vote.proposal_digest, certificate.proposal_digest);
            assert_eq!(vote.height, proposal.proposal.height);
            assert_eq!(vote.view, proposal.proposal.view);
            current
                .ordered_policy()
                .engine()
                .verify_vote(vote, &FastPathEd25519Verifier)
                .unwrap();
            actual_votes.push(vote.clone());
            if round == rounds.len() - 1 {
                assert_eq!(certified.committed.len(), 1);
                let outcome: &OrderedOutcome = &certified.committed[0];
                assert_eq!(outcome.request_id, candidate.request_id);
                assert_eq!(outcome.candidate_digest, candidate_digest);
                assert_eq!(
                    outcome.block_height,
                    rounds[candidate_round].0.proposal.height
                );
                assert_eq!(
                    outcome.block_digest,
                    rounds[candidate_round].1.proposal_digest
                );
                assert_eq!(outcome.output.responses().len(), 1);
                assert_eq!(
                    outcome.output.responses()[0].status(),
                    node_core::NodeResponseStatus::Accepted
                );
                if let Some(previous) = &completed {
                    assert_eq!(previous, outcome);
                }
                completed = Some(outcome.clone());
            } else {
                assert!(
                    certified.committed.is_empty(),
                    "alignment and earlier suffix certificates cannot acknowledge completion"
                );
            }
        }
        assert_eq!(
            actual_votes[3].validator, targets.members[3].validator_id,
            "the reopened fourth really signs the candidate and both certified descendants"
        );
        let reconstructed: QuorumCertificate = current
            .ordered_policy()
            .engine()
            .certificate_from_votes(&proposal.proposal, &actual_votes, &FastPathEd25519Verifier)
            .unwrap()
            .unwrap();
        assert_eq!(reconstructed.votes.len(), 3);
        assert_eq!(
            consensus::encode_quorum_certificate(&reconstructed).unwrap(),
            std::fs::read(format!("{}.round-{round}.certificate", prefix.display())).unwrap(),
            "all four verified returned votes reproduce the exact saved minimal QC"
        );
    }
    let completed: OrderedOutcome = completed.unwrap();
    let last_certificate: &QuorumCertificate = &rounds.last().unwrap().1;
    let request: runtime::DurableRequestId =
        runtime::DurableRequestId::new(candidate.request_id).unwrap();
    let mut agreed_receipt: Option<runtime::DurableRequestReceipt> = None;
    for (index, host) in hosts.iter().enumerate() {
        assert_eq!(
            &status(host.address).high_qc,
            last_certificate,
            "every real endpoint applied the exact final certified suffix"
        );
        let store: SqliteDurableStore = SqliteDurableStore::open_historical(
            targets.paths[index].join("state.db"),
            SqliteNamespace::new(
                fixture.network.chain_id.clone(),
                host.validator,
                fixture.network.domain,
            ),
        )
        .unwrap();
        let operation: runtime::DurableOperationContext = runtime::DurableOperationContext::new(
            store.writer_fence().unwrap(),
            runtime::StorageDeadline::new(u64::MAX / 2).unwrap(),
            runtime::StorageCorrelationId::new([0xd3; 16]).unwrap(),
        );
        let receipt: runtime::DurableRequestReceipt = store
            .get_request_receipt(&operation, fixture.network.domain, request)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.request_id(), request);
        assert_eq!(receipt.event_digest(), candidate_digest);
        let record: node_core::NodeDedupRecord =
            node_core::NodeDedupRecord::decode(receipt.canonical_bytes()).unwrap();
        assert_eq!(record.request_id().as_bytes(), &candidate.request_id);
        assert_eq!(record.event_digest(), candidate_digest);
        assert_eq!(record.responses(), completed.output.responses());
        if let Some(previous) = &agreed_receipt {
            assert_eq!(
                previous, &receipt,
                "all four durable canonical receipts agree"
            );
        }
        agreed_receipt = Some(receipt);
    }
    completed
}

/// Like `cli`, but reports failure instead of panicking: used only to prove
/// that a genuinely malformed-authority submission is never admitted.
fn cli_attempt(prefix: &[&str], tail: Vec<String>) -> Result<(), String> {
    let mut arguments: Vec<OsString> = prefix.iter().map(OsString::from).collect();
    arguments.extend(tail.into_iter().map(OsString::from));
    tokio::task::block_in_place(|| sunrise_edge_cli::run(arguments))
        .map_err(|error| error.to_string())
}

fn export_history(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    network: &Path,
    validator: ValidatorId,
    output: &Path,
) {
    let mut flags: Vec<String> = ordered_network_pins(fixture, links, current, network);
    flags.extend([
        "--target-validator-id".into(),
        hex(validator.as_bytes()),
        "--out-dir".into(),
        output.to_str().unwrap().into(),
        "--history-max-heights".into(),
        "4096".into(),
    ]);
    cli(&["economics", "history-export"], flags);
    sunrise_edge_client::ordered_history_archive::read_verified_ordered_history_archive(
        current.ordered_policy(),
        output,
    )
    .unwrap();
}

fn next_set(
    current: &SuccessorWorkflowAuthority,
    members: &[SuccessorProcessMember],
) -> validator_set::ValidatorSet {
    let infos: Vec<validator_set::ValidatorInfo> = members
        .iter()
        .map(|member: &SuccessorProcessMember| {
            let power: u64 = current
                .fastvote_certifier()
                .validator_set()
                .get(member.validator_id)
                .map_or(1, |previous: &validator_set::ValidatorInfo| {
                    previous.voting_power
                });
            validator_set::ValidatorInfo {
                id: member.validator_id,
                voting_power: power,
                signature_scheme: SignatureSchemeId::Ed25519,
                public_key: member.validator_id.as_bytes().to_vec(),
            }
        })
        .collect();
    // This is an operator advisory only. Freeze, readiness and Seal check
    // the actual committed registration, bond, key and eligibility.
    validator_set::ValidatorSet::new(
        Epoch::new(
            current
                .expected_context()
                .epoch()
                .get()
                .checked_add(1)
                .unwrap(),
        ),
        infos,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn freeze_and_drain(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    targets: &CurrentTargets,
    hosts: &[HostProcess],
    directory: &Path,
    network: &Path,
    next_members: &[SuccessorProcessMember],
) -> (Vec<u8>, Vec<u8>) {
    let epoch: u64 = current.expected_context().epoch().get();
    let next_context: execution::publication::PublicationContext =
        execution::publication::PublicationContext::new(
            fixture.network.chain_id.clone(),
            fixture.network.protocol_version,
            Epoch::new(epoch + 1),
        )
        .unwrap();
    let advisory: FastPathValidatorSetRecord = FastPathValidatorSetRecord {
        context: next_context,
        validators: next_set(current, next_members)
            .validators()
            .iter()
            .map(
                |member: &validator_set::ValidatorInfo| FastPathValidatorEntry {
                    id: member.id,
                    voting_power: member.voting_power,
                    signature_scheme: member.signature_scheme,
                    public_key: member.public_key.clone(),
                },
            )
            .collect(),
    };
    let advisory_path: PathBuf = directory.join("advisory-next-set.bin");
    std::fs::write(
        &advisory_path,
        node_core::fast_path::records::encode_fastpath_validator_set_record(&advisory).unwrap(),
    )
    .unwrap();
    let freeze_request: [u8; 32] = epoch_request_id(epoch, 0xb1);
    let freeze_path: PathBuf = directory.join("freeze.candidate");
    let mut flags: Vec<String> = ordered_network_pins(fixture, links, current, network);
    flags.extend([
        "--request-id".into(),
        hex(&freeze_request),
        "--created-checkpoint".into(),
        HOST_CHECKPOINT.to_string(),
        "--advisory-next-set".into(),
        advisory_path.to_str().unwrap().into(),
        "--out".into(),
        freeze_path.to_str().unwrap().into(),
    ]);
    cli(&["economics", "ordered-freeze-build"], flags);
    let freeze_submission: PathBuf = directory.join("freeze-submission");
    let freeze_parent: Option<QuorumCertificate> =
        (epoch == 2).then(|| status(hosts[0].address).high_qc);
    submit(
        fixture,
        links,
        current,
        network,
        &freeze_path,
        &freeze_submission,
    );
    let freeze: OrderedOutcome = committed_outcome(hosts, freeze_request);
    if let Some(initial_parent) = &freeze_parent {
        assert_eq!(
            reopened_host_submission(
                fixture,
                current,
                targets,
                hosts,
                &freeze_path,
                &freeze_submission,
                initial_parent,
            ),
            freeze,
            "actual HTTP completion acknowledgements match every host's retained Freeze outcome"
        );
    }
    let mut votes: Vec<PathBuf> = Vec::new();
    let mut selected_ids: Vec<ValidatorId> =
        current_quorum_ids(current.fastvote_certifier().validator_set());
    if epoch == 2 && !selected_ids.contains(&targets.members[3].validator_id) {
        selected_ids.push(targets.members[3].validator_id);
        selected_ids.sort_unstable();
    }
    for (index, member) in targets
        .members
        .iter()
        .enumerate()
        .filter(|(_, member)| selected_ids.contains(&member.validator_id))
    {
        let vote_path: PathBuf = directory.join(format!("frontier-{index}.vote"));
        let mut flags: Vec<String> = fastvote_pins(fixture, links, current, network, true);
        flags.extend([
            "--validator-id".into(),
            hex(member.validator_id.as_bytes()),
            "--freeze-request-id".into(),
            hex(&freeze_request),
            "--freeze-height".into(),
            freeze.block_height.to_string(),
            "--max-steps".into(),
            "4096".into(),
            "--vote-out".into(),
            vote_path.to_str().unwrap().into(),
        ]);
        cli(&["contract", "fastvote-frontier-advance"], flags);
        let actual_vote: sunrise_edge_client::FrozenFrontierVote =
            sunrise_edge_client::decode_frozen_frontier_vote(&std::fs::read(&vote_path).unwrap())
                .unwrap();
        assert_eq!(actual_vote.validator, member.validator_id);
        assert_eq!(
            actual_vote.identity.chain_id,
            *current.expected_context().chain_id()
        );
        assert_eq!(
            actual_vote.identity.protocol_version,
            current.expected_context().protocol_version()
        );
        assert_eq!(
            actual_vote.identity.epoch,
            current.expected_context().epoch()
        );
        votes.push(vote_path);
    }
    let selection: PathBuf = directory.join("selection.manifest");
    let paths: String = votes
        .iter()
        .map(|path: &PathBuf| format!("{}\n", path.to_str().unwrap()))
        .collect();
    std::fs::write(&selection, paths).unwrap();
    let mut union_files: Vec<PathBuf> = Vec::new();
    for (index, member) in targets.members.iter().enumerate() {
        let union_path: PathBuf = directory.join(format!("union-{index}.bin"));
        let mut flags: Vec<String> = fastvote_pins(fixture, links, current, network, false);
        flags.extend([
            "--target-validator".into(),
            hex(member.validator_id.as_bytes()),
            "--drain-selection-manifest".into(),
            selection.to_str().unwrap().into(),
            "--drain-freeze-request-id".into(),
            hex(&freeze_request),
            "--drain-freeze-height".into(),
            freeze.block_height.to_string(),
            "--drain-page-limit".into(),
            "128".into(),
            "--drain-max-mutation-attempts".into(),
            "4096".into(),
            "--out-drain-union-identity".into(),
            union_path.to_str().unwrap().into(),
        ]);
        cli(&["contract", "fastvote-drain-local-ready"], flags);
        union_files.push(union_path);
    }
    let first: Vec<u8> = std::fs::read(&union_files[0]).unwrap();
    for union in &union_files {
        assert_eq!(std::fs::read(union).unwrap(), first);
    }
    let drain_request: [u8; 32] = epoch_request_id(epoch, 0xb2);
    let drain_path: PathBuf = directory.join("drain-set.candidate");
    let mut flags: Vec<String> = ordered_pins(fixture, links, current);
    flags.extend([
        "--drain-selection-manifest".into(),
        selection.to_str().unwrap().into(),
        "--drain-union-identity".into(),
        union_files[0].to_str().unwrap().into(),
        "--request-id".into(),
        hex(&drain_request),
        "--created-checkpoint".into(),
        HOST_CHECKPOINT.to_string(),
        "--out".into(),
        drain_path.to_str().unwrap().into(),
    ]);
    cli(&["economics", "drain-set-build"], flags);
    submit(
        fixture,
        links,
        current,
        network,
        &drain_path,
        &directory.join("drain-submission"),
    );
    committed_outcome(hosts, drain_request);
    // Real retained paid inputs, not reconstructed or re-signed members.
    for tag in [0x6f, 0x70, 0x71] {
        let request: [u8; 32] = epoch_request_id(epoch, tag);
        for (index, member) in targets.members.iter().enumerate() {
            let output: PathBuf = directory.join(format!("member-{tag}-{index}.result"));
            let mut flags: Vec<String> = fastvote_pins(fixture, links, current, network, false);
            flags.extend([
                "--validator-id".into(),
                hex(member.validator_id.as_bytes()),
                "--signed-intent".into(),
                paid_intent_path(fixture, request).to_str().unwrap().into(),
                "--out-result".into(),
                output.to_str().unwrap().into(),
            ]);
            cli(&["contract", "fastvote-drain-member"], flags.clone());
            let original: Vec<u8> = std::fs::read(&output).unwrap();
            cli(&["contract", "fastvote-drain-member"], flags);
            assert_eq!(std::fs::read(&output).unwrap(), original);
        }
    }
    let endpoints: Vec<OrderedEconomicsEndpoint<LoopbackHttpTransport>> = ordered_endpoints(
        &hosts
            .iter()
            .map(Some)
            .collect::<Vec<Option<&HostProcess>>>(),
    );
    let mut last_round: Option<(Vec<u8>, Vec<u8>)> = None;
    for _ in 0..2 {
        let outcome: RoundOutcome = round(&endpoints, current, None);
        last_round = Some((outcome.proposal_bytes, outcome.certificate_bytes));
    }
    // A genuine EMPTY-round envelope (no business candidate), reused below as
    // authentic stale material instead of being discarded.
    last_round.unwrap()
}

/// The live authority, physical targets and exported history of one source epoch.
struct CurrentSource<'a> {
    authority: &'a SuccessorWorkflowAuthority,
    targets: &'a CurrentTargets,
    history: &'a Path,
}

fn install_next(
    executables: &CompiledExecutableSnapshot,
    fixture: &Fixture,
    links: &[Link],
    source: CurrentSource<'_>,
    directory: &Path,
    next_members: &[SuccessorProcessMember],
) -> (CurrentTargets, PathBuf, PathBuf) {
    let current: &SuccessorWorkflowAuthority = source.authority;
    let targets: &CurrentTargets = source.targets;
    let history: &Path = source.history;
    let cut: PathBuf = directory.join("business-cut");
    std::fs::create_dir(&cut).unwrap();
    let mut flags: Vec<String> = current_operator_pins(fixture, links, history);
    flags.extend(target_flags(targets, 0, true));
    flags.extend([
        "--out-dir".into(),
        cut.to_str().unwrap().into(),
        "--timeout-seconds".into(),
        "3600".into(),
    ]);
    assert!(
        operator(
            executables.business_cut.to_str().unwrap(),
            "export-sqlite",
            flags
        )
        .contains("business_cut=complete")
    );
    let next_set: validator_set::ValidatorSet = next_set(current, next_members);
    let next_path: PathBuf = directory.join("readiness-next-set.bin");
    std::fs::write(
        &next_path,
        validator_set::encode_validator_set(&next_set).unwrap(),
    )
    .unwrap();
    let next: CurrentTargets = CurrentTargets {
        paths: next_members
            .iter()
            .enumerate()
            .map(|(index, _)| directory.join(format!("next-target-{index}")))
            .collect(),
        members: next_members.to_vec(),
    };
    let mut votes: Vec<PathBuf> = Vec::new();
    for (index, member) in next.members.iter().enumerate() {
        std::fs::create_dir(&next.paths[index]).unwrap();
        let key: PathBuf = next.paths[index].join("private.key");
        std::fs::write(&key, member.seed).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut flags: Vec<String> = current_operator_pins(fixture, links, history);
        flags.extend(target_flags(&next, index, false));
        flags.extend([
            "--cut-dir".into(),
            cut.to_str().unwrap().into(),
            "--timeout-seconds".into(),
            "3600".into(),
        ]);
        assert!(
            operator(
                executables.business_import.to_str().unwrap(),
                "create-sqlite",
                flags
            )
            .contains("business_import=complete-inactive")
        );
        let vote: PathBuf = directory.join(format!("readiness-{index}"));
        std::fs::create_dir(&vote).unwrap();
        let mut flags: Vec<String> = current_operator_pins(fixture, links, history);
        flags.extend(target_flags(&next, index, true));
        flags.extend([
            "--cut-dir".into(),
            cut.to_str().unwrap().into(),
            "--next-set".into(),
            next_path.to_str().unwrap().into(),
            "--out-dir".into(),
            vote.to_str().unwrap().into(),
            "--timeout-seconds".into(),
            "3600".into(),
        ]);
        operator(
            executables.conditional_readiness.to_str().unwrap(),
            "vote-sqlite",
            flags,
        );
        votes.push(vote.join("vote.bin"));
    }
    let certificate: PathBuf = directory.join("readiness-certificate");
    std::fs::create_dir(&certificate).unwrap();
    let mut flags: Vec<String> = current_operator_pins(fixture, links, history);
    flags.extend([
        "--cut-dir".into(),
        cut.to_str().unwrap().into(),
        "--next-set".into(),
        next_path.to_str().unwrap().into(),
        "--out-dir".into(),
        certificate.to_str().unwrap().into(),
    ]);
    let selected: Vec<ValidatorId> = current_quorum_ids(&next_set);
    for (vote, member) in votes
        .into_iter()
        .zip(&next.members)
        .filter(|(_, member)| selected.contains(&member.validator_id))
    {
        assert!(next_set.get(member.validator_id).is_some());
        flags.extend(["--vote".into(), vote.to_str().unwrap().into()]);
    }
    operator(
        executables.conditional_readiness.to_str().unwrap(),
        "certificate",
        flags,
    );
    let verified: ReadinessCertificate = consensus::readiness::decode_readiness_certificate(
        &std::fs::read(certificate.join("certificate.bin")).unwrap(),
    )
    .unwrap();
    assert_eq!(verified.next_set, next_set);
    let f: ValidatorId = member_from_seed([0xf6; 32]).validator_id;
    if next_set.get(f).is_some() {
        assert_eq!(next.paths.len(), 5);
        assert!(
            verified.votes.iter().any(|vote| vote.signer == f),
            "e3 readiness contains F's actual independent signature"
        );
    }
    (next, cut, certificate)
}

fn inspect_old_share(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    targets: &CurrentTargets,
    claimant: usize,
) -> node_core::fee_claims::FeeClaimInspection {
    let original = &fixture.network.validators[claimant];
    let index: usize = targets
        .members
        .iter()
        .position(|member: &SuccessorProcessMember| member.validator_id == original.validator_id)
        .unwrap();
    let directories: Vec<SuccessorArtifactDirectories<'_>> =
        links.iter().map(Link::directories).collect();
    let mut artifacts: SuccessorChainArtifactFiles =
        SuccessorChainArtifactFiles::open(&directories, budget()).unwrap();
    let pins: Vec<node_core::serving_authority::SuccessorLinkPins> = artifacts.pins();
    let target: runtime_sqlite::SqliteImportTarget =
        runtime_sqlite::SqliteImportTarget::open_existing(
            targets.paths[index].join("state.db"),
            SqliteNamespace::new(
                fixture.network.chain_id.clone(),
                original.validator_id,
                fixture.network.domain,
            ),
            current.authority().import_binding(),
        )
        .unwrap();
    let blobs: SqliteBlobStore =
        SqliteBlobStore::open_existing(targets.paths[index].join("body.db")).unwrap();
    let operation: runtime::DurableOperationContext = runtime::DurableOperationContext::new(
        target.writer_fence().unwrap(),
        runtime::StorageDeadline::new(u64::MAX / 2).unwrap(),
        runtime::StorageCorrelationId::new([0xca; 16]).unwrap(),
    );
    let public: [u8; 32] = ed25519_zebra::VerificationKey::from(&original.signing_key).into();
    let warrant = match resolve_live_authority_chain(
        &target,
        &operation,
        fixture.network.domain,
        fixture.plan(&pins[0].cut_identity, operation),
        &pins,
        budget(),
        &mut artifacts,
        public,
    )
    .unwrap()
    {
        LiveAuthority::Successor(warrant) => warrant,
        LiveAuthority::OriginalGenesis => panic!("a later imported target is not original genesis"),
    };
    node_core::serving_authority::inspect_fee_claim_successor(
        &warrant,
        &target,
        &blobs,
        &fixture.network.resolver,
        &[],
        &execution::local_execution::LocalExecutionPolicy::generic_object_results(
            current.expected_context().clone(),
        ),
        node_core::serving_authority::SuccessorFeeClaimInspection {
            escrow_request_id: fixture.network.request_id,
            validator_id: original.validator_id,
            leg_sender: public,
        },
    )
    .unwrap()
}

fn remember_receipt(
    history: &mut BTreeMap<[u8; 32], Vec<u8>>,
    hosts: &[HostProcess],
    request: [u8; 32],
) {
    let references: Vec<&HostProcess> = hosts.iter().collect();
    let receipt: sunrise_edge_client::HttpReceiptQueryResult = receipts(&references, request);
    assert!(
        matches!(
            receipt,
            sunrise_edge_client::HttpReceiptQueryResult::Present { .. }
        ),
        "only an actual independently reverified durable receipt enters history"
    );
    let bytes: Vec<u8> = receipt.encode().unwrap();
    if let Some(previous) = history.insert(request, bytes.clone()) {
        assert_eq!(previous, bytes, "receipt identity cannot change");
    }
}

fn verify_receipts(history: &BTreeMap<[u8; 32], Vec<u8>>, hosts: &[HostProcess]) {
    let references: Vec<&HostProcess> = hosts.iter().collect();
    for (request, expected) in history {
        assert_eq!(
            receipts(&references, *request).encode().unwrap(),
            *expected,
            "every later host preserves the exact earlier canonical receipt bytes"
        );
    }
}

fn prove_f_ordered_quorum(
    current: &SuccessorWorkflowAuthority,
    hosts: &[HostProcess],
    directory: &Path,
) -> (Vec<u8>, Vec<u8>) {
    let f: ValidatorId = member_from_seed([0xf6; 32]).validator_id;
    assert_eq!(hosts.len(), 5);
    assert!(hosts.iter().any(|host| host.validator == f));
    let selected: Vec<ValidatorId> =
        current_quorum_ids(current.fastvote_certifier().validator_set());
    assert_eq!(selected.len(), 4);
    assert!(selected.contains(&f));
    let participating: Vec<Option<&HostProcess>> = hosts
        .iter()
        .filter(|host| selected.contains(&host.validator))
        .map(Some)
        .collect();
    let certified: RoundOutcome = round(&ordered_endpoints(&participating), current, None);
    assert_eq!(certified.qc_formed_from, selected);
    let certificate: QuorumCertificate =
        consensus::decode_quorum_certificate(&certified.certificate_bytes).unwrap();
    assert!(
        certificate.votes.iter().any(|vote| vote.validator == f),
        "F's own independently stored host must sign the actual current QC"
    );
    std::fs::write(
        directory.join("f-quorum.proposal"),
        &certified.proposal_bytes,
    )
    .unwrap();
    std::fs::write(
        directory.join("f-quorum.certificate"),
        &certified.certificate_bytes,
    )
    .unwrap();
    let retained: (Vec<u8>, Vec<u8>) = (
        certified.proposal_bytes.clone(),
        certified.certificate_bytes.clone(),
    );
    let all: Vec<Option<&HostProcess>> = hosts.iter().map(Some).collect();
    replay_declared_prefix_with_sink(
        &ordered_endpoints(&all),
        current.ordered_policy(),
        &[(certified.proposal_bytes, certified.certificate_bytes)],
        Instant::now() + Duration::from_secs(1800),
        Duration::from_secs(300),
        &mut Sink,
    )
    .unwrap();
    for host in hosts {
        assert_eq!(
            status(host.address).high_qc,
            certificate,
            "all five hosts replay the same verified certificate bytes"
        );
    }
    retained
}

#[allow(clippy::too_many_arguments)]
fn restart_fourth_current_host(
    executables: &CompiledExecutableSnapshot,
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    targets: &CurrentTargets,
    hosts: &mut Vec<HostProcess>,
    receipt_history: &BTreeMap<[u8; 32], Vec<u8>>,
) {
    assert_eq!(current.expected_context().epoch().get(), 2);
    assert_eq!(hosts.len(), 4);
    for tag in [0x70, 0x71] {
        assert!(
            receipt_history.contains_key(&epoch_request_id(2, tag)),
            "paid e2 Publish/Instantiate preceded the real restart"
        );
    }
    verify_receipts(receipt_history, hosts);
    let paused: HostProcess = hosts.remove(3);
    assert_eq!(paused.validator, targets.members[3].validator_id);
    let generation: u64 = paused.generation;
    let paused_status: OrderedStatus = status(paused.address);
    drop(paused);
    let before_miss: ProtectedState = protected_state(fixture, targets);
    let alive: Vec<Option<&HostProcess>> = hosts.iter().map(Some).collect();
    let missed: RoundOutcome = round(&ordered_endpoints(&alive), current, None);
    assert_eq!(missed.qc_formed_from.len(), 3);
    assert!(
        !missed
            .qc_formed_from
            .contains(&targets.members[3].validator_id)
    );
    let missed_qc: QuorumCertificate =
        consensus::decode_quorum_certificate(&missed.certificate_bytes).unwrap();
    assert!(missed_qc.height > paused_status.high_qc.height);
    for host in hosts.iter() {
        assert_eq!(status(host.address).high_qc, missed_qc);
    }
    let after_miss: ProtectedState = protected_state(fixture, targets);
    assert_eq!(
        after_miss.business[3], before_miss.business[3],
        "the stopped fourth host really missed the current round"
    );
    assert_eq!(after_miss.metadata[3], before_miss.metadata[3]);
    assert_eq!(after_miss.state_rows[3], before_miss.state_rows[3]);
    assert_eq!(after_miss.blob_rows[3], before_miss.blob_rows[3]);
    let reopened: HostProcess = start(executables, fixture, links, targets, 3, false, 2);
    assert!(
        reopened.generation > generation,
        "the SAME target state/body files reopen under a higher writer generation"
    );
    assert_eq!(
        status(reopened.address).high_qc,
        paused_status.high_qc,
        "before replay the reopened file has the old high QC"
    );
    let replayed: Vec<sunrise_edge_client::ordered_economics_client::ReplayRoundOutcome> =
        replay_declared_prefix_with_sink(
            &ordered_endpoints(&[Some(&reopened)]),
            current.ordered_policy(),
            &[(missed.proposal_bytes, missed.certificate_bytes)],
            Instant::now() + Duration::from_secs(1800),
            Duration::from_secs(300),
            &mut Sink,
        )
        .unwrap();
    assert_eq!(replayed.len(), 1);
    for phase in [&replayed[0].observe_phase, &replayed[0].certificate_phase] {
        assert_eq!(phase.len(), 1);
        assert_eq!(phase[0].0, reopened.validator);
        let sunrise_edge_client::ordered_economics_client::PeerPhaseOutcome::Applied(output) =
            &phase[0].1
        else {
            panic!(
                "the reopened peer must acknowledge each declared signerless recovery phase: {:?}",
                phase[0].1
            );
        };
        assert!(
            output.messages.is_empty(),
            "declared-prefix recovery creates no fresh proposal or vote"
        );
    }
    assert_eq!(status(reopened.address).high_qc, missed_qc);
    hosts.push(reopened);
    verify_receipts(receipt_history, hosts);
    // The caller now uses all four independent hosts for the next genuine
    // Freeze, every local frontier/drain and the outgoing Seal.
}

/// Genuine former-domain envelopes must refuse before voting or committing.
/// The rows come from the same idle real target files the child hosts serve.
fn assert_prior_epoch_envelopes_refused(
    fixture: &Fixture,
    targets: &CurrentTargets,
    hosts: &[HostProcess],
    retained: &(Vec<u8>, Vec<u8>),
) {
    let before: ProtectedState = protected_state(fixture, targets);
    let high_qcs: Vec<QuorumCertificate> = hosts
        .iter()
        .map(|host: &HostProcess| status(host.address).high_qc)
        .collect();
    for host in hosts {
        for (path, media, body, expected_error) in [
            (
                node_wire::ordered_economics::ORDERED_ECONOMICS_PROPOSAL_PATH,
                node_wire::ordered_economics::ORDERED_PROPOSAL_MEDIA_TYPE,
                &retained.0,
                "invalid-ordered-proposal-signature",
            ),
            (
                node_wire::ordered_economics::ORDERED_ECONOMICS_CERTIFICATE_PATH,
                node_wire::ordered_economics::ORDERED_CERTIFICATE_MEDIA_TYPE,
                &retained.1,
                "invalid-ordered-certificate-signature",
            ),
        ] {
            let response: WireResponse =
                raw(host.address, Method::Post, path, Some(media), body.clone());
            assert_eq!(response.status, 400);
            assert!(
                std::str::from_utf8(&response.body)
                    .unwrap()
                    .contains(expected_error),
                "canonical former-epoch material reaches the current signature-domain verifier \
             on every live host"
            );
        }
    }
    assert_eq!(protected_state(fixture, targets), before);
    assert_eq!(
        hosts
            .iter()
            .map(|host: &HostProcess| status(host.address).high_qc)
            .collect::<Vec<QuorumCertificate>>(),
        high_qcs
    );
}

pub(super) fn run(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    initial_history: &Path,
    original_seal_request: [u8; 32],
    original_round: &(Vec<u8>, Vec<u8>),
    mut hosts: Vec<HostProcess>,
) {
    let mut original_ids: Vec<ValidatorId> = fixture
        .network
        .validators
        .iter()
        .map(|member| member.validator_id)
        .collect();
    let mut current_ids: Vec<ValidatorId> = inputs
        .members
        .iter()
        .map(|member| member.validator_id)
        .collect();
    original_ids.sort_unstable();
    current_ids.sort_unstable();
    if !inputs.recur_changed_committee {
        assert_eq!(
            original_ids, current_ids,
            "the explicitly selected baseline proves first-link original-committee behavior only"
        );
        return;
    }
    assert_ne!(
        original_ids, current_ids,
        "the selected recurring case must actually replace the committee"
    );
    let mut links: Vec<Link> = vec![Link {
        plan_history: inputs.plan_history.clone(),
        cut: inputs.cut.clone(),
        manifest_history: initial_history.to_path_buf(),
        certificate: inputs.certificate.clone(),
    }];
    let mut targets: CurrentTargets = CurrentTargets {
        paths: inputs.targets.clone(),
        members: inputs.members.clone(),
    };
    let initial: SuccessorWorkflowAuthority = workflow(fixture, &links);
    let initial_epoch: Epoch = initial.expected_context().epoch();
    let lifecycle_directory: PathBuf = fixture.directory.0.join("recurring-lifecycle-start");
    std::fs::create_dir(&lifecycle_directory).unwrap();
    let lifecycle_network: PathBuf = network_file(&lifecycle_directory, &hosts);
    let mut receipt_history: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for request in [
        fixture.network.request_id,
        original_seal_request,
        epoch_request_id(initial_epoch.get(), 0x6f),
        epoch_request_id(initial_epoch.get(), 0x70),
        epoch_request_id(initial_epoch.get(), 0x71),
        epoch_request_id(initial_epoch.get(), 0xa5),
    ] {
        remember_receipt(&mut receipt_history, &hosts, request);
    }
    let owners: Vec<lifecycle::ExitOwner> = lifecycle::start_exits(
        fixture,
        &links,
        &initial,
        &targets,
        &hosts,
        &lifecycle_network,
        &lifecycle_directory,
    );
    let terminal_epoch: Epoch = owners.iter().map(|owner| owner.unlock).max().unwrap();
    assert!(
        terminal_epoch
            .get()
            .checked_sub(fixture.network.epoch.get())
            .unwrap()
            <= u64::from(MAXIMUM_LINKS)
    );
    assert!(owners.iter().all(|owner| owner.unlock == terminal_epoch));
    let g: SuccessorProcessMember = member_from_seed([0xe9; 32]);
    remember_receipt(
        &mut receipt_history,
        &hosts,
        lifecycle::request(initial_epoch, 0x41, &g),
    );
    for owner in &owners {
        remember_receipt(
            &mut receipt_history,
            &hosts,
            lifecycle::request(initial_epoch, 0x42, &owner.member),
        );
    }
    // The endpoint comes from actual committed unlock rows and the installed
    // signed delay. No genesis reset or shortened economics profile occurs.
    let mut expected_epoch: u64 = initial_epoch.get();
    while expected_epoch < terminal_epoch.get() {
        let current: SuccessorWorkflowAuthority = workflow(fixture, &links);
        assert_eq!(current.expected_context().epoch().get(), expected_epoch);
        let directory: PathBuf = fixture
            .directory
            .0
            .join(format!("recurring-epoch-{expected_epoch}"));
        std::fs::create_dir(&directory).unwrap();
        if expected_epoch == 2 {
            restart_fourth_current_host(
                &inputs.executables,
                fixture,
                &links,
                &current,
                &targets,
                &mut hosts,
                &receipt_history,
            );
        }
        let network: PathBuf = network_file(&directory, &hosts);
        verify_receipts(&receipt_history, &hosts);
        if expected_epoch == 1 {
            // Correct chain, epoch, member, completed import and live files;
            // only the actual outgoing barrier is still Unsealed.
            assert_historical_startup_refused(
                &inputs.executables,
                fixture,
                &targets,
                historical_startup_flags(fixture, &links, &targets, expected_epoch),
                "historical namespace has not sealed its current epoch",
            );
        }
        lifecycle::withdrawals(
            fixture, &links, &current, &targets, &hosts, &network, &directory, &owners,
        );
        for owner in &owners {
            remember_receipt(
                &mut receipt_history,
                &hosts,
                lifecycle::request(current.expected_context().epoch(), 0x43, &owner.member),
            );
        }
        let mut next_members: Vec<SuccessorProcessMember> = targets.members.clone();
        if expected_epoch == 2 {
            let f: SuccessorProcessMember = lifecycle::register(
                fixture, &links, &current, &targets, &hosts, &network, &directory, [0xf6; 32], 0x19,
            );
            remember_receipt(
                &mut receipt_history,
                &hosts,
                lifecycle::request(current.expected_context().epoch(), 0x41, &f),
            );
            next_members.push(f);
            next_members.sort_unstable_by_key(|member| member.validator_id);
        }
        let former_epoch: Option<(Vec<u8>, Vec<u8>)> = if expected_epoch >= 3 {
            Some(prove_f_ordered_quorum(&current, &hosts, &directory))
        } else {
            None
        };
        let round_envelope: (Vec<u8>, Vec<u8>) = freeze_and_drain(
            fixture,
            &links,
            &current,
            &targets,
            &hosts,
            &directory,
            &network,
            &next_members,
        );
        // The earliest epochs this module observes (before F exists) are not
        // covered by `prove_f_ordered_quorum`'s dedicated quorum; a genuine
        // EMPTY-round envelope from the same freeze/drain window fills that
        // gap one epoch later, exactly like the e3+ case below.
        let stale_envelope: Option<(Vec<u8>, Vec<u8>)> = if expected_epoch < 3 {
            Some(round_envelope)
        } else {
            None
        };
        for tag in [0xb1, 0xb2] {
            remember_receipt(
                &mut receipt_history,
                &hosts,
                epoch_request_id(expected_epoch, tag),
            );
        }
        let history: PathBuf = directory.join("history-through-cut");
        export_history(
            fixture,
            &links,
            &current,
            &network,
            hosts[0].validator,
            &history,
        );
        let (next, cut, certificate): (CurrentTargets, PathBuf, PathBuf) = install_next(
            &inputs.executables,
            fixture,
            &links,
            CurrentSource {
                authority: &current,
                targets: &targets,
                history: &history,
            },
            &directory,
            &next_members,
        );
        let mut seal_bytes: Option<Vec<u8>> = None;
        let mut seal_path: Option<PathBuf> = None;
        for index in 0..targets.paths.len() {
            let output: PathBuf = directory.join(format!("seal-source-{index}"));
            std::fs::create_dir(&output).unwrap();
            let mut flags: Vec<String> = current_operator_pins(fixture, &links, &history);
            flags.extend(target_flags(&targets, index, true));
            flags.extend([
                "--cut-dir".into(),
                cut.to_str().unwrap().into(),
                "--certificate".into(),
                certificate.join("certificate.bin").to_str().unwrap().into(),
                "--out-dir".into(),
                output.to_str().unwrap().into(),
                "--timeout-seconds".into(),
                "3600".into(),
            ]);
            operator(
                inputs.executables.ordered_seal.to_str().unwrap(),
                "prepare-sqlite",
                flags,
            );
            let candidate: PathBuf = output.join("candidate.bin");
            let bytes: Vec<u8> = std::fs::read(&candidate).unwrap();
            if let Some(previous) = &seal_bytes {
                assert_eq!(previous, &bytes);
            }
            seal_bytes = Some(bytes);
            seal_path = Some(candidate);
        }
        let seal: OrderedCandidate =
            node_core::ordered_economics::decode_ordered_candidate(&seal_bytes.unwrap()).unwrap();
        let intent: node_core::ordered_economics::SealIntent =
            node_core::ordered_economics::decode_seal_intent(&seal.intent).unwrap();
        assert_eq!(intent.predecessor_tag, 2);
        assert_eq!(
            intent.predecessor_digest,
            current.authority().subject_digest()
        );
        let seal_path: PathBuf = seal_path.unwrap();
        let seal_submission: PathBuf = directory.join("seal-submission");
        let seal_parent: Option<QuorumCertificate> =
            (expected_epoch == 2).then(|| status(hosts[0].address).high_qc);
        submit(
            fixture,
            &links,
            &current,
            &network,
            &seal_path,
            &seal_submission,
        );
        if let Some(initial_parent) = &seal_parent {
            assert_eq!(
                reopened_host_submission(
                    fixture,
                    &current,
                    &targets,
                    &hosts,
                    &seal_path,
                    &seal_submission,
                    initial_parent,
                ),
                committed_outcome(&hosts, seal.request_id),
                "actual HTTP completion acknowledgements match every host's retained Seal outcome"
            );
        }
        for host in &hosts {
            let response: WireResponse = raw(
                host.address,
                Method::Post,
                node_wire::FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
                Some(node_wire::NODE_EVENT_MEDIA_TYPE),
                Vec::new(),
            );
            assert_eq!(
                response.status, 409,
                "a retired Seal namespace never signs again"
            );
        }
        let generations: Vec<u64> = hosts
            .iter()
            .map(|host: &HostProcess| host.generation)
            .collect();
        hosts.clear();
        let historical: Vec<HostProcess> = (0..targets.paths.len())
            .map(|index: usize| {
                start(
                    &inputs.executables,
                    fixture,
                    &links,
                    &targets,
                    index,
                    true,
                    expected_epoch,
                )
            })
            .collect();
        for (host, generation) in historical.iter().zip(&generations) {
            assert_eq!(
                host.generation, *generation,
                "material-only consumption never advances a fence"
            );
            for path in [
                node_wire::QUERY_CONTEXT_PATH,
                node_wire::FASTVOTE_PREPARE_PATH,
                node_wire::FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
                node_wire::ordered_economics::ORDERED_ECONOMICS_PROPOSE_PATH,
                node_wire::ordered_economics::ORDERED_ECONOMICS_PROPOSAL_PATH,
                node_wire::ordered_economics::ORDERED_ECONOMICS_CERTIFICATE_PATH,
                node_wire::ordered_economics::ORDERED_ECONOMICS_TICK_PATH,
            ] {
                let response: WireResponse = raw(
                    host.address,
                    if path == node_wire::QUERY_CONTEXT_PATH {
                        Method::Get
                    } else {
                        Method::Post
                    },
                    path,
                    Some(node_wire::NODE_EVENT_MEDIA_TYPE),
                    Vec::new(),
                );
                assert_eq!(
                    response.status, 404,
                    "historical material has no serving or signing route"
                );
            }
        }
        if expected_epoch == 1 {
            prove_historical_artifact_controls(
                &inputs.executables,
                fixture,
                &links,
                &current,
                &targets,
                &historical,
                &directory,
                &seal,
            );
        }
        let historical_network: PathBuf = network_file(&directory.join("historical"), &historical);
        let through_seal: PathBuf = directory.join("history-through-seal");
        export_history(
            fixture,
            &links,
            &current,
            &historical_network,
            historical[0].validator,
            &through_seal,
        );
        drop(historical);
        links.push(Link {
            plan_history: history,
            cut,
            manifest_history: through_seal,
            certificate,
        });
        let activated: SuccessorWorkflowAuthority = workflow(fixture, &links);
        assert_eq!(
            activated.expected_context().epoch().get(),
            expected_epoch + 1
        );
        for index in 0..next.paths.len() {
            let flags: Vec<String> =
                host_flags(fixture, &links, &next, index, false, expected_epoch + 1);
            assert!(
                operator(
                    inputs.executables.successor_activation.to_str().unwrap(),
                    "activate",
                    flags.clone()
                )
                .contains("successor_activation=activated")
            );
            assert!(
                operator(
                    inputs.executables.successor_activation.to_str().unwrap(),
                    "activate",
                    flags
                )
                .contains("successor_activation=already-activated")
            );
        }
        let old_claimant: usize = original_member_index(fixture, [0xa1; 32]);
        let old_share: Option<node_core::fee_claims::FeeClaimInspection> =
            if expected_epoch + 1 == 2 {
                Some(inspect_old_share(
                    fixture,
                    &links,
                    &activated,
                    &next,
                    old_claimant,
                ))
            } else {
                None
            };
        targets = next;
        hosts = (0..targets.paths.len())
            .map(|index: usize| {
                start(
                    &inputs.executables,
                    fixture,
                    &links,
                    &targets,
                    index,
                    false,
                    expected_epoch + 1,
                )
            })
            .collect();
        if let Some(retained) = &former_epoch {
            assert_prior_epoch_envelopes_refused(fixture, &targets, &hosts, retained);
        }
        if let Some(retained) = &stale_envelope {
            assert_prior_epoch_envelopes_refused(fixture, &targets, &hosts, retained);
        }
        if expected_epoch + 1 == 2 {
            let original: node_core::ordered_economics::OrderedProposal =
                node_core::ordered_economics::decode_ordered_proposal(&original_round.0).unwrap();
            let original_qc: QuorumCertificate =
                consensus::decode_quorum_certificate(&original_round.1).unwrap();
            assert_eq!(original.proposal.epoch, fixture.network.epoch);
            assert_eq!(original_qc.epoch, fixture.network.epoch);
            assert_eq!(original.proposal.chain_id, fixture.network.chain_id);
            assert_eq!(original_qc.chain_id, fixture.network.chain_id);
            assert_prior_epoch_envelopes_refused(fixture, &targets, &hosts, original_round);
            // The same hosts still vote and deliver a valid current-domain
            // round after refusing both the actual e0 and e1 envelopes.
            let all: Vec<Option<&HostProcess>> = hosts.iter().map(Some).collect();
            let _current_positive: RoundOutcome = round(&ordered_endpoints(&all), &activated, None);
        }
        verify_receipts(&receipt_history, &hosts);
        remember_receipt(&mut receipt_history, &hosts, seal.request_id);
        let next_network: PathBuf = network_file(&directory, &hosts);
        if let Some(view) = &old_share {
            let claim: [u8; 32] = imported_escrow_fee_claim(
                fixture,
                &hosts,
                &activated,
                view,
                old_claimant,
                ordered_network_pins(fixture, &links, &activated, &next_network),
            );
            remember_receipt(&mut receipt_history, &hosts, claim);
        }
        let call: [u8; 32] = paid_call_on_imported_instance(fixture, &hosts, &activated);
        let (publish, instantiate, _definition): ([u8; 32], [u8; 32], objects::ObjectId) =
            paid_publish_and_instantiate_fresh_asset(fixture, &hosts, &activated);
        for request in [call, publish, instantiate] {
            remember_receipt(&mut receipt_history, &hosts, request);
        }
        for host in &hosts {
            let context = Client::new(transport(host.address))
                .query_context()
                .unwrap();
            assert_eq!(context.epoch().get(), expected_epoch + 1);
        }
        expected_epoch = expected_epoch.checked_add(1).unwrap();
    }
    let unlocked: SuccessorWorkflowAuthority = workflow(fixture, &links);
    assert_eq!(unlocked.expected_context().epoch(), terminal_epoch);
    assert_eq!(
        links.len(),
        usize::try_from(
            terminal_epoch
                .get()
                .checked_sub(fixture.network.epoch.get())
                .unwrap()
        )
        .unwrap()
    );
    let final_directory: PathBuf = fixture.directory.0.join("recurring-computed-unlock");
    std::fs::create_dir(&final_directory).unwrap();
    let final_network: PathBuf = network_file(&final_directory, &hosts);
    lifecycle::withdrawals(
        fixture,
        &links,
        &unlocked,
        &targets,
        &hosts,
        &final_network,
        &final_directory,
        &owners,
    );
    for owner in &owners {
        remember_receipt(
            &mut receipt_history,
            &hosts,
            lifecycle::request(terminal_epoch, 0x43, &owner.member),
        );
    }
    for owner in &owners {
        lifecycle::assert_retired_owner_cannot_register(
            fixture,
            &links,
            &unlocked,
            &targets,
            &hosts,
            &final_network,
            &final_directory,
            owner,
        );
        lifecycle::assert_retired_member_cannot_redeposit(
            fixture,
            &links,
            &unlocked,
            &targets,
            &hosts,
            &final_network,
            &final_directory,
            owner,
        );
    }
    let _terminal_envelopes: (Vec<u8>, Vec<u8>) =
        prove_f_ordered_quorum(&unlocked, &hosts, &final_directory);
    verify_receipts(&receipt_history, &hosts);
}
