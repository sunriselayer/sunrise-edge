//! Shipped successor process acceptance over the genuine sealed source
//! produced by ordered_seal_sqlite_acceptance.
//!
//! The independently staged target identities and keys must exactly match
//! the committee authenticated by the sealed chain. No original-committee
//! ordering is used to route successor requests. Every operation crosses real
//! process and TCP boundaries: the
//! accepted Seal suffix is exported from the sealed read-only stores by the
//! shipped CLI, four successor_activation executables install it, four
//! successor_host processes serve it on loopback, and independently loaded
//! SDK and CLI successor pins drive e+1 work before signing anything.

use super::compiled_executable_snapshot::CompiledExecutableSnapshot;
use super::compiled_source_host_process as process;
use super::{fixture::Fixture, hex};
use consensus::{ConsensusSigner, QuorumCertificate, decode_quorum_certificate};
use execution::LocalWasmExecutionEngine;
use native_http::ordered_economics::{OrderedEconomicsState, certified_ordered_economics_router};
use native_http::{NativeBlockingExecutor, NativeBlockingPolicy};
use node_core::ordered_economics::{OrderedCandidate, OrderedStatus, decode_ordered_status};
use protocol_types::{SignatureSchemeId, ValidatorId};
use runtime::{SystemClock, WriterFenceGeneration};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    ffi::OsString,
    net::SocketAddr,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use sunrise_edge_client::ordered_economics_client::{
    ArtifactSink, OrderedEconomicsEndpoint, RoundOutcome, drive_empty_ordered_round,
    replay_declared_prefix_with_sink,
};
use sunrise_edge_client::{
    Client, FastVoteEndpoint, LoopbackHttpTransport, Method, RemoteTlsHttpTransport,
    SuccessorArtifactDirectories, SuccessorWorkflowAuthority, Transport, WireRequest, WireResponse,
    load_successor_workflow_from_directories,
};

#[path = "recurring_host_acceptance.rs"]
mod recurring;

#[path = "../../../../clients/rust/tests/support/external_signer.rs"]
mod external_signer;

// Reuse the existing disposable certificate owner; the relay API itself is
// unused here because the compiled successor terminates these connections.
#[allow(dead_code)]
#[path = "https_relay.rs"]
mod tls_fixture;

#[path = "compiled_cli_process.rs"]
mod compiled_cli_process;

struct NativeTlsFiles {
    ca: tls_fixture::FixtureCa,
    leaf: tls_fixture::FixtureLeaf,
    cert: PathBuf,
    key: PathBuf,
    root: PathBuf,
}
impl NativeTlsFiles {
    fn new(directory: &Path, label: &str) -> Self {
        let name: String = tls_fixture::fixture_server_name();
        let ca: tls_fixture::FixtureCa = tls_fixture::FixtureCa::new(&format!("{name}-{label}"));
        let leaf: tls_fixture::FixtureLeaf = ca.issue_leaf(&name);
        let cert: PathBuf = directory.join(format!("{label}.der"));
        let key: PathBuf = directory.join(format!("{label}.key"));
        let root: PathBuf = directory.join(format!("{label}-ca.der"));
        for (path, bytes) in [
            (&cert, leaf.der.as_slice()),
            (&key, leaf.key_pkcs8_der.as_slice()),
            (&root, ca.der.as_slice()),
        ] {
            use std::io::Write;
            let mut options: std::fs::OpenOptions = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file: std::fs::File = options.open(path).unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }
        Self {
            ca,
            leaf,
            cert,
            key,
            root,
        }
    }
    fn flags(&self, command: &mut Command) {
        command
            .arg("--tls-cert-der-file")
            .arg(&self.cert)
            .arg("--tls-key-pkcs8-der-file")
            .arg(&self.key);
    }
    fn transport(&self, address: SocketAddr) -> RemoteTlsHttpTransport {
        RemoteTlsHttpTransport::new(
            address,
            &self.leaf.server_name,
            &self.ca.der,
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(60),
            Duration::from_secs(120),
            Duration::from_secs(5),
            NonZeroUsize::new(64 * 1024).unwrap(),
            NonZeroUsize::new(64 * 1024 * 1024).unwrap(),
        )
        .unwrap()
    }
    fn received(&self, address: SocketAddr) {
        assert_eq!(
            tls_fixture::authenticated_leaf(address, &self.leaf.server_name, &self.ca.der),
            self.leaf.der
        );
    }
    fn raw(
        &self,
        address: SocketAddr,
        method: Method,
        path: &str,
        content_type: Option<&'static str>,
        body: Vec<u8>,
    ) -> WireResponse {
        self.transport(address)
            .send(&WireRequest {
                method,
                path: path.to_owned(),
                content_type,
                body,
                deadline: Some(Instant::now() + Duration::from_secs(120)),
            })
            .unwrap()
    }
}

/// Host checkpoint for FastVote preparation and fee-claim preparation.
const HOST_CHECKPOINT: u64 = 1_000;

fn original_member_index(fixture: &Fixture, seed: [u8; 32]) -> usize {
    fixture
        .network
        .validators
        .iter()
        .position(|member| member.seed == seed)
        .expect("the independently derived original identity must exist")
}

fn member_from_seed(seed: [u8; 32]) -> SuccessorProcessMember {
    let key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from(seed);
    let public: [u8; 32] = ed25519_zebra::VerificationKey::from(&key).into();
    SuccessorProcessMember {
        validator_id: ValidatorId::new(public),
        seed,
    }
}

/// A genuine minimal current-member quorum containing the actual later
/// registrant F when present. Core still verifies every vote and power.
fn current_quorum_ids(set: &validator_set::ValidatorSet) -> Vec<ValidatorId> {
    let f: ValidatorId = member_from_seed([0xf6; 32]).validator_id;
    let mut chosen: Vec<ValidatorId> = Vec::new();
    let mut power: u64 = 0;
    if let Some(member) = set.get(f) {
        chosen.push(f);
        power = member.voting_power;
    }
    for member in set.validators() {
        if power >= set.quorum_threshold() {
            break;
        }
        if member.id == f {
            continue;
        }
        chosen.push(member.id);
        power = power.checked_add(member.voting_power).unwrap();
    }
    assert!(power >= set.quorum_threshold());
    chosen.sort_unstable();
    chosen
}

/// Independently supplied current member, aligned with its staged target.
#[derive(Clone)]
pub struct SuccessorProcessMember {
    /// Physical namespace and consensus identity of this target.
    pub validator_id: ValidatorId,
    /// Actual member signing seed, authenticated against the verified committee.
    pub seed: [u8; 32],
}

/// Original directories owned by the conditional readiness caller.
pub struct SuccessorProcessInputs {
    /// Exact real compiled children captured before the complete workflow.
    pub executables: CompiledExecutableSnapshot,
    /// Explicit acceptance selection, never inferred as a silent successful skip.
    pub recur_changed_committee: bool,
    /// Ordered history through T feeding the plan.
    pub plan_history: PathBuf,
    /// Saved pre-Seal business cut.
    pub cut: PathBuf,
    /// Retained readiness certificate selected by the accepted Seal.
    pub certificate: PathBuf,
    /// A genuine competing certificate variant the Seal does not name.
    pub competing_certificate: PathBuf,
    /// Four staged import targets, each with state.db, body.db, private.key.
    pub targets: Vec<PathBuf>,
    /// Actual successor members in the same order as `targets`.
    pub members: Vec<SuccessorProcessMember>,
    /// The immutable import binding the targets were staged under.
    pub binding: runtime::inactive_import::ImportBinding,
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn pins(command: &mut Command, fixture: &Fixture, inputs: &SuccessorProcessInputs) {
    command.args([
        "--chain-id",
        fixture.network.chain_id.as_str(),
        "--protocol-version",
        &fixture.network.protocol_version.get().to_string(),
        "--epoch",
        &fixture.network.epoch.get().to_string(),
        "--domain",
        &hex(fixture.network.domain.as_bytes()),
        "--suite",
        "0:1:1:1:1:1:1:1",
        "--genesis-manifest",
        fixture.directory.0.join("genesis.bin").to_str().unwrap(),
        "--expected-genesis-digest",
        &hex(&fixture.network.manifest_digest),
        "--ordered-history-dir",
        inputs.plan_history.to_str().unwrap(),
        "--cut-dir",
        inputs.cut.to_str().unwrap(),
        "--successor-max-links",
        "1",
    ]);
}

fn target_flags(
    command: &mut Command,
    inputs: &SuccessorProcessInputs,
    export: &Path,
    certificate: &Path,
    index: usize,
) {
    let target: &Path = &inputs.targets[index];
    command.args([
        "--manifest-history-dir",
        export.to_str().unwrap(),
        "--certificate-dir",
        certificate.to_str().unwrap(),
        "--target-state-db",
        target.join("state.db").to_str().unwrap(),
        "--target-blob-db",
        target.join("body.db").to_str().unwrap(),
        "--validator-id",
        &hex(inputs.members[index].validator_id.as_bytes()),
        "--signer-key-file",
        target.join("private.key").to_str().unwrap(),
    ]);
}

fn activation(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    export: &Path,
    certificate: &Path,
    index: usize,
) -> Output {
    let mut command: Command = Command::new(&inputs.executables.successor_activation);
    command.arg("activate");
    pins(&mut command, fixture, inputs);
    target_flags(&mut command, inputs, export, certificate, index);
    process::spawn_bounded_output(command, Duration::from_secs(600))
}

/// One real successor_host process. Dropping it kills and reaps the child.
struct HostProcess {
    child: Child,
    address: SocketAddr,
    generation: u64,
    validator: ValidatorId,
}

impl Drop for HostProcess {
    fn drop(&mut self) {
        let _ignored = self.child.kill();
        let _ignored = self.child.wait();
    }
}

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|token: &str| token.strip_prefix(key))
        .unwrap_or_else(|| panic!("host line lacks {key}: {line}"))
}

fn start_host(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    export: &Path,
    index: usize,
) -> HostProcess {
    let mut command: Command = Command::new(&inputs.executables.successor_host);
    command.arg("serve");
    pins(&mut command, fixture, inputs);
    target_flags(&mut command, inputs, export, &inputs.certificate, index);
    command
        .args([
            "--listen",
            "127.0.0.1:0",
            "--created-checkpoint",
            &HOST_CHECKPOINT.to_string(),
            "--timeout-seconds",
            "600",
            "--confirm-offline-fence-advance",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let (mut guard, line): (process::ChildGuard, String) =
        process::spawn_bounded_status_line(command, Duration::from_secs(600));
    // The host prints exactly one flushed line after its startup gate and
    // the actual bind; a failed startup closes stdout without it.
    assert!(
        !line.is_empty(),
        "successor host {index} exited: {:?}",
        guard.try_wait()
    );
    assert!(line.contains("mode=successor-serving"), "{line}");
    let address: SocketAddr = field(&line, "listen=").parse().unwrap();
    let generation: u64 = field(&line, "writer_generation=").parse().unwrap();
    HostProcess {
        address,
        generation,
        validator: inputs.members[index].validator_id,
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

fn raw(
    address: SocketAddr,
    method: Method,
    path: &str,
    media: Option<&'static str>,
    body: Vec<u8>,
) -> WireResponse {
    transport(address)
        .send(&WireRequest {
            method,
            path: path.to_owned(),
            content_type: media,
            body,
            deadline: None,
        })
        .unwrap()
}

fn status(address: SocketAddr) -> OrderedStatus {
    let response: WireResponse = raw(
        address,
        Method::Get,
        node_wire::ordered_economics::ORDERED_ECONOMICS_STATUS_PATH,
        None,
        Vec::new(),
    );
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

/// History export never signs; the router type merely needs a signer.
struct NeverSigner(ValidatorId);
impl ConsensusSigner for NeverSigner {
    fn validator_id(&self) -> ValidatorId {
        self.0
    }
    fn signature_scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }
    fn sign_framed(&self, _framed: &[u8]) -> Result<Vec<u8>, String> {
        Err("sealed read-only history export never signs".into())
    }
}

/// Serves the four sealed source files only through their historical
/// read-only open and runs the shipped CLI history-export against them, so
/// the accepted Seal suffix through h is exported exactly as an operator
/// would, never assembled from private state.
async fn export_sealed_history(fixture: &Fixture, fence: WriterFenceGeneration) -> PathBuf {
    let mut servers = Vec::new();
    let mut stops = Vec::new();
    let mut peers: String = String::new();
    for (index, validator) in fixture.network.validators.iter().enumerate() {
        let store: Arc<SqliteDurableStore> = Arc::new(
            SqliteDurableStore::open_historical(
                fixture.directory.0.join(format!("state-{index}.sqlite")),
                SqliteNamespace::new(
                    fixture.network.chain_id.clone(),
                    validator.validator_id,
                    fixture.network.domain,
                ),
            )
            .unwrap(),
        );
        let blobs: Arc<SqliteBlobStore> =
            Arc::new(SqliteBlobStore::open(fixture.directory.0.join("blobs.sqlite")).unwrap());
        let router = certified_ordered_economics_router(OrderedEconomicsState {
            store,
            clock: Arc::new(SystemClock),
            identities: Arc::new(sunrise_edge_devnet::DevnetOutboxIdentitySource::new(fence)),
            domain: fixture.network.domain,
            writer_fence: fence,
            operation_timeout: Duration::from_secs(120),
            policy: fixture.policy.clone(),
            history: Vec::new(),
            leg_policy: fixture.local_policy.clone(),
            engine: Arc::new(LocalWasmExecutionEngine::new()),
            blobs,
            seal: None,
            signer: NeverSigner(validator.validator_id),
            blocking_executor: NativeBlockingExecutor::new(NativeBlockingPolicy::new(
                NonZeroUsize::new(2).unwrap(),
            )),
            cancellation: None,
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        peers.push_str(&format!(
            "{} {address} - -\n",
            hex(validator.validator_id.as_bytes())
        ));
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        stops.push(stop);
        servers.push(tokio::spawn(native_http::serve(listener, router, async {
            let _ = shutdown.await;
        })));
    }
    let network: PathBuf = fixture.directory.0.join("sealed-history-network.conf");
    std::fs::write(&network, peers).unwrap();
    let out: PathBuf = fixture.directory.0.join("successor-seal-history-export");
    let arguments: Vec<OsString> = [
        "economics".to_string(),
        "history-export".into(),
        "--ordered-network".into(),
        network.to_str().unwrap().into(),
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
        fixture.network.epoch.get().to_string(),
        "--domain".into(),
        hex(fixture.network.domain.as_bytes()),
        "--target-validator-id".into(),
        hex(fixture.network.validators[0].validator_id.as_bytes()),
        "--out-dir".into(),
        out.to_str().unwrap().into(),
        "--history-max-heights".into(),
        "4096".into(),
        "--deadline-seconds".into(),
        "600".into(),
        "--per-request-cap-seconds".into(),
        "120".into(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    tokio::task::block_in_place(|| sunrise_edge_cli::run(arguments)).unwrap();
    assert!(
        out.join("complete").exists(),
        "the full sealed prefix verified"
    );
    for stop in stops {
        stop.send(()).unwrap();
    }
    for server in servers {
        server.await.unwrap().unwrap();
    }
    out
}

fn load_workflow(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    export: &Path,
) -> SuccessorWorkflowAuthority {
    load_successor_workflow_from_directories(
        &fixture.directory.0.join("genesis.bin"),
        &fixture.network.resolver,
        fixture.network.manifest_digest,
        &fixture.network.context,
        fixture.network.domain,
        &SuccessorArtifactDirectories {
            plan_history: &inputs.plan_history,
            cut: &inputs.cut,
            manifest_history: export,
            certificate: &inputs.certificate,
        },
    )
    .unwrap()
}

fn ordered_endpoints(
    hosts: &[Option<&HostProcess>],
) -> Vec<OrderedEconomicsEndpoint<LoopbackHttpTransport>> {
    hosts
        .iter()
        .filter_map(|host: &Option<&HostProcess>| {
            host.map(|host: &HostProcess| OrderedEconomicsEndpoint {
                validator_id: host.validator,
                endpoint_label: host.address.to_string(),
                client: Client::new(transport(host.address)),
            })
        })
        .collect()
}

fn fastvote_endpoints(hosts: &[HostProcess]) -> Vec<FastVoteEndpoint<LoopbackHttpTransport>> {
    hosts
        .iter()
        .map(|host: &HostProcess| FastVoteEndpoint {
            validator_id: host.validator,
            endpoint_label: host.address.to_string(),
            client: Client::new(transport(host.address)),
        })
        .collect()
}

fn round(
    endpoints: &[OrderedEconomicsEndpoint<LoopbackHttpTransport>],
    workflow: &SuccessorWorkflowAuthority,
    parent: Option<&QuorumCertificate>,
) -> RoundOutcome {
    let deadline: Instant = Instant::now() + Duration::from_secs(1800);
    drive_empty_ordered_round(
        endpoints,
        workflow.ordered_policy(),
        parent,
        deadline,
        Duration::from_secs(300),
        &mut Sink,
    )
    .unwrap()
}

/// One host observed current fee coin, sender nonce and installed e+1 fee
/// policy digest; re-observed before every genuine paid intent so each one
/// uses the live successor-host state rather than a value computed once.
struct FeeObservation {
    coin_ref: objects::ObjectRef,
    nonce: u64,
    fee_policy_digest: protocol_types::Digest32,
}

fn observe_fee_context(
    fixture: &Fixture,
    hosts: &[HostProcess],
    context: &execution::publication::PublicationContext,
) -> FeeObservation {
    let client: Client<LoopbackHttpTransport> = Client::new(transport(hosts[0].address));
    let coin = client.query_object(fixture.network.fee_coin).unwrap();
    let coin_ref: objects::ObjectRef = sunrise_edge_client::current_inline_object_ref(&coin)
        .expect("the imported fee coin is a live inline object");
    let nonce: u64 = client
        .query_next_nonce(objects::Address::new(fixture.network.sender))
        .unwrap()
        .next_nonce();
    let response: WireResponse = raw(
        hosts[0].address,
        Method::Get,
        sunrise_edge_client::PAID_FEE_POLICY_PATH,
        None,
        Vec::new(),
    );
    assert_eq!(response.status, 200);
    let policy: execution::paid_execution::PaidFeePolicy =
        execution::paid_execution::decode_paid_fee_policy(&response.body).unwrap();
    assert_eq!(&policy.context, context, "the installed e+1 fee policy row");
    let fee_policy_digest: protocol_types::Digest32 =
        execution::paid_execution::paid_fee_policy_digest(&fixture.network.resolver, &policy)
            .unwrap();
    FeeObservation {
        coin_ref,
        nonce,
        fee_policy_digest,
    }
}

/// Certifies one real signed paid intent under the e+1 FastVote quorum,
/// publishes its availability, and applies it on all four successor hosts;
/// an exact re-apply of the identical certificate returns byte-identical
/// results on every host.
fn certify_and_apply_paid_intent(
    fixture: &Fixture,
    hosts: &[HostProcess],
    workflow: &SuccessorWorkflowAuthority,
    signed: &execution::paid_execution::SignedPaidIntent,
) -> Vec<sunrise_edge_client::FastVoteApplyAttempt> {
    let retained: PathBuf = paid_intent_path(fixture, signed.intent.request_id);
    let signed_bytes: Vec<u8> =
        execution::paid_execution::encode_signed_paid_intent(signed).unwrap();
    match std::fs::read(&retained) {
        Ok(previous) => assert_eq!(
            previous, signed_bytes,
            "an exact paid request never changes its retained bytes"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::write(&retained, &signed_bytes).unwrap();
        }
        Err(error) => panic!("cannot retain signed process input: {error}"),
    }
    let endpoints: Vec<FastVoteEndpoint<LoopbackHttpTransport>> = fastvote_endpoints(hosts);
    let certifier: &consensus::FastPathCertifier = workflow.fastvote_certifier();
    let f: ValidatorId = member_from_seed([0xf6; 32]).validator_id;
    let selected: Vec<ValidatorId> = current_quorum_ids(certifier.validator_set());
    let certificate_endpoints: Vec<FastVoteEndpoint<LoopbackHttpTransport>> = endpoints
        .iter()
        .filter(|endpoint| {
            certifier.validator_set().get(f).is_none() || selected.contains(&endpoint.validator_id)
        })
        .map(|endpoint| FastVoteEndpoint {
            validator_id: endpoint.validator_id,
            endpoint_label: endpoint.endpoint_label.clone(),
            client: Client::new(endpoint.client.transport().clone()),
        })
        .collect();
    let deadline: Instant = Instant::now() + Duration::from_secs(1800);
    let cap: Duration = Duration::from_secs(300);
    let (certificate, _attempts) = sunrise_edge_client::collect_fastvote_certificate(
        &certificate_endpoints,
        certifier,
        &fixture.network.resolver,
        signed,
        deadline,
        cap,
    )
    .unwrap();
    if certifier.validator_set().get(f).is_some() {
        assert_eq!(hosts.len(), 5);
        assert!(
            certificate.votes.iter().any(|vote| vote.validator == f),
            "F's own host supplied its real current paid vote"
        );
    }
    let published = sunrise_edge_client::collect_fastvote_availability_certificate(
        &endpoints,
        certifier,
        &fixture.network.resolver,
        &[],
        fixture.network.domain,
        signed,
        &certificate,
        deadline,
        cap,
    )
    .unwrap();
    let apply = || {
        sunrise_edge_client::apply_published_fastvote_to_all(
            &endpoints,
            certifier,
            &fixture.network.resolver,
            fixture.network.domain,
            signed,
            &certificate,
            &published.availability_certificate,
            deadline,
            cap,
        )
        .unwrap()
    };
    let applied = apply();
    assert_eq!(applied.len(), hosts.len());
    for attempt in &applied {
        let result = attempt.result.as_ref().unwrap();
        assert!(
            matches!(
                result.status,
                execution::paid_execution::PaidExecutionStatus::Success
            ),
            "e+1 paid application succeeded at {}",
            attempt.validator_id
        );
    }
    let replayed = apply();
    for (first, second) in applied.iter().zip(&replayed) {
        assert_eq!(
            first.result.as_ref().unwrap(),
            second.result.as_ref().unwrap(),
            "exact certified re-apply returns the original result"
        );
    }
    applied
}

fn paid_intent_path(fixture: &Fixture, request_id: [u8; 32]) -> PathBuf {
    fixture
        .directory
        .0
        .join(format!("successor-paid-{}.signed", hex(&request_id)))
}

/// A genuine certified paid Call at e+1 on the imported epoch-e Standard
/// Asset instance: every input is observed through a successor host, signed
/// only after the SDK pins confirm the verified e+1 context, certified by
/// the e+1 FastVote quorum, published and applied on all four hosts; an
/// exact re-apply returns the identical original results.
fn paid_call_on_imported_instance(
    fixture: &Fixture,
    hosts: &[HostProcess],
    workflow: &SuccessorWorkflowAuthority,
) -> [u8; 32] {
    let context: execution::publication::PublicationContext = workflow.expected_context().clone();
    let observed: FeeObservation = observe_fee_context(fixture, hosts, &context);
    let request_id: [u8; 32] = epoch_request_id(context.epoch().get(), 0x6f);
    workflow.require_signing_context(&context).unwrap();
    let signed_bytes: Vec<u8> = fixture.network.sign_transfer_with(
        &context,
        request_id,
        observed.nonce,
        observed.coin_ref,
        observed.fee_policy_digest,
        fixture.network.sender,
    );
    let signed: execution::paid_execution::SignedPaidIntent =
        execution::paid_execution::decode_signed_paid_intent(&signed_bytes).unwrap();
    certify_and_apply_paid_intent(fixture, hosts, workflow, &signed);
    request_id
}

/// Distinct deterministic caller-owned identifiers for every actual epoch.
/// The epoch comes only from the independently verified workflow, never a
/// network context hint. These identifiers are not authority or state rows.
fn epoch_request_id(epoch: u64, tag: u8) -> [u8; 32] {
    let mut request_id: [u8; 32] = [tag; 32];
    request_id[1..9].copy_from_slice(&epoch.to_be_bytes());
    request_id
}

/// A genuine certified paid Publish of a freshly originated Standard Asset
/// package at e+1, followed by a certified paid Instantiate of that fresh
/// package own instance: every input is observed through a successor host,
/// signed only after the SDK pins confirm the verified e+1 context,
/// certified by the e+1 FastVote quorum, published and applied on all four
/// hosts with byte-identical re-apply; the freshly created Definition is
/// then queried back from a live host.
fn paid_publish_and_instantiate_fresh_asset(
    fixture: &Fixture,
    hosts: &[HostProcess],
    workflow: &SuccessorWorkflowAuthority,
) -> ([u8; 32], [u8; 32], objects::ObjectId) {
    use abi::package_types::{PackageOrigin, ScopedTypeTag, verify_scoped_type_id};
    use execution::call::CallIntent;
    use execution::local_execution::{
        InstanceRecord, generic_object_result_semantics, instance_target,
    };
    use execution::paid_execution::{
        FeeSourceConsent, PaidApplication, PaidIntent, ReservationAccessKind,
    };
    use execution::publication::{
        ArtifactParts, CodeArtifact, UnverifiedDependencyRef, artifact_commitment,
    };

    let context: execution::publication::PublicationContext = workflow.expected_context().clone();
    // A fresh code origin distinct from the imported epoch-e Standard Asset
    // instance own code; only the fee coin and quorum are shared.
    let origin: PackageOrigin = PackageOrigin::unverified(
        fixture.network.chain_id.clone(),
        fixture.network.sender,
        epoch_request_id(context.epoch().get(), 0x73),
    )
    .unwrap();
    let package: public_standard_asset::StandardAssetPackage =
        public_standard_asset::build_package(&origin).unwrap();
    let semantics: protocol_types::Digest32 =
        generic_object_result_semantics(&fixture.network.resolver, &context).unwrap();
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: context.clone(),
        origin: origin.clone(),
        revision: 1,
        wasm_profile: execution::GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION,
        semantics,
        wasm: package.wasm.clone(),
        unverified_abi: package.encoded_abi.clone(),
        exports: package.exports.clone(),
        unverified_dependencies: Vec::new(),
    })
    .unwrap();
    let artifact_digest: protocol_types::Digest32 =
        artifact_commitment(&fixture.network.resolver, &context, &artifact).unwrap();
    let code_ref: UnverifiedDependencyRef =
        UnverifiedDependencyRef::new(origin.clone(), 1, context.clone(), artifact_digest).unwrap();

    let publish_request: [u8; 32] = epoch_request_id(context.epoch().get(), 0x70);
    let observed: FeeObservation = observe_fee_context(fixture, hosts, &context);
    workflow.require_signing_context(&context).unwrap();
    let publish_intent: PaidIntent = PaidIntent {
        context: context.clone(),
        request_id: publish_request,
        sender: fixture.network.sender,
        nonce: observed.nonce,
        fee_policy_digest: observed.fee_policy_digest,
        consent: FeeSourceConsent {
            source: observed.coin_ref,
            access: ReservationAccessKind::Write,
            max_fee: fees::Amount::new(1_000_000),
            refund_recipient: fixture.network.sender,
        },
        application: PaidApplication::Publish(artifact),
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let publish_signed_bytes: Vec<u8> = fixture.network.sign_intent(publish_intent);
    let publish_signed: execution::paid_execution::SignedPaidIntent =
        execution::paid_execution::decode_signed_paid_intent(&publish_signed_bytes).unwrap();
    certify_and_apply_paid_intent(fixture, hosts, workflow, &publish_signed);

    let instance_seed: [u8; 32] = epoch_request_id(context.epoch().get(), 0x74);
    let instance_record: InstanceRecord = InstanceRecord {
        context: context.clone(),
        creator: fixture.network.sender,
        seed: instance_seed,
        code: code_ref.clone(),
        revision: 1,
        initializer: public_standard_asset::INITIALIZER.to_owned(),
    };
    let instance = instance_target(&fixture.network.resolver, &instance_record).unwrap();
    let instantiate_request: [u8; 32] = epoch_request_id(context.epoch().get(), 0x71);
    let observed: FeeObservation = observe_fee_context(fixture, hosts, &context);
    let instantiate_call: CallIntent = CallIntent {
        context: context.clone(),
        request_id: instantiate_request,
        sender: fixture.network.sender,
        nonce: observed.nonce,
        code: code_ref.clone(),
        instance: instance.clone(),
        entrypoint: public_standard_asset::INITIALIZER.to_owned(),
        type_arguments: Vec::new(),
        access: abi::AccessManifest::new(),
        arguments: public_standard_asset::no_arguments().unwrap(),
        gas_limit: 100_000,
    };
    workflow.require_signing_context(&context).unwrap();
    let instantiate_intent: PaidIntent = PaidIntent {
        context: context.clone(),
        request_id: instantiate_request,
        sender: fixture.network.sender,
        nonce: observed.nonce,
        fee_policy_digest: observed.fee_policy_digest,
        consent: FeeSourceConsent {
            source: observed.coin_ref,
            access: ReservationAccessKind::Write,
            max_fee: fees::Amount::new(1_000_000),
            refund_recipient: fixture.network.sender,
        },
        application: PaidApplication::Instantiate(instantiate_call),
        gas_limit: 100_000,
        authorizations: Vec::new(),
    };
    let instantiate_signed_bytes: Vec<u8> = fixture.network.sign_intent(instantiate_intent);
    let instantiate_signed: execution::paid_execution::SignedPaidIntent =
        execution::paid_execution::decode_signed_paid_intent(&instantiate_signed_bytes).unwrap();
    let applied = certify_and_apply_paid_intent(fixture, hosts, workflow, &instantiate_signed);

    // Identify the freshly created Definition (excluding the fee/refund
    // settlement outputs), then prove it is genuinely live by querying it
    // back from a live host.
    let result: &execution::paid_execution::PaidExecutionResult =
        applied[0].result.as_ref().unwrap();
    let charged = result.charged.as_ref().unwrap();
    let fee_id: objects::ObjectId = charged.fee_output.id;
    let refund_id: Option<objects::ObjectId> = charged.refund_output.as_ref().map(|value| value.id);
    let definition_tag: ScopedTypeTag =
        public_standard_asset::definition_type_tag(&origin).unwrap();
    let definition_id: objects::ObjectId = result
        .effects
        .object_effects
        .iter()
        .find_map(|effect: &execution::ObjectEffect| match effect {
            execution::ObjectEffect::Created(object)
                if object.id != fee_id && Some(object.id) != refund_id =>
            {
                verify_scoped_type_id(
                    &fixture.network.resolver,
                    &object.type_hash,
                    context.epoch(),
                    &definition_tag,
                )
                .unwrap_or(false)
                .then_some(object.id)
            }
            _ => None,
        })
        .expect("instantiate must create a Definition");
    let queried = Client::new(transport(hosts[0].address))
        .query_object(definition_id)
        .unwrap();
    assert!(
        sunrise_edge_client::current_inline_object_ref(&queried).is_some(),
        "the freshly instantiated Definition is live on a successor host"
    );

    (publish_request, instantiate_request, definition_id)
}

fn successor_cli_flags(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    export: &Path,
    network: &Path,
) -> Vec<String> {
    let next_epoch: u64 = fixture.network.epoch.get() + 1;
    vec![
        "--ordered-network".into(),
        network.to_str().unwrap().into(),
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
        next_epoch.to_string(),
        "--domain".into(),
        hex(fixture.network.domain.as_bytes()),
        "--successor-genesis-epoch".into(),
        fixture.network.epoch.get().to_string(),
        "--successor-plan-history-dir".into(),
        inputs.plan_history.to_str().unwrap().into(),
        "--successor-cut-dir".into(),
        inputs.cut.to_str().unwrap().into(),
        "--successor-manifest-history-dir".into(),
        export.to_str().unwrap().into(),
        "--successor-certificate-dir".into(),
        inputs.certificate.to_str().unwrap().into(),
        "--successor-max-links".into(),
        "1".into(),
        "--suite".into(),
        "0:1:1:1:1:1:1:1".into(),
        "--deadline-seconds".into(),
        "1800".into(),
        "--per-request-cap-seconds".into(),
        "300".into(),
    ]
}

fn cli(prefix: &[&str], tail: Vec<String>) {
    let mut arguments: Vec<OsString> = prefix.iter().map(OsString::from).collect();
    arguments.extend(tail.into_iter().map(OsString::from));
    tokio::task::block_in_place(|| sunrise_edge_cli::run(arguments)).unwrap();
}

/// Real read-only inspection of the imported epoch-e escrow share on the
/// claimant own activated target at e+1, before its host claims the fence.
/// The sealed source correctly refuses (admission closed by the committed
/// Freeze) and the escrow does not exist before Freeze (it is created by the
/// post-Freeze drain apply), so the activated target is the genuine owner of
/// this state. The view is untrusted client construction input only: the
/// host preparation and the ordered claim evaluator recheck the object and
/// share under a fresh warrant.
fn inspect_imported_share(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    workflow: &SuccessorWorkflowAuthority,
    export: &Path,
    claimant: usize,
) -> node_core::fee_claims::FeeClaimInspection {
    let validator = &fixture.network.validators[claimant];
    let target_index: usize = inputs
        .members
        .iter()
        .position(|member: &SuccessorProcessMember| member.validator_id == validator.validator_id)
        .expect("the retained original claimant has a current physical target");
    let public: [u8; 32] = ed25519_zebra::VerificationKey::from(&validator.signing_key).into();
    let target: runtime_sqlite::SqliteImportTarget =
        runtime_sqlite::SqliteImportTarget::open_existing(
            inputs.targets[target_index].join("state.db"),
            SqliteNamespace::new(
                fixture.network.chain_id.clone(),
                validator.validator_id,
                fixture.network.domain,
            ),
            &inputs.binding,
        )
        .unwrap();
    let blobs: SqliteBlobStore =
        SqliteBlobStore::open_existing(inputs.targets[target_index].join("body.db")).unwrap();
    let operation: runtime::DurableOperationContext = runtime::DurableOperationContext::new(
        target.writer_fence().unwrap(),
        runtime::StorageDeadline::new(u64::MAX / 2).unwrap(),
        runtime::StorageCorrelationId::new([0xC9; 16]).unwrap(),
    );
    let (identity, _ordered): (
        node_core::ordered_economics::OrderedHistoryIdentity,
        Vec<node_core::ordered_economics::OrderedHistoryHeightMaterial>,
    ) = sunrise_edge_client::ordered_history_archive::read_verified_ordered_history_archive(
        &fixture.policy,
        &inputs.plan_history,
    )
    .unwrap();
    let manifest_archive: sunrise_edge_client::immutable_archive::ImmutableArchiveReader =
        sunrise_edge_client::immutable_archive::ImmutableArchiveReader::open(export).unwrap();
    let manifest_identity_bytes: Vec<u8> =
        sunrise_edge_client::ordered_history_archive::read_regular_archive_file(
            manifest_archive.root(),
            Path::new("identity.bin"),
            node_core::ordered_economics::MAX_ORDERED_HISTORY_DESCRIPTOR_BYTES,
        )
        .unwrap();
    let manifest_identity: node_core::ordered_economics::OrderedHistoryIdentity =
        node_core::ordered_economics::decode_ordered_history_identity(&manifest_identity_bytes)
            .unwrap();
    let mut artifacts: sunrise_edge_client::successor_artifacts::SuccessorArtifactFiles<'_> =
        sunrise_edge_client::successor_artifacts::SuccessorArtifactFiles::new(
            fixture.plan(&identity, operation),
            sunrise_edge_client::immutable_archive::ImmutableArchiveReader::open(&inputs.cut)
                .unwrap(),
            manifest_archive,
            sunrise_edge_client::immutable_archive::ImmutableArchiveReader::open(
                &inputs.certificate,
            )
            .unwrap(),
        );
    let authority: node_core::serving_authority::LiveAuthority<'_> =
        node_core::serving_authority::resolve_live_authority(
            &target,
            &operation,
            fixture.network.domain,
            fixture.plan(&identity, operation),
            &manifest_identity,
            &mut artifacts,
            public,
        )
        .unwrap();
    let node_core::serving_authority::LiveAuthority::Successor(warrant) = authority else {
        panic!("the activated claimant target requires verified successor authority");
    };
    node_core::serving_authority::inspect_fee_claim_successor(
        &warrant,
        &target,
        &blobs,
        &fixture.network.resolver,
        &[],
        &execution::local_execution::LocalExecutionPolicy::generic_object_results(
            workflow.expected_context().clone(),
        ),
        node_core::serving_authority::SuccessorFeeClaimInspection {
            escrow_request_id: fixture.network.request_id,
            validator_id: validator.validator_id,
            leg_sender: public,
        },
    )
    .unwrap()
}

/// Positive fee claim against the imported epoch-e escrow. The signed leg
/// is built from the real activated-target inspection, scoped to e+1 with
/// the claimant e+1 nonce observed through a host. The SDK first proves its
/// pre-signing refusals on the real independently loaded workflow; then the
/// shipped CLI prepares through a host, verifies against its own successor
/// pins, signs, wraps and submits it as an ordered e+1 candidate.
#[allow(clippy::too_many_arguments)]
fn imported_escrow_fee_claim(
    fixture: &Fixture,
    hosts: &[HostProcess],
    workflow: &SuccessorWorkflowAuthority,
    view: &node_core::fee_claims::FeeClaimInspection,
    claimant_index: usize,
    flags: Vec<String>,
) -> [u8; 32] {
    use abi::call_values::{CallValue, encode_call_value};
    use execution::local_execution::{
        LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy, SignedLocalExecutionIntent,
        encode_signed_local_execution, local_execution_signing_frame,
    };
    use node_core::fee_claims::{FeeClaimExecutionView, FeeClaimKind};
    let claimant = &fixture.network.validators[claimant_index];
    let public: [u8; 32] = ed25519_zebra::VerificationKey::from(&claimant.signing_key).into();
    let kind: FeeClaimKind = view.entitlement.kind.expect("an unclaimed imported share");
    let next: execution::publication::PublicationContext = workflow.expected_context().clone();
    let request: [u8; 32] = epoch_request_id(next.epoch().get(), 0xA5);
    workflow.require_signing_context(&next).unwrap();
    let leg: Option<Vec<u8>> = match kind {
        FeeClaimKind::ZeroShare => None,
        FeeClaimKind::Split | FeeClaimKind::FinalTransfer => {
            let execution: &FeeClaimExecutionView = view.execution.as_ref().unwrap();
            let split: bool = kind == FeeClaimKind::Split;
            let entrypoint: String = if split {
                execution.resource.split_entrypoint.clone()
            } else {
                execution.resource.transfer_entrypoint.clone()
            };
            let argument: CallValue = CallValue::Tuple(if split {
                vec![
                    CallValue::U64(view.entitlement.amount),
                    CallValue::Bytes(public.to_vec()),
                ]
            } else {
                vec![CallValue::Bytes(public.to_vec())]
            });
            let arguments: Vec<u8> = encode_call_value(
                execution.interface.argument_layout(&entrypoint).unwrap(),
                &argument,
            )
            .unwrap();
            let nonce: u64 = Client::new(transport(hosts[0].address))
                .query_next_nonce(objects::Address::new(public))
                .unwrap()
                .next_nonce();
            let leg_policy: LocalExecutionPolicy =
                LocalExecutionPolicy::generic_object_results(next.clone());
            let intent: LocalExecutionIntent = LocalExecutionIntent {
                mode: LocalExecutionMode::Call,
                policy_digest: leg_policy.digest(&fixture.network.resolver).unwrap(),
                call: execution::call::CallIntent {
                    context: next.clone(),
                    request_id: request,
                    sender: public,
                    nonce,
                    code: execution.resource.code.clone(),
                    instance: execution.resource.instance.clone(),
                    entrypoint,
                    type_arguments: execution.resource.ty.args().to_vec(),
                    access: abi::AccessManifest {
                        entries: vec![abi::AccessEntry {
                            object_ref: view.escrow.settlement.fee_output.clone().unwrap(),
                            mode: objects::AccessMode::Write,
                        }],
                    },
                    arguments,
                    gas_limit: 500_000,
                },
                authorizations: Vec::new(),
            };
            let frame: Vec<u8> = local_execution_signing_frame(&next, &intent).unwrap();
            Some(
                encode_signed_local_execution(&SignedLocalExecutionIntent {
                    intent,
                    signature: claimant.signing_key.sign(&frame).into(),
                })
                .unwrap(),
            )
        }
    };
    let seed_file: PathBuf = fixture.directory.0.join("successor-claimant.seed");
    // SDK signature/refusal controls use the independently loaded workflow and
    // an actual host-prepared intent; no additional operation is submitted.
    let request_frame: node_wire::FeeClaimPrepareRequest = node_wire::FeeClaimPrepareRequest {
        context: next.clone(),
        escrow_request_id: fixture.network.request_id,
        request_id: request,
        validator_id: claimant.validator_id,
        claimant_public_key: public,
        recipient: objects::Address::new(public),
        signed_leg: leg.clone(),
    };
    let prepared = Client::new(transport(hosts[0].address))
        .prepare_successor_fee_claim(workflow, &request_frame, None)
        .unwrap();
    sunrise_edge_client::verify_prepared_fee_claim(workflow, &request_frame, &prepared).unwrap();
    let historical: &validator_set::ValidatorSet = workflow
        .ordered_policy()
        .certificate_set(prepared.certificate_epoch)
        .unwrap();
    assert!(prepared.certificate_epoch < next.epoch());
    assert_eq!(
        historical
            .get(claimant.validator_id)
            .unwrap()
            .public_key
            .as_slice(),
        public.as_slice()
    );
    // Pin the original seed-only sequence independently of the SDK owner.
    let digest: protocol_types::Digest32 = node_core::fee_claims::fee_claim_intent_digest(
        workflow.ordered_policy().resolver(),
        &prepared,
    )
    .unwrap();
    let frame: Vec<u8> =
        node_core::fee_claims::fee_claim_signing_frame(&prepared.context, digest).unwrap();
    let original_signature: [u8; 64] = claimant.signing_key.sign(&frame).into();
    let original_claim: Vec<u8> = node_core::fee_claims::codec::encode_signed_fee_claim_intent(
        &node_core::fee_claims::codec::SignedFeeClaimIntent {
            intent: prepared.clone(),
            signature: original_signature,
        },
    )
    .unwrap();
    let retained =
        sunrise_edge_client::PreparedFeeClaim::prepare(workflow, &request_frame, prepared.clone())
            .unwrap();
    assert_eq!(retained.claimant(), objects::Address::new(public));
    assert_eq!(retained.signable_frame(), frame);
    assert_eq!(retained.request(), &request_frame);
    let external =
        external_signer::TestSigner::new(claimant.seed, external_signer::Behavior::Valid);
    assert_eq!(
        retained.sign_and_finalize_external(&external).unwrap(),
        original_claim
    );
    assert_eq!(external.calls(), 1);
    assert_eq!(
        sunrise_edge_client::sign_prepared_fee_claim(
            workflow,
            &request_frame,
            prepared.clone(),
            claimant.seed
        )
        .unwrap(),
        original_claim
    );
    for behavior in external_signer::REFUSALS {
        let external = external_signer::TestSigner::new(claimant.seed, behavior);
        let retained = sunrise_edge_client::PreparedFeeClaim::prepare(
            workflow,
            &request_frame,
            prepared.clone(),
        )
        .unwrap();
        let error = retained.sign_and_finalize_external(&external).unwrap_err();
        assert!(!error.to_string().contains("secret-provider-failure-marker"));
        assert_eq!(external.calls(), external_signer::expected_calls(behavior));
    }
    let mut changed_preimage = prepared.clone();
    changed_preimage.expected_generation += 1;
    let retained =
        sunrise_edge_client::PreparedFeeClaim::prepare(workflow, &request_frame, changed_preimage)
            .unwrap();
    assert!(retained.finalize(original_signature.to_vec()).is_err());
    // A genuinely registered current member absent from this old certificate
    // set must not acquire the original historical claimant's entitlement.
    for current_member in workflow
        .fastvote_certifier()
        .validator_set()
        .validators()
        .iter()
        .filter(|member| historical.get(member.id).is_none())
    {
        let mut current_request = request_frame.clone();
        current_request.validator_id = current_member.id;
        current_request.claimant_public_key =
            current_member.public_key.as_slice().try_into().unwrap();
        let mut current_intent = prepared.clone();
        current_intent.validator_id = current_member.id;
        let external =
            external_signer::TestSigner::new(claimant.seed, external_signer::Behavior::Valid);
        let current_result: Result<Vec<u8>, sunrise_edge_client::FeeClaimPreparationError> =
            match sunrise_edge_client::PreparedFeeClaim::prepare(
                workflow,
                &current_request,
                current_intent,
            ) {
                Ok(retained) => retained.sign_and_finalize_external(&external),
                Err(error) => Err(error),
            };
        assert!(current_result.is_err());
        assert_eq!(external.calls(), 0);
    }
    let mut later_epoch = prepared.clone();
    later_epoch.certificate_epoch = protocol_types::Epoch::new(next.epoch().get() + 1);
    let mut other_claimant = prepared.clone();
    other_claimant.validator_id = fixture.network.validators[2].validator_id;
    let mut other_recipient = prepared.clone();
    other_recipient.recipient = objects::Address::new([0x44; 32]);
    let mut other_escrow = prepared.clone();
    other_escrow.escrow_request_id = [0x45; 32];
    for (label, altered) in [
        ("certificate epoch after e+1", &later_epoch),
        ("claimant selector", &other_claimant),
        ("recipient", &other_recipient),
        ("escrow selector", &other_escrow),
    ] {
        assert!(
            sunrise_edge_client::verify_prepared_fee_claim(workflow, &request_frame, altered)
                .is_err(),
            "{label} must refuse before signing"
        );
        let external =
            external_signer::TestSigner::new(claimant.seed, external_signer::Behavior::Valid);
        let altered_result: Result<Vec<u8>, sunrise_edge_client::FeeClaimPreparationError> =
            match sunrise_edge_client::PreparedFeeClaim::prepare(
                workflow,
                &request_frame,
                altered.clone(),
            ) {
                Ok(retained) => retained.sign_and_finalize_external(&external),
                Err(error) => Err(error),
            };
        assert!(altered_result.is_err(), "{label}");
        assert_eq!(external.calls(), 0, "{label}");
    }
    let mut stale_scope: node_wire::FeeClaimPrepareRequest = request_frame.clone();
    stale_scope.context = fixture.network.context.clone();
    assert!(
        sunrise_edge_client::verify_prepared_fee_claim(workflow, &stale_scope, &prepared).is_err()
    );
    let external =
        external_signer::TestSigner::new(claimant.seed, external_signer::Behavior::Valid);
    let stale_result: Result<Vec<u8>, sunrise_edge_client::FeeClaimPreparationError> =
        match sunrise_edge_client::PreparedFeeClaim::prepare(
            workflow,
            &stale_scope,
            prepared.clone(),
        ) {
            Ok(retained) => retained.sign_and_finalize_external(&external),
            Err(error) => Err(error),
        };
    assert!(stale_result.is_err());
    assert_eq!(external.calls(), 0);
    assert!(
        sunrise_edge_client::sign_prepared_fee_claim(
            workflow,
            &request_frame,
            prepared.clone(),
            fixture.network.validators[2].seed,
        )
        .is_err(),
        "a different claimant key never signs"
    );
    std::fs::write(&seed_file, hex(&claimant.seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let candidate: PathBuf = fixture.directory.0.join(format!(
        "successor-fee-claim-{}.candidate",
        next.epoch().get()
    ));
    let mut tail: Vec<String> = flags.clone();
    tail.extend([
        "--prepare-peer".to_string(),
        hex(hosts[0].validator.as_bytes()),
        "--escrow-request-id".into(),
        hex(&fixture.network.request_id),
        "--request-id".into(),
        hex(&request),
        "--claimant-validator-id".into(),
        hex(claimant.validator_id.as_bytes()),
        "--claimant-seed-file".into(),
        seed_file.to_str().unwrap().into(),
        "--recipient".into(),
        hex(&public),
        "--created-checkpoint".into(),
        HOST_CHECKPOINT.to_string(),
        "--out".into(),
        candidate.to_str().unwrap().into(),
    ]);
    if let Some(leg) = &leg {
        let leg_file: PathBuf = fixture.directory.0.join("successor-fee-claim.leg");
        std::fs::write(&leg_file, leg).unwrap();
        tail.extend([
            "--signed-leg".to_string(),
            leg_file.to_str().unwrap().into(),
        ]);
    }
    cli(&["economics", "fee-claim-prepare"], tail);
    let cli_candidate: node_core::ordered_economics::OrderedCandidate =
        node_core::ordered_economics::decode_ordered_candidate(&std::fs::read(&candidate).unwrap())
            .unwrap();
    assert_eq!(
        cli_candidate.intent, original_claim,
        "the actual development CLI retains original historical claim bytes"
    );
    let mut submit: Vec<String> = flags;
    submit.extend([
        "--candidate".to_string(),
        candidate.to_str().unwrap().into(),
        "--out".into(),
        fixture
            .directory
            .0
            .join(format!(
                "successor-fee-claim-submission-{}",
                next.epoch().get()
            ))
            .to_str()
            .unwrap()
            .into(),
    ]);
    cli(&["economics", "network-submit"], submit);
    request
}

fn receipts(
    hosts: &[&HostProcess],
    request: [u8; 32],
) -> sunrise_edge_client::HttpReceiptQueryResult {
    struct ReceiptTarget {
        validator: ValidatorId,
        process_id: u32,
        address: SocketAddr,
        generation: u64,
    }
    type ReceiptResult = Result<
        sunrise_edge_client::HttpReceiptQueryResult,
        Box<sunrise_edge_client::error::ClientError>,
    >;
    let request_id: sunrise_edge_client::RequestId =
        sunrise_edge_client::RequestId::new(request).unwrap();
    let targets: Vec<ReceiptTarget> = hosts
        .iter()
        .map(|host: &&HostProcess| ReceiptTarget {
            validator: host.validator,
            process_id: host.child.id(),
            address: host.address,
            generation: host.generation,
        })
        .collect();
    let results: Vec<ReceiptResult> = std::thread::scope(|scope| {
        let handles: Vec<std::thread::ScopedJoinHandle<'_, ReceiptResult>> = targets
            .iter()
            .map(|target: &ReceiptTarget| {
                let address: SocketAddr = target.address;
                scope.spawn(move || {
                    Client::new(transport(address))
                        .query_receipt(request_id)
                        .map_err(Box::new)
                })
            })
            .collect();
        let joined: Vec<std::thread::Result<ReceiptResult>> =
            handles.into_iter().map(|handle| handle.join()).collect();
        let mut collected: Vec<ReceiptResult> = Vec::with_capacity(joined.len());
        for outcome in joined {
            match outcome {
                Ok(result) => collected.push(result),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
        collected
    });
    // Every query has ended before diagnostics or comparisons run, retaining
    // host order without sharing the live Child/store owners with workers.
    let mut agreed: Option<sunrise_edge_client::HttpReceiptQueryResult> = None;
    for (target, result) in targets.into_iter().zip(results) {
        let receipt: sunrise_edge_client::HttpReceiptQueryResult = result
            .unwrap_or_else(|error: Box<sunrise_edge_client::error::ClientError>| {
                panic!(
                    "receipt query failed: validator={} process={} address={} writer_generation={} request_id={} error={error:?}",
                    hex(target.validator.as_bytes()),
                    target.process_id,
                    target.address,
                    target.generation,
                    hex(&request)
                )
            });
        if let Some(previous) = &agreed {
            assert_eq!(
                previous, &receipt,
                "every successor host exposes the same receipt"
            );
        }
        agreed = Some(receipt);
    }
    agreed.unwrap()
}

/// Positive first-successor process acceptance; see the module boundary.
pub async fn run(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    seal: &OrderedCandidate,
    fence: WriterFenceGeneration,
    original_round: &(Vec<u8>, Vec<u8>),
) {
    let export: PathBuf = export_sealed_history(fixture, fence).await;
    tokio::task::block_in_place(|| accept(fixture, inputs, seal, &export, original_round));
}

fn accept(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    seal: &OrderedCandidate,
    export: &Path,
    original_round: &(Vec<u8>, Vec<u8>),
) {
    assert_eq!(inputs.targets.len(), 4);
    assert_eq!(inputs.members.len(), inputs.targets.len());
    let workflow: SuccessorWorkflowAuthority = load_workflow(fixture, inputs, export);
    let first_successor: crate::acceptance_timing::AcceptanceSpan =
        crate::acceptance_timing::AcceptanceSpan::start(
            crate::acceptance_timing::Stage::FirstSuccessor,
            Some(workflow.expected_context().epoch()),
        );
    let verified: &validator_set::ValidatorSet = workflow.fastvote_certifier().validator_set();
    assert_eq!(verified.validators().len(), inputs.members.len());
    let mut actual_ids: Vec<ValidatorId> = Vec::with_capacity(inputs.members.len());
    for member in &inputs.members {
        let current: &validator_set::ValidatorInfo = verified
            .get(member.validator_id)
            .expect("every staged target must be an actual verified current member");
        let key: ed25519_zebra::SigningKey = ed25519_zebra::SigningKey::from(member.seed);
        let public: [u8; 32] = ed25519_zebra::VerificationKey::from(&key).into();
        assert_eq!(current.public_key.as_slice(), public.as_slice());
        actual_ids.push(member.validator_id);
    }
    actual_ids.sort_unstable();
    assert_eq!(
        actual_ids,
        verified
            .validators()
            .iter()
            .map(|member: &validator_set::ValidatorInfo| member.id)
            .collect::<Vec<ValidatorId>>()
    );
    // Artifact substitution: a genuine but unnamed certificate variant is
    // refused by the source-free verifier before any destination write.
    assert!(
        !activation(fixture, inputs, export, &inputs.competing_certificate, 0)
            .status
            .success()
    );
    for index in 0..4 {
        let stdout: String = success(activation(
            fixture,
            inputs,
            export,
            &inputs.certificate,
            index,
        ));
        assert!(
            stdout.contains("successor_activation=activated"),
            "the substituted run installed nothing: {stdout}"
        );
    }
    assert!(
        success(activation(fixture, inputs, export, &inputs.certificate, 0))
            .contains("successor_activation=already-activated")
    );

    // Read-only inspection of the claimant own activated target, before
    // any host claims its writer fence.
    let claimant_index: usize = original_member_index(fixture, [0xa2; 32]);
    let share: node_core::fee_claims::FeeClaimInspection =
        inspect_imported_share(fixture, inputs, &workflow, export, claimant_index);
    recurring::prove_direct_live_tls(fixture, inputs, export, &workflow, seal);
    let mut hosts: Vec<HostProcess> = (0..4)
        .map(|index: usize| start_host(fixture, inputs, export, index))
        .collect();
    let next_epoch: u64 = fixture.network.epoch.get() + 1;
    assert_eq!(workflow.expected_context().epoch().get(), next_epoch);
    for host in &hosts {
        let context = Client::new(transport(host.address))
            .query_context()
            .unwrap();
        assert_eq!(
            context.epoch().get(),
            next_epoch,
            "hosts serve the verified e+1 scope"
        );
    }
    let all: Vec<&HostProcess> = hosts.iter().collect();
    let seal_receipt = receipts(&all, seal.request_id);
    let imported_receipt = receipts(&all, fixture.network.request_id);

    // Malformed scope and unready/malformed controls refuse before any signature.
    let before: OrderedStatus = status(hosts[0].address);
    let stale_request = node_wire::FeeClaimPrepareRequest {
        context: fixture.network.context.clone(),
        escrow_request_id: fixture.network.request_id,
        request_id: [0xA6; 32],
        validator_id: fixture.network.validators[1].validator_id,
        claimant_public_key: *fixture.network.validators[1].validator_id.as_bytes(),
        recipient: objects::Address::new(*fixture.network.validators[1].validator_id.as_bytes()),
        signed_leg: None,
    };
    let response: WireResponse = raw(
        hosts[0].address,
        Method::Post,
        node_wire::FEE_CLAIM_PREPARE_PATH,
        Some(node_wire::FEE_CLAIM_PREPARE_REQUEST_MEDIA_TYPE),
        stale_request.encode().unwrap(),
    );
    assert_eq!(
        response.status,
        409,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let stale_intent: Vec<u8> =
        fixture
            .network
            .sign_transfer([0x6e; 32], 1, fixture.network.sender);
    let response: WireResponse = raw(
        hosts[0].address,
        Method::Post,
        node_wire::FASTVOTE_PREPARE_PATH,
        Some(node_wire::NODE_EVENT_MEDIA_TYPE),
        stale_intent,
    );
    assert_eq!(
        response.status,
        409,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    for (path, expected_status) in [
        (node_wire::FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH, 409),
        (node_wire::FASTVOTE_DRAIN_APPLY_PATH, 400),
    ] {
        let response: WireResponse = raw(
            hosts[0].address,
            Method::Post,
            path,
            Some(node_wire::NODE_EVENT_MEDIA_TYPE),
            Vec::new(),
        );
        assert_eq!(
            response.status,
            expected_status,
            "{path}: {}",
            String::from_utf8_lossy(&response.body)
        );
    }
    assert_eq!(
        status(hosts[0].address),
        before,
        "refusals change no consensus state"
    );

    // Genuine e+1 ordered rounds under independently loaded SDK pins.
    let endpoints = ordered_endpoints(&[
        Some(&hosts[0]),
        Some(&hosts[1]),
        Some(&hosts[2]),
        Some(&hosts[3]),
    ]);
    let mut parent: Option<QuorumCertificate> = None;
    for _ in 0..3 {
        let outcome: RoundOutcome = round(&endpoints, &workflow, parent.as_ref());
        assert!(outcome.qc_formed_from.len() >= 3);
        parent = Some(decode_quorum_certificate(&outcome.certificate_bytes).unwrap());
    }
    let advanced: OrderedStatus = status(hosts[0].address);
    assert!(advanced.committed_height > before.committed_height);

    let call: [u8; 32] = paid_call_on_imported_instance(fixture, &hosts, &workflow);
    let call_receipt = receipts(&all, call);

    let (publish_request, instantiate_request, fresh_definition): (
        [u8; 32],
        [u8; 32],
        objects::ObjectId,
    ) = paid_publish_and_instantiate_fresh_asset(fixture, &hosts, &workflow);
    let publish_receipt = receipts(&all, publish_request);
    let instantiate_receipt = receipts(&all, instantiate_request);

    let network: PathBuf = fixture.directory.0.join("successor-network.conf");
    let peers: String = hosts
        .iter()
        .map(|host: &HostProcess| {
            format!("{} {} - -\n", hex(host.validator.as_bytes()), host.address)
        })
        .collect();
    std::fs::write(&network, peers).unwrap();
    let claim: [u8; 32] = imported_escrow_fee_claim(
        fixture,
        &hosts,
        &workflow,
        &share,
        claimant_index,
        successor_cli_flags(fixture, inputs, export, &network),
    );
    let claim_receipt = receipts(&all, claim);
    drop(all);

    // Live artifact tamper: every request re-verifies, so a substituted
    // certificate stops serving (and signing) until the original returns.
    let certificate_file: PathBuf = inputs.certificate.join("certificate.bin");
    let original: Vec<u8> = std::fs::read(&certificate_file).unwrap();
    let competing: Vec<u8> =
        std::fs::read(inputs.competing_certificate.join("certificate.bin")).unwrap();
    std::fs::write(&certificate_file, &competing).unwrap();
    let response: WireResponse = raw(
        hosts[0].address,
        Method::Get,
        node_wire::ordered_economics::ORDERED_ECONOMICS_STATUS_PATH,
        None,
        Vec::new(),
    );
    assert_ne!(response.status, 200, "tampered evidence never serves");
    std::fs::write(&certificate_file, &original).unwrap();
    let _ = status(hosts[0].address);

    // Close one host, certify a round without it, reopen it under a fresh
    // writer generation and catch it up from the certified prefix.
    let paused: HostProcess = hosts.remove(3);
    let paused_generation: u64 = paused.generation;
    drop(paused);
    let alive = ordered_endpoints(&[Some(&hosts[0]), Some(&hosts[1]), Some(&hosts[2]), None]);
    // The paid Call and fee-claim rounds advanced the prefix since the last
    // empty round, so the routing hint (not a stale parent) selects it.
    let missed: RoundOutcome = round(&alive, &workflow, None);
    let reopened: HostProcess = start_host(fixture, inputs, export, 3);
    assert!(
        reopened.generation > paused_generation,
        "reopen claims a new writer fence"
    );
    let deadline: Instant = Instant::now() + Duration::from_secs(1800);
    replay_declared_prefix_with_sink(
        &ordered_endpoints(&[None, None, None, Some(&reopened)]),
        workflow.ordered_policy(),
        &[(
            missed.proposal_bytes.clone(),
            missed.certificate_bytes.clone(),
        )],
        deadline,
        Duration::from_secs(300),
        &mut Sink,
    )
    .unwrap();
    assert_eq!(
        status(reopened.address).high_qc,
        status(hosts[0].address).high_qc,
        "the paused peer caught up through verified signerless replay"
    );
    hosts.push(reopened);
    let reopened_all: Vec<&HostProcess> = hosts.iter().collect();
    assert_eq!(receipts(&reopened_all, seal.request_id), seal_receipt);
    assert_eq!(
        receipts(&reopened_all, fixture.network.request_id),
        imported_receipt
    );
    assert_eq!(receipts(&reopened_all, call), call_receipt);
    assert_eq!(receipts(&reopened_all, claim), claim_receipt);
    assert_eq!(receipts(&reopened_all, publish_request), publish_receipt);
    assert_eq!(
        receipts(&reopened_all, instantiate_request),
        instantiate_receipt
    );
    let refreshed = Client::new(transport(reopened_all.last().unwrap().address))
        .query_object(fresh_definition)
        .unwrap();
    assert!(
        sunrise_edge_client::current_inline_object_ref(&refreshed).is_some(),
        "the freshly instantiated Definition is live on the caught-up successor host"
    );
    drop(reopened_all);
    drop(first_successor);
    recurring::run(
        fixture,
        inputs,
        export,
        seal.request_id,
        original_round,
        hosts,
    );
}
