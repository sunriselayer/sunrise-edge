//! Positive first-successor process acceptance over the genuine sealed
//! source produced by ordered_seal_sqlite_acceptance.
//!
//! Boundary: this operator world stages the SAME four-member committee as
//! the outgoing epoch (the genuine A/B/C/D source re-certified for e+1).
//! Real A/B/C/E replacement is owned by the independently passing core
//! tests. Everything here crosses real process and TCP boundaries: the
//! accepted Seal suffix is exported from the sealed read-only stores by the
//! shipped CLI, four successor_activation executables install it, four
//! successor_host processes serve it on loopback, and independently loaded
//! SDK and CLI successor pins drive e+1 work before signing anything.

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
    io::{BufRead, BufReader},
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
    Client, FastVoteEndpoint, LoopbackHttpTransport, Method, SuccessorArtifactDirectories,
    SuccessorWorkflowAuthority, Transport, WireRequest, WireResponse,
    load_successor_workflow_from_directories,
};

/// Host checkpoint for FastVote preparation and fee-claim preparation.
const HOST_CHECKPOINT: u64 = 1_000;

/// Original directories owned by the conditional readiness caller.
pub struct SuccessorProcessInputs {
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
    ]);
}

fn target_flags(
    command: &mut Command,
    fixture: &Fixture,
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
        &hex(fixture.network.validators[index].validator_id.as_bytes()),
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
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_successor_activation"));
    command.arg("activate");
    pins(&mut command, fixture, inputs);
    target_flags(&mut command, fixture, inputs, export, certificate, index);
    command.output().unwrap()
}

/// One real successor_host process. Dropping it kills and reaps the child.
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
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_successor_host"));
    command.arg("serve");
    pins(&mut command, fixture, inputs);
    target_flags(
        &mut command,
        fixture,
        inputs,
        export,
        &inputs.certificate,
        index,
    );
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
    let mut child: Child = command.spawn().unwrap();
    let mut line: String = String::new();
    // The host prints exactly one flushed line after its startup gate and
    // the actual bind; a failed startup closes stdout without it.
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    if line.is_empty() {
        panic!("successor host {index} exited: {:?}", child.wait());
    }
    assert!(line.contains("mode=successor-serving"), "{line}");
    HostProcess {
        address: field(&line, "listen=").parse().unwrap(),
        generation: field(&line, "writer_generation=").parse().unwrap(),
        child,
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

fn fastvote_endpoints(
    fixture: &Fixture,
    hosts: &[HostProcess],
) -> Vec<FastVoteEndpoint<LoopbackHttpTransport>> {
    hosts
        .iter()
        .zip(&fixture.network.validators)
        .map(|(host, validator)| FastVoteEndpoint {
            validator_id: validator.validator_id,
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
    assert_eq!(policy.context, context, "the installed e+1 fee policy row");
    let fee_policy_digest: protocol_types::Digest32 =
        execution::paid_execution::paid_fee_policy_digest(&fixture.network.resolver, &policy)
            .unwrap();
    let request_id: [u8; 32] = [0x6f; 32];
    workflow.require_signing_context(&context).unwrap();
    let signed_bytes: Vec<u8> = fixture.network.sign_transfer_with(
        &context,
        request_id,
        nonce,
        coin_ref,
        fee_policy_digest,
        fixture.network.sender,
    );
    let signed: execution::paid_execution::SignedPaidIntent =
        execution::paid_execution::decode_signed_paid_intent(&signed_bytes).unwrap();
    let endpoints: Vec<FastVoteEndpoint<LoopbackHttpTransport>> =
        fastvote_endpoints(fixture, hosts);
    let certifier: &consensus::FastPathCertifier = workflow.fastvote_certifier();
    let deadline: Instant = Instant::now() + Duration::from_secs(1800);
    let cap: Duration = Duration::from_secs(300);
    let (certificate, _attempts) = sunrise_edge_client::collect_fastvote_certificate(
        &endpoints,
        certifier,
        &fixture.network.resolver,
        &signed,
        deadline,
        cap,
    )
    .unwrap();
    let published = sunrise_edge_client::collect_fastvote_availability_certificate(
        &endpoints,
        certifier,
        &fixture.network.resolver,
        &[],
        fixture.network.domain,
        &signed,
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
            &signed,
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
            "e+1 paid Call on the epoch-e instance succeeded at {}",
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
    request_id
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

/// Positive fee claim against the imported epoch-e escrow. The signed leg
/// is built from a real local inspection of the sealed source (read-only
/// historical open) at the claim certificate epoch, re-scoped to e+1 with
/// the claimant e+1 nonce observed through a host. The successor host
/// prepares the unsigned intent; the shipped CLI verifies it against its own
/// successor pins, signs, wraps and submits it as an ordered e+1 candidate.
#[allow(clippy::too_many_arguments)]
fn imported_escrow_fee_claim(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    export: &Path,
    network: &Path,
    hosts: &[HostProcess],
    workflow: &SuccessorWorkflowAuthority,
) -> [u8; 32] {
    use abi::call_values::{CallValue, encode_call_value};
    use execution::local_execution::{
        LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy, SignedLocalExecutionIntent,
        encode_signed_local_execution, local_execution_signing_frame,
    };
    use node_core::fee_claims::{FeeClaimExecutionView, FeeClaimInspection, FeeClaimKind};
    let claimant = &fixture.network.validators[1];
    let public: [u8; 32] = ed25519_zebra::VerificationKey::from(&claimant.signing_key).into();
    let source: SqliteDurableStore = SqliteDurableStore::open_historical(
        fixture.directory.0.join("state-0.sqlite"),
        SqliteNamespace::new(
            fixture.network.chain_id.clone(),
            fixture.network.validators[0].validator_id,
            fixture.network.domain,
        ),
    )
    .unwrap();
    let source_blobs: SqliteBlobStore =
        SqliteBlobStore::open(fixture.directory.0.join("blobs.sqlite")).unwrap();
    let view: FeeClaimInspection = node_core::fee_claims::inspect_fee_claim(
        &source,
        &source_blobs,
        &fixture.operation,
        fixture.network.domain,
        &fixture.network.resolver,
        &[],
        &fixture.network.context,
        fixture.network.request_id,
        claimant.validator_id,
        public,
        &fixture.local_policy,
    )
    .unwrap();
    drop(source);
    let kind: FeeClaimKind = view.entitlement.kind.expect("an unclaimed imported share");
    let next: execution::publication::PublicationContext = workflow.expected_context().clone();
    let request: [u8; 32] = [0xA5; 32];
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
    std::fs::write(&seed_file, hex(&claimant.seed)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let candidate: PathBuf = fixture.directory.0.join("successor-fee-claim.candidate");
    let mut tail: Vec<String> = successor_cli_flags(fixture, inputs, export, network);
    tail.extend([
        "--prepare-peer".to_string(),
        hex(fixture.network.validators[0].validator_id.as_bytes()),
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
    let mut submit: Vec<String> = successor_cli_flags(fixture, inputs, export, network);
    submit.extend([
        "--candidate".to_string(),
        candidate.to_str().unwrap().into(),
        "--out".into(),
        fixture
            .directory
            .0
            .join("successor-fee-claim-submission")
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
    let request_id: sunrise_edge_client::RequestId =
        sunrise_edge_client::RequestId::new(request).unwrap();
    let mut agreed: Option<sunrise_edge_client::HttpReceiptQueryResult> = None;
    for host in hosts {
        let receipt = Client::new(transport(host.address))
            .query_receipt(request_id)
            .unwrap();
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
) {
    let export: PathBuf = export_sealed_history(fixture, fence).await;
    tokio::task::block_in_place(|| accept(fixture, inputs, seal, &export));
}

fn accept(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    seal: &OrderedCandidate,
    export: &Path,
) {
    assert_eq!(inputs.targets.len(), 4);
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

    let mut hosts: Vec<HostProcess> = (0..4)
        .map(|index: usize| start_host(fixture, inputs, export, index))
        .collect();
    let workflow: SuccessorWorkflowAuthority = load_workflow(fixture, inputs, export);
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

    // Malformed scope and unsupported controls refuse before any signature.
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
    for path in [
        node_wire::FASTVOTE_FROZEN_FRONTIER_ADVANCE_PATH,
        node_wire::FASTVOTE_DRAIN_APPLY_PATH,
    ] {
        let response: WireResponse = raw(
            hosts[0].address,
            Method::Post,
            path,
            Some(node_wire::NODE_EVENT_MEDIA_TYPE),
            Vec::new(),
        );
        assert_eq!(response.status, 422, "{path}");
    }
    assert_eq!(
        status(hosts[0].address),
        before,
        "refusals change no consensus state"
    );

    // Genuine e+1 ordered rounds under independently loaded SDK pins.
    let endpoints = ordered_endpoints(
        fixture,
        &[
            Some(&hosts[0]),
            Some(&hosts[1]),
            Some(&hosts[2]),
            Some(&hosts[3]),
        ],
    );
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

    let network: PathBuf = fixture.directory.0.join("successor-network.conf");
    let peers: String = hosts
        .iter()
        .zip(&fixture.network.validators)
        .map(|(host, validator)| {
            format!(
                "{} {} - -\n",
                hex(validator.validator_id.as_bytes()),
                host.address
            )
        })
        .collect();
    std::fs::write(&network, peers).unwrap();
    let claim: [u8; 32] =
        imported_escrow_fee_claim(fixture, inputs, export, &network, &hosts, &workflow);
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
    let alive = ordered_endpoints(
        fixture,
        &[Some(&hosts[0]), Some(&hosts[1]), Some(&hosts[2]), None],
    );
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
        &ordered_endpoints(fixture, &[None, None, None, Some(&reopened)]),
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
}
