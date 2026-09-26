//! `contract paid-call --fastvote-network` and `contract fastvote-replay`
//! (DR-0148): the CLI half of the certified-only FastVote network.
//!
//! `run_network_submit` is invoked only after the exact same generic paid
//! `Call` construction/signing path `contract paid-call` already uses
//! without `--fastvote-network` -- this module never builds or signs a call
//! itself, only routes an already-signed one through prepare/quorum/apply
//! instead of a single direct POST.
//!
//! Trust and persistence contract, all required by DR-0148's acceptance:
//!
//! * The local expected protocol context (`--expected-*`, unchanged) and the
//!   FastVote genesis/validator-set pin (`--fastvote-genesis-manifest`/
//!   `--fastvote-expected-genesis-digest`) are two separately supplied,
//!   cross-checked local pins: [`load_endpoints_and_certifier`] requires the
//!   genesis manifest's own embedded context to equal the caller's
//!   `--expected-*` context. Neither is ever replaced by a value read from
//!   any endpoint.
//! * Endpoint-to-validator mapping is verified
//!   ([`sunrise_edge_client::validate_fastvote_endpoints`]) immediately
//!   after loading the network config and genesis pin, before the call is
//!   ever built or signed.
//! * Every configured endpoint uses either loopback plaintext or its own
//!   independently configured TLS server name/CA -- never a system trust
//!   store -- and this module rejects a network config that mixes loopback
//!   and remote-TLS peers in one cohort.
//! * All requested output artifacts are reserved (`create_new`) before the
//!   first mutation. Original file and parent-directory handles are retained.
//!   The exact signed intent is written and file+directory synced before
//!   prepare; the exact certificate is written and synced before apply.
//!   Neither file is ever overwritten: an existing path fails closed with a
//!   diagnostic that points at manual recovery, never silently regenerating
//!   new bytes.
//! * `run_replay` reads back the exact saved signed-intent bytes (and, if
//!   explicitly supplied, the exact saved certificate bytes) and resubmits
//!   them unchanged -- it never queries a fresh nonce, never re-signs, and
//!   never invents a new request id.

use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use sunrise_edge_client::{
    Client, FastCertificate, FastPathCertifier, FastVoteEndpoint, FastVoteNetworkError,
    FastVoteQuorumError, MAX_FASTVOTE_NETWORK_ENDPOINTS, PaidExecutionResult, PaidExecutionStatus,
    SignedPaidIntent, Transport, ValidatorId, apply_fastvote_to_all, collect_fastvote_certificate,
    decode_fast_certificate, decode_signed_paid_intent, encode_fast_certificate,
    encode_signed_paid_intent, load_trusted_fastvote_genesis, local_publication_resolver,
    validate_fastvote_endpoints,
};

use crate::{
    args::{ParsedArgs, parse_flags, scalar},
    error::CliError,
    hex::{decode_hex_32, encode_hex},
    net::{CliTransport, OperationBudget, TLS_CA_CERT_DER_FILE, TLS_SERVER_NAME, build_transport},
    parse::parse_u64,
};

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}
fn invalid(message: impl Into<String>) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

/// Maximum accepted `--fastvote-network` config file size: comfortably above
/// [`MAX_FASTVOTE_NETWORK_ENDPOINTS`] lines of `validator_id endpoint
/// tls_server_name tls_ca_cert_der_file`.
const MAX_NETWORK_CONFIG_BYTES: usize = 64 * 1024;

/// The bounded, caller-facing flags this module adds to `paid-call`. Present
/// (accepted) on every paid contract action so a caller combining
/// `--fastvote-network` with `paid-publish`/`paid-instantiate` gets an
/// explicit "unsupported for FastVote" diagnostic instead of "unknown flag".
pub(super) fn network_flag_specs() -> Vec<crate::args::FlagSpec> {
    vec![
        scalar("--fastvote-network"),
        scalar("--fastvote-genesis-manifest"),
        scalar("--fastvote-expected-genesis-digest"),
        scalar("--fastvote-signed-intent-out"),
        scalar("--fastvote-certificate-out"),
        scalar("--fastvote-deadline-seconds"),
        scalar("--fastvote-per-request-cap-seconds"),
    ]
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes: Vec<u8> = Vec::new();
    File::open(path)
        .map_err(failure)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() > maximum {
        return Err(invalid(format!("{path} exceeds the maximum accepted size")));
    }
    Ok(bytes)
}

/// A newly reserved output whose original file and parent-directory handles
/// remain held until the workflow ends. Persistence never reopens its path.
struct ReservedArtifact {
    path: PathBuf,
    file: File,
    parent: File,
    kind: &'static str,
}

fn artifact_path(path: &str) -> Result<PathBuf, CliError> {
    let supplied: &Path = Path::new(path);
    let filename = supplied
        .file_name()
        .ok_or_else(|| invalid("artifact path needs a filename"))?;
    let parent: &Path = supplied
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent.canonicalize().map_err(failure)?.join(filename))
}

/// Resolve all destinations before reserving any. Canonical parents catch
/// relative and symlink-directory aliases; existing destinations (including
/// symlinks and hard links to inputs) are always rejected by create_new.
fn reserve_artifacts(
    outputs: &[(&str, &'static str)],
    inputs: &[&str],
) -> Result<Vec<ReservedArtifact>, CliError> {
    let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
    for input in inputs {
        paths.insert(Path::new(input).canonicalize().map_err(failure)?);
    }
    let mut destinations: Vec<(PathBuf, &'static str)> = Vec::new();
    for (path, kind) in outputs {
        let destination: PathBuf = artifact_path(path)?;
        if !paths.insert(destination.clone()) {
            return Err(invalid(format!(
                "artifact paths alias at {destination:?}; recover exact saved bytes, never a fresh nonce"
            )));
        }
        destinations.push((destination, *kind));
    }
    let mut artifacts: Vec<ReservedArtifact> = Vec::new();
    for (path, kind) in destinations {
        let parent_path: &Path = path
            .parent()
            .ok_or_else(|| invalid("artifact parent missing"))?;
        let parent: File = File::open(parent_path).map_err(failure)?;
        // Refuse unsupported directory synchronization before any POST.
        parent.sync_all().map_err(failure)?;
        let file: File = OpenOptions::new().write(true).create_new(true).open(&path)
            .map_err(|source| invalid(format!(
                "failed to reserve {kind} artifact at {path:?} (an existing file is never overwritten; recover exact saved bytes rather than re-signing): {source}"
            )))?;
        parent.sync_all().map_err(failure)?;
        artifacts.push(ReservedArtifact {
            path,
            file,
            parent,
            kind,
        });
    }
    Ok(artifacts)
}

impl ReservedArtifact {
    fn ensure_attached(&self) -> Result<(), CliError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let actual: std::fs::Metadata =
                std::fs::symlink_metadata(&self.path).map_err(failure)?;
            let held: std::fs::Metadata = self.file.metadata().map_err(failure)?;
            let parent_path = self
                .path
                .parent()
                .ok_or_else(|| invalid("artifact parent missing"))?;
            let actual_parent: std::fs::Metadata =
                std::fs::metadata(parent_path).map_err(failure)?;
            let held_parent: std::fs::Metadata = self.parent.metadata().map_err(failure)?;
            if (actual.dev(), actual.ino()) != (held.dev(), held.ino())
                || (actual_parent.dev(), actual_parent.ino())
                    != (held_parent.dev(), held_parent.ino())
            {
                return Err(invalid(format!(
                    "reserved {} artifact path was replaced at {:?}; recover exact saved bytes from the original file, never a fresh nonce",
                    self.kind, self.path
                )));
            }
        }
        Ok(())
    }

    fn persist(&mut self, bytes: &[u8]) -> Result<(), CliError> {
        self.ensure_attached()?;
        let recovery = |source: &dyn Error| {
            invalid(format!(
                "failed to persist {} artifact at {:?}: {source}; retained recovery bytes may be partial; replay identical saved signed bytes with the same request ID and nonce, never a fresh nonce",
                self.kind, self.path
            ))
        };
        persist_handles(&mut self.file, &self.parent, bytes).map_err(|source| recovery(&source))?;
        self.ensure_attached()?;
        Ok(())
    }
}

fn persist_handles(file: &mut File, parent: &File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()?;
    parent.sync_all()?;
    Ok(())
}

/// One line of `--fastvote-network`: `validator_id endpoint tls_server_name
/// tls_ca_cert_der_file`, whitespace-separated; `tls_server_name`/
/// `tls_ca_cert_der_file` are the literal `-` when this peer uses loopback
/// plaintext. Blank lines and lines starting with `#` are ignored.
#[derive(Debug)]
struct PeerConfig {
    validator_id: ValidatorId,
    endpoint: String,
    tls_server_name: Option<String>,
    tls_ca_cert_der_file: Option<String>,
}

fn parse_network_config(path: &str) -> Result<Vec<PeerConfig>, CliError> {
    let bytes = read_bounded(path, MAX_NETWORK_CONFIG_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("--fastvote-network config file must be UTF-8"))?;
    let mut peers: Vec<PeerConfig> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [
            validator_id,
            endpoint,
            tls_server_name,
            tls_ca_cert_der_file,
        ] = fields.as_slice()
        else {
            return Err(invalid(format!(
                "--fastvote-network config line must have exactly 4 fields (validator_id endpoint tls_server_name tls_ca_cert_der_file), got: {line:?}"
            )));
        };
        if peers.len() >= MAX_FASTVOTE_NETWORK_ENDPOINTS {
            return Err(invalid(format!(
                "--fastvote-network configures more than the maximum accepted {MAX_FASTVOTE_NETWORK_ENDPOINTS} endpoints"
            )));
        }
        let validator_id = ValidatorId::new(decode_hex_32(
            "--fastvote-network validator_id",
            validator_id,
        )?);
        let (tls_server_name, tls_ca_cert_der_file) = match (
            *tls_server_name,
            *tls_ca_cert_der_file,
        ) {
            ("-", "-") => (None, None),
            (server_name, ca_file) if server_name != "-" && ca_file != "-" => {
                (Some(server_name.to_string()), Some(ca_file.to_string()))
            }
            _ => {
                return Err(invalid(format!(
                    "--fastvote-network line for {endpoint} must supply both tls_server_name and tls_ca_cert_der_file, or both as '-'"
                )));
            }
        };
        peers.push(PeerConfig {
            validator_id,
            endpoint: (*endpoint).to_string(),
            tls_server_name,
            tls_ca_cert_der_file,
        });
    }
    Ok(peers)
}

/// Builds one [`FastVoteEndpoint`] per configured peer and rejects a config
/// that mixes loopback-plaintext and remote-TLS peers in one cohort, before
/// any of them is dialed.
fn build_endpoints(peers: &[PeerConfig]) -> Result<Vec<FastVoteEndpoint<CliTransport>>, CliError> {
    let mut endpoints: Vec<FastVoteEndpoint<CliTransport>> = Vec::with_capacity(peers.len());
    let mut saw_loopback = false;
    let mut saw_remote_tls = false;
    for peer in peers {
        let transport = build_transport(
            &peer.endpoint,
            peer.tls_server_name.as_deref(),
            peer.tls_ca_cert_der_file.as_deref(),
        )?;
        match &transport {
            CliTransport::Loopback(_) => saw_loopback = true,
            CliTransport::RemoteTls(_) => saw_remote_tls = true,
        }
        if saw_loopback && saw_remote_tls {
            return Err(invalid(
                "--fastvote-network cannot mix loopback-plaintext and remote-TLS peers in one cohort",
            ));
        }
        endpoints.push(FastVoteEndpoint {
            validator_id: peer.validator_id,
            endpoint_label: peer.endpoint.clone(),
            client: Client::new(transport),
        });
    }
    Ok(endpoints)
}

/// Loads the FastVote genesis/validator-set pin and configured endpoints,
/// verifying endpoint-to-validator mapping before the caller signs anything.
pub(super) fn load_endpoints_and_certifier(
    parsed: &ParsedArgs,
    resolver: &sunrise_edge_client::HashSuiteResolver,
    context: &sunrise_edge_client::PublicationContext,
) -> Result<(Vec<FastVoteEndpoint<CliTransport>>, FastPathCertifier), CliError> {
    let peers = parse_network_config(parsed.require("--fastvote-network")?)?;
    if let Some(endpoint) = parsed.get("--endpoint")
        && !peers.iter().any(|peer| peer.endpoint == endpoint)
    {
        return Err(invalid(
            "--endpoint must select an exact endpoint_label from --fastvote-network; preparation uses that peer's TLS configuration",
        ));
    }
    let endpoints = build_endpoints(&peers)?;
    let manifest_path = parsed.require("--fastvote-genesis-manifest")?;
    let expected_digest = decode_hex_32(
        "--fastvote-expected-genesis-digest",
        parsed.require("--fastvote-expected-genesis-digest")?,
    )?;
    let certifier =
        load_trusted_fastvote_genesis(Path::new(manifest_path), resolver, expected_digest, context)
            .map_err(failure)?;
    validate_fastvote_endpoints(&endpoints, &certifier).map_err(failure)?;
    Ok((endpoints, certifier))
}

pub(super) fn parse_deadline(parsed: &ParsedArgs) -> Result<OperationBudget, CliError> {
    let deadline_seconds = match parsed.get("--fastvote-deadline-seconds") {
        Some(value) => parse_u64("--fastvote-deadline-seconds", value)?,
        None => 60,
    };
    let per_request_cap_seconds = match parsed.get("--fastvote-per-request-cap-seconds") {
        Some(value) => parse_u64("--fastvote-per-request-cap-seconds", value)?,
        None => 15,
    };
    if deadline_seconds == 0 || per_request_cap_seconds == 0 {
        return Err(invalid(
            "--fastvote-deadline-seconds and --fastvote-per-request-cap-seconds must be positive",
        ));
    }
    // Resource ceilings, not latency targets. Match the SDK's request cap.
    if deadline_seconds > 3600
        || per_request_cap_seconds > 300
        || per_request_cap_seconds > deadline_seconds
    {
        return Err(invalid(
            "FastVote deadline must be at most 3600 seconds and per-request cap at most 300 seconds and no greater than the deadline",
        ));
    }
    let deadline: Instant = Instant::now()
        .checked_add(Duration::from_secs(deadline_seconds))
        .ok_or_else(|| invalid("FastVote deadline overflows the monotonic clock"))?;
    Ok(OperationBudget {
        deadline,
        per_request_cap: Duration::from_secs(per_request_cap_seconds),
    })
}

pub(super) fn validate_paid_network_flags(parsed: &ParsedArgs) -> Result<(), CliError> {
    if parsed.get(TLS_SERVER_NAME).is_some() || parsed.get(TLS_CA_CERT_DER_FILE).is_some() {
        return Err(invalid(
            "global TLS flags are unsupported with --fastvote-network; configure TLS independently for each cohort peer",
        ));
    }
    if parsed.get("--submission-out").is_some() {
        return Err(invalid(
            "--submission-out is unsupported with --fastvote-network; use --fastvote-signed-intent-out",
        ));
    }
    parsed.require("--endpoint")?;
    parsed.require("--fastvote-signed-intent-out")?;
    parsed.require("--fastvote-certificate-out")?;
    Ok(())
}

pub(super) fn selected_preparation_client<'a, T: Transport>(
    endpoints: &'a [FastVoteEndpoint<T>],
    selected: &str,
) -> Result<&'a Client<T>, CliError> {
    endpoints
        .iter()
        .find(|peer| peer.endpoint_label == selected)
        .map(|peer| &peer.client)
        .ok_or_else(|| invalid("--endpoint must select a configured FastVote cohort peer"))
}

fn print_prepare_attempts(attempts: &[sunrise_edge_client::FastVoteAttempt]) {
    for attempt in attempts {
        match &attempt.result {
            Ok(vote) => println!(
                "prepare validator={} status=vote_received execution_effects_hash={}",
                attempt.validator_id, vote.execution_effects_hash
            ),
            Err(error) => println!(
                "prepare validator={} status=failed reason={error}",
                attempt.validator_id
            ),
        }
        if let Err(error) = &attempt.result {
            print_repin_diagnostic(error);
        }
    }
}

fn print_apply_attempts(attempts: &[sunrise_edge_client::FastVoteApplyAttempt]) -> bool {
    let mut any_applied = false;
    for attempt in attempts {
        match &attempt.result {
            Ok(result) => {
                any_applied = true;
                println!(
                    "apply validator={} status=received paid_status={:?}",
                    attempt.validator_id, result.status
                );
            }
            Err(error) => println!(
                "apply validator={} status=failed reason={error}",
                attempt.validator_id
            ),
        }
        if let Err(error) = &attempt.result {
            print_repin_diagnostic(error);
        }
    }
    any_applied
}

fn print_repin_diagnostic(error: &impl std::fmt::Display) {
    if error.to_string().contains("fastvote-epoch-repin-required") {
        println!(
            "FastVote epoch advanced or host pin differs: operator out-of-band re-pin required; do not automatically refresh genesis/context or re-sign; preserve exact replay artifacts"
        );
    }
}

/// Runs the network prepare/quorum/apply flow for an already-built, already
/// signed ordinary paid `Call`. Persists the mandatory signed-intent and
/// certificate artifacts before their respective mutating POSTs.
pub(super) fn run_network_submit<T: Transport>(
    parsed: &ParsedArgs,
    endpoints: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
    resolver: &sunrise_edge_client::HashSuiteResolver,
    signed: &SignedPaidIntent,
    budget: OperationBudget,
) -> Result<PaidExecutionResult, CliError> {
    let signed_intent_out = parsed.require("--fastvote-signed-intent-out")?;
    let certificate_out = parsed.require("--fastvote-certificate-out")?;
    let OperationBudget {
        deadline,
        per_request_cap,
    } = budget;
    budget.ensure_live()?;
    let mut outputs: Vec<(&str, &'static str)> = vec![
        (signed_intent_out, "signed-intent"),
        (certificate_out, "certificate"),
    ];
    if let Some(path) = parsed.get("--result-out") {
        outputs.push((path, "result"));
    }
    let mut artifacts: Vec<ReservedArtifact> = reserve_artifacts(&outputs, &[])?;

    let signed_bytes = encode_signed_paid_intent(signed).map_err(failure)?;
    artifacts[0].persist(&signed_bytes)?;
    for artifact in &artifacts {
        artifact.ensure_attached()?;
    }
    println!("fastvote_signed_intent_out={signed_intent_out}");

    let (certificate, attempts) = collect_fastvote_certificate(
        endpoints,
        certifier,
        resolver,
        signed,
        deadline,
        per_request_cap,
    )
    .map_err(|error| describe_quorum_error(&error))?;
    print_prepare_attempts(&attempts);
    println!(
        "fastvote_certificate_formed=true votes={} tx_hash={}",
        certificate.votes.len(),
        certificate.tx_hash
    );

    let certificate_bytes = encode_fast_certificate(&certificate).map_err(failure)?;
    artifacts[1].persist(&certificate_bytes)?;
    for artifact in &artifacts {
        artifact.ensure_attached()?;
    }
    println!("fastvote_certificate_out={certificate_out}");

    let result: PaidExecutionResult = apply_certificate_and_report(
        endpoints,
        certifier,
        resolver,
        signed,
        &certificate,
        deadline,
        per_request_cap,
    )?;
    persist_result(artifacts.get_mut(2), &result, signed)?;
    Ok(result)
}

fn persist_result(
    artifact: Option<&mut ReservedArtifact>,
    result: &PaidExecutionResult,
    signed: &SignedPaidIntent,
) -> Result<(), CliError> {
    if let Some(artifact) = artifact {
        let bytes: Vec<u8> =
            sunrise_edge_client::encode_paid_execution_result(result).map_err(failure)?;
        artifact.persist(&bytes).map_err(|error| invalid(format!(
            "validated paid outcome received but result output failed: {error}; request_id={} nonce={}; recover the exact result bytes by replaying identical signed-intent and certificate bytes; do not retry with a fresh nonce",
            encode_hex(&signed.intent.request_id), signed.intent.nonce
        )))?;
    }
    Ok(())
}

fn apply_certificate_and_report<T: Transport>(
    endpoints: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
    resolver: &sunrise_edge_client::HashSuiteResolver,
    signed: &SignedPaidIntent,
    certificate: &FastCertificate,
    deadline: Instant,
    per_request_cap: Duration,
) -> Result<PaidExecutionResult, CliError> {
    let attempts = apply_fastvote_to_all(
        endpoints,
        certifier,
        signed,
        resolver,
        certificate,
        deadline,
        per_request_cap,
    )
    .map_err(|error| invalid(format!("fastvote apply preflight rejected: {error}")))?;
    let any_applied = print_apply_attempts(&attempts);
    // Report only the acknowledgements this call actually received: never a
    // manufactured "all validators applied" or global-durability claim.
    let first_ok = attempts.into_iter().find_map(|attempt| attempt.result.ok());
    if !any_applied {
        return Err(invalid(
            "no configured FastVote endpoint acknowledged the apply; the certified certificate was formed and saved and can be replayed with fastvote-replay",
        ));
    }
    first_ok.ok_or_else(|| invalid("unreachable: any_applied was true but no Ok attempt found"))
}

fn describe_quorum_error(error: &FastVoteQuorumError) -> CliError {
    match error {
        FastVoteQuorumError::Network(FastVoteNetworkError::EndpointConfig(reason)) => {
            invalid(format!("fastvote network configuration rejected: {reason}"))
        }
        FastVoteQuorumError::Network(FastVoteNetworkError::Preflight(reason)) => invalid(format!(
            "fastvote preflight rejected before any endpoint was contacted: {reason}"
        )),
        FastVoteQuorumError::Network(
            FastVoteNetworkError::ZeroPerRequestCap
            | FastVoteNetworkError::ExcessivePerRequestCap { .. }
            | FastVoteNetworkError::OverallDeadlineElapsed
            | FastVoteNetworkError::DeadlineOverflow,
        ) => invalid(format!(
            "fastvote deadline/cap rejected before any endpoint was contacted: {error:?}"
        )),
        FastVoteQuorumError::InsufficientQuorum(failure) => {
            for attempt in &failure.attempts {
                if let Err(reason) = &attempt.result {
                    println!(
                        "prepare validator={} status=failed reason={reason}",
                        attempt.validator_id
                    );
                    print_repin_diagnostic(reason);
                }
            }
            invalid(
                "insufficient FastVote quorum: no candidate execution outcome reached quorum voting power",
            )
        }
    }
}

// ---------------------------------------------------------------------
// fastvote-replay
// ---------------------------------------------------------------------

const REPLAY_VALUE_FLAGS_EXTRA: &[&str] = &["--submission", "--certificate", "--result-out"];

/// `contract fastvote-replay`: reads back the exact saved signed-intent
/// bytes (mandatory) and, if present, the exact saved certificate bytes,
/// and resubmits them unchanged. Never queries a fresh nonce, never
/// re-signs, never invents a new request id. If no certificate was saved
/// yet, this runs the same prepare/quorum/apply flow
/// `run_network_submit` does, from the exact saved intent; if a certificate
/// was already saved, this independently re-verifies it (via
/// `apply_fastvote_to_all`'s own preflight) and goes straight to apply.
pub(super) fn run_replay<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = vec![
        scalar("--expected-chain-id"),
        scalar("--expected-protocol-version"),
        scalar("--expected-epoch"),
        scalar("--expected-hash-suite-id"),
        scalar("--expected-domain"),
    ];
    specs.extend(network_flag_specs());
    specs.extend(REPLAY_VALUE_FLAGS_EXTRA.iter().map(|name| scalar(name)));
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let budget: OperationBudget = parse_deadline(&parsed)?;
    if parsed.get("--fastvote-signed-intent-out").is_some() {
        return Err(invalid(
            "--fastvote-signed-intent-out is unsupported for replay; --submission already supplies the exact signed intent",
        ));
    }
    if parsed.get("--certificate").is_some() && parsed.get("--fastvote-certificate-out").is_some() {
        return Err(invalid(
            "--fastvote-certificate-out is unsupported when replay supplies --certificate",
        ));
    }

    let submission_path = parsed.require("--submission")?;
    let signed_bytes: Vec<u8> = read_bounded(
        submission_path,
        sunrise_edge_client::MAX_SIGNED_PAID_INTENT_BYTES,
    )
    .map_err(|error| artifact_read_error(submission_path, "signed-intent", &error))?;
    let signed: SignedPaidIntent = decode_signed_paid_intent(&signed_bytes)
        .map_err(|error| artifact_read_error(submission_path, "signed-intent", &error))?;
    let certificate: Option<FastCertificate> = parsed
        .get("--certificate")
        .map(|path| {
            let bytes: Vec<u8> =
                read_bounded(path, sunrise_edge_client::MAX_FASTVOTE_CERTIFICATE_BYTES)
                    .map_err(|error| artifact_read_error(path, "certificate", &error))?;
            decode_fast_certificate(&bytes)
                .map_err(|error| artifact_read_error(path, "certificate", &error))
        })
        .transpose()?;

    let expected = super::standard_asset::parse_expected_context(&parsed)?;
    let resolver = local_publication_resolver(&expected)?;
    let context = sunrise_edge_client::PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(failure)?;
    let (endpoints, certifier) = load_endpoints_and_certifier(&parsed, &resolver, &context)?;

    println!("fastvote_replay_submission={submission_path}");
    println!("request_id={}", encode_hex(&signed.intent.request_id));
    println!("nonce={}", signed.intent.nonce);

    let result: PaidExecutionResult = replay_loaded(
        &parsed,
        &endpoints,
        &certifier,
        &resolver,
        &signed,
        certificate.as_ref(),
        budget,
    )?;
    println!("paid_status={:?}", result.status);
    if result.status != PaidExecutionStatus::Success {
        return Err(invalid(
            "fastvote apply committed a charged/rejected trap; this is a valid final result, not a fresh-retry condition",
        ));
    }
    Ok(())
}

fn artifact_read_error(path: &str, kind: &str, error: &dyn std::fmt::Display) -> CliError {
    invalid(format!(
        "cannot read exact saved {kind} artifact at {path:?}: {error}; recover the original signed-intent/certificate bytes; do not re-sign or retry with a fresh nonce"
    ))
}

#[allow(clippy::too_many_arguments)]
fn replay_loaded<T: Transport>(
    parsed: &ParsedArgs,
    endpoints: &[FastVoteEndpoint<T>],
    certifier: &FastPathCertifier,
    resolver: &sunrise_edge_client::HashSuiteResolver,
    signed: &SignedPaidIntent,
    certificate: Option<&FastCertificate>,
    budget: OperationBudget,
) -> Result<PaidExecutionResult, CliError> {
    let submission_path: &str = parsed.require("--submission")?;

    let OperationBudget {
        deadline,
        per_request_cap,
    } = budget;

    budget.ensure_live()?;
    let mut outputs: Vec<(&str, &'static str)> = Vec::new();
    if certificate.is_none() {
        outputs.push((parsed.require("--fastvote-certificate-out")?, "certificate"));
    }
    if let Some(path) = parsed.get("--result-out") {
        outputs.push((path, "result"));
    }
    let mut inputs: Vec<&str> = vec![submission_path];
    if let Some(path) = parsed.get("--certificate") {
        inputs.push(path);
    }
    let mut artifacts: Vec<ReservedArtifact> = reserve_artifacts(&outputs, &inputs)?;
    let result_index: usize = usize::from(certificate.is_none());

    let result = if let Some(certificate) = certificate {
        println!("fastvote_replay_mode=saved_certificate");
        apply_certificate_and_report(
            endpoints,
            certifier,
            resolver,
            signed,
            certificate,
            deadline,
            per_request_cap,
        )?
    } else {
        println!("fastvote_replay_mode=prepare_from_saved_intent");
        let certificate_out = parsed.require("--fastvote-certificate-out")?;
        let (certificate, attempts) = collect_fastvote_certificate(
            endpoints,
            certifier,
            resolver,
            signed,
            deadline,
            per_request_cap,
        )
        .map_err(|error| describe_quorum_error(&error))?;
        print_prepare_attempts(&attempts);
        let certificate_bytes = encode_fast_certificate(&certificate).map_err(failure)?;
        artifacts[0].persist(&certificate_bytes)?;
        for artifact in &artifacts {
            artifact.ensure_attached()?;
        }
        println!("fastvote_certificate_out={certificate_out}");
        apply_certificate_and_report(
            endpoints,
            certifier,
            resolver,
            signed,
            &certificate,
            deadline,
            per_request_cap,
        )?
    };

    persist_result(artifacts.get_mut(result_index), &result, signed)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "sunrise-fastvote-network-unit-{}-{name}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn write_config(text: &str) -> std::path::PathBuf {
        let path = temp_path("config");
        std::fs::write(&path, text).unwrap();
        path
    }

    fn validator_hex(byte: u8) -> String {
        encode_hex(&[byte; 32])
    }

    #[test]
    fn parse_network_config_accepts_comments_and_blank_lines_and_loopback_sentinels() {
        let text = format!(
            "# comment\n\n{} 127.0.0.1:9001 - -\n  \n{} 127.0.0.1:9002 - -\n",
            validator_hex(0xA1),
            validator_hex(0xA2),
        );
        let path = write_config(&text);
        let peers = parse_network_config(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(peers.len(), 2);
        assert!(peers[0].tls_server_name.is_none());
        assert!(peers[0].tls_ca_cert_der_file.is_none());
        assert_eq!(peers[1].endpoint, "127.0.0.1:9002");
    }

    #[test]
    fn parse_network_config_accepts_a_fully_configured_remote_tls_peer() {
        let text = format!(
            "{} example.test:9443 example.test /tmp/ca.der\n",
            validator_hex(0xA1)
        );
        let path = write_config(&text);
        let peers = parse_network_config(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].tls_server_name.as_deref(), Some("example.test"));
        assert_eq!(
            peers[0].tls_ca_cert_der_file.as_deref(),
            Some("/tmp/ca.der")
        );
    }

    #[test]
    fn parse_network_config_rejects_a_line_with_the_wrong_field_count() {
        let path = write_config(&format!("{} 127.0.0.1:9001 -\n", validator_hex(0xA1)));
        let error = parse_network_config(path.to_str().unwrap()).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(format!("{error}").contains("exactly 4 fields"));
    }

    #[test]
    fn parse_network_config_rejects_a_partially_configured_tls_peer() {
        let path = write_config(&format!(
            "{} example.test:9443 example.test -\n",
            validator_hex(0xA1)
        ));
        let error = parse_network_config(path.to_str().unwrap()).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(format!("{error}").contains("must supply both"));
    }

    #[test]
    fn parse_network_config_rejects_an_invalid_hex_validator_id() {
        let path = write_config("not-hex 127.0.0.1:9001 - -\n");
        let error = parse_network_config(path.to_str().unwrap()).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(format!("{error}").contains("--fastvote-network validator_id"));
    }

    #[test]
    fn parse_network_config_rejects_more_than_the_maximum_endpoints() {
        let mut text = String::new();
        for index in 0..=MAX_FASTVOTE_NETWORK_ENDPOINTS {
            text.push_str(&format!(
                "{} 127.0.0.1:{} - -\n",
                validator_hex(u8::try_from(index % 256).unwrap()),
                9000 + index
            ));
        }
        let path = write_config(&text);
        let error = parse_network_config(path.to_str().unwrap()).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(format!("{error}").contains("maximum accepted"));
    }

    #[test]
    fn build_endpoints_rejects_mixing_loopback_and_remote_tls_peers() {
        let ca_der = rcgen::generate_simple_self_signed(vec!["example.test".to_string()])
            .unwrap()
            .cert
            .der()
            .to_vec();
        let ca_path = temp_path("ca.der");
        std::fs::write(&ca_path, &ca_der).unwrap();

        let peers = vec![
            PeerConfig {
                validator_id: ValidatorId::new([0xA1; 32]),
                endpoint: "127.0.0.1:9001".to_string(),
                tls_server_name: None,
                tls_ca_cert_der_file: None,
            },
            PeerConfig {
                validator_id: ValidatorId::new([0xA2; 32]),
                endpoint: "203.0.113.1:9443".to_string(),
                tls_server_name: Some("example.test".to_string()),
                tls_ca_cert_der_file: Some(ca_path.to_str().unwrap().to_string()),
            },
        ];
        let error = match build_endpoints(&peers) {
            Ok(_) => {
                panic!("expected build_endpoints to reject a mixed loopback/remote-TLS cohort")
            }
            Err(error) => error,
        };
        let _ = std::fs::remove_file(&ca_path);
        assert!(format!("{error}").contains("cannot mix loopback-plaintext and remote-TLS"));
    }

    #[test]
    fn build_endpoints_accepts_distinct_per_peer_tls_configuration() {
        let ca_der_1 = rcgen::generate_simple_self_signed(vec!["one.example.test".to_string()])
            .unwrap()
            .cert
            .der()
            .to_vec();
        let ca_der_2 = rcgen::generate_simple_self_signed(vec!["two.example.test".to_string()])
            .unwrap()
            .cert
            .der()
            .to_vec();
        let ca_path_1 = temp_path("ca1.der");
        let ca_path_2 = temp_path("ca2.der");
        std::fs::write(&ca_path_1, &ca_der_1).unwrap();
        std::fs::write(&ca_path_2, &ca_der_2).unwrap();

        let peers = vec![
            PeerConfig {
                validator_id: ValidatorId::new([0xA1; 32]),
                endpoint: "203.0.113.1:9443".to_string(),
                tls_server_name: Some("one.example.test".to_string()),
                tls_ca_cert_der_file: Some(ca_path_1.to_str().unwrap().to_string()),
            },
            PeerConfig {
                validator_id: ValidatorId::new([0xA2; 32]),
                endpoint: "203.0.113.2:9443".to_string(),
                tls_server_name: Some("two.example.test".to_string()),
                tls_ca_cert_der_file: Some(ca_path_2.to_str().unwrap().to_string()),
            },
        ];
        let endpoints = build_endpoints(&peers).unwrap();
        let _ = std::fs::remove_file(&ca_path_1);
        let _ = std::fs::remove_file(&ca_path_2);
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn persist_new_artifact_writes_exact_bytes_and_never_overwrites() {
        let path = temp_path("artifact");
        reserve_artifacts(&[(path.to_str().unwrap(), "test")], &[]).unwrap()[0]
            .persist(b"hello")
            .unwrap();
        let readback = std::fs::read(&path).unwrap();
        assert_eq!(readback, b"hello");

        let error = reserve_artifacts(&[(path.to_str().unwrap(), "test")], &[])
            .err()
            .unwrap();
        assert!(format!("{error}").contains("an existing file is never overwritten"));
        let unchanged = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            unchanged, b"hello",
            "a rejected overwrite must leave the original artifact bytes untouched"
        );
    }

    #[test]
    fn read_bounded_rejects_an_oversized_file() {
        let path = temp_path("oversized");
        std::fs::write(&path, vec![0u8; 32]).unwrap();
        let error = read_bounded(path.to_str().unwrap(), 16).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(format!("{error}").contains("exceeds the maximum accepted size"));
    }

    #[test]
    fn read_bounded_accepts_a_file_at_exactly_the_limit() {
        let path = temp_path("exact");
        std::fs::write(&path, vec![0u8; 16]).unwrap();
        let bytes = read_bounded(path.to_str().unwrap(), 16).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(bytes.len(), 16);
    }
}

#[cfg(test)]
#[path = "fastvote_network_tests.rs"]
mod boundary_tests;

#[path = "fastvote_catch_up.rs"]
pub(super) mod catch_up;
