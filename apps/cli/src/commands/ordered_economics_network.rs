//! `economics network-submit --candidate FILE`, `economics network-replay
//! --manifest FILE`, and `economics candidate-wrap` (DR-0153): the CLI half
//! of the opt-in ordered-economics network surface.
//!
//! Reuses `fastvote_network.rs`'s own network-config parser
//! ([`super::fastvote_network::{PeerConfig, parse_network_config}`]),
//! per-peer transport/bearer-token/cohort-purity builder
//! ([`super::fastvote_network::configure_peer_transport`]), and artifact
//! reservation helpers ([`super::fastvote_network::{reserve_artifacts,
//! ReservedArtifact, read_bounded}`]) unchanged -- this module never
//! reimplements a weaker duplicate of any of them. Every bound below is the
//! real wire-layer cap from `sunrise_edge_client::ordered_economics`
//! (re-exporting `node_wire::ordered_economics`), not an arbitrary smaller
//! CLI constant.
//!
//! `network-submit` never builds or signs a candidate itself -- it only
//! routes an already-built, exact canonical `OrderedCandidate` file through
//! propose/vote/certificate. `candidate-wrap` is a separate, purely
//! structural helper: it wraps an already-signed existing canonical intent
//! (fee-claim/bond-lifecycle/bond-slash/evidence, produced by existing
//! production tooling) into an `OrderedCandidate`, after validating the
//! caller's declared context against the local genesis pin. It never signs
//! anything and never guesses the intent's kind/checkpoint/context.

use std::{
    error::Error,
    ffi::OsString,
    path::Path,
    time::{Duration, Instant},
};

use sunrise_edge_client::{
    Client,
    ordered_economics::{
        MAX_ORDERED_CANDIDATE_BYTES, MAX_ORDERED_CERTIFICATE_BYTES, MAX_ORDERED_PROPOSAL_BYTES,
    },
    ordered_economics_client::{
        ArtifactSink, MAX_REPLAY_BYTES, MAX_REPLAY_ROUNDS, OrderedEconomicsEndpoint,
        PeerPhaseOutcome, PeerResult, authenticate_ordered_candidate, load_trusted_ordered_policy,
        replay_declared_prefix_with_sink, submit_candidate, validate_ordered_economics_endpoints,
    },
};

use crate::{
    args::{ParsedArgs, parse_flags, scalar},
    error::CliError,
    hex::decode_hex_32,
    net::CliTransport,
    parse::parse_u64,
};
use protocol_types::{AtomicityDomainId, ChainId, Epoch, ProtocolVersion};

use super::fastvote_network::{
    PeerConfig, ReservedArtifact, configure_peer_transport, parse_network_config, read_bounded,
    reserve_artifacts,
};

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: impl Into<String>) -> CliError {
    CliError::LocalExecution(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    )))
}

/// Number of empty descendant rounds after the real candidate round, per the
/// three-chain commit profile.
const EMPTY_DESCENDANT_ROUNDS: usize = 2;
const TOTAL_ROUNDS: usize = EMPTY_DESCENDANT_ROUNDS + 1;
/// Bounded total manifest size: one path pair (proposal + certificate file
/// path) per round, generously bounding each path at 4KiB.
const MAX_MANIFEST_BYTES: usize = MAX_REPLAY_ROUNDS * 2 * 4096;
/// Bounded total results-file size: one round's proposal/certificate/event-
/// output triple, each individually bounded by the real wire caps.
const MAX_RESULTS_BYTES: usize = 64 * 1024 * 1024;

/// Fixed-epoch genesis hash suite resolver, matching
/// [`sunrise_edge_client::local_publication_resolver`]'s own internal
/// construction: DR-0153's closed profile pins the existing genesis
/// consensus parameters/hash suite, never a remote-provided schedule.
fn genesis_hash_suite_resolver(
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
) -> Result<sunrise_edge_client::HashSuiteResolver, CliError> {
    sunrise_edge_client::HashSuiteResolver::new(
        chain_id,
        protocol_version,
        vec![sunrise_edge_client::HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: sunrise_edge_client::HashSuite::genesis(),
        }],
    )
    .map_err(failure)
}

/// Rejects an `--out` prefix containing whitespace/control characters: every
/// artifact path this module derives from it is later written one-per-line
/// into a whitespace-delimited manifest, so an embedded space or tab would
/// make that manifest's own path framing ambiguous on read-back.
fn reject_ambiguous_out_prefix(flag: &str, value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 4000
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid(format!(
            "{flag} must not contain whitespace: it becomes part of a whitespace-delimited replay manifest path"
        )));
    }
    Ok(())
}

fn parse_protocol(value: &str) -> Result<ProtocolVersion, CliError> {
    let parsed: u64 = parse_u64("--expected-protocol-version", value)?;
    let version: u32 =
        u32::try_from(parsed).map_err(|_| invalid("protocol version exceeds u32"))?;
    Ok(ProtocolVersion::new(version))
}

fn build_ordered_endpoints(
    peers: &[PeerConfig],
) -> Result<Vec<OrderedEconomicsEndpoint<CliTransport>>, CliError> {
    let mut endpoints = Vec::with_capacity(peers.len());
    let mut saw_loopback = false;
    let mut saw_remote_tls = false;
    for peer in peers {
        let maximum: std::num::NonZeroUsize = std::num::NonZeroUsize::new(
            sunrise_edge_client::ordered_economics::MAX_ORDERED_EVENT_OUTPUT_BYTES,
        )
        .ok_or_else(|| invalid("zero ordered response bound"))?;
        let transport = configure_peer_transport(peer, &mut saw_loopback, &mut saw_remote_tls)?
            .with_max_response_body_bytes(maximum);
        endpoints.push(OrderedEconomicsEndpoint {
            validator_id: peer.validator_id,
            endpoint_label: peer.endpoint.clone(),
            client: Client::new(transport),
        });
    }
    Ok(endpoints)
}

fn parse_budget(parsed: &ParsedArgs) -> Result<(Instant, Duration), CliError> {
    let deadline_seconds = match parsed.get("--deadline-seconds") {
        Some(value) => parse_u64("--deadline-seconds", value)?,
        None => 60,
    };
    let per_request_cap_seconds = match parsed.get("--per-request-cap-seconds") {
        Some(value) => parse_u64("--per-request-cap-seconds", value)?,
        None => 15,
    };
    if deadline_seconds == 0
        || per_request_cap_seconds == 0
        || deadline_seconds > 3600
        || per_request_cap_seconds > 300
        || per_request_cap_seconds > deadline_seconds
    {
        return Err(invalid(
            "--deadline-seconds and --per-request-cap-seconds must be positive, bounded, and consistent",
        ));
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(deadline_seconds))
        .ok_or_else(|| invalid("deadline overflows the monotonic clock"))?;
    Ok((deadline, Duration::from_secs(per_request_cap_seconds)))
}

fn network_flag_specs(extra: &[&'static str]) -> Vec<crate::args::FlagSpec> {
    let mut flags = vec![
        scalar("--ordered-network"),
        scalar("--ordered-genesis-manifest"),
        scalar("--ordered-expected-genesis-digest"),
        scalar("--expected-chain-id"),
        scalar("--expected-protocol-version"),
        scalar("--expected-epoch"),
        scalar("--domain"),
        scalar("--deadline-seconds"),
        scalar("--per-request-cap-seconds"),
    ];
    flags.extend(extra.iter().map(|flag| scalar(flag)));
    flags
}

struct LoadedPolicyInputs {
    endpoints: Vec<OrderedEconomicsEndpoint<CliTransport>>,
    policy: sunrise_edge_client::ordered_economics_core::OrderedEconomicsPolicy,
}

fn load_policy_and_endpoints(parsed: &ParsedArgs) -> Result<LoadedPolicyInputs, CliError> {
    let peers = parse_network_config(parsed.require("--ordered-network")?)?;
    let endpoints = build_ordered_endpoints(&peers)?;
    let chain_id =
        ChainId::new(parsed.require("--expected-chain-id")?.to_string()).map_err(failure)?;
    let protocol_version = parse_protocol(parsed.require("--expected-protocol-version")?)?;
    let epoch = Epoch::new(parse_u64(
        "--expected-epoch",
        parsed.require("--expected-epoch")?,
    )?);
    let context =
        sunrise_edge_client::PublicationContext::new(chain_id.clone(), protocol_version, epoch)
            .map_err(failure)?;
    let domain = AtomicityDomainId::new(decode_hex_32("--domain", parsed.require("--domain")?)?)
        .map_err(failure)?;
    let expected_digest = decode_hex_32(
        "--ordered-expected-genesis-digest",
        parsed.require("--ordered-expected-genesis-digest")?,
    )?;
    let resolver = genesis_hash_suite_resolver(chain_id, protocol_version)?;
    let policy = load_trusted_ordered_policy(
        Path::new(parsed.require("--ordered-genesis-manifest")?),
        &resolver,
        expected_digest,
        &context,
        domain,
    )
    .map_err(failure)?;
    validate_ordered_economics_endpoints(&endpoints, policy.engine().validator_set())
        .map_err(failure)?;
    Ok(LoadedPolicyInputs { endpoints, policy })
}

/// Reserves every round's proposal/certificate artifact, the one candidate
/// artifact, the declared replay manifest, and the results file -- all
/// up front, before any network call. `ArtifactSink::persist` writes into
/// the already-reserved handle for round artifacts; the manifest/results
/// handles are returned separately so their final content (only known after
/// every round completes) is still written into an already-reserved,
/// already-synced destination, never a freshly created one after mutation.
struct CliArtifactSink {
    reserved: std::collections::BTreeMap<String, ReservedArtifact>,
    manifest: ReservedArtifact,
    results: ReservedArtifact,
    manifest_text: String,
    results_text: String,
}

impl ArtifactSink for CliArtifactSink {
    fn persist(&mut self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        let artifact = self
            .reserved
            .get_mut(name)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, name.to_string()))?;
        artifact
            .persist(bytes)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }

    fn record_certified_round(&mut self, round: usize) -> std::io::Result<()> {
        // Canonical absolute paths, read from the already-open, already-
        // canonicalized handles this same sink holds (never a re-derived or
        // re-opened path), so a later replay resolves correctly regardless
        // of its own current working directory.
        let proposal_key: String = format!("round-{round}.proposal");
        let certificate_key: String = format!("round-{round}.certificate");
        let proposal_path = self
            .reserved
            .get(&proposal_key)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, proposal_key))?
            .path()
            .to_path_buf();
        let certificate_path = self
            .reserved
            .get(&certificate_key)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, certificate_key))?
            .path()
            .to_path_buf();
        // Whitespace/control-character rejection for every reserved
        // artifact resolved path already ran at reservation preflight, in
        // `reserve_submission_artifacts`, before any network call -- this
        // handle could only exist if that check already passed.
        let line: String = format!(
            "{} {}\n",
            proposal_path.display(),
            certificate_path.display()
        );
        let projected = self
            .manifest_text
            .len()
            .checked_add(line.len())
            .filter(|length| *length <= MAX_MANIFEST_BYTES)
            .ok_or_else(|| std::io::Error::other("replay manifest byte bound"))?;
        self.manifest_text.reserve(line.len());
        self.manifest_text.push_str(&line);
        debug_assert_eq!(self.manifest_text.len(), projected);
        self.manifest
            .persist(line.as_bytes())
            .map_err(|error| std::io::Error::other(error.to_string()))
    }

    fn record_peer_result(&mut self, round: usize, peer: &PeerResult) -> std::io::Result<()> {
        let vote: String = phase_report(&peer.vote_phase)?;
        let certificate: String = phase_report(&peer.certificate_phase)?;
        let line: String = format!(
            "round={round} validator={} endpoint_hex={} vote={vote} certificate={certificate}\n",
            peer.validator_id,
            crate::hex::encode_hex(peer.endpoint_label.as_bytes())
        );
        let projected = self
            .results_text
            .len()
            .checked_add(line.len())
            .filter(|length| *length <= MAX_RESULTS_BYTES)
            .ok_or_else(|| std::io::Error::other("replica results byte bound"))?;
        self.results_text.reserve(line.len());
        self.results_text.push_str(&line);
        debug_assert_eq!(self.results_text.len(), projected);
        self.results
            .persist(line.as_bytes())
            .map_err(|error| std::io::Error::other(error.to_string()))
    }
}

/// Minimal sink for `economics network-replay`: records only per-peer
/// results, incrementally, synced before the next POST/round -- there is no
/// manifest or round artifact to persist during replay, only the already-
/// declared prefix being resent.
struct ReplayResultsSink {
    results: ReservedArtifact,
    results_text: String,
}

impl ArtifactSink for ReplayResultsSink {
    fn persist(&mut self, name: &str, _bytes: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::other(format!(
            "unexpected replay artifact persist call: {name}"
        )))
    }

    fn record_peer_result(&mut self, round: usize, peer: &PeerResult) -> std::io::Result<()> {
        let vote: String = phase_report(&peer.vote_phase)?;
        let certificate: String = phase_report(&peer.certificate_phase)?;
        let line: String = format!(
            "round={round} validator={} endpoint_hex={} vote={vote} certificate={certificate}\n",
            peer.validator_id,
            crate::hex::encode_hex(peer.endpoint_label.as_bytes())
        );
        let projected = self
            .results_text
            .len()
            .checked_add(line.len())
            .filter(|length| *length <= MAX_RESULTS_BYTES)
            .ok_or_else(|| std::io::Error::other("replica results byte bound"))?;
        self.results_text.reserve(line.len());
        self.results_text.push_str(&line);
        debug_assert_eq!(self.results_text.len(), projected);
        self.results
            .persist(line.as_bytes())
            .map_err(|error| std::io::Error::other(error.to_string()))
    }
}

fn phase_report(phase: &PeerPhaseOutcome) -> std::io::Result<String> {
    match phase {
        PeerPhaseOutcome::Applied(output) => {
            let bytes: Vec<u8> =
                sunrise_edge_client::ordered_economics_core::encode_ordered_event_output(output)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            if bytes.len() > (MAX_RESULTS_BYTES / 2).saturating_sub(4096) {
                return Err(std::io::Error::other(
                    "replica acknowledgement report byte bound",
                ));
            }
            Ok(format!("acknowledged:{}", crate::hex::encode_hex(&bytes)))
        }
        PeerPhaseOutcome::Rejected(reason) => Ok(format!(
            "rejected:{}",
            crate::hex::encode_hex(reason.as_bytes())
        )),
        PeerPhaseOutcome::Unreachable(reason) => Ok(format!(
            "unreachable:{}",
            crate::hex::encode_hex(reason.as_bytes())
        )),
        PeerPhaseOutcome::Skipped(reason) => Ok(format!(
            "skipped:{}",
            crate::hex::encode_hex(reason.as_bytes())
        )),
    }
}

/// Rejects a resolved canonical artifact path containing whitespace or
/// control characters. Run at reservation preflight, for every reserved
/// artifact, before any network call -- not deferred to first use, since a
/// deferred check (e.g. only when a manifest line is finally written) would
/// run only after round-0 propose/vote traffic already happened.
fn reject_ambiguous_resolved_path(path: &Path) -> Result<(), CliError> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid("resolved artifact path is not valid UTF-8"))?;
    if text
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid(
            "resolved artifact path contains whitespace or control characters",
        ));
    }
    Ok(())
}

fn reserve_submission_artifacts(out_prefix: &str) -> Result<CliArtifactSink, CliError> {
    // `key` is exactly the name `submit_candidate`'s `ArtifactSink::persist`
    // calls use; `path` is the caller-chosen on-disk destination.
    let mut keys: Vec<(String, String, &'static str)> = vec![(
        "round-0.candidate".to_string(),
        format!("{out_prefix}.round-0.candidate"),
        "ordered-economics-candidate",
    )];
    for round in 0..TOTAL_ROUNDS {
        keys.push((
            format!("round-{round}.proposal"),
            format!("{out_prefix}.round-{round}.proposal"),
            "ordered-economics-proposal",
        ));
        keys.push((
            format!("round-{round}.certificate"),
            format!("{out_prefix}.round-{round}.certificate"),
            "ordered-economics-certificate",
        ));
    }
    let manifest_path = format!("{out_prefix}.manifest");
    let results_path = format!("{out_prefix}.results");
    let mut outputs: Vec<(&str, &'static str)> = keys
        .iter()
        .map(|(_, path, kind)| (path.as_str(), *kind))
        .collect();
    outputs.push((manifest_path.as_str(), "ordered-economics-replay-manifest"));
    outputs.push((results_path.as_str(), "ordered-economics-results"));
    let mut reserved_list = reserve_artifacts(&outputs, &[])?;
    for artifact in &reserved_list {
        reject_ambiguous_resolved_path(artifact.path())?;
    }
    let results = reserved_list
        .pop()
        .ok_or_else(|| invalid("missing reserved results handle"))?;
    let manifest = reserved_list
        .pop()
        .ok_or_else(|| invalid("missing reserved manifest handle"))?;
    let mut reserved = std::collections::BTreeMap::new();
    for ((key, _path, _kind), artifact) in keys.into_iter().zip(reserved_list) {
        reserved.insert(key, artifact);
    }
    Ok(CliArtifactSink {
        reserved,
        manifest,
        results,
        manifest_text: String::new(),
        results_text: String::new(),
    })
}

fn network_submit_flag_specs() -> Vec<crate::args::FlagSpec> {
    network_flag_specs(&["--candidate", "--out", "--resume-proposal"])
}

fn run_network_submit<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let parsed = parse_flags(args, &network_submit_flag_specs())?;
    let candidate_path = parsed.require("--candidate")?;
    let candidate_bytes = read_bounded(candidate_path, MAX_ORDERED_CANDIDATE_BYTES)?;
    // Decoded once here, purely to independently re-check the returned
    // committed outcome request id below -- `submit_candidate` decodes and
    // authenticates its own copy separately; this CLI layer never skips
    // that by trusting this decode as authentication.
    let candidate =
        sunrise_edge_client::ordered_economics_core::decode_ordered_candidate(&candidate_bytes)
            .map_err(failure)?;
    let loaded = load_policy_and_endpoints(&parsed)?;

    let resume_proposal = match parsed.get("--resume-proposal") {
        Some(path) => Some(read_bounded(path, MAX_ORDERED_PROPOSAL_BYTES)?),
        None => None,
    };

    let out_prefix = parsed.require("--out")?;
    reject_ambiguous_out_prefix("--out", out_prefix)?;
    let mut reservation = reserve_submission_artifacts(out_prefix)?;
    let (deadline, per_request_cap) = parse_budget(&parsed)?;
    let submission = submit_candidate(
        &loaded.endpoints,
        &loaded.policy,
        &candidate_bytes,
        resume_proposal,
        deadline,
        per_request_cap,
        &mut reservation,
    )
    .map_err(failure)?;

    // `submit_candidate` itself already fails closed with
    // `NoCommittedOutcome` rather than ever returning `Ok` with an
    // unconfirmed submission, so `committed_outcome` here is always the
    // unsigned replica acknowledgement bound to the certified prefix -- a raw
    // peer HTTP 200 across the three rounds is never reported as success by
    // itself. This CLI layer still independently re-verifies the binding
    // rather than trusting the SDK result blindly.
    if submission.committed_outcome.request_id != candidate.request_id {
        return Err(invalid(
            "returned committed outcome request id does not match the submitted candidate",
        ));
    }
    println!(
        "rounds={} committed_acknowledged=true block_height={} manifest={out_prefix}.manifest results={out_prefix}.results",
        submission.rounds.len(),
        submission.committed_outcome.block_height
    );
    Ok(())
}

fn run_network_replay<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let parsed = parse_flags(args, &network_flag_specs(&["--manifest", "--out"]))?;
    let manifest_bytes = read_bounded(parsed.require("--manifest")?, MAX_MANIFEST_BYTES)?;
    let manifest_text =
        std::str::from_utf8(&manifest_bytes).map_err(|_| invalid("--manifest must be UTF-8"))?;
    if manifest_text.lines().count() > MAX_REPLAY_ROUNDS {
        return Err(invalid(format!(
            "--manifest declares more than the maximum accepted {MAX_REPLAY_ROUNDS} rounds"
        )));
    }
    let mut rounds: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut total_bytes: usize = 0;
    for line in manifest_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 2 {
            return Err(invalid("--manifest line must name exactly two files"));
        }
        for field in &fields {
            if field.chars().any(|character| character.is_control())
                || !Path::new(field).is_absolute()
            {
                return Err(invalid(
                    "--manifest path must be a canonical absolute path with no control characters",
                ));
            }
        }
        let proposal_bytes = read_bounded(fields[0], MAX_ORDERED_PROPOSAL_BYTES)?;
        let certificate_bytes = read_bounded(fields[1], MAX_ORDERED_CERTIFICATE_BYTES)?;
        total_bytes = total_bytes
            .checked_add(proposal_bytes.len())
            .and_then(|value| value.checked_add(certificate_bytes.len()))
            .filter(|value| *value <= MAX_REPLAY_BYTES)
            .ok_or_else(|| invalid("declared prefix aggregate byte bound"))?;
        rounds.push((proposal_bytes, certificate_bytes));
    }

    let loaded = load_policy_and_endpoints(&parsed)?;

    // Reserve the results file before the first mutating (`observe`/
    // `certificate`) POST, exactly like `network-submit`.
    let out_prefix = parsed.require("--out")?;
    reject_ambiguous_out_prefix("--out", out_prefix)?;
    let results_reserved = reserve_artifacts(
        &[(
            &format!("{out_prefix}.results"),
            "ordered-economics-results",
        )],
        &[],
    )?;
    let results = results_reserved
        .into_iter()
        .next()
        .ok_or_else(|| invalid("missing reserved results handle"))?;
    reject_ambiguous_resolved_path(results.path())?;
    let mut sink = ReplayResultsSink {
        results,
        results_text: String::new(),
    };

    let (deadline, per_request_cap) = parse_budget(&parsed)?;
    // Each per-peer result is synced via `sink` before the next POST/round,
    // so an already-acknowledged or already-rejected prefix step survives
    // on disk even if a later round then makes this call return `Err`.
    let outputs = replay_declared_prefix_with_sink(
        &loaded.endpoints,
        &loaded.policy,
        &rounds,
        deadline,
        per_request_cap,
        &mut sink,
    )
    .map_err(failure)?;
    println!(
        "replayed_rounds={} outputs={} results={out_prefix}.results",
        rounds.len(),
        outputs.len()
    );
    Ok(())
}

fn candidate_wrap_flag_specs() -> Vec<crate::args::FlagSpec> {
    vec![
        scalar("--intent"),
        scalar("--kind"),
        scalar("--request-id"),
        scalar("--created-checkpoint"),
        scalar("--expected-chain-id"),
        scalar("--expected-protocol-version"),
        scalar("--expected-epoch"),
        scalar("--ordered-genesis-manifest"),
        scalar("--ordered-expected-genesis-digest"),
        scalar("--domain"),
        scalar("--out"),
    ]
}

/// Wraps an already-signed existing canonical intent into an exact
/// `OrderedCandidate`, after validating the caller's declared context
/// against the local genesis pin. Never signs, never guesses `--kind`,
/// `--request-id`, or `--created-checkpoint` -- every field is either an
/// explicit flag or copied verbatim from `--intent`'s own bytes. This is a
/// pure, read-only, offline construction step: it performs no network I/O
/// and never mutates any durable/fenced state.
fn run_candidate_wrap<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let parsed = parse_flags(args, &candidate_wrap_flag_specs())?;
    let intent_bytes = read_bounded(parsed.require("--intent")?, MAX_ORDERED_CANDIDATE_BYTES)?;
    let kind = parsed.require("--kind")?;
    let ordered_kind = match kind {
        "fee-claim" => sunrise_edge_client::ordered_economics_core::OrderedOperationKind::FeeClaim,
        "bond-lifecycle" => {
            sunrise_edge_client::ordered_economics_core::OrderedOperationKind::BondLifecycle
        }
        "bond-slash" => {
            sunrise_edge_client::ordered_economics_core::OrderedOperationKind::BondSlash
        }
        "evidence" => sunrise_edge_client::ordered_economics_core::OrderedOperationKind::Evidence,
        other => return Err(invalid(format!("unknown --kind: {other}"))),
    };
    let request_id = decode_hex_32("--request-id", parsed.require("--request-id")?)?;
    let created_checkpoint = parse_u64(
        "--created-checkpoint",
        parsed.require("--created-checkpoint")?,
    )?;

    let chain_id =
        ChainId::new(parsed.require("--expected-chain-id")?.to_string()).map_err(failure)?;
    let protocol_version = parse_protocol(parsed.require("--expected-protocol-version")?)?;
    let epoch = Epoch::new(parse_u64(
        "--expected-epoch",
        parsed.require("--expected-epoch")?,
    )?);
    let context =
        sunrise_edge_client::PublicationContext::new(chain_id.clone(), protocol_version, epoch)
            .map_err(failure)?;
    let domain = AtomicityDomainId::new(decode_hex_32("--domain", parsed.require("--domain")?)?)
        .map_err(failure)?;
    let expected_digest = decode_hex_32(
        "--ordered-expected-genesis-digest",
        parsed.require("--ordered-expected-genesis-digest")?,
    )?;
    let resolver = genesis_hash_suite_resolver(chain_id, protocol_version)?;
    // Local genesis validation only -- confirms the declared context is the
    // one this operator actually trusts before any candidate bytes are
    // produced; never contacts a network endpoint.
    let policy = load_trusted_ordered_policy(
        Path::new(parsed.require("--ordered-genesis-manifest")?),
        &resolver,
        expected_digest,
        &context,
        domain,
    )
    .map_err(failure)?;

    let candidate = sunrise_edge_client::ordered_economics_core::OrderedCandidate {
        context,
        request_id,
        kind: ordered_kind,
        intent: intent_bytes,
        created_checkpoint,
    };
    authenticate_ordered_candidate(&policy, &candidate).map_err(failure)?;
    let encoded = sunrise_edge_client::ordered_economics_core::encode_ordered_candidate(&candidate)
        .map_err(failure)?;

    let out_path = parsed.require("--out")?;
    let mut reserved = reserve_artifacts(&[(out_path, "ordered-economics-candidate")], &[])?;
    let mut reserved = reserved.pop().expect("candidate artifact reserved");
    reserved.persist(&encoded).map_err(failure)?;
    println!("candidate_bytes={} out={out_path}", encoded.len());
    Ok(())
}

/// Builds only an advisory Freeze body. The actual consensus height and
/// committed bond/key/power eligibility remain authoritative host checks.
fn run_freeze_build<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let specs: Vec<crate::args::FlagSpec> = network_flag_specs(&[
        "--request-id",
        "--created-checkpoint",
        "--advisory-next-set",
        "--out",
    ]);
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let inputs: LoadedPolicyInputs = load_policy_and_endpoints(&parsed)?;
    if inputs.policy.minimum_freeze_block_height() == 0 {
        return Err(invalid(
            "ordered Freeze requires a locally pinned signed-v3 genesis",
        ));
    }
    let request_id: [u8; 32] = decode_hex_32("--request-id", parsed.require("--request-id")?)?;
    let created_checkpoint: u64 = parse_u64(
        "--created-checkpoint",
        parsed.require("--created-checkpoint")?,
    )?;
    let advisory_path: &str = parsed.require("--advisory-next-set")?;
    let advisory_bytes: Vec<u8> = read_bounded(advisory_path, MAX_ORDERED_CANDIDATE_BYTES)?;
    let advisory = sunrise_edge_client::decode_fastpath_validator_set_record(&advisory_bytes)
        .map_err(failure)?;
    let intent = sunrise_edge_client::ordered_economics_core::FreezeIntent {
        context: inputs.policy.context().clone(),
        request_id,
        advisory_next_set: advisory,
    };
    let candidate = sunrise_edge_client::ordered_economics_core::OrderedCandidate {
        context: inputs.policy.context().clone(),
        request_id,
        kind: sunrise_edge_client::ordered_economics_core::OrderedOperationKind::Freeze,
        intent: sunrise_edge_client::ordered_economics_core::encode_freeze_intent(&intent)
            .map_err(failure)?,
        created_checkpoint,
    };
    authenticate_ordered_candidate(&inputs.policy, &candidate).map_err(failure)?;
    let encoded: Vec<u8> =
        sunrise_edge_client::ordered_economics_core::encode_ordered_candidate(&candidate)
            .map_err(failure)?;
    let out: &str = parsed.require("--out")?;
    let mut reserved: Vec<ReservedArtifact> = reserve_artifacts(
        &[(out, "ordered-freeze-candidate")],
        &[advisory_path, parsed.require("--ordered-genesis-manifest")?],
    )?;
    let mut artifact: ReservedArtifact = reserved
        .pop()
        .ok_or_else(|| invalid("missing Freeze output reservation"))?;
    artifact.persist(&encoded)?;
    println!(
        "candidate_bytes={} out={out} minimum_freeze_block_height={}",
        encoded.len(),
        inputs.policy.minimum_freeze_block_height()
    );
    Ok(())
}

/// Dispatches `economics <subcommand>`.
pub(crate) fn run<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut iterator = args.into_iter();
    let subcommand = iterator
        .next()
        .ok_or_else(|| invalid("economics requires a subcommand"))?
        .to_str()
        .ok_or_else(|| invalid("non-UTF-8 subcommand"))?
        .to_string();
    match subcommand.as_str() {
        "network-submit" => run_network_submit(iterator),
        "network-replay" => run_network_replay(iterator),
        "candidate-wrap" => run_candidate_wrap(iterator),
        "ordered-freeze-build" => run_freeze_build(iterator),
        other => Err(invalid(format!("unknown economics subcommand: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn unknown_subcommand_is_rejected() {
        let error = run(vec![OsString::from("bogus")]);
        assert!(error.is_err());
    }

    #[test]
    fn network_submit_requires_a_candidate_flag() {
        let error = run_network_submit(Vec::<OsString>::new());
        assert!(error.is_err());
    }

    #[test]
    fn network_replay_requires_a_manifest_flag() {
        let error = run_network_replay(Vec::<OsString>::new());
        assert!(error.is_err());
    }

    #[test]
    fn candidate_wrap_requires_an_intent_flag() {
        let error = run_candidate_wrap(Vec::<OsString>::new());
        assert!(error.is_err());
    }

    #[test]
    fn oversized_protocol_never_truncates_into_a_valid_pin() {
        assert_eq!(parse_protocol("3").unwrap(), ProtocolVersion::new(3));
        assert!(parse_protocol("4294967299").is_err());
    }

    #[test]
    fn output_path_delimiters_fail_before_network_or_reservation() {
        for prefix in ["", "with space", "with\ttab", "with\nnewline", "with\0nul"] {
            assert!(reject_ambiguous_out_prefix("--out", prefix).is_err());
        }
        assert!(reject_ambiguous_out_prefix("--out", "valid-prefix").is_ok());
    }

    fn unique_test_directory(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ordered-cli-artifact-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn persisted_manifest_appends_each_certified_pair_only_once() {
        let directory = unique_test_directory("basic");
        fs::create_dir(&directory).unwrap();
        let prefix: String = directory.join("out").to_str().unwrap().to_owned();
        let mut sink: CliArtifactSink = reserve_submission_artifacts(&prefix).unwrap();
        for round in 0..2 {
            sink.persist(&format!("round-{round}.proposal"), &[1])
                .unwrap();
            sink.persist(&format!("round-{round}.certificate"), &[2])
                .unwrap();
            sink.record_certified_round(round).unwrap();
            assert_eq!(
                fs::read_to_string(format!("{prefix}.manifest"))
                    .unwrap()
                    .lines()
                    .count(),
                round + 1
            );
        }
        assert!(
            reserve_submission_artifacts(&prefix).is_err(),
            "no output overwrite on retry"
        );
        drop(sink);
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn manifest_records_canonical_absolute_paths_regardless_of_the_out_prefix_own_form() {
        // Proves recovery from a different current directory: the manifest
        // line stored here does not depend on the process current directory
        // at read time, only at write time -- `record_certified_round` reads
        // each already-reserved handle own canonicalized path, never
        // re-derives one from a caller-relative prefix string.
        let directory = unique_test_directory("absolute");
        fs::create_dir(&directory).unwrap();
        let expected_round0_proposal = fs::canonicalize(&directory)
            .unwrap()
            .join("out.round-0.proposal");
        let prefix: String = directory.join("out").to_str().unwrap().to_owned();
        let mut sink: CliArtifactSink = reserve_submission_artifacts(&prefix).unwrap();
        sink.persist("round-0.proposal", &[1]).unwrap();
        sink.persist("round-0.certificate", &[2]).unwrap();
        sink.record_certified_round(0).unwrap();
        let manifest = fs::read_to_string(format!("{prefix}.manifest")).unwrap();
        let first_field = manifest.split_whitespace().next().unwrap();
        assert!(Path::new(first_field).is_absolute());
        assert_eq!(Path::new(first_field), expected_round0_proposal.as_path());
        drop(sink);
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_whitespace_parent_directory_is_rejected_before_the_first_mutating_post() {
        let directory = unique_test_directory("with space in it");
        fs::create_dir(&directory).unwrap();
        let prefix: String = directory.join("out").to_str().unwrap().to_owned();
        // The raw `--out` prefix check runs on the caller-supplied prefix
        // string, not the resolved path, so a whitespace parent directory
        // is only caught by the resolved-path preflight check
        // `reserve_submission_artifacts` itself performs, immediately after
        // reservation and before any network call -- this proves that
        // check runs before even one artifact can be persisted.
        assert!(reserve_submission_artifacts(&prefix).is_err());
        fs::remove_dir_all(&directory).unwrap();
    }
}
