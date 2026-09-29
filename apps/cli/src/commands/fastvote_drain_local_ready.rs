//! `contract fastvote-drain-local-ready`: a bounded operator command that
//! resumes one target validator's *local* post-Freeze drain readiness (see
//! [`sunrise_edge_client::drive_drain_to_local_ready`], DR-0157/DR-0158).
//!
//! This command never forms an ordered DrainSet vote, never establishes a
//! signed/portable cut, and never activates the next epoch: its only
//! possible successful outcome is the target's own selection-scoped local
//! readiness, exactly as the underlying driver documents. An `Incomplete`
//! outcome is expected and safe to retry unchanged; it is reported as a
//! non-zero exit so operator tooling notices a rerun is needed, but it is
//! not a corruption or protocol violation.
//!
//! Trust boundaries mirror [`super::network_flag_specs`]'s FastVote commands:
//! * `--expected-*` plus `--fastvote-genesis-manifest`/
//!   `--fastvote-expected-genesis-digest` are the locally trusted
//!   protocol/genesis pin, loaded and cross-checked by
//!   [`load_endpoints_and_certifier`] before anything else.
//! * `--fastvote-network` supplies each configured peer's own independent
//!   TLS identity (or loopback plaintext); this command declares no global
//!   `--tls-server-name`/`--tls-ca-cert-der-file` flags at all, so TLS
//!   endpoint identity can never be confused with the separate protocol
//!   pin above.
//! * `--target-validator` selects the driven target from that same
//!   validated endpoint set, by validator id, never by an untrusted
//!   response. The target may be outside the selected signer quorum.
//! * `--drain-selection-manifest` is a bounded, locally supplied list of
//!   exact canonical-encoded, already-signed [`consensus::FrozenFrontierVote`]
//!   files -- this command never signs, mints, or otherwise produces a vote
//!   itself. Every vote is independently verified (including against
//!   `--drain-freeze-request-id`/`--drain-freeze-height`) before any
//!   mutation, by [`sunrise_edge_client::drive_drain_to_local_ready`]
//!   itself.
use super::*;
use crate::parse::{parse_u16, parse_u32};
use consensus::{FrozenFrontierVote, decode_frozen_frontier_vote};

/// Matches [`MAX_FASTVOTE_NETWORK_ENDPOINTS`]: a selection can never
/// legitimately name more signers than one configured cohort.
const MAX_DRAIN_SELECTION_ENTRIES: usize = MAX_FASTVOTE_NETWORK_ENDPOINTS;
const MAX_DRAIN_SELECTION_MANIFEST_BYTES: usize = 64 * 1024;
/// Mirrors `node_wire::MAX_FRONTIER_VOTE_BYTES` without adding that crate to
/// the CLI's dependencies; this bounds the read before decoding.
const MAX_DRAIN_SELECTION_VOTE_FILE_BYTES: usize = 8 * 1024;

const HELP: &str = "contract fastvote-drain-local-ready
  --target-validator VALIDATOR_ID_HEX
  --fastvote-network CONFIG --fastvote-genesis-manifest FILE
  --fastvote-expected-genesis-digest DIGEST_HEX
  --expected-chain-id CHAIN --expected-protocol-version VERSION --expected-epoch EPOCH
  --expected-hash-suite-id SUITE --expected-domain DOMAIN_HEX
  --drain-selection-manifest FILE
  --drain-freeze-request-id REQUEST_ID_HEX --drain-freeze-height HEIGHT
  --drain-page-limit LIMIT --drain-max-mutation-attempts ATTEMPTS
  [--fastvote-deadline-seconds SECONDS] [--fastvote-per-request-cap-seconds SECONDS]
Resumes only the target validator's own local post-Freeze drain readiness (DR-0157/DR-0158).
This never forms an ordered DrainSet vote, never establishes a signed/portable cut, and never
activates the next epoch. --target-validator selects the driven target from the same validated
--fastvote-network cohort used for every configured peer's own independent TLS identity; that
TLS check is always separate from the locally trusted --expected-*/--fastvote-genesis-manifest
protocol pin. --drain-selection-manifest: UTF-8, one file path per line, each file the exact
canonical bytes of one already-signed outgoing-committee FrozenFrontierVote selection member;
blank lines and full-line # comments are ignored; relative paths resolve against the manifest's
own canonical parent directory; whitespace in paths is unsupported. This command never signs or
mints a vote itself. On completion, exactly one of drain_local_ready=true (locally ready; no
finality claim) or drain_local_ready=false/drain_incomplete=true (safe to rerun unchanged, exit
non-zero) is printed; durable signer/union progress may already have advanced either way.";

pub(in crate::commands) fn run<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let args: Vec<OsString> = args.into_iter().collect();
    if args.as_slice() == [OsString::from("--help")] {
        println!("{HELP}");
        return Ok(());
    }
    let specs: Vec<crate::args::FlagSpec> = [
        "--target-validator",
        "--fastvote-network",
        "--fastvote-genesis-manifest",
        "--fastvote-expected-genesis-digest",
        "--fastvote-deadline-seconds",
        "--fastvote-per-request-cap-seconds",
        "--expected-chain-id",
        "--expected-protocol-version",
        "--expected-epoch",
        "--expected-hash-suite-id",
        "--expected-domain",
        "--drain-selection-manifest",
        "--drain-freeze-request-id",
        "--drain-freeze-height",
        "--drain-page-limit",
        "--drain-max-mutation-attempts",
    ]
    .into_iter()
    .map(scalar)
    .collect();
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    // One deadline covers manifest/genesis loading through the final mutation.
    let budget: OperationBudget = parse_deadline(&parsed)?;
    // Every cheap, purely local flag (no file I/O) decodes first and fails
    // closed before any genesis/network config file is ever opened.
    let target_validator: ValidatorId = ValidatorId::new(decode_hex_32(
        "--target-validator",
        parsed.require("--target-validator")?,
    )?);
    let closure_request_id: [u8; 32] = decode_hex_32(
        "--drain-freeze-request-id",
        parsed.require("--drain-freeze-request-id")?,
    )?;
    let closure_height: u64 = parse_u64(
        "--drain-freeze-height",
        parsed.require("--drain-freeze-height")?,
    )?;
    let bounds = sunrise_edge_client::DrainDriveBounds {
        overall_deadline: budget.deadline,
        per_request_cap: budget.per_request_cap,
        page_limit: parse_u16("--drain-page-limit", parsed.require("--drain-page-limit")?)?,
        max_mutation_attempts: parse_u32(
            "--drain-max-mutation-attempts",
            parsed.require("--drain-max-mutation-attempts")?,
        )?,
    };
    let expected: sunrise_edge_client::ExpectedProtocolContext =
        crate::commands::standard_asset::parse_expected_context(&parsed)?;
    let resolver: sunrise_edge_client::HashSuiteResolver = local_publication_resolver(&expected)?;
    let context: sunrise_edge_client::PublicationContext =
        sunrise_edge_client::PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .map_err(failure)?;
    let freeze = sunrise_edge_client::fastvote_drain_client::ExpectedDrainFreeze {
        domain: expected.domain(),
        closure_request_id,
        closure_height,
    };
    let (endpoints, certifier): (Vec<FastVoteEndpoint<CliTransport>>, FastPathCertifier) =
        load_endpoints_and_certifier(&parsed, &resolver, &context)?;
    let target: &Client<CliTransport> = selected_target_client(&endpoints, target_validator)?;
    let selected_votes: Vec<FrozenFrontierVote> =
        load_drain_selection(parsed.require("--drain-selection-manifest")?)?;
    let sources: Vec<FastVoteEndpoint<CliTransport>> =
        selected_source_endpoints(&endpoints, &selected_votes)?;
    execute(
        target,
        &sources,
        &selected_votes,
        &certifier,
        &resolver,
        freeze,
        bounds,
    )
}

/// The driven target need not be a selected frontier signer. Copy only the
/// selected signers' already-validated transports, in vote order, while the
/// target remains independently pinned by the full network configuration.
fn selected_source_endpoints<T: Transport + Clone>(
    endpoints: &[FastVoteEndpoint<T>],
    selected_votes: &[FrozenFrontierVote],
) -> Result<Vec<FastVoteEndpoint<T>>, CliError> {
    let mut sources: Vec<FastVoteEndpoint<T>> = Vec::with_capacity(selected_votes.len());
    for vote in selected_votes {
        let endpoint: &FastVoteEndpoint<T> = endpoints
            .iter()
            .find(|endpoint| endpoint.validator_id == vote.validator)
            .ok_or_else(|| invalid("selected drain signer is absent from --fastvote-network"))?;
        sources.push(FastVoteEndpoint {
            validator_id: endpoint.validator_id,
            endpoint_label: endpoint.endpoint_label.clone(),
            client: Client::new(endpoint.client.transport().clone()),
        });
    }
    Ok(sources)
}

/// The core, argv-independent orchestration: drives the target to local
/// readiness (or a bounded incomplete step count) and reports the outcome.
/// Split out from [`run`] so tests can supply fake transports directly,
/// exactly as the sibling FastVote commands' own inner functions do.
fn execute<T: Transport>(
    target: &Client<T>,
    sources: &[FastVoteEndpoint<T>],
    selected_votes: &[FrozenFrontierVote],
    certifier: &FastPathCertifier,
    resolver: &sunrise_edge_client::HashSuiteResolver,
    freeze: sunrise_edge_client::fastvote_drain_client::ExpectedDrainFreeze,
    bounds: sunrise_edge_client::DrainDriveBounds,
) -> Result<(), CliError> {
    // No rotation history: this bounded command only replays the currently
    // active hash suite, matching the other FastVote CLI commands' default.
    let outcome = sunrise_edge_client::drive_drain_to_local_ready(
        target,
        sources,
        selected_votes,
        certifier,
        resolver,
        &[],
        freeze,
        bounds,
    )
    .map_err(failure)?;
    match outcome {
        sunrise_edge_client::DrainDriveOutcome::LocallyReady {
            identity,
            mutation_attempts,
        } => {
            println!("drain_local_ready=true");
            println!("drain_scope=local_readiness_only");
            println!("drain_ordered_drainset=not_established");
            println!("drain_activation=not_authorized");
            println!("mutation_attempts={mutation_attempts}");
            println!("chain_id={}", identity.chain_id);
            println!("protocol_version={}", identity.protocol_version.get());
            println!("epoch={}", identity.epoch.get());
            println!("domain={}", identity.domain);
            println!(
                "closure_request_id={}",
                encode_hex(&identity.closure_request_id)
            );
            println!("closure_height={}", identity.closure_height);
            println!("signer_count={}", identity.signer_count);
            println!("member_count={}", identity.member_count);
            println!("entries_digest={}", identity.entries_digest);
            Ok(())
        }
        sunrise_edge_client::DrainDriveOutcome::Incomplete { mutation_attempts } => {
            println!("drain_local_ready=false");
            println!("drain_incomplete=true");
            println!("mutation_attempts={mutation_attempts}");
            Err(invalid(format!(
                "drain-local-ready incomplete after {mutation_attempts} mutation attempts; this is not a finality claim and not a corruption; durable signer/union progress may already have advanced; rerun with the exact same locally pinned selection and source mapping"
            )))
        }
    }
}

/// Selects the driven target's [`Client`] by validator id from the same
/// TLS-validated `--fastvote-network` cohort every selected source vote is
/// checked against -- never a separately supplied, unvalidated endpoint.
fn selected_target_client<T: Transport>(
    endpoints: &[FastVoteEndpoint<T>],
    target: ValidatorId,
) -> Result<&Client<T>, CliError> {
    endpoints
        .iter()
        .find(|peer| peer.validator_id == target)
        .map(|peer| &peer.client)
        .ok_or_else(|| {
            invalid("--target-validator must select a validator configured in --fastvote-network")
        })
}

/// Loads and decodes the bounded, locally supplied frontier-vote selection.
/// Every file's exact canonical bytes must decode to a well-formed
/// [`FrozenFrontierVote`] (signature and quorum/Freeze-identity checks
/// happen only later, inside [`sunrise_edge_client::drive_drain_to_local_ready`],
/// against the caller's own pinned outgoing set); this function performs no
/// cryptographic verification of its own and mints nothing.
fn load_drain_selection(path: &str) -> Result<Vec<FrozenFrontierVote>, CliError> {
    let bytes: Vec<u8> = read_bounded(path, MAX_DRAIN_SELECTION_MANIFEST_BYTES)?;
    let text: &str = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("--drain-selection-manifest must be UTF-8"))?;
    let parent: PathBuf = Path::new(path)
        .canonicalize()
        .map_err(failure)?
        .parent()
        .ok_or_else(|| invalid("--drain-selection-manifest parent missing"))?
        .to_owned();
    let mut votes: Vec<FrozenFrontierVote> = Vec::new();
    for raw_line in text.lines() {
        let line: &str = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.split_whitespace().count() != 1 {
            return Err(invalid(
                "--drain-selection-manifest line must be a single path; whitespace in paths is unsupported",
            ));
        }
        if votes.len() >= MAX_DRAIN_SELECTION_ENTRIES {
            return Err(invalid(format!(
                "--drain-selection-manifest exceeds the maximum accepted {MAX_DRAIN_SELECTION_ENTRIES} entries"
            )));
        }
        let vote_path: PathBuf = parent.join(line);
        let vote_bytes: Vec<u8> = read_bounded(
            vote_path
                .to_str()
                .ok_or_else(|| invalid("--drain-selection-manifest vote path must be UTF-8"))?,
            MAX_DRAIN_SELECTION_VOTE_FILE_BYTES,
        )?;
        let vote: FrozenFrontierVote = decode_frozen_frontier_vote(&vote_bytes).map_err(failure)?;
        votes.push(vote);
    }
    if votes.is_empty() {
        return Err(invalid(
            "--drain-selection-manifest needs at least one selected signer",
        ));
    }
    Ok(votes)
}

#[cfg(test)]
mod tests {
    use super::super::boundary_tests::Fixture;
    use super::*;
    use crate::test_support::FakeTransport;
    use consensus::{
        ConsensusSigner, FrozenFrontierAccumulator, FrozenFrontierCertifier,
        encode_frozen_frontier_vote,
    };
    use crypto::SignatureSigner;
    use sunrise_edge_client::*;

    #[derive(Clone)]
    struct NoopTransport;

    impl Transport for NoopTransport {
        fn send(&self, _: &WireRequest) -> Result<WireResponse, TransportError> {
            unreachable!("source selection must not dispatch a request")
        }
    }

    struct VoteSigner(LocalSigner);
    impl ConsensusSigner for VoteSigner {
        fn validator_id(&self) -> ValidatorId {
            ValidatorId::new(*self.0.address().as_bytes())
        }
        fn signature_scheme(&self) -> SignatureSchemeId {
            SignatureSchemeId::Ed25519
        }
        fn sign_framed(&self, framed: &[u8]) -> Result<Vec<u8>, String> {
            self.0
                .sign_framed(framed)
                .map_err(|error| error.to_string())
        }
    }

    fn budget() -> OperationBudget {
        OperationBudget {
            deadline: Instant::now().checked_add(Duration::from_secs(2)).unwrap(),
            per_request_cap: Duration::from_secs(1),
        }
    }

    #[test]
    fn help_flag_prints_without_any_other_flags() {
        run([OsString::from("--help")]).unwrap();
    }

    #[test]
    fn unknown_missing_and_duplicate_flags_reject_before_any_file_read() {
        assert!(run(Vec::<OsString>::new()).is_err());
        assert!(run(["--bogus", "x"].into_iter().map(OsString::from)).is_err());
        assert!(
            run([
                "--target-validator",
                &"11".repeat(32),
                "--target-validator",
                &"11".repeat(32),
            ]
            .into_iter()
            .map(OsString::from))
            .is_err()
        );
    }

    #[test]
    fn invalid_deadlines_reject_before_any_network_config_load() {
        for (flag, value) in [
            ("--fastvote-deadline-seconds", "0"),
            ("--fastvote-per-request-cap-seconds", "0"),
        ] {
            let error = run([
                "--target-validator",
                &"11".repeat(32),
                "--fastvote-network",
                "/missing-config",
                flag,
                value,
            ]
            .into_iter()
            .map(OsString::from))
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("positive") || error.contains("at most"),
                "{error}"
            );
        }
    }

    #[test]
    fn malformed_target_validator_hex_rejects_before_any_other_required_flag() {
        // `--target-validator` decodes first, before genesis/network/context
        // flags are ever required, so no other flag needs to be supplied.
        let error = run(["--target-validator", "not-hex"]
            .into_iter()
            .map(OsString::from))
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("--target-validator") || error.contains("hexadecimal"),
            "{error}"
        );
    }

    #[test]
    fn missing_network_config_or_genesis_manifest_fails_closed() {
        let error = run([
            "--target-validator",
            &"11".repeat(32),
            "--fastvote-network",
            "/definitely-missing-network-config",
            "--fastvote-genesis-manifest",
            "/definitely-missing-genesis-manifest",
            "--fastvote-expected-genesis-digest",
            &"22".repeat(32),
            "--expected-chain-id",
            "x",
            "--expected-protocol-version",
            "1",
            "--expected-epoch",
            "0",
            "--expected-hash-suite-id",
            "1",
            "--expected-domain",
            &"33".repeat(32),
            "--drain-selection-manifest",
            "/definitely-missing-selection-manifest",
            "--drain-freeze-request-id",
            &"44".repeat(32),
            "--drain-freeze-height",
            "1",
            "--drain-page-limit",
            "16",
            "--drain-max-mutation-attempts",
            "8",
        ]
        .into_iter()
        .map(OsString::from))
        .unwrap_err();
        assert!(!matches!(error, CliError::MissingCommand));
    }

    #[test]
    fn selected_target_client_rejects_a_validator_absent_from_the_cohort() {
        let endpoints: Vec<FastVoteEndpoint<FakeTransport>> = vec![FastVoteEndpoint {
            validator_id: ValidatorId::new([0xAA; 32]),
            endpoint_label: "peer".to_owned(),
            client: Client::new(FakeTransport::new(Vec::new())),
        }];
        assert!(selected_target_client(&endpoints, ValidatorId::new([0xBB; 32])).is_err());
        assert!(selected_target_client(&endpoints, ValidatorId::new([0xAA; 32])).is_ok());
    }

    #[test]
    fn selected_sources_exclude_an_unselected_target_validator() {
        let fixture: Fixture = Fixture::new();
        let signer: VoteSigner = VoteSigner(LocalSigner::from_seed(
            sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED,
        ));
        let frontier_certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
            fixture.certifier.chain_id().clone(),
            fixture.certifier.protocol_version(),
            fixture.certifier.epoch(),
            fixture.certifier.validator_set().clone(),
        )
        .unwrap();
        let identity = FrozenFrontierAccumulator::new(
            &fixture.resolver,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
            fixture.expected.epoch(),
            fixture.expected.domain(),
            [0xCC; 32],
            9,
        )
        .unwrap()
        .into_identity();
        let vote: FrozenFrontierVote = frontier_certifier.cast_vote(identity, &signer).unwrap();
        let unselected_target: ValidatorId = ValidatorId::new([0xDD; 32]);
        let endpoints: Vec<FastVoteEndpoint<NoopTransport>> = vec![
            FastVoteEndpoint {
                validator_id: signer.validator_id(),
                endpoint_label: "source".to_owned(),
                client: Client::new(NoopTransport),
            },
            FastVoteEndpoint {
                validator_id: unselected_target,
                endpoint_label: "target".to_owned(),
                client: Client::new(NoopTransport),
            },
        ];
        assert!(selected_target_client(&endpoints, unselected_target).is_ok());
        let sources: Vec<FastVoteEndpoint<NoopTransport>> =
            selected_source_endpoints(&endpoints, &[vote]).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].validator_id, signer.validator_id());
        assert_eq!(sources[0].endpoint_label, "source");
    }

    #[test]
    fn drain_selection_manifest_bounds_grammar_and_decoding_fail_closed() {
        let fixture: Fixture = Fixture::new();
        let vote_path: String = fixture.path("vote.bin");
        std::fs::write(&vote_path, b"not a valid canonical frontier vote frame").unwrap();

        // Empty manifest.
        assert!(load_drain_selection(&fixture.path("missing-manifest")).is_err());
        let manifest: String = fixture.path("selection");
        std::fs::write(&manifest, "\n# comment\n").unwrap();
        assert!(
            load_drain_selection(&manifest)
                .unwrap_err()
                .to_string()
                .contains("at least one")
        );

        // Whitespace within a line is rejected.
        std::fs::write(&manifest, "two words\n").unwrap();
        assert!(
            load_drain_selection(&manifest)
                .unwrap_err()
                .to_string()
                .contains("whitespace")
        );

        // A listed file that does not decode as a canonical vote fails closed.
        std::fs::write(&manifest, "vote.bin\n").unwrap();
        assert!(load_drain_selection(&manifest).is_err());

        // More entries than the bounded maximum are rejected, even when
        // every individual file decodes as a well-formed vote (repeating the
        // same file is fine here: duplicate/quorum checks happen later,
        // inside the driver itself, not in this manifest loader).
        let validator: VoteSigner = VoteSigner(LocalSigner::from_seed(
            sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED,
        ));
        let frontier_certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
            fixture.certifier.chain_id().clone(),
            fixture.certifier.protocol_version(),
            fixture.certifier.epoch(),
            fixture.certifier.validator_set().clone(),
        )
        .unwrap();
        let identity = FrozenFrontierAccumulator::new(
            &fixture.resolver,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
            fixture.expected.epoch(),
            fixture.expected.domain(),
            [0xCC; 32],
            9,
        )
        .unwrap()
        .into_identity();
        let valid_vote = frontier_certifier.cast_vote(identity, &validator).unwrap();
        std::fs::write(
            &vote_path,
            encode_frozen_frontier_vote(&valid_vote).unwrap(),
        )
        .unwrap();
        let mut oversized: String = String::new();
        for _ in 0..=MAX_DRAIN_SELECTION_ENTRIES {
            oversized.push_str("vote.bin\n");
        }
        std::fs::write(&manifest, &oversized).unwrap();
        assert!(
            load_drain_selection(&manifest)
                .unwrap_err()
                .to_string()
                .contains("maximum accepted")
        );
    }

    /// A fully valid local setup (genesis pin, network config, target
    /// selection, and a correctly signed, quorum-sufficient frontier-vote
    /// selection matching the expected Freeze) must pass every local check
    /// -- signature, quorum, endpoint mapping, and genesis pin -- before the
    /// very first network call. With an empty [`FakeTransport`] response
    /// queue that first call fails as a transport error, which proves every
    /// local verification step already succeeded. A full wire-level
    /// LocallyReady walk additionally requires `node-wire`'s drain
    /// request/response envelope types, which are not re-exported by
    /// `sunrise-edge-client` and are intentionally not added as a new
    /// dependency here.
    #[test]
    fn valid_local_selection_and_pins_reach_the_network_boundary_before_any_mutation() {
        let fixture: Fixture = Fixture::new();
        let validator: VoteSigner = VoteSigner(LocalSigner::from_seed(
            sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED,
        ));
        let frontier_certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
            fixture.certifier.chain_id().clone(),
            fixture.certifier.protocol_version(),
            fixture.certifier.epoch(),
            fixture.certifier.validator_set().clone(),
        )
        .unwrap();
        let identity = FrozenFrontierAccumulator::new(
            &fixture.resolver,
            fixture.expected.chain_id().clone(),
            fixture.expected.protocol_version(),
            fixture.expected.epoch(),
            fixture.expected.domain(),
            [0xAA; 32],
            5,
        )
        .unwrap()
        .into_identity();
        let vote = frontier_certifier.cast_vote(identity, &validator).unwrap();

        let endpoint: FastVoteEndpoint<FakeTransport> = FastVoteEndpoint {
            validator_id: validator.validator_id(),
            endpoint_label: "peer".to_owned(),
            client: Client::new(FakeTransport::new(Vec::new())),
        };
        let endpoints: Vec<FastVoteEndpoint<FakeTransport>> = vec![endpoint];
        let freeze = fastvote_drain_client::ExpectedDrainFreeze {
            domain: fixture.expected.domain(),
            closure_request_id: [0xAA; 32],
            closure_height: 5,
        };
        let bounds = DrainDriveBounds {
            overall_deadline: budget().deadline,
            per_request_cap: budget().per_request_cap,
            page_limit: 16,
            max_mutation_attempts: 8,
        };
        let error: String = execute(
            &endpoints[0].client,
            &endpoints,
            std::slice::from_ref(&vote),
            &fixture.certifier,
            &fixture.resolver,
            freeze,
            bounds,
        )
        .unwrap_err()
        .to_string();
        // Reaching `DrainDriveError::Client` (not `InvalidConfig`/`Mismatch`/
        // `Frontier`) proves quorum/signature/endpoint/genesis verification
        // already passed before the first (and only) network call.
        assert!(error.contains("drain transport"), "{error}");
        assert_eq!(endpoints[0].client.transport().requests().len(), 1);

        // Round-trip through the exact manifest file format this command
        // reads, to also cover `load_drain_selection`'s happy path.
        let manifest_dir: String = fixture.path("selection-dir");
        std::fs::create_dir(&manifest_dir).unwrap();
        let vote_path: PathBuf = Path::new(&manifest_dir).join("vote-0.bin");
        std::fs::write(&vote_path, encode_frozen_frontier_vote(&vote).unwrap()).unwrap();
        let manifest_path: PathBuf = Path::new(&manifest_dir).join("manifest");
        std::fs::write(&manifest_path, "vote-0.bin\n").unwrap();
        let loaded: Vec<FrozenFrontierVote> =
            load_drain_selection(manifest_path.to_str().unwrap()).unwrap();
        assert_eq!(loaded, vec![vote]);
    }
}
