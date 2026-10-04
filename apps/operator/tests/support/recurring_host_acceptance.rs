//! Actual repeated compiled-process handoffs, starting from the independently
//! staged changed committee. Each step exports its own current history/cut,
//! obtains genuine successor readiness, commits its own Seal, then activates
//! from the entire ordered chain rooted in the original signed genesis.

use super::*;
use consensus::readiness::ReadinessCertificate;
use node_core::fast_path::records::{FastPathValidatorEntry, FastPathValidatorSetRecord};
use node_core::ordered_economics::{OrderedOutcome, decode_ordered_outcome};
use node_core::serving_authority::{
    LiveAuthority, SuccessorChainBudget, resolve_live_authority_chain,
};
use protocol_types::Epoch;
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
    success(command.output().unwrap())
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
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_successor_host"));
    command
        .arg(if historical { "serve-history" } else { "serve" })
        .args(flags)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child: Child = command.spawn().unwrap();
    let mut line: String = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    if line.is_empty() {
        panic!("recurring host failed: {:?}", child.wait());
    }
    let mode: &str = if historical {
        "mode=successor-history-material-only"
    } else {
        "mode=successor-serving"
    };
    assert!(line.contains(mode), "{line}");
    assert_eq!(field(&line, "epoch="), epoch.to_string());
    HostProcess {
        child,
        address: field(&line, "listen=").parse().unwrap(),
        generation: field(&line, "writer_generation=").parse().unwrap(),
        validator: targets.members[index].validator_id,
    }
}

fn committed_outcome(hosts: &[HostProcess], request: [u8; 32]) -> OrderedOutcome {
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
                .all(|response: &node_core::NodeResponse| response.status()
                    == node_core::NodeResponseStatus::Accepted)
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
) {
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
    submit(
        fixture,
        links,
        current,
        network,
        &freeze_path,
        &directory.join("freeze-submission"),
    );
    let freeze: OrderedOutcome = committed_outcome(hosts, freeze_request);
    let mut votes: Vec<PathBuf> = Vec::new();
    let selected_ids: Vec<ValidatorId> =
        current_quorum_ids(current.fastvote_certifier().validator_set());
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
    for _ in 0..2 {
        round(&endpoints, current, None);
    }
}

fn install_next(
    fixture: &Fixture,
    links: &[Link],
    current: &SuccessorWorkflowAuthority,
    targets: &CurrentTargets,
    history: &Path,
    directory: &Path,
    next_members: &[SuccessorProcessMember],
) -> (CurrentTargets, PathBuf, PathBuf) {
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
        operator(env!("CARGO_BIN_EXE_business_cut"), "export-sqlite", flags)
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
                env!("CARGO_BIN_EXE_business_import"),
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
            env!("CARGO_BIN_EXE_conditional_readiness"),
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
        env!("CARGO_BIN_EXE_conditional_readiness"),
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
) {
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
}

pub(super) fn run(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    initial_history: &Path,
    original_seal_request: [u8; 32],
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
    if original_ids == current_ids {
        return;
    }
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
        let network: PathBuf = network_file(&directory, &hosts);
        verify_receipts(&receipt_history, &hosts);
        lifecycle::withdrawals(
            fixture, &links, &current, &targets, &hosts, &network, &directory, &owners,
        );
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
        if expected_epoch >= 3 {
            prove_f_ordered_quorum(&current, &hosts, &directory);
        }
        freeze_and_drain(
            fixture,
            &links,
            &current,
            &targets,
            &hosts,
            &directory,
            &network,
            &next_members,
        );
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
            fixture,
            &links,
            &current,
            &targets,
            &history,
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
            operator(env!("CARGO_BIN_EXE_ordered_seal"), "prepare-sqlite", flags);
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
        submit(
            fixture,
            &links,
            &current,
            &network,
            &seal_path.unwrap(),
            &directory.join("seal-submission"),
        );
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
            .map(|index: usize| start(fixture, &links, &targets, index, true, expected_epoch))
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
                    env!("CARGO_BIN_EXE_successor_activation"),
                    "activate",
                    flags.clone()
                )
                .contains("successor_activation=activated")
            );
            assert!(
                operator(
                    env!("CARGO_BIN_EXE_successor_activation"),
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
            .map(|index: usize| start(fixture, &links, &targets, index, false, expected_epoch + 1))
            .collect();
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
    prove_f_ordered_quorum(&unlocked, &hosts, &final_directory);
    verify_receipts(&receipt_history, &hosts);
}
