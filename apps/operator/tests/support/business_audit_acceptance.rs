//! Separate-process ordering export and fixed-source business audit acceptance.
//! All at-rest corruption is explicitly confined to the disposable namespace.
use super::*;
use canonical_encoding::{CanonicalStruct, decode_canonical_frame};
use node_core::ordered_economics::{
    OrderedEconomicsPolicy, OrderedHistoryComponentKind, OrderedHistoryHeightMaterial,
    OrderedHistoryIdentity, decode_ordered_history_identity,
};
use std::collections::BTreeMap;
use std::process::Command;
use validator_set::{ValidatorInfo, ValidatorSet};

pub(super) struct Harness<'a> {
    pub fixture: &'a FastVoteGenesisFixture,
    pub pool: &'a AdminPool,
    pub namespaces: &'a [PostgresNamespace],
    pub ca: &'a Path,
    pub dsn: &'a str,
    pub genesis: &'a Path,
    pub network: &'a Path,
    pub keys: &'a [PathBuf],
    pub dir: &'a Path,
}

const FREEZE_REQUEST: [u8; 32] = [0xC1; 32];
const DRAIN_REQUEST: [u8; 32] = [0xC2; 32];
const OWNED_PUBLICATIONS: usize = 6;

impl Harness<'_> {
    fn snapshot(&self) -> Vec<Snapshot> {
        snapshots(self.pool, self.namespaces)
    }

    fn ordered_policy(&self) -> OrderedEconomicsPolicy {
        let manifest: node_core::GenesisManifest =
            node_core::decode_genesis_manifest(&self.fixture.manifest_bytes).unwrap();
        let members: Vec<ValidatorInfo> = manifest
            .validator_set
            .validators
            .iter()
            .map(|entry| ValidatorInfo {
                id: entry.id,
                voting_power: entry.voting_power,
                signature_scheme: entry.signature_scheme,
                public_key: entry.public_key.clone(),
            })
            .collect();
        OrderedEconomicsPolicy::new(
            self.fixture.context.clone(),
            self.fixture.domain,
            node_core::genesis_manifest_commitment(&self.fixture.resolver, &manifest).unwrap(),
            Some(&manifest),
            ValidatorSet::new(self.fixture.epoch, members).unwrap(),
            self.fixture.resolver.clone(),
        )
        .unwrap()
    }

    fn contract(&self, action: &str, extra: &[&str]) -> Output {
        let fixture: &FastVoteGenesisFixture = self.fixture;
        let mut args: Vec<OsString> = [
            "contract",
            action,
            "--fastvote-network",
            self.network.to_str().unwrap(),
            "--fastvote-genesis-manifest",
            self.genesis.to_str().unwrap(),
            "--fastvote-expected-genesis-digest",
            &cli::to_hex(&fixture.manifest_digest),
            "--expected-chain-id",
            &fixture.chain_id.to_string(),
            "--expected-protocol-version",
            &fixture.protocol_version.get().to_string(),
            "--expected-epoch",
            &fixture.epoch.get().to_string(),
            "--expected-domain",
            &fixture.domain.to_string(),
            "--fastvote-deadline-seconds",
            "90",
            "--fastvote-per-request-cap-seconds",
            "10",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        // Frontier actions deliberately have a narrower flag grammar: their
        // hash schedule is derived from the pinned genesis, not this scalar.
        if !action.starts_with("fastvote-frontier-") {
            args.extend(
                ["--expected-hash-suite-id", "1"]
                    .into_iter()
                    .map(OsString::from),
            );
        }
        args.extend(extra.iter().map(OsString::from));
        cli::edge_cli_command(args).output().unwrap()
    }

    fn frontier(
        &self,
        action: &str,
        validator: ValidatorId,
        height: u64,
        extra: &[&str],
    ) -> Output {
        let mut flags: Vec<String> = vec![
            "--freeze-request-id".into(),
            cli::to_hex(&FREEZE_REQUEST),
            "--freeze-height".into(),
            height.to_string(),
            "--validator-id".into(),
            validator.to_string(),
        ];
        flags.extend(extra.iter().map(|value| (*value).to_owned()));
        let refs: Vec<&str> = flags.iter().map(String::as_str).collect();
        self.contract(action, &refs)
    }

    fn history(&self, directory: &Path, through: Option<&OrderedHistoryIdentity>) -> Output {
        let mut flags: Vec<String> = vec![
            "--target-validator-id".into(),
            self.fixture.validators[0].validator_id.to_string(),
            "--out-dir".into(),
            directory.to_str().unwrap().into(),
            "--history-max-heights".into(),
            "1".into(),
            "--history-chunk-bytes".into(),
            "1024".into(),
        ];
        if let Some(identity) = through {
            flags.extend([
                "--history-through-height".into(),
                identity.through_height.to_string(),
                "--history-through-digest".into(),
                cli::to_hex(&identity.through_digest.bytes()),
            ]);
        }
        let refs: Vec<&str> = flags.iter().map(String::as_str).collect();
        let before: Vec<Snapshot> = self.snapshot();
        let output: Output = ordered_command(
            self.fixture,
            self.network,
            self.genesis,
            "history-export",
            &refs,
        );
        assert_eq!(
            self.snapshot(),
            before,
            "HTTP ordering export must not change any row, revision, sequence or fence"
        );
        output
    }

    fn audit(
        &self,
        history: &Path,
        output_dir: &Path,
        maximum_new: usize,
        pin: [u8; 32],
    ) -> Output {
        let fixture: &FastVoteGenesisFixture = self.fixture;
        let mut command: Command = Command::new(env!("CARGO_BIN_EXE_business_audit_pg"));
        command.env(cli::DSN_ENV, self.dsn).args([
            "--tls-root-der",
            self.ca.to_str().unwrap(),
            "--chain-id",
            &fixture.chain_id.to_string(),
            "--protocol-version",
            &fixture.protocol_version.get().to_string(),
            "--epoch",
            &fixture.epoch.get().to_string(),
            "--validator-id",
            &fixture.validators[0].validator_id.to_string(),
            "--domain",
            &fixture.domain.to_string(),
            "--suite",
            support::genesis_fixture::SUITE_FLAG,
            "--genesis-manifest",
            self.genesis.to_str().unwrap(),
            "--expected-genesis-digest",
            &cli::to_hex(&pin),
            "--ordered-history-dir",
            history.to_str().unwrap(),
            "--out-dir",
            output_dir.to_str().unwrap(),
            "--page-size",
            "2",
            "--timeout-seconds",
            "300",
            "--max-new-publications",
            &maximum_new.to_string(),
        ]);
        let before: Vec<Snapshot> = self.snapshot();
        let output: Output = command.output().unwrap();
        assert_eq!(
            self.snapshot(),
            before,
            "compiled audit, including every refusal, is source-read-only across all twelve scoped tables"
        );
        output
    }

    fn refuse(&self, history: &Path, label: &str) {
        let directory: PathBuf = self.dir.join(format!("refused-{label}"));
        let output: Output = self.audit(history, &directory, 64, self.fixture.manifest_digest);
        assert!(
            !output.status.success(),
            "{label} must fail: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            !directory.join("complete").exists(),
            "refusal is never semantic-equality completion"
        );
    }

    /// An actual process termination/reopen advances the writer fence. Keep
    /// this deliberate transition separate from all no-write comparisons.
    fn reopen_source(&self, hosts: &mut Vec<HostProcess>) {
        let source: HostProcess = hosts.remove(0);
        let address: String = source.addr.to_string();
        drop(source);
        let reopened: HostProcess = host::spawn_ordered_host(
            self.ca,
            self.dsn,
            &self.fixture.chain_id.to_string(),
            &self.fixture.validators[0].validator_id.to_string(),
            &self.fixture.domain.to_string(),
            self.genesis,
            &cli::to_hex(&self.fixture.manifest_digest),
            &self.keys[0],
            &address,
        );
        hosts.insert(0, reopened);
        host::write_network_config(self.network, self.fixture, hosts);
    }
}

/// Actual ordered closure and material-based DrainSet. No invented QC, staged
/// business receipt or runtime Standard Asset shortcut is involved.
#[allow(clippy::too_many_lines)]
pub(super) fn commit_freeze_and_drainset(harness: &Harness<'_>, _hosts: &[HostProcess]) {
    let fixture: &FastVoteGenesisFixture = harness.fixture;
    let manifest: node_core::GenesisManifest =
        node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    // Exclude the previously slashed/re-activated member from the advisory
    // set. Its current-epoch committee authority is not a next-epoch claim.
    let mut advisory: node_core::fast_path::records::FastPathValidatorSetRecord =
        node_core::fast_path::records::FastPathValidatorSetRecord {
            context: execution::publication::PublicationContext::new(
                fixture.chain_id.clone(),
                fixture.protocol_version,
                protocol_types::Epoch::new(fixture.epoch.get() + 1),
            )
            .unwrap(),
            validators: manifest
                .validator_set
                .validators
                .into_iter()
                .filter(|entry| entry.id != fixture.validators[0].validator_id)
                .collect(),
        };
    advisory.validators.sort_by_key(|entry| entry.id);
    let roster: PathBuf = harness.dir.join("advisory.set");
    let candidate: PathBuf = harness.dir.join("freeze.candidate");
    let prefix: PathBuf = harness.dir.join("freeze-network");
    host::write_new(
        &roster,
        &node_core::fast_path::records::encode_fastpath_validator_set_record(&advisory).unwrap(),
    );
    require_success(
        ordered_command(
            fixture,
            harness.network,
            harness.genesis,
            "ordered-freeze-build",
            &[
                "--request-id",
                &cli::to_hex(&FREEZE_REQUEST),
                "--created-checkpoint",
                "1",
                "--advisory-next-set",
                roster.to_str().unwrap(),
                "--out",
                candidate.to_str().unwrap(),
            ],
        ),
        "build pinned Freeze",
    );
    let committed: String = require_success(
        ordered_command(
            fixture,
            harness.network,
            harness.genesis,
            "network-submit",
            &[
                "--candidate",
                candidate.to_str().unwrap(),
                "--out",
                prefix.to_str().unwrap(),
            ],
        ),
        "commit actual Freeze",
    );
    let height: u64 = committed
        .split_whitespace()
        .find_map(|field| field.strip_prefix("block_height="))
        .expect("Freeze response must carry its actual committed consensus height")
        .parse()
        .unwrap();
    assert!(height >= 1);
    let mut votes: Vec<PathBuf> = Vec::new();
    for (index, validator) in fixture.validators.iter().enumerate() {
        let vote: PathBuf = harness.dir.join(format!("frontier-{index}.vote"));
        let complete: String = require_success(
            harness.frontier(
                "fastvote-frontier-advance",
                validator.validator_id,
                height,
                &["--max-steps", "32", "--vote-out", vote.to_str().unwrap()],
            ),
            "complete bounded authenticated frontier",
        );
        assert!(complete.contains("frontier=finalized"));
        let decoded: consensus::FrozenFrontierVote =
            consensus::decode_frozen_frontier_vote(&fs::read(&vote).unwrap()).unwrap();
        assert_eq!(decoded.identity.entry_count, OWNED_PUBLICATIONS as u64);
        votes.push(vote);
    }
    let selection: PathBuf = harness.dir.join("selected-frontiers.manifest");
    host::write_new(
        &selection,
        votes[..3]
            .iter()
            .map(|path| format!("{}\n", path.display()))
            .collect::<String>()
            .as_bytes(),
    );
    let mut identities: Vec<PathBuf> = Vec::new();
    for (index, validator) in fixture.validators.iter().enumerate() {
        let identity: PathBuf = harness.dir.join(format!("union-{index}.identity"));
        require_success(
            harness.contract(
                "fastvote-drain-local-ready",
                &[
                    "--target-validator",
                    &validator.validator_id.to_string(),
                    "--drain-selection-manifest",
                    selection.to_str().unwrap(),
                    "--drain-freeze-request-id",
                    &cli::to_hex(&FREEZE_REQUEST),
                    "--drain-freeze-height",
                    &height.to_string(),
                    "--drain-page-limit",
                    "2",
                    "--drain-max-mutation-attempts",
                    "256",
                    "--drain-artifact-network",
                    harness.network.to_str().unwrap(),
                    "--out-drain-union-identity",
                    identity.to_str().unwrap(),
                ],
            ),
            "genuine local drain readiness",
        );
        identities.push(identity);
    }
    let first: Vec<u8> = fs::read(&identities[0]).unwrap();
    for identity in &identities[1..] {
        assert_eq!(fs::read(identity).unwrap(), first);
    }
    let drain: PathBuf = harness.dir.join("drainset.candidate");
    let mut flags: Vec<OsString> = [
        "economics",
        "drain-set-build",
        "--drain-selection-manifest",
        selection.to_str().unwrap(),
        "--drain-union-identity",
        identities[0].to_str().unwrap(),
        "--request-id",
        &cli::to_hex(&DRAIN_REQUEST),
        "--created-checkpoint",
        "2",
        "--expected-chain-id",
        &fixture.chain_id.to_string(),
        "--expected-protocol-version",
        &fixture.protocol_version.get().to_string(),
        "--expected-epoch",
        &fixture.epoch.get().to_string(),
        "--domain",
        &fixture.domain.to_string(),
        "--ordered-genesis-manifest",
        harness.genesis.to_str().unwrap(),
        "--ordered-expected-genesis-digest",
        &cli::to_hex(&fixture.manifest_digest),
        "--out",
        drain.to_str().unwrap(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    require_success(
        cli::edge_cli_command(std::mem::take(&mut flags))
            .output()
            .unwrap(),
        "build exact union DrainSet",
    );
    let out: PathBuf = harness.dir.join("drainset-network");
    require_success(
        ordered_command(
            fixture,
            harness.network,
            harness.genesis,
            "network-submit",
            &[
                "--candidate",
                drain.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ],
        ),
        "commit genuine DrainSet",
    );
}

fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, current: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries: Vec<fs::DirEntry> =
            fs::read_dir(current).unwrap().map(Result::unwrap).collect();
        entries.sort_by_key(fs::DirEntry::path);
        for entry in entries {
            let path: PathBuf = entry.path();
            let kind: fs::FileType = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                visit(root, &path, output);
            } else {
                assert!(kind.is_file());
                output.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut output: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

fn clone_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    for (name, bytes) in files(source) {
        let target: PathBuf = destination.join(name);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        host::write_new(&target, &bytes);
    }
}

fn verified_archive(
    harness: &Harness<'_>,
    directory: &Path,
) -> (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) {
    sunrise_edge_client::ordered_history_archive::read_verified_ordered_history_archive(
        &harness.ordered_policy(),
        directory,
    )
    .unwrap()
}

fn semantic_equal(output: Output) -> String {
    let report: String =
        require_success(output, "compiled fixed-source independent business audit");
    assert!(
        report.contains("audit=semantic-equal"),
        "only completed semantic replay is equality: {report}"
    );
    assert!(report.contains("owned_publications=6"));
    assert!(report.contains("not-network-freshness-cut-import-readiness-seal-or-activation"));
    report
}

/// Corrupt both unsigned completion companions consistently, and rehash their
/// transfer descriptors. The independent ordering verifier must still accept
/// the unchanged genuine QCs/candidates; private business replay must refuse the
/// fabricated result rather than mistake companion consistency for authority.
#[allow(clippy::too_many_lines)]
fn forge_refusal_companions(harness: &Harness<'_>, archive: &Path, forged: &Path) {
    clone_directory(archive, forged);
    let (_, materials) = verified_archive(harness, archive);
    let policy: OrderedEconomicsPolicy = harness.ordered_policy();
    let mut changed: usize = 0;
    for mut material in materials {
        let Some((_, candidate_bytes)) = material
            .components
            .iter()
            .find(|(kind, _)| *kind == OrderedHistoryComponentKind::Candidate)
        else {
            continue;
        };
        let candidate: OrderedCandidate =
            node_core::ordered_economics::decode_ordered_candidate(candidate_bytes).unwrap();
        if candidate.request_id != [0xE2; 32] {
            continue;
        }
        let receipt_bytes: &[u8] = &material
            .components
            .iter()
            .find(|(kind, _)| *kind == OrderedHistoryComponentKind::OriginalReceipt)
            .unwrap()
            .1;
        let original: node_core::NodeDedupRecord =
            node_core::NodeDedupRecord::decode(receipt_bytes).unwrap();
        assert_eq!(
            original.responses()[0].status(),
            node_core::NodeResponseStatus::Rejected
        );
        let response: node_core::NodeResponse = node_core::NodeResponse::new(
            original.request_id(),
            node_core::NodeResponseStatus::Rejected,
            Some(
                node_core::ordered_economics::encode_ordered_refusal_payload(
                    node_core::ordered_economics::OrderedRefusal::IneligibleState,
                )
                .unwrap(),
            ),
        )
        .unwrap();
        let forged_receipt: Vec<u8> = node_core::NodeDedupRecord::new(
            original.request_id(),
            original.event_digest(),
            vec![response.clone()],
        )
        .unwrap()
        .encode()
        .unwrap();
        let retained: &[u8] = &material
            .components
            .iter()
            .find(|(kind, _)| *kind == OrderedHistoryComponentKind::RetainedOutcome)
            .unwrap()
            .1;
        let wrapper = decode_canonical_frame(retained).unwrap();
        wrapper.require_type(0x644F).unwrap();
        let mut outcome: node_core::ordered_economics::OrderedOutcome =
            node_core::ordered_economics::decode_ordered_outcome(
                wrapper.required_field(1).unwrap(),
            )
            .unwrap();
        outcome.output = node_core::NodeOutput::new(vec![response], Vec::new()).unwrap();
        let mut frame: CanonicalStruct = CanonicalStruct::new(0x644F, 1);
        frame
            .field_bytes(
                1,
                node_core::ordered_economics::encode_ordered_outcome(&outcome).unwrap(),
            )
            .unwrap();
        let forged_outcome: Vec<u8> = frame.finish().unwrap();
        let directory: PathBuf = forged.join(format!("height-{:020}", material.descriptor.height));
        for (kind, bytes) in &mut material.components {
            let replacement: Option<&Vec<u8>> = match kind {
                OrderedHistoryComponentKind::OriginalReceipt => Some(&forged_receipt),
                OrderedHistoryComponentKind::RetainedOutcome => Some(&forged_outcome),
                _ => None,
            };
            if let Some(replacement) = replacement {
                bytes.clone_from(replacement);
                let component: PathBuf = directory.join(format!("component-{:02}", *kind as u16));
                // Exact disposable component directory from our own fresh copy.
                fs::remove_dir_all(&component).unwrap();
                fs::create_dir(&component).unwrap();
                for (index, chunk) in bytes.chunks(1024).enumerate() {
                    host::write_new(
                        &component.join(format!("chunk-{:020}.bin", index * 1024)),
                        chunk,
                    );
                }
                let reference = material
                    .descriptor
                    .components
                    .iter_mut()
                    .find(|entry| entry.kind == *kind)
                    .unwrap();
                reference.length = u64::try_from(bytes.len()).unwrap();
                reference.digest =
                    node_core::ordered_economics::ordered_history_component_digest(&policy, bytes)
                        .unwrap();
            }
        }
        host::write_new(
            &directory.join("descriptor.bin"),
            &node_core::ordered_economics::encode_ordered_history_height_descriptor(
                &material.descriptor,
            )
            .unwrap(),
        );
        changed += 1;
    }
    assert!(
        changed > 0,
        "must forge an actual authenticated stale candidate's companions"
    );
    let original_identity: OrderedHistoryIdentity = verified_archive(harness, archive).0;
    let forged_identity: OrderedHistoryIdentity = verified_archive(harness, forged).0;
    assert_eq!(
        forged_identity, original_identity,
        "ordering proof is deliberately unchanged"
    );
}

fn replace_and_refuse(
    harness: &Harness<'_>,
    archive: &Path,
    key: Vec<u8>,
    bytes: Vec<u8>,
    label: &str,
) {
    let source: Store = store(harness.pool, &harness.namespaces[0]);
    let before: runtime::VersionedStateValue = source
        .get_versioned_durable(
            &cli::read_context(harness.pool, &harness.namespaces[0]),
            harness.fixture.domain,
            &key,
        )
        .unwrap();
    let original: Vec<u8> = before
        .value()
        .expect("negative must corrupt an actual genuine retained row")
        .to_vec();
    support::durable_state::replace(
        &source,
        &cli::read_context(harness.pool, &harness.namespaces[0]),
        harness.fixture.domain,
        key.clone(),
        bytes,
    );
    harness.refuse(archive, label);
    support::durable_state::replace(
        &source,
        &cli::read_context(harness.pool, &harness.namespaces[0]),
        harness.fixture.domain,
        key,
        original,
    );
}

#[allow(clippy::too_many_lines)]
pub(super) fn run(harness: &Harness<'_>, hosts: &mut Vec<HostProcess>) {
    let archive: PathBuf = harness.dir.join("ordered-history");
    require_success(
        harness.history(&archive, None),
        "one-height tiny-chunk ordering export",
    );
    assert!(
        !archive.join("complete").exists(),
        "partial prefix is not complete history"
    );
    let partial: BTreeMap<PathBuf, Vec<u8>> = files(&archive);
    let fixed: OrderedHistoryIdentity =
        decode_ordered_history_identity(&fs::read(archive.join("identity.bin")).unwrap()).unwrap();
    assert!(fixed.through_height > 1);
    harness.reopen_source(hosts);
    for _ in 0..128 {
        require_success(
            harness.history(&archive, Some(&fixed)),
            "resume original fixed ordered target after actual source restart",
        );
        if archive.join("complete").exists() {
            break;
        }
    }
    assert!(
        archive.join("complete").exists(),
        "fixture's bounded 128 invocations must finish its fixed prefix"
    );
    assert_eq!(verified_archive(harness, &archive).0, fixed);
    for (name, bytes) in partial {
        assert!(
            fs::read(archive.join(name)).unwrap() == bytes,
            "saved provisional prefix cannot be overwritten"
        );
    }
    let completed: BTreeMap<PathBuf, Vec<u8>> = files(&archive);
    require_success(
        harness.history(&archive, Some(&fixed)),
        "completed archive re-verification",
    );
    assert!(
        files(&archive) == completed,
        "completed ordering archive is immutable"
    );
    let incomplete: PathBuf = harness.dir.join("truncated-history");
    clone_directory(&archive, &incomplete);
    fs::remove_file(incomplete.join("complete")).unwrap();
    harness.refuse(&incomplete, "incomplete-history");
    let audit: PathBuf = harness.dir.join("audit-resume");
    let progress: String = require_success(
        harness.audit(&archive, &audit, 1, harness.fixture.manifest_digest),
        "bounded publication-cache progress",
    );
    assert!(progress.contains("audit=partial"));
    assert!(progress.contains("no-semantic-equality-claim"));
    assert!(!progress.contains("audit=semantic-equal"));
    assert!(!audit.join("complete").exists());
    let saved_partial: BTreeMap<PathBuf, Vec<u8>> = files(&audit);
    for _ in 0..OWNED_PUBLICATIONS {
        let output: Output = harness.audit(&archive, &audit, 1, harness.fixture.manifest_digest);
        require_success(output, "same-source bounded audit-cache continuation");
        if audit.join("complete").exists() {
            break;
        }
    }
    assert!(audit.join("complete").exists());
    for (name, bytes) in saved_partial {
        assert!(
            fs::read(audit.join(name)).unwrap() == bytes,
            "audit resume preserves synced immutable original cache bytes"
        );
    }
    semantic_equal(harness.audit(&archive, &audit, 1, harness.fixture.manifest_digest));
    let audit_files: BTreeMap<PathBuf, Vec<u8>> = files(&audit);
    let report: Vec<u8> = fs::read(audit.join("complete")).unwrap();
    assert!(String::from_utf8_lossy(&report).contains("audit=semantic-equal"));
    semantic_equal(harness.audit(&archive, &audit, 1, harness.fixture.manifest_digest));
    assert!(
        files(&audit) == audit_files,
        "completed same-source replay must not overwrite cache or completion"
    );

    // A real reopen changes the writer token, even when every business byte
    // is unchanged. Old cache refuses; fresh HTTP export is byte-identical.
    harness.reopen_source(hosts);
    let refused: Output = harness.audit(&archive, &audit, 64, harness.fixture.manifest_digest);
    assert!(!refused.status.success());
    assert!(
        files(&audit) == audit_files,
        "changed writer cannot repin an old completed observation"
    );
    let fresh_archive: PathBuf = harness.dir.join("fresh-ordered-history");
    for _ in 0..128 {
        require_success(
            harness.history(&fresh_archive, Some(&fixed)),
            "fresh real HTTP export after second restart",
        );
        if fresh_archive.join("complete").exists() {
            break;
        }
    }
    assert!(
        files(&fresh_archive) == completed,
        "fixed-target fresh/restarted ordering bytes must be identical"
    );
    let fresh_audit: PathBuf = harness.dir.join("fresh-audit");
    semantic_equal(harness.audit(
        &fresh_archive,
        &fresh_audit,
        64,
        harness.fixture.manifest_digest,
    ));
    replay_completed_publish(harness);
    let mut wrong_pin: [u8; 32] = harness.fixture.manifest_digest;
    wrong_pin[0] ^= 1;
    let wrong: PathBuf = harness.dir.join("wrong-pin");
    assert!(
        !harness
            .audit(&archive, &wrong, 64, wrong_pin)
            .status
            .success()
    );
    assert!(!wrong.join("complete").exists());
    let corrupt_cache: PathBuf = harness.dir.join("corrupt-cache");
    clone_directory(&fresh_audit, &corrupt_cache);
    let name: PathBuf = files(&corrupt_cache)
        .keys()
        .find(|name| name.extension().is_some_and(|value| value == "bundle"))
        .unwrap()
        .clone();
    let mut corrupted: Vec<u8> = fs::read(corrupt_cache.join(&name)).unwrap();
    corrupted[0] ^= 1;
    host::write_new(&corrupt_cache.join(name), &corrupted);
    let corrupt_before: BTreeMap<PathBuf, Vec<u8>> = files(&corrupt_cache);
    assert!(
        !harness
            .audit(
                &archive,
                &corrupt_cache,
                64,
                harness.fixture.manifest_digest
            )
            .status
            .success()
    );
    assert!(
        files(&corrupt_cache) == corrupt_before,
        "corrupt saved cache must be refused, never repaired/overwritten"
    );
    let forged: PathBuf = harness.dir.join("forged-companions");
    forge_refusal_companions(harness, &archive, &forged);
    harness.refuse(&forged, "unsigned-consistent-companions");

    // Canonically valid but fabricated nonce. A fresh out-dir intentionally
    // avoids conflating independent semantic refusal with token mismatch.
    let source: Store = store(harness.pool, &harness.namespaces[0]);
    let nonce_key: Vec<u8> = runtime::PersistenceLayout::new(
        harness.fixture.chain_id.clone(),
        harness.fixture.protocol_version,
    )
    .sender_nonce_key(harness.fixture.sender, harness.fixture.epoch);
    let row: runtime::VersionedStateValue = source
        .get_versioned_durable(
            &cli::read_context(harness.pool, &harness.namespaces[0]),
            harness.fixture.domain,
            &nonce_key,
        )
        .unwrap();
    let frame = decode_canonical_frame(row.value().unwrap()).unwrap();
    frame.require_type(0xE006).unwrap();
    let mut invented: CanonicalStruct = CanonicalStruct::new(0xE006, 1);
    invented
        .field_bytes(1, frame.required_field(1).unwrap().to_vec())
        .unwrap();
    invented
        .field_u64(2, frame.required_u64(2).unwrap())
        .unwrap();
    invented
        .field_u64(3, frame.required_u64(3).unwrap() + 1)
        .unwrap();
    replace_and_refuse(
        harness,
        &archive,
        nonce_key,
        invented.finish().unwrap(),
        "canonical-source-nonce",
    );
    corrupt_source_receipt(harness, &archive);
    corrupt_source_head(harness, &archive);
    let bond_key: Vec<u8> = node_core::local_instance_state::fastpath_bond_record_key(
        &harness.fixture.chain_id,
        &harness.fixture.validators[0].validator_id,
    )
    .unwrap();
    let observed: runtime::VersionedStateValue = source
        .get_versioned_durable(
            &cli::read_context(harness.pool, &harness.namespaces[0]),
            harness.fixture.domain,
            &bond_key,
        )
        .unwrap();
    let mut bond: node_core::fast_path::records::FastPathBondRecord =
        node_core::fast_path::records::decode_fastpath_bond_record(observed.value().unwrap())
            .unwrap();
    bond.generation += 1;
    replace_and_refuse(
        harness,
        &archive,
        bond_key,
        node_core::fast_path::records::encode_fastpath_bond_record(&bond).unwrap(),
        "canonical-source-bond",
    );
    let retained_key: Vec<u8> = node_core::fast_path::publication::fastpath_publication_key(
        &harness.fixture.chain_id,
        &harness.fixture.request_id,
    )
    .unwrap();
    let retained: runtime::VersionedStateValue = source
        .get_versioned_durable(
            &cli::read_context(harness.pool, &harness.namespaces[0]),
            harness.fixture.domain,
            &retained_key,
        )
        .unwrap();
    let publication: node_core::fast_path::publication::FastPathPublicationRecord =
        node_core::fast_path::publication::decode_fastpath_publication_record(
            retained.value().unwrap(),
        )
        .unwrap();
    let manifest: consensus::bundle::ArtifactManifest =
        consensus::bundle::decode_artifact_manifest(&publication.manifest).unwrap();
    let body: &consensus::bundle::ArtifactEntry = manifest
        .entries
        .iter()
        .find(|entry| entry.kind == consensus::bundle::ArtifactKind::ObjectBody)
        .expect("real base transfer must retain the immutable source object body");
    let artifact_key: Vec<u8> =
        node_core::fast_path::publication::fastpath_publication_artifact_key(
            &harness.fixture.chain_id,
            &harness.fixture.request_id,
            body.kind,
            &body.content_digest.bytes(),
        )
        .unwrap();
    for (label, key) in [
        (
            "missing-publication",
            node_core::fast_path::publication::fastpath_publication_key(
                &harness.fixture.chain_id,
                &[0x41; 32],
            )
            .unwrap(),
        ),
        (
            "missing-availability",
            node_core::fast_path::records::fastpath_availability_certificate_key(
                &harness.fixture.chain_id,
                &[0x41; 32],
            )
            .unwrap(),
        ),
        ("missing-authenticated-object-body-artifact", artifact_key),
    ] {
        let prior: runtime::VersionedStateValue = support::durable_state::delete(
            &source,
            &cli::read_context(harness.pool, &harness.namespaces[0]),
            harness.fixture.domain,
            key.clone(),
        );
        assert!(
            prior.value().is_some(),
            "must remove genuine {label} material"
        );
        harness.refuse(&archive, label);
        support::durable_state::replace(
            &source,
            &cli::read_context(harness.pool, &harness.namespaces[0]),
            harness.fixture.domain,
            key,
            prior.value().unwrap().to_vec(),
        );
    }
    semantic_equal(harness.audit(
        &archive,
        &harness.dir.join("restored-audit"),
        64,
        harness.fixture.manifest_digest,
    ));
    // This last deliberate corruption is left in the disposable namespace:
    // even tombstoning an unknown reserved row must not make it trusted.
    support::durable_state::replace(
        &source,
        &cli::read_context(harness.pool, &harness.namespaces[0]),
        harness.fixture.domain,
        b"se/instances/v1/fastpath/unrecognized-business-v999".to_vec(),
        node_core::ordered_economics::encode_ordered_refusal_payload(
            node_core::ordered_economics::OrderedRefusal::IneligibleState,
        )
        .unwrap(),
    );
    harness.refuse(&archive, "unknown-reserved-source-row");
}

fn replay_completed_publish(harness: &Harness<'_>) {
    let before: Vec<Snapshot> = harness.snapshot();
    let result: PathBuf = harness.dir.join("publish-replay.result");
    require_success(
        harness.contract(
            "fastvote-replay",
            &[
                "--submission",
                harness.dir.join("publish.intent").to_str().unwrap(),
                "--certificate",
                harness.dir.join("publish.cert").to_str().unwrap(),
                "--availability-certificate",
                harness.dir.join("publish.avail").to_str().unwrap(),
                "--result-out",
                result.to_str().unwrap(),
            ],
        ),
        "exact completed Publish replay after closure and two source restarts",
    );
    assert_eq!(
        fs::read(result).unwrap(),
        fs::read(harness.dir.join("publish.result")).unwrap()
    );
    assert_eq!(
        harness.snapshot(),
        before,
        "exact completed Publish replay preserves every source and observer row/revision/fence"
    );
}

fn corrupt_source_receipt(harness: &Harness<'_>, archive: &Path) {
    let namespace: &PostgresNamespace = &harness.namespaces[0];
    let mut connection = harness.pool.get().unwrap();
    let query: &str = "SELECT canonical_response_bytes FROM sunrise_edge.request_receipts WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 AND request_id=$4";
    let key: [u8; 32] = [0x41; 32];
    let original: Vec<u8> = connection
        .query_one(
            query,
            &[
                &namespace.chain_id_bytes(),
                &namespace.validator_id().as_bytes().as_slice(),
                &namespace.domain().as_bytes().as_slice(),
                &key.as_slice(),
            ],
        )
        .unwrap()
        .get(0);
    let record: node_core::NodeDedupRecord = node_core::NodeDedupRecord::decode(&original).unwrap();
    let altered: node_core::NodeResponse = node_core::NodeResponse::new(
        record.request_id(),
        node_core::NodeResponseStatus::Rejected,
        record.responses()[0].payload().map(<[u8]>::to_vec),
    )
    .unwrap();
    let bytes: Vec<u8> =
        node_core::NodeDedupRecord::new(record.request_id(), record.event_digest(), vec![altered])
            .unwrap()
            .encode()
            .unwrap();
    let update: &str = "UPDATE sunrise_edge.request_receipts SET canonical_response_bytes=$5 WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 AND request_id=$4";
    assert_eq!(
        connection
            .execute(
                update,
                &[
                    &namespace.chain_id_bytes(),
                    &namespace.validator_id().as_bytes().as_slice(),
                    &namespace.domain().as_bytes().as_slice(),
                    &key.as_slice(),
                    &bytes
                ]
            )
            .unwrap(),
        1
    );
    drop(connection);
    harness.refuse(archive, "canonical-source-original-receipt");
    let mut connection = harness.pool.get().unwrap();
    assert_eq!(
        connection
            .execute(
                update,
                &[
                    &namespace.chain_id_bytes(),
                    &namespace.validator_id().as_bytes().as_slice(),
                    &namespace.domain().as_bytes().as_slice(),
                    &key.as_slice(),
                    &original
                ]
            )
            .unwrap(),
        1
    );
}

fn corrupt_source_head(harness: &Harness<'_>, archive: &Path) {
    let namespace: &PostgresNamespace = &harness.namespaces[0];
    let id: ObjectId = harness.fixture.fee_coin;
    let mut connection = harness.pool.get().unwrap();
    let original: Vec<u8> = connection.query_one("SELECT owner_projection FROM sunrise_edge.object_heads WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 AND object_id=$4",
        &[&namespace.chain_id_bytes(), &namespace.validator_id().as_bytes().as_slice(), &namespace.domain().as_bytes().as_slice(), &id.as_bytes().as_slice()]).unwrap().get(0);
    // Another real canonical owner projection, not malformed decoder input.
    let wrong: Vec<u8> = connection.query_one("SELECT owner_projection FROM sunrise_edge.object_heads WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 AND NOT tombstone AND owner_projection <> $4 ORDER BY object_id LIMIT 1",
        &[&namespace.chain_id_bytes(), &namespace.validator_id().as_bytes().as_slice(), &namespace.domain().as_bytes().as_slice(), &original]).unwrap().get(0);
    let update: &str = "UPDATE sunrise_edge.object_heads SET owner_projection=$5 WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 AND object_id=$4";
    assert_eq!(
        connection
            .execute(
                update,
                &[
                    &namespace.chain_id_bytes(),
                    &namespace.validator_id().as_bytes().as_slice(),
                    &namespace.domain().as_bytes().as_slice(),
                    &id.as_bytes().as_slice(),
                    &wrong
                ]
            )
            .unwrap(),
        1
    );
    drop(connection);
    harness.refuse(archive, "canonical-source-object-head");
    let mut connection = harness.pool.get().unwrap();
    assert_eq!(
        connection
            .execute(
                update,
                &[
                    &namespace.chain_id_bytes(),
                    &namespace.validator_id().as_bytes().as_slice(),
                    &namespace.domain().as_bytes().as_slice(),
                    &id.as_bytes().as_slice(),
                    &original
                ]
            )
            .unwrap(),
        1
    );
}
