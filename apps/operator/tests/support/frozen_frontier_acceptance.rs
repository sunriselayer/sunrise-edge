//! Actual ordered Freeze and immutable frontier acceptance, sharing the
//! parent test's ordinary contract lifecycle rather than copying its harness.

#[path = "drainset_acceptance.rs"]
mod drainset_acceptance;

use super::{AdminPool, HostProcess, Store, publication_client, replay_flags, store};
use crate::support::cli::{edge_cli_command, read_context, to_hex};
use crate::support::durable_state::{convergence_snapshot, execution_snapshot};
use crate::support::genesis_fixture::FastVoteGenesisFixture;
use crate::support::host::{spawn_ordered_host, temp_file, write_network_config, write_new};
use crate::support::paid_calls::current_object_ref;
use abi::package_types::PackageOrigin;
use consensus::{AvailabilityIdentity, FastCertificate, FastVote};
use execution::paid_execution::{
    PaidApplication, SignedPaidIntent, decode_signed_paid_intent, encode_signed_paid_intent,
};
use node_core::fast_path::FastPathEd25519Verifier;
use objects::{ObjectId, ObjectRef};
use protocol_types::ValidatorId;
use runtime::DurableOperationContext;
use runtime_postgres::PostgresNamespace;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Output,
};
use sunrise_edge_client::{Client, LoopbackHttpTransport, TrustedFastVoteGenesis};

const UNAPPLIED_REQUEST: [u8; 32] = [0xBC; 32];
const FREEZE_REQUEST: [u8; 32] = [0xC1; 32];

fn all_snapshots(
    fixture: &FastVoteGenesisFixture,
    pool: &AdminPool,
    namespaces: &[PostgresNamespace],
    ids: &BTreeSet<ObjectId>,
    requests: &[[u8; 32]],
    publications: &[PackageOrigin],
) -> Vec<String> {
    namespaces
        .iter()
        .map(|namespace: &PostgresNamespace| -> String {
            convergence_snapshot(
                &store(pool, namespace),
                &read_context(pool, namespace),
                fixture,
                ids,
                requests,
                publications,
            )
        })
        .collect()
}

/// Retain a genuine full certificate on one host without applying it or
/// aggregating availability ACKs. Its inclusion cannot be inferred from a
/// user receipt or locally held availability certificate.
#[allow(clippy::too_many_arguments)]
fn retain_unapplied_publication(
    fixture: &FastVoteGenesisFixture,
    pool: &AdminPool,
    namespaces: &[PostgresNamespace],
    hosts: &[HostProcess],
    manifest_path: &Path,
    ids: &BTreeSet<ObjectId>,
    requests: &[[u8; 32]],
    publications: &[PackageOrigin],
) -> (
    SignedPaidIntent,
    FastCertificate,
    AvailabilityIdentity,
    Vec<u8>,
) {
    let sender_store: Store = store(pool, &namespaces[0]);
    let context: DurableOperationContext = read_context(pool, &namespaces[0]);
    let current: ObjectRef = current_object_ref(
        &sender_store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        fixture.fee_coin,
    );
    let mut signed: SignedPaidIntent =
        decode_signed_paid_intent(&fixture.paid_intent_bytes).unwrap();
    signed.intent.request_id = UNAPPLIED_REQUEST;
    signed.intent.nonce = 11;
    signed.intent.consent.source = current.clone();
    let PaidApplication::Call(call) = &mut signed.intent.application else {
        panic!("network fixture must carry an ordinary paid Call");
    };
    call.request_id = UNAPPLIED_REQUEST;
    call.nonce = 11;
    call.access.entries[0].object_ref = current;
    // Transfer to the same owner so the application/fee-source composition
    // remains valid without a special chain-native balance operation.
    call.arguments = public_standard_asset::transfer_arguments(&fixture.sender).unwrap();
    signed = decode_signed_paid_intent(&fixture.sign_intent(signed.intent)).unwrap();
    let bytes: Vec<u8> = encode_signed_paid_intent(&signed).unwrap();
    let trusted: TrustedFastVoteGenesis =
        sunrise_edge_client::load_trusted_fastvote_genesis_with_profile(
            manifest_path,
            &fixture.resolver,
            fixture.manifest_digest,
            &fixture.context,
        )
        .unwrap();
    let application_before: Vec<String> = namespaces
        .iter()
        .map(|namespace: &PostgresNamespace| -> String {
            execution_snapshot(
                &store(pool, namespace),
                &read_context(pool, namespace),
                fixture,
                ids,
                requests,
                publications,
            )
        })
        .collect();
    let votes: Vec<FastVote> = hosts
        .iter()
        .take(3)
        .map(|host: &HostProcess| -> FastVote {
            publication_client(host.addr)
                .prepare_fastvote(&bytes, None)
                .unwrap()
        })
        .collect();
    let certificate: FastCertificate = trusted
        .certifier
        .try_form_certificate(
            votes[0].tx_hash,
            votes[0].execution_effects_hash,
            votes[0].locked_objects_digest,
            &votes,
            &FastPathEd25519Verifier,
        )
        .unwrap()
        .expect("three genuine prepare signatures must form a strict quorum");
    let holder: Client<LoopbackHttpTransport> = publication_client(hosts[0].addr);
    let (bundle, identity) = holder
        .source_fastvote_publication(
            &signed,
            &certificate,
            &trusted.certifier,
            &fixture.resolver,
            &[],
            fixture.domain,
            None,
        )
        .unwrap();
    let bundle_bytes: Vec<u8> = consensus::bundle::encode_publication_bundle(&bundle).unwrap();
    let ack: consensus::AvailabilityVote = holder
        .retain_fastvote_publication(&bundle_bytes, None)
        .unwrap();
    assert_eq!(ack.identity, identity);
    assert_eq!(ack.validator, fixture.validators[0].validator_id);
    let availability: consensus::AvailabilityCertifier = consensus::AvailabilityCertifier::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        trusted.certifier.validator_set().clone(),
    )
    .unwrap();
    availability
        .verify_vote(&ack, &FastPathEd25519Verifier)
        .unwrap();
    assert_eq!(
        namespaces
            .iter()
            .map(|namespace: &PostgresNamespace| -> String {
                execution_snapshot(
                    &store(pool, namespace),
                    &read_context(pool, namespace),
                    fixture,
                    ids,
                    requests,
                    publications,
                )
            })
            .collect::<Vec<String>>(),
        application_before,
        "prepare and retention must not apply or charge the additional request"
    );
    assert!(matches!(
        node_core::query_request_receipt(
            &sender_store,
            &context,
            fixture.domain,
            node_core::RequestId::new(UNAPPLIED_REQUEST).unwrap(),
        )
        .unwrap(),
        node_core::ReceiptQueryResult::Absent { .. }
    ));
    (signed, certificate, identity, bundle_bytes)
}

fn ordered_command(
    fixture: &FastVoteGenesisFixture,
    network: &Path,
    genesis: &Path,
    action: &str,
    extra: &[&str],
) -> Output {
    let chain: String = fixture.chain_id.to_string();
    let protocol: String = fixture.protocol_version.get().to_string();
    let epoch: String = fixture.epoch.get().to_string();
    let domain: String = fixture.domain.to_string();
    let digest: String = to_hex(&fixture.manifest_digest);
    let mut args: Vec<OsString> = [
        "economics",
        action,
        "--ordered-network",
        network.to_str().unwrap(),
        "--ordered-genesis-manifest",
        genesis.to_str().unwrap(),
        "--ordered-expected-genesis-digest",
        &digest,
        "--expected-chain-id",
        &chain,
        "--expected-protocol-version",
        &protocol,
        "--expected-epoch",
        &epoch,
        "--domain",
        &domain,
        "--deadline-seconds",
        "90",
        "--per-request-cap-seconds",
        "10",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.extend(extra.iter().map(OsString::from));
    edge_cli_command(args).output().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn frontier_command(
    fixture: &FastVoteGenesisFixture,
    network: &Path,
    genesis: &Path,
    action: &str,
    validator: ValidatorId,
    height: u64,
    extra: &[&str],
) -> Output {
    let chain: String = fixture.chain_id.to_string();
    let protocol: String = fixture.protocol_version.get().to_string();
    let epoch: String = fixture.epoch.get().to_string();
    let domain: String = fixture.domain.to_string();
    let digest: String = to_hex(&fixture.manifest_digest);
    let request: String = to_hex(&FREEZE_REQUEST);
    let validator_hex: String = validator.to_string();
    let height_text: String = height.to_string();
    let mut args: Vec<OsString> = [
        "contract",
        action,
        "--fastvote-network",
        network.to_str().unwrap(),
        "--fastvote-genesis-manifest",
        genesis.to_str().unwrap(),
        "--fastvote-expected-genesis-digest",
        &digest,
        "--expected-chain-id",
        &chain,
        "--expected-protocol-version",
        &protocol,
        "--expected-epoch",
        &epoch,
        "--expected-domain",
        &domain,
        "--freeze-request-id",
        &request,
        "--freeze-height",
        &height_text,
        "--validator-id",
        &validator_hex,
        "--fastvote-deadline-seconds",
        "90",
        "--fastvote-per-request-cap-seconds",
        "10",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.extend(extra.iter().map(OsString::from));
    edge_cli_command(args).output().unwrap()
}

fn require_success(output: Output, action: &str) {
    assert!(
        output.status.success(),
        "{action}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn verify_export(
    fixture: &FastVoteGenesisFixture,
    directory: &Path,
    validator: ValidatorId,
    height: u64,
    expected_entries: u64,
    expected_unapplied: Option<&AvailabilityIdentity>,
) -> Vec<Vec<u8>> {
    let vote_bytes: Vec<u8> = fs::read(directory.join("frontier.vote")).unwrap();
    let vote: consensus::FrozenFrontierVote =
        consensus::decode_frozen_frontier_vote(&vote_bytes).unwrap();
    let manifest: node_core::GenesisManifest =
        node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let validators: Vec<validator_set::ValidatorInfo> = manifest
        .validator_set
        .validators
        .iter()
        .map(|entry| validator_set::ValidatorInfo {
            id: entry.id,
            voting_power: entry.voting_power,
            signature_scheme: entry.signature_scheme,
            public_key: entry.public_key.clone(),
        })
        .collect();
    let certifier: consensus::FrozenFrontierCertifier = consensus::FrozenFrontierCertifier::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        validator_set::ValidatorSet::new(fixture.epoch, validators).unwrap(),
    )
    .unwrap();
    certifier
        .verify_vote(&vote, &FastPathEd25519Verifier)
        .unwrap();
    assert_eq!(vote.validator, validator);
    assert_eq!(vote.identity.domain, fixture.domain);
    assert_eq!(vote.identity.closure_request_id, FREEZE_REQUEST);
    assert_eq!(vote.identity.closure_height, height);
    assert_eq!(vote.identity.entry_count, expected_entries);
    let mut verifier: consensus::FrozenFrontierPageVerifier =
        consensus::FrozenFrontierPageVerifier::new(
            &fixture.resolver,
            &certifier,
            vote,
            &FastPathEd25519Verifier,
        )
        .unwrap();
    let mut saved: Vec<Vec<u8>> = vec![vote_bytes.clone()];
    let mut saw_unapplied: bool = false;
    for index in 0_u64..32_u64 {
        let bytes: Vec<u8> =
            fs::read(directory.join(format!("page-{index:020}.response"))).unwrap();
        let response: node_wire::FrozenFrontierPageResponse =
            node_wire::FrozenFrontierPageResponse::decode(&bytes).unwrap();
        assert_eq!(response.vote, vote_bytes);
        let page: consensus::FrozenFrontierPage =
            consensus::decode_frozen_frontier_page(&response.page).unwrap();
        if let Some(expected) = expected_unapplied {
            saw_unapplied |= page.entries.iter().any(|entry| entry == expected);
        }
        verifier.push_page(&fixture.resolver, &page).unwrap();
        saved.push(bytes);
        if page.terminal {
            break;
        }
    }
    assert!(
        verifier.is_terminal(),
        "the complete stream must end in a verified terminal page"
    );
    assert_eq!(fs::read(directory.join("complete")).unwrap(), vote_bytes);
    if expected_unapplied.is_some() {
        assert!(
            saw_unapplied,
            "frontier must contain retained full certificate without a local receipt or aggregated ACK proof"
        );
    }
    saved
}

fn application_snapshots(
    fixture: &FastVoteGenesisFixture,
    pool: &AdminPool,
    namespaces: &[PostgresNamespace],
    ids: &BTreeSet<ObjectId>,
    requests: &[[u8; 32]],
    publications: &[PackageOrigin],
) -> Vec<String> {
    namespaces
        .iter()
        .map(|namespace: &PostgresNamespace| -> String {
            execution_snapshot(
                &store(pool, namespace),
                &read_context(pool, namespace),
                fixture,
                ids,
                requests,
                publications,
            )
        })
        .collect()
}

fn replay_completed_publish(
    fixture: &FastVoteGenesisFixture,
    network: &Path,
    manifest: &Path,
    data_dir: &Path,
    label: &str,
) {
    let output_path: PathBuf = temp_file(data_dir, &format!("{label}.result"));
    require_success(
        edge_cli_command(replay_flags(
            &fixture.chain_id.to_string(),
            &fixture.domain.to_string(),
            network,
            manifest,
            &to_hex(&fixture.manifest_digest),
            &temp_file(data_dir, "publish.intent"),
            &temp_file(data_dir, "publish.cert"),
            &temp_file(data_dir, "publish.avail"),
            &output_path,
        ))
        .output()
        .unwrap(),
        "completed original publication replay remains available after Freeze",
    );
    assert_eq!(
        fs::read(output_path).unwrap(),
        fs::read(temp_file(data_dir, "publish.result")).unwrap(),
    );
}

#[allow(clippy::too_many_arguments)]
fn reopen_hosts(
    fixture: &FastVoteGenesisFixture,
    ca_path: &Path,
    dsn: &str,
    manifest: &Path,
    digest: &str,
    validator_hex: &[String],
    key_paths: [&Path; 4],
    network: &Path,
) -> Vec<HostProcess> {
    let hosts: Vec<HostProcess> = key_paths
        .into_iter()
        .enumerate()
        .map(|(index, key)| -> HostProcess {
            spawn_ordered_host(
                ca_path,
                dsn,
                &fixture.chain_id.to_string(),
                &validator_hex[index],
                &fixture.domain.to_string(),
                manifest,
                digest,
                key,
                "127.0.0.1:0",
            )
        })
        .collect();
    write_network_config(network, fixture, &hosts);
    hosts
}

/// This deliberately operates the same ordinary user-contract history as
/// the parent lifecycle test. No privileged Standard Asset state or forged
/// frontier/Freeze rows are installed to make the acceptance path succeed.
#[allow(clippy::too_many_arguments)]
pub fn run(
    fixture: &FastVoteGenesisFixture,
    pool: &AdminPool,
    namespaces: &[PostgresNamespace],
    data_dir: &Path,
    ca_path: &Path,
    dsn: &str,
    manifest_path: &Path,
    digest_hex: &str,
    network: &Path,
    validator_hex: &[String],
    key_paths: [&Path; 4],
    mut hosts: Vec<HostProcess>,
    follower: HostProcess,
    ids: &BTreeSet<ObjectId>,
    requests: &[[u8; 32]],
    publications: &[PackageOrigin],
    member_drain: bool,
) {
    assert_eq!(requests.len(), 11);
    hosts.push(follower);
    write_network_config(network, fixture, &hosts);
    let mut all_requests: Vec<[u8; 32]> = requests.to_vec();
    all_requests.push(UNAPPLIED_REQUEST);
    let (unapplied, certificate, unapplied_identity, bundle_bytes) = retain_unapplied_publication(
        fixture,
        pool,
        namespaces,
        &hosts,
        manifest_path,
        ids,
        &all_requests,
        publications,
    );
    if member_drain {
        drainset_acceptance::prepare_conflicting_partial(fixture, &hosts[3], &unapplied);
        all_requests.push(drainset_acceptance::CONFLICTING_REQUEST);
    }
    let application_before: Vec<String> =
        application_snapshots(fixture, pool, namespaces, ids, &all_requests, publications);

    // The advisory roster is derived from locally trusted signed genesis.
    // Its exact next epoch and committed member eligibility are independently
    // checked by every replica at proposal/vote and execution.
    let manifest: node_core::GenesisManifest =
        node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let mut advisory: node_core::fast_path::records::FastPathValidatorSetRecord =
        node_core::fast_path::records::FastPathValidatorSetRecord {
            context: execution::publication::PublicationContext::new(
                fixture.chain_id.clone(),
                fixture.protocol_version,
                protocol_types::Epoch::new(fixture.epoch.get().checked_add(1).unwrap()),
            )
            .unwrap(),
            validators: manifest.validator_set.validators,
        };
    advisory
        .validators
        .sort_by_key(|entry: &node_core::fast_path::FastPathValidatorEntry| entry.id);
    let advisory_path: PathBuf = temp_file(data_dir, "freeze-advisory.set");
    write_new(
        &advisory_path,
        &node_core::fast_path::records::encode_fastpath_validator_set_record(&advisory).unwrap(),
    );
    let candidate_path: PathBuf = temp_file(data_dir, "freeze.candidate");
    require_success(
        ordered_command(
            fixture,
            network,
            manifest_path,
            "ordered-freeze-build",
            &[
                "--request-id",
                &to_hex(&FREEZE_REQUEST),
                "--created-checkpoint",
                "1",
                "--advisory-next-set",
                advisory_path.to_str().unwrap(),
                "--out",
                candidate_path.to_str().unwrap(),
            ],
        ),
        "build locally pinned ordered Freeze",
    );
    let freeze_prefix: PathBuf = temp_file(data_dir, "freeze-network");
    let freeze: Output = ordered_command(
        fixture,
        network,
        manifest_path,
        "network-submit",
        &[
            "--candidate",
            candidate_path.to_str().unwrap(),
            "--out",
            freeze_prefix.to_str().unwrap(),
        ],
    );
    let stdout: String = String::from_utf8(freeze.stdout.clone()).unwrap();
    let height: u64 = stdout
        .split_whitespace()
        .find_map(|field: &str| field.strip_prefix("block_height="))
        .unwrap_or_else(|| panic!("Freeze lacks an acknowledged actual consensus height: {stdout}"))
        .parse()
        .unwrap();
    require_success(freeze, "commit genuine ordered Freeze on four replicas");
    assert!(height >= manifest.minimum_freeze_block_height);
    assert_eq!(
        application_snapshots(fixture, pool, namespaces, ids, &all_requests, publications),
        application_before,
        "Freeze must not apply the outstanding full certificate or change any business object, receipt, publication or nonce"
    );

    // An exact ACK replay on the old holder remains read-only. No new
    // holder may issue an ACK, even for a genuine certificate already
    // prepared before the closure; this binds the complete frozen frontier.
    let before_closed_attempts: Vec<String> =
        all_snapshots(fixture, pool, namespaces, ids, &all_requests, publications);
    publication_client(hosts[0].addr)
        .retain_fastvote_publication(&bundle_bytes, None)
        .unwrap();
    for host in &hosts[1..] {
        assert!(
            publication_client(host.addr)
                .retain_fastvote_publication(&bundle_bytes, None)
                .is_err(),
            "closed epoch must refuse a fresh availability ACK"
        );
    }
    let mut fresh: SignedPaidIntent = unapplied.clone();
    fresh.intent.request_id = [0xBD; 32];
    let PaidApplication::Call(call) = &mut fresh.intent.application else {
        unreachable!()
    };
    call.request_id = fresh.intent.request_id;
    let fresh_bytes: Vec<u8> = fixture.sign_intent(fresh.intent);
    for host in &hosts {
        assert!(
            publication_client(host.addr)
                .prepare_fastvote(&fresh_bytes, None)
                .is_err(),
            "closed epoch must refuse a new application prepare"
        );
    }
    replay_completed_publish(fixture, network, manifest_path, data_dir, "frozen-replay");
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, &all_requests, publications),
        before_closed_attempts,
        "closed admission refusals and exact ACK replay must leave every durable revision unchanged"
    );

    // Make just one bounded scan step, then really terminate and reopen all
    // four host processes. A durable cursor is progress, not a complete vote.
    let provisional_vote: PathBuf = temp_file(data_dir, "provisional-frontier.vote");
    let partial: Output = frontier_command(
        fixture,
        network,
        manifest_path,
        "fastvote-frontier-advance",
        fixture.validators[0].validator_id,
        height,
        &[
            "--max-steps",
            "1",
            "--vote-out",
            provisional_vote.to_str().unwrap(),
        ],
    );
    let partial_stdout: String = String::from_utf8(partial.stdout.clone()).unwrap();
    require_success(partial, "bounded provisional frontier advance");
    assert!(
        partial_stdout.contains("frontier=partial"),
        "one bounded step must not claim this multi-publication frontier is complete: {partial_stdout}"
    );
    assert!(!provisional_vote.exists());
    let partial_snapshot: Vec<String> =
        all_snapshots(fixture, pool, namespaces, ids, &all_requests, publications);
    drop(hosts);
    hosts = reopen_hosts(
        fixture,
        ca_path,
        dsn,
        manifest_path,
        digest_hex,
        validator_hex,
        key_paths,
        network,
    );
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, &all_requests, publications),
        partial_snapshot,
        "reopen must preserve the exact partial cursor bytes and revision, not reset progress"
    );

    for (index, validator) in fixture.validators.iter().enumerate() {
        let vote_out: PathBuf = temp_file(data_dir, &format!("resumed-frontier-{index}.vote"));
        // Holder0 already confirmed one of12entries. Its11remaining
        // entries plus finalization fit12steps; restarting from scratch
        // needs13 and therefore cannot pass this assertion.
        require_success(
            frontier_command(
                fixture,
                network,
                manifest_path,
                "fastvote-frontier-advance",
                validator.validator_id,
                height,
                &[
                    "--max-steps",
                    "12",
                    "--vote-out",
                    vote_out.to_str().unwrap(),
                ],
            ),
            "resume bounded frontier scan after actual host restart",
        );
        assert!(
            vote_out.exists(),
            "bounded restart must actually finalize from the retained cursor"
        );
    }
    let finalized: Vec<String> =
        all_snapshots(fixture, pool, namespaces, ids, &all_requests, publications);
    let mut exports: Vec<(PathBuf, Vec<Vec<u8>>)> = Vec::new();
    for (index, validator) in fixture.validators.iter().enumerate() {
        let directory: PathBuf = temp_file(data_dir, &format!("frontier-export-{index}"));
        require_success(
            frontier_command(
                fixture,
                network,
                manifest_path,
                "fastvote-frontier-export",
                validator.validator_id,
                height,
                &[
                    "--output-dir",
                    directory.to_str().unwrap(),
                    "--page-limit",
                    "2",
                    "--max-pages",
                    "1",
                ],
            ),
            "bounded first page export",
        );
        assert!(directory.join("frontier.vote").exists());
        assert!(
            directory
                .join("page-00000000000000000000.response")
                .exists()
        );
        assert!(
            !directory.join("complete").exists(),
            "partial saved frontier cannot be certified complete"
        );
        require_success(
            frontier_command(
                fixture,
                network,
                manifest_path,
                "fastvote-frontier-export",
                validator.validator_id,
                height,
                &[
                    "--output-dir",
                    directory.to_str().unwrap(),
                    "--page-limit",
                    "2",
                    "--max-pages",
                    "32",
                ],
            ),
            "resume and independently verify every frontier page",
        );
        let expected_entries: u64 = u64::try_from(requests.len()).unwrap() + u64::from(index == 0);
        let saved: Vec<Vec<u8>> = verify_export(
            fixture,
            &directory,
            validator.validator_id,
            height,
            expected_entries,
            (index == 0).then_some(&unapplied_identity),
        );
        exports.push((directory, saved));
    }
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, &all_requests, publications),
        finalized,
        "frontier export must remain read-only after the durable final vote"
    );
    assert_eq!(
        application_snapshots(fixture, pool, namespaces, ids, &all_requests, publications),
        application_before,
        "frontier scan/sign/export is execution-free"
    );

    // Reopen once more with finalized votes and saved complete streams.
    // Exact local signatures/pages are reused, never re-signed or overwritten.
    drop(hosts);
    hosts = reopen_hosts(
        fixture,
        ca_path,
        dsn,
        manifest_path,
        digest_hex,
        validator_hex,
        key_paths,
        network,
    );
    for (index, (directory, saved)) in exports.iter().enumerate() {
        let validator: ValidatorId = fixture.validators[index].validator_id;
        require_success(
            frontier_command(
                fixture,
                network,
                manifest_path,
                "fastvote-frontier-advance",
                validator,
                height,
                &["--max-steps", "1"],
            ),
            "exact finalized frontier replay after restart",
        );
        require_success(
            frontier_command(
                fixture,
                network,
                manifest_path,
                "fastvote-frontier-export",
                validator,
                height,
                &[
                    "--output-dir",
                    directory.to_str().unwrap(),
                    "--page-limit",
                    "2",
                    "--max-pages",
                    "1",
                ],
            ),
            "read-only complete export replay after restart",
        );
        assert_eq!(
            verify_export(
                fixture,
                directory,
                validator,
                height,
                u64::try_from(requests.len()).unwrap() + u64::from(index == 0),
                (index == 0).then_some(&unapplied_identity),
            ),
            *saved,
        );
        let fresh_directory: PathBuf =
            temp_file(data_dir, &format!("frontier-fresh-restart-{index}"));
        require_success(
            frontier_command(
                fixture,
                network,
                manifest_path,
                "fastvote-frontier-export",
                validator,
                height,
                &[
                    "--output-dir",
                    fresh_directory.to_str().unwrap(),
                    "--page-limit",
                    "2",
                    "--max-pages",
                    "32",
                ],
            ),
            "fetch actual server vote/pages into a fresh directory after restart",
        );
        assert_eq!(
            verify_export(
                fixture,
                &fresh_directory,
                validator,
                height,
                u64::try_from(requests.len()).unwrap() + u64::from(index == 0),
                (index == 0).then_some(&unapplied_identity),
            ),
            *saved,
            "fresh post-restart HTTP reads must return byte-identical vote and pages"
        );
    }
    replay_completed_publish(
        fixture,
        network,
        manifest_path,
        data_dir,
        "frozen-restart-replay",
    );
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, &all_requests, publications),
        finalized
    );

    let (directory, saved) = &exports[0];
    let validator: ValidatorId = fixture.validators[0].validator_id;
    let wrong_height: Output = frontier_command(
        fixture,
        network,
        manifest_path,
        "fastvote-frontier-export",
        validator,
        height.checked_add(1).unwrap(),
        &[
            "--output-dir",
            directory.to_str().unwrap(),
            "--page-limit",
            "2",
        ],
    );
    assert!(
        !wrong_height.status.success(),
        "local actual-height mismatch must fail before accepting saved evidence"
    );
    assert_eq!(
        verify_export(
            fixture,
            directory,
            validator,
            height,
            12,
            Some(&unapplied_identity)
        ),
        *saved
    );

    // Deliberate corruption is confined to this disposable test directory.
    // Resume must refuse it, preserve the corrupted bytes and avoid publishing
    // a replacement or touching any replica's complete durable state.
    let page_path: PathBuf = directory.join("page-00000000000000000000.response");
    let corrupt: Vec<u8> = b"invalid-frontier-page".to_vec();
    fs::write(&page_path, &corrupt).unwrap();
    let refused: Output = frontier_command(
        fixture,
        network,
        manifest_path,
        "fastvote-frontier-export",
        validator,
        height,
        &[
            "--output-dir",
            directory.to_str().unwrap(),
            "--page-limit",
            "2",
        ],
    );
    assert!(
        !refused.status.success(),
        "corrupt saved page must fail closed"
    );
    assert_eq!(
        fs::read(&page_path).unwrap(),
        corrupt,
        "never overwrite saved corruption with peer-supplied bytes"
    );
    assert_eq!(fs::read(directory.join("complete")).unwrap(), saved[0]);
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, &all_requests, publications),
        finalized
    );
    if member_drain {
        drainset_acceptance::run(
            fixture,
            pool,
            namespaces,
            data_dir,
            ca_path,
            dsn,
            manifest_path,
            digest_hex,
            network,
            validator_hex,
            key_paths,
            hosts,
            ids,
            &all_requests,
            publications,
            height,
            &unapplied,
            &certificate,
            &unapplied_identity,
        );
    } else {
        drop(hosts);
    }
}
