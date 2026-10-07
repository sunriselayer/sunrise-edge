//! DR-0169 real HTTP/compiled-CLI history acceptance. Empty progress uses
//! ordinary leader proposals, registered votes and actual certificates;
//! no progress counter or proof row is seeded.

use super::*;
use consensus::{ConsensusMessage, ConsensusVote, QuorumCertificate};
use node_core::ordered_economics::{
    OrderedEconomicsPolicy, OrderedEventOutput, OrderedProposal, OrderedStatus,
};
use std::{collections::BTreeMap, net::SocketAddr, time::Instant};
use sunrise_edge_client::transport::{Method, Transport, WireRequest, WireResponse};

const CLAIM_REQUEST: [u8; 32] = [0xC7; 32];
const REFUSAL_REQUEST: [u8; 32] = [0xC8; 32];
type SqlSnapshot = Vec<crate::support::durable_state::PostgresRowsSnapshot>;

/// Both distinct candidates are authenticated against one genuine positive
/// escrow before any writer runs. After the first claim commits, the other
/// signed old-generation claim is an actual ordered refusal, not a forged
/// output fixture or an unauthenticated proposal rejected before ordering.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_economic_history(
    fixture: &FastVoteGenesisFixture,
    pool: &AdminPool,
    namespaces: &[PostgresNamespace],
    data_dir: &Path,
    genesis: &Path,
    network: &Path,
    hosts: &[HostProcess],
    escrow: [u8; 32],
) -> [[u8; 32]; 2] {
    use crate::support::fee_claim_candidate::{ClaimRequest, prepare};
    use node_core::fee_claims;
    use node_core::ordered_economics::{OrderedCandidate, OrderedOutcome};
    use runtime_postgres::PostgresBlobStore;

    let durable: Store = store(pool, &namespaces[0]);
    let blobs: PostgresBlobStore<r2d2_postgres::PostgresConnectionManager<postgres::NoTls>> =
        PostgresBlobStore::new(pool.clone(), namespaces[0].clone()).unwrap();
    let context: DurableOperationContext = read_context(pool, &namespaces[0]);
    let before: fee_claims::FeeEscrowInspection = fee_claims::inspect_fee_escrow(
        &durable,
        &blobs,
        &context,
        fixture.domain,
        &fixture.resolver,
        &[],
        &fixture.context,
        escrow,
    )
    .unwrap();
    let claimant: ValidatorId = before
        .claimants
        .iter()
        .find(|claim| claim.amount > 0 && !claim.claimed)
        .unwrap()
        .validator_id;
    let candidates: Vec<OrderedCandidate> = [CLAIM_REQUEST, REFUSAL_REQUEST]
        .into_iter()
        .map(|request| {
            prepare(
                pool,
                &namespaces[0],
                fixture,
                ClaimRequest {
                    escrow,
                    claimant,
                    request,
                    recipient: objects::Address::new(fixture.sender),
                    checkpoint: None,
                },
            )
        })
        .collect();
    let mut after_claim: Option<Vec<u8>> = None;
    for (index, candidate) in candidates.iter().enumerate() {
        let path: PathBuf = temp_file(data_dir, &format!("history-claim-{index}.candidate"));
        write_new(
            &path,
            &node_core::ordered_economics::encode_ordered_candidate(candidate).unwrap(),
        );
        let prefix: PathBuf = temp_file(data_dir, &format!("history-claim-{index}.network"));
        require_success(
            ordered_command(
                fixture,
                network,
                genesis,
                "network-submit",
                &[
                    "--candidate",
                    path.to_str().unwrap(),
                    "--out",
                    prefix.to_str().unwrap(),
                ],
            ),
            "genuine ordered positive claim / signed stale refusal",
        );
        let deadline: Instant = Instant::now() + std::time::Duration::from_secs(10);
        let mut first: Option<OrderedOutcome> = None;
        for host in hosts {
            let bytes: Vec<u8> = successful_body(
                request(
                    host.addr,
                    Method::Get,
                    &format!(
                        "{}{}",
                        node_wire::ordered_economics::ORDERED_ECONOMICS_OUTCOME_PATH_PREFIX,
                        to_hex(&candidate.request_id)
                    ),
                    None,
                    Vec::new(),
                    deadline,
                ),
                node_wire::ordered_economics::ORDERED_OUTCOME_MEDIA_TYPE,
            );
            let outcome: OrderedOutcome =
                node_core::ordered_economics::decode_ordered_outcome(&bytes).unwrap();
            assert_eq!(outcome.request_id, candidate.request_id);
            assert_eq!(outcome.output.responses().len(), 1);
            assert_eq!(
                outcome.output.responses()[0].status(),
                if index == 0 {
                    node_core::NodeResponseStatus::Accepted
                } else {
                    node_core::NodeResponseStatus::Rejected
                }
            );
            if index == 1 {
                assert_eq!(
                    node_core::ordered_economics::decode_ordered_refusal_payload(
                        outcome.output.responses()[0].payload().unwrap(),
                    )
                    .unwrap(),
                    node_core::ordered_economics::OrderedRefusal::StaleGeneration
                );
            }
            if let Some(expected) = &first {
                assert_eq!(&outcome, expected);
            } else {
                first = Some(outcome);
            }
        }
        let inspection: fee_claims::FeeEscrowInspection = fee_claims::inspect_fee_escrow(
            &durable,
            &blobs,
            &context,
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.context,
            escrow,
        )
        .unwrap();
        assert!(
            inspection
                .claimants
                .iter()
                .find(|claim| claim.validator_id == claimant)
                .unwrap()
                .claimed
        );
        if let Some(expected) = &after_claim {
            assert_eq!(
                &inspection.canonical_settlement, expected,
                "the stale signed refusal must not claim or charge the escrow again"
            );
        } else {
            assert_ne!(inspection.canonical_settlement, before.canonical_settlement);
            after_claim = Some(inspection.canonical_settlement);
        }
    }
    [CLAIM_REQUEST, REFUSAL_REQUEST]
}

fn request(
    addr: SocketAddr,
    method: Method,
    path: &str,
    media: Option<&'static str>,
    body: Vec<u8>,
    deadline: Instant,
) -> WireResponse {
    publication_client(addr)
        .transport()
        .send(&WireRequest {
            method,
            path: path.to_owned(),
            content_type: media,
            body,
            deadline: Some(deadline),
        })
        .unwrap()
}

fn successful_body(response: WireResponse, media: &str) -> Vec<u8> {
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.content_type.as_deref(), Some(media));
    response.body
}

/// The three surviving old-set validators advance a bounded empty suffix
/// through the existing protocol. The absent validator is not replaced by
/// a synthetic vote or hand-picked leader. Unsigned status chooses a view
/// only when independently verified high QCs and a registered voting quorum
/// report it; missing-leader views advance only via real trusted-clock Tick.
fn advance_empty_history(
    peers: &[(ValidatorId, SocketAddr)],
    policy: &OrderedEconomicsPolicy,
    rounds: usize,
) {
    use node_wire::ordered_economics::*;

    let verifier: consensus::Ed25519ConsensusVerifier = consensus::Ed25519ConsensusVerifier::new(
        consensus::UnsupportedSignatureSchemeResponse::FastPathProfileError,
    );
    let overall: Instant = Instant::now() + std::time::Duration::from_secs(90);
    for _ in 0..rounds {
        let mut chosen: Option<(ValidatorId, SocketAddr, u64)> = None;
        for _ in 0..128 {
            assert!(Instant::now() < overall, "empty history progress timed out");
            let mut powers: BTreeMap<u64, u64> = BTreeMap::new();
            for (id, addr) in peers {
                let bytes: Vec<u8> = successful_body(
                    request(
                        *addr,
                        Method::Get,
                        ORDERED_ECONOMICS_STATUS_PATH,
                        None,
                        Vec::new(),
                        overall,
                    ),
                    ORDERED_STATUS_MEDIA_TYPE,
                );
                let status: OrderedStatus =
                    node_core::ordered_economics::decode_ordered_status(&bytes).unwrap();
                policy
                    .engine()
                    .verify_certificate(&status.high_qc, &verifier)
                    .unwrap();
                assert!(status.current_view > status.high_qc.view);
                let power: u64 = policy
                    .engine()
                    .validator_set()
                    .get(*id)
                    .unwrap()
                    .voting_power;
                let total: &mut u64 = powers.entry(status.current_view).or_default();
                *total = total.checked_add(power).unwrap();
            }
            if let Some(view) = powers.into_iter().rev().find_map(|(view, power)| {
                (power >= policy.engine().validator_set().quorum_threshold()).then_some(view)
            }) {
                let leader: ValidatorId = policy.engine().validator_set().leader(view).unwrap();
                if let Some((_, addr)) = peers.iter().find(|(id, _)| *id == leader) {
                    chosen = Some((leader, *addr, view));
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
            for (_, addr) in peers {
                let output: Vec<u8> = successful_body(
                    request(
                        *addr,
                        Method::Post,
                        ORDERED_ECONOMICS_TICK_PATH,
                        None,
                        Vec::new(),
                        overall,
                    ),
                    ORDERED_EVENT_OUTPUT_MEDIA_TYPE,
                );
                node_core::ordered_economics::decode_ordered_event_output(&output).unwrap();
            }
        }
        let (leader, addr, view): (ValidatorId, SocketAddr, u64) =
            chosen.expect("a real registered quorum must route the surviving leader");
        let proposal_bytes: Vec<u8> = successful_body(
            request(
                addr,
                Method::Post,
                ORDERED_ECONOMICS_PROPOSE_PATH,
                Some(ORDERED_PROPOSE_REQUEST_MEDIA_TYPE),
                OrderedProposeRequest { candidate: None }.encode().unwrap(),
                overall,
            ),
            ORDERED_PROPOSAL_MEDIA_TYPE,
        );
        let proposal: OrderedProposal =
            node_core::ordered_economics::decode_ordered_proposal(&proposal_bytes).unwrap();
        assert_eq!(proposal.proposal.leader, leader);
        assert_eq!(proposal.proposal.view, view);
        assert!(proposal.candidate.is_none());
        assert!(proposal.proposal.transactions.is_empty());
        policy
            .engine()
            .verify_proposal(&proposal.proposal, &verifier)
            .unwrap();
        let digest: protocol_types::Digest32 =
            policy.engine().proposal_digest(&proposal.proposal).unwrap();
        let mut votes: Vec<ConsensusVote> = Vec::new();
        for (id, peer_addr) in peers {
            let body: Vec<u8> = successful_body(
                request(
                    *peer_addr,
                    Method::Post,
                    ORDERED_ECONOMICS_PROPOSAL_PATH,
                    Some(ORDERED_PROPOSAL_MEDIA_TYPE),
                    proposal_bytes.clone(),
                    overall,
                ),
                ORDERED_EVENT_OUTPUT_MEDIA_TYPE,
            );
            let output: OrderedEventOutput =
                node_core::ordered_economics::decode_ordered_event_output(&body).unwrap();
            let vote: ConsensusVote = output
                .messages
                .iter()
                .find_map(|message: &ConsensusMessage| match message {
                    ConsensusMessage::Vote(vote)
                        if vote.validator == *id
                            && vote.view == view
                            && vote.height == proposal.proposal.height
                            && vote.proposal_digest == digest =>
                    {
                        Some(vote.clone())
                    }
                    _ => None,
                })
                .expect("every healthy survivor returns its own real empty proposal vote");
            policy.engine().verify_vote(&vote, &verifier).unwrap();
            votes.push(vote);
        }
        let certificate: QuorumCertificate = policy
            .engine()
            .certificate_from_votes(&proposal.proposal, &votes, &verifier)
            .unwrap()
            .expect("three real survivor votes reach the registered quorum");
        let certificate_bytes: Vec<u8> =
            consensus::encode_quorum_certificate(&certificate).unwrap();
        for (_, peer_addr) in peers {
            let body: Vec<u8> = successful_body(
                request(
                    *peer_addr,
                    Method::Post,
                    ORDERED_ECONOMICS_CERTIFICATE_PATH,
                    Some(ORDERED_CERTIFICATE_MEDIA_TYPE),
                    certificate_bytes.clone(),
                    overall,
                ),
                ORDERED_EVENT_OUTPUT_MEDIA_TYPE,
            );
            node_core::ordered_economics::decode_ordered_event_output(&body).unwrap();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn history_command(
    fixture: &FastVoteGenesisFixture,
    network: &Path,
    genesis: &Path,
    source: ValidatorId,
    directory: &Path,
    cap: &str,
    pins: Option<(u64, protocol_types::Digest32)>,
    chunk_bytes: u32,
) -> Output {
    let mut extra: Vec<String> = vec![
        "--target-validator-id".to_owned(),
        source.to_string(),
        "--out-dir".to_owned(),
        directory.to_str().unwrap().to_owned(),
        "--history-max-heights".to_owned(),
        cap.to_owned(),
        "--history-chunk-bytes".to_owned(),
        chunk_bytes.to_string(),
    ];
    if let Some((height, digest)) = pins {
        extra.extend([
            "--history-through-height".to_owned(),
            height.to_string(),
            "--history-through-digest".to_owned(),
            to_hex(&digest.bytes()),
        ]);
    }
    let borrowed: Vec<&str> = extra.iter().map(String::as_str).collect();
    ordered_command(fixture, network, genesis, "history-export", &borrowed)
}

fn sql_snapshots(pool: &AdminPool, namespaces: &[PostgresNamespace]) -> SqlSnapshot {
    namespaces
        .iter()
        .map(|namespace: &PostgresNamespace| {
            crate::support::durable_state::postgres_rows_snapshot(pool, namespace)
        })
        .collect()
}

fn files(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, path: &Path, saved: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries: Vec<PathBuf> = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for entry in entries {
            if entry.is_dir() {
                walk(root, &entry, saved);
            } else {
                saved.insert(
                    entry.strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry).unwrap(),
                );
            }
        }
    }
    let mut saved: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    walk(directory, directory, &mut saved);
    saved
}

fn saved_material(
    directory: &Path,
    height: u64,
) -> node_core::ordered_economics::OrderedHistoryHeightMaterial {
    use node_core::ordered_economics::{
        OrderedHistoryHeightDescriptor, OrderedHistoryHeightMaterial,
        decode_ordered_history_height_descriptor,
    };
    let height_dir: PathBuf = directory.join(format!("height-{height:020}"));
    let setting: [u8; 4] = fs::read(directory.join("chunk-size.bin"))
        .unwrap()
        .try_into()
        .unwrap();
    let chunk_bytes: usize = usize::try_from(u32::from_be_bytes(setting)).unwrap();
    assert!(
        chunk_bytes > 0
            && chunk_bytes <= node_core::ordered_economics::MAX_ORDERED_HISTORY_CHUNK_BYTES
    );
    let descriptor: OrderedHistoryHeightDescriptor = decode_ordered_history_height_descriptor(
        &fs::read(height_dir.join("descriptor.bin")).unwrap(),
    )
    .unwrap();
    let components: Vec<(
        node_core::ordered_economics::OrderedHistoryComponentKind,
        Vec<u8>,
    )> = descriptor
        .components
        .iter()
        .map(|reference| {
            let component_dir: PathBuf =
                height_dir.join(format!("component-{:02}", reference.kind as u16));
            let mut entries: Vec<PathBuf> = fs::read_dir(component_dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            entries.sort();
            let mut bytes: Vec<u8> = Vec::new();
            for entry in entries {
                assert_eq!(
                    entry.file_name().unwrap().to_str().unwrap(),
                    format!("chunk-{:020}.bin", bytes.len())
                );
                let chunk: Vec<u8> = fs::read(entry).unwrap();
                let remaining: usize = usize::try_from(reference.length)
                    .unwrap()
                    .checked_sub(bytes.len())
                    .expect("saved chunks cannot exceed the descriptor length");
                assert!(!chunk.is_empty());
                assert_eq!(chunk.len(), chunk_bytes.min(remaining));
                bytes.extend(chunk);
            }
            assert_eq!(bytes.len() as u64, reference.length);
            (reference.kind, bytes)
        })
        .collect();
    OrderedHistoryHeightMaterial {
        descriptor,
        components,
    }
}

/// Re-examine files through the independent core verifier, rather than
/// accepting the command's exit status, a saved cursor or a `complete` name.
fn verify_saved(
    policy: &OrderedEconomicsPolicy,
    directory: &Path,
    complete: bool,
) -> node_core::ordered_economics::OrderedHistoryIdentity {
    use node_core::ordered_economics::{
        OrderedHistoryComponentKind, OrderedHistoryIdentity, OrderedHistoryVerifier,
        decode_ordered_candidate, decode_ordered_history_identity,
    };
    let identity_bytes: Vec<u8> = fs::read(directory.join("identity.bin")).unwrap();
    let identity: OrderedHistoryIdentity =
        decode_ordered_history_identity(&identity_bytes).unwrap();
    let mut verifier: OrderedHistoryVerifier =
        OrderedHistoryVerifier::new(policy.clone(), identity.clone()).unwrap();
    let mut claims: Vec<[u8; 32]> = Vec::new();
    let limit: u64 = if complete { identity.through_height } else { 1 };
    for height in 1..=limit {
        let material: node_core::ordered_economics::OrderedHistoryHeightMaterial =
            saved_material(directory, height);
        verifier.verify_next_height(&material).unwrap();
        if let Some((_, bytes)) = material
            .components
            .iter()
            .find(|(kind, _)| *kind == OrderedHistoryComponentKind::Candidate)
        {
            claims.push(decode_ordered_candidate(bytes).unwrap().request_id);
        }
    }
    if complete {
        let verified: node_core::ordered_economics::VerifiedOrderedHistory =
            verifier.finish().unwrap();
        assert!(
            verified.target_is_empty_three_chain(),
            "only describes the verified target"
        );
        assert_eq!(
            fs::read(directory.join("complete")).unwrap(),
            identity_bytes
        );
        assert!(claims.contains(&CLAIM_REQUEST) && claims.contains(&REFUSAL_REQUEST));
        assert!(claims.contains(&FREEZE_REQUEST));
    } else {
        assert!(verifier.finish().is_err());
        assert!(!directory.join("complete").exists());
    }
    identity
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn run(
    fixture: &FastVoteGenesisFixture,
    pool: &AdminPool,
    namespaces: &[PostgresNamespace],
    data_dir: &Path,
    ca_path: &Path,
    dsn: &str,
    genesis: &Path,
    digest: &str,
    source_key: &Path,
    hosts: &[HostProcess],
    source: HostProcess,
) {
    use node_core::ordered_economics::{OrderedHistoryIdentity, decode_ordered_history_identity};
    use runtime::DurableDomainStateStore;

    let source_id: ValidatorId = fixture.validators[3].validator_id;
    let policy: OrderedEconomicsPolicy =
        sunrise_edge_client::ordered_economics_client::load_trusted_ordered_policy(
            genesis,
            &fixture.resolver,
            fixture.manifest_digest,
            &fixture.context,
            fixture.domain,
        )
        .unwrap();
    let peers: Vec<(ValidatorId, SocketAddr)> = vec![
        (fixture.validators[1].validator_id, hosts[0].addr),
        (fixture.validators[2].validator_id, hosts[1].addr),
        (source_id, source.addr),
    ];
    advance_empty_history(&peers, &policy, 4);
    let network: PathBuf = temp_file(data_dir, "history-source.conf");
    fs::write(&network, format!("{source_id} {} - -\n", source.addr)).unwrap();
    let directory: PathBuf = temp_file(data_dir, "ordered-history-export");
    let before: SqlSnapshot = sql_snapshots(pool, namespaces);
    let partial: Output = history_command(
        fixture, &network, genesis, source_id, &directory, "1", None, 1024,
    );
    require_success(
        partial,
        "bounded history invocation reports a genuine partial prefix",
    );
    assert_eq!(
        fs::read(directory.join("chunk-size.bin")).unwrap(),
        1024_u32.to_be_bytes(),
        "partial/restarted exports retain the deliberately small chunk setting"
    );
    let fixed: OrderedHistoryIdentity = verify_saved(&policy, &directory, false);
    assert!(fixed.through_height >= 10);
    assert_eq!(
        sql_snapshots(pool, namespaces),
        before,
        "partial source export changes no PostgreSQL row or revision"
    );
    let original: BTreeMap<PathBuf, Vec<u8>> = files(&directory);
    let first: node_core::ordered_economics::OrderedHistoryHeightMaterial =
        saved_material(&directory, 1);
    let mut state_key: Vec<u8> = b"se/instances/v1/ordered-economics/state/".to_vec();
    state_key.extend(canonical_encoding::encode_chain_id(&fixture.chain_id).unwrap());
    let durable: Store = store(pool, &namespaces[3]);
    let state: runtime::VersionedStateValue = durable
        .get_versioned_durable(
            &read_context(pool, &namespaces[3]),
            fixture.domain,
            &state_key,
        )
        .unwrap();
    let consensus_state: consensus::ConsensusState =
        consensus::decode_consensus_state(state.value().unwrap()).unwrap();
    assert!(
        consensus_state
            .known_proposal(&first.descriptor.block_digest)
            .is_none(),
        "history must remain exportable after actual live proposal pruning"
    );

    drop(source);
    let reopened: HostProcess = spawn_ordered_host(
        ca_path,
        dsn,
        &fixture.chain_id.to_string(),
        &source_id.to_string(),
        &fixture.domain.to_string(),
        genesis,
        digest,
        source_key,
        "127.0.0.1:0",
    );
    fs::write(&network, format!("{source_id} {} - -\n", reopened.addr)).unwrap();
    let advanced_peers: Vec<(ValidatorId, SocketAddr)> =
        vec![peers[0], peers[1], (source_id, reopened.addr)];
    advance_empty_history(&advanced_peers, &policy, 3);
    let after_restart: SqlSnapshot = sql_snapshots(pool, namespaces);
    for _ in 0..64 {
        require_success(
            history_command(
                fixture, &network, genesis, source_id, &directory, "1", None, 1024,
            ),
            "compiled CLI resumes the original fixed target after real source restart / progress",
        );
        if directory.join("complete").exists() {
            break;
        }
    }
    assert_eq!(
        verify_saved(&policy, &directory, true),
        fixed,
        "source progress must never silently repin an incomplete export"
    );
    for (path, bytes) in &original {
        assert_eq!(&fs::read(directory.join(path)).unwrap(), bytes);
    }
    assert_eq!(sql_snapshots(pool, namespaces), after_restart);
    let completed: BTreeMap<PathBuf, Vec<u8>> = files(&directory);
    require_success(
        history_command(
            fixture, &network, genesis, source_id, &directory, "1", None, 1024,
        ),
        "same-boot completed CLI resume re-verifies immutable saved material",
    );
    assert_eq!(files(&directory), completed);
    assert_eq!(sql_snapshots(pool, namespaces), after_restart);

    let mismatch: Output = history_command(
        fixture,
        &network,
        genesis,
        source_id,
        &directory,
        "1",
        Some((
            fixed.through_height.checked_add(1).unwrap(),
            fixed.through_digest,
        )),
        1024,
    );
    assert!(
        !mismatch.status.success(),
        "changed explicit target refuses saved identity"
    );
    assert_eq!(files(&directory), completed);
    assert_eq!(sql_snapshots(pool, namespaces), after_restart);
    let tampered: PathBuf = temp_file(data_dir, "history-tampered");
    fs::create_dir(&tampered).unwrap();
    for (path, bytes) in &completed {
        if path == Path::new("complete") {
            continue;
        }
        fs::create_dir_all(tampered.join(path).parent().unwrap()).unwrap();
        fs::write(tampered.join(path), bytes).unwrap();
    }
    let chunk: PathBuf =
        tampered.join("height-00000000000000000001/component-01/chunk-00000000000000000000.bin");
    let mut bad: Vec<u8> = fs::read(&chunk).unwrap();
    bad[0] ^= 1;
    fs::write(chunk, bad).unwrap();
    let corrupt_files: BTreeMap<PathBuf, Vec<u8>> = files(&tampered);
    let corrupt: Output = history_command(
        fixture, &network, genesis, source_id, &tampered, "64", None, 1024,
    );
    assert!(
        !corrupt.status.success(),
        "changed saved canonical proof must refuse"
    );
    assert!(!tampered.join("complete").exists());
    assert_eq!(
        files(&tampered),
        corrupt_files,
        "failed resume never overwrites corrupt evidence"
    );
    assert_eq!(sql_snapshots(pool, namespaces), after_restart);

    // Actual second host boot advances this namespace's writer generation.
    // The still-running predecessor must fail its source read, without a
    // restart shortcut or a manufactured context / fencing record.
    let rival: HostProcess = spawn_ordered_host(
        ca_path,
        dsn,
        &fixture.chain_id.to_string(),
        &source_id.to_string(),
        &fixture.domain.to_string(),
        genesis,
        digest,
        source_key,
        "127.0.0.1:0",
    );
    let after_fence: SqlSnapshot = sql_snapshots(pool, namespaces);
    let stale: WireResponse = request(
        reopened.addr,
        Method::Get,
        "/v1/ordered-economics/history/summary",
        None,
        Vec::new(),
        Instant::now() + std::time::Duration::from_secs(10),
    );
    assert_eq!(stale.status, 503);
    let stale_dir: PathBuf = temp_file(data_dir, "history-stale-source");
    assert!(
        !history_command(
            fixture, &network, genesis, source_id, &stale_dir, "64", None, 1024
        )
        .status
        .success()
    );
    assert!(!stale_dir.join("complete").exists());
    assert_eq!(sql_snapshots(pool, namespaces), after_fence);
    fs::write(&network, format!("{source_id} {} - -\n", rival.addr)).unwrap();
    let fresh: PathBuf = temp_file(data_dir, "history-fresh-source");
    // The separate fresh-source positive control uses the real CLI's normal
    // one-MiB transfer size. Tiny chunks and fixed-target interruption/resume
    // remain exercised above without turning this control into a load test
    // or increasing any production/test operation deadline.
    require_success(
        history_command(
            fixture,
            &network,
            genesis,
            source_id,
            &fresh,
            "64",
            None,
            1024 * 1024,
        ),
        "newly fenced active host serves genuine fresh HTTP history after restart",
    );
    assert_eq!(
        fs::read(fresh.join("chunk-size.bin")).unwrap(),
        (1024_u32 * 1024).to_be_bytes()
    );
    let newer: OrderedHistoryIdentity = verify_saved(&policy, &fresh, true);
    assert!(newer.through_height > fixed.through_height);
    let newer_bytes: Vec<u8> = fs::read(fresh.join("identity.bin")).unwrap();
    assert_eq!(
        decode_ordered_history_identity(&newer_bytes).unwrap(),
        newer
    );
    assert_eq!(
        sql_snapshots(pool, namespaces),
        after_fence,
        "source reads preserve every application, signing safety and metadata row"
    );
    drop(rival);
    drop(reopened);
}
