//! Real DR-0168 continuation of the ordinary contract/Freeze fixture. Only
//! actual HTTP transitions and the separately compiled CLI create authority.

use super::*;
use consensus::{FrozenFrontierCertifier, FrozenFrontierPage, FrozenFrontierVote};
use runtime::{
    DurableDomainStateStore, DurableRequestId, DurableStateKeyScanner, StateKeyScan,
    StructuredDurableDomainStateStore, VersionedStateValue,
};
use std::num::NonZeroUsize;
use sunrise_edge_client::fastvote_drain_client::ExpectedDrainFreeze;

pub(super) const CONFLICTING_REQUEST: [u8; 32] = [0xBE; 32];
const DRAIN_SET_REQUEST: [u8; 32] = [0xD5; 32];

/// D honestly prepares a different request at the same fee-object version
/// and sender nonce. It has no full certificate, receipt or application.
pub(super) fn prepare_conflicting_partial(
    fixture: &FastVoteGenesisFixture,
    host: &HostProcess,
    original: &SignedPaidIntent,
) {
    let mut intent: execution::paid_execution::PaidIntent = original.intent.clone();
    intent.request_id = CONFLICTING_REQUEST;
    let PaidApplication::Call(call) = &mut intent.application else {
        panic!("the outstanding member is an ordinary paid Call");
    };
    call.request_id = CONFLICTING_REQUEST;
    let vote: FastVote = publication_client(host.addr)
        .prepare_fastvote(&fixture.sign_intent(intent), None)
        .unwrap();
    assert_eq!(vote.validator, fixture.validators[3].validator_id);
}

fn drain_command(
    fixture: &FastVoteGenesisFixture,
    network: &Path,
    genesis: &Path,
    action: &str,
    extra: &[&str],
) -> Output {
    let mut args: Vec<OsString> = [
        "contract",
        action,
        "--fastvote-network",
        network.to_str().unwrap(),
        "--fastvote-genesis-manifest",
        genesis.to_str().unwrap(),
        "--fastvote-expected-genesis-digest",
        &to_hex(&fixture.manifest_digest),
        "--expected-chain-id",
        &fixture.chain_id.to_string(),
        "--expected-protocol-version",
        &fixture.protocol_version.get().to_string(),
        "--expected-epoch",
        &fixture.epoch.get().to_string(),
        "--expected-hash-suite-id",
        "1",
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
    args.extend(extra.iter().map(OsString::from));
    edge_cli_command(args).output().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn ready_command(
    fixture: &FastVoteGenesisFixture,
    network: &Path,
    artifact_network: &Path,
    genesis: &Path,
    selection: &Path,
    target: ValidatorId,
    height: u64,
    attempts: &str,
    identity_out: &Path,
) -> Output {
    drain_command(
        fixture,
        network,
        genesis,
        "fastvote-drain-local-ready",
        &[
            "--target-validator",
            &target.to_string(),
            "--drain-selection-manifest",
            selection.to_str().unwrap(),
            "--drain-freeze-request-id",
            &to_hex(&FREEZE_REQUEST),
            "--drain-freeze-height",
            &height.to_string(),
            "--drain-page-limit",
            "128",
            "--drain-max-mutation-attempts",
            attempts,
            "--drain-artifact-network",
            artifact_network.to_str().unwrap(),
            "--out-drain-union-identity",
            identity_out.to_str().unwrap(),
        ],
    )
}

fn write_subset_network(
    path: &Path,
    fixture: &FastVoteGenesisFixture,
    hosts: &[HostProcess],
    indices: &[usize],
) {
    let bytes: String = indices
        .iter()
        .map(|index: &usize| -> String {
            format!(
                "{} {} - -\n",
                fixture.validators[*index].validator_id, hosts[*index].addr
            )
        })
        .collect();
    // These files are disposable transport locators, not signed authority.
    fs::write(path, bytes).unwrap();
}

fn locks_except_member(
    fixture: &FastVoteGenesisFixture,
    pool: &AdminPool,
    namespace: &PostgresNamespace,
) -> Vec<(Vec<u8>, VersionedStateValue)> {
    let store: Store = store(pool, namespace);
    let context: DurableOperationContext = read_context(pool, namespace);
    let needed: [Vec<u8>; 2] = [
        node_core::local_instance_state::fastpath_lock_key(&fixture.chain_id, fixture.fee_coin)
            .unwrap(),
        node_core::local_instance_state::fastpath_nonce_lock_key(
            &fixture.chain_id,
            &fixture.sender,
            fixture.epoch,
        )
        .unwrap(),
    ];
    let mut rows: Vec<(Vec<u8>, VersionedStateValue)> = Vec::new();
    for prefix in [
        b"se/instances/v1/fastpath/lock/".as_slice(),
        b"se/instances/v1/fastpath/nonce-lock/".as_slice(),
    ] {
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page: runtime::StateKeyPage = store
                .scan_durable_keys(
                    &context,
                    fixture.domain,
                    &StateKeyScan::new(prefix.to_vec(), after, NonZeroUsize::new(128).unwrap())
                        .unwrap(),
                )
                .unwrap();
            for key in page.keys() {
                if !needed.contains(key) {
                    rows.push((
                        key.clone(),
                        store
                            .get_versioned_durable(&context, fixture.domain, key)
                            .unwrap(),
                    ));
                }
            }
            after = page.continuation_cursor().map(<[u8]>::to_vec);
            if after.is_none() {
                break;
            }
        }
    }
    rows
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
    network: &Path,
    validator_hex: &[String],
    key_paths: [&Path; 4],
    mut hosts: Vec<HostProcess>,
    ids: &BTreeSet<ObjectId>,
    requests: &[[u8; 32]],
    publications: &[PackageOrigin],
    height: u64,
    unapplied: &SignedPaidIntent,
    certificate: &FastCertificate,
    unapplied_identity: &AvailabilityIdentity,
) {
    let trusted: TrustedFastVoteGenesis =
        sunrise_edge_client::load_trusted_fastvote_genesis_with_profile(
            genesis,
            &fixture.resolver,
            fixture.manifest_digest,
            &fixture.context,
        )
        .unwrap();
    let certifier: FrozenFrontierCertifier = FrozenFrontierCertifier::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        trusted.certifier.validator_set().clone(),
    )
    .unwrap();
    let mut selected: Vec<(usize, FrozenFrontierVote)> = (0..3)
        .map(|index: usize| {
            let bytes: Vec<u8> = fs::read(temp_file(
                data_dir,
                &format!("resumed-frontier-{index}.vote"),
            ))
            .unwrap();
            (
                index,
                consensus::decode_frozen_frontier_vote(&bytes).unwrap(),
            )
        })
        .collect();
    selected.sort_by_key(|(_, vote)| vote.validator);
    let selection: PathBuf = temp_file(data_dir, "drain.selection");
    let selection_text: String = selected
        .iter()
        .map(|(index, _)| -> String {
            format!(
                "{}\n",
                temp_file(data_dir, &format!("resumed-frontier-{index}.vote")).display()
            )
        })
        .collect();
    write_new(&selection, selection_text.as_bytes());
    let original_application: Vec<String> =
        application_snapshots(fixture, pool, namespaces, ids, requests, publications);
    let mut identities: Vec<PathBuf> = Vec::new();
    for index in 0..3 {
        let identity: PathBuf = temp_file(data_dir, &format!("drain-ready-{index}.identity"));
        require_success(
            ready_command(
                fixture,
                network,
                network,
                genesis,
                &selection,
                fixture.validators[index].validator_id,
                height,
                "512",
                &identity,
            ),
            "quorum voter independently retains complete drain material",
        );
        assert!(identity.exists());
        if let Some(previous) = identities.first() {
            assert_eq!(fs::read(previous).unwrap(), fs::read(&identity).unwrap());
        }
        identities.push(identity);
    }
    let union: consensus::DrainUnionIdentity =
        consensus::decode_drain_union_identity(&fs::read(&identities[0]).unwrap()).unwrap();
    assert_eq!(union.member_count, 12);
    assert_eq!(union.signer_count, 3);

    // D receives all exact terminal pages while A is still responsive, but
    // not their proof material. No forged cursor or local readiness is seeded.
    let target: Client<LoopbackHttpTransport> = publication_client(hosts[3].addr);
    let freeze: ExpectedDrainFreeze = ExpectedDrainFreeze {
        domain: fixture.domain,
        closure_request_id: FREEZE_REQUEST,
        closure_height: height,
    };
    for (index, expected_vote) in &selected {
        let (vote, page): (FrozenFrontierVote, FrozenFrontierPage) =
            publication_client(hosts[*index].addr)
                .fetch_signed_frozen_frontier_page(
                    &node_wire::FrozenFrontierPageRequest {
                        epoch: fixture.epoch,
                        after_request_id: None,
                        limit: 128,
                    },
                    &certifier,
                    expected_vote.validator,
                    None,
                )
                .unwrap();
        assert_eq!(&vote, expected_vote);
        assert!(page.terminal);
        target
            .stage_drain_signer_page(&certifier, vote.validator, freeze, &vote, &page, None)
            .unwrap();
    }
    let target_identity: PathBuf = temp_file(data_dir, "drain-ready-3.identity");
    let partial: Output = ready_command(
        fixture,
        network,
        network,
        genesis,
        &selection,
        fixture.validators[3].validator_id,
        height,
        "1",
        &target_identity,
    );
    assert!(
        !partial.status.success(),
        "one mutation must report bounded incomplete readiness"
    );
    assert!(!target_identity.exists());
    let partial_rows: Vec<String> =
        all_snapshots(fixture, pool, namespaces, ids, requests, publications);
    drop(hosts.pop().unwrap());
    hosts.push(spawn_ordered_host(
        ca_path,
        dsn,
        &fixture.chain_id.to_string(),
        &validator_hex[3],
        &fixture.domain.to_string(),
        genesis,
        digest,
        key_paths[3],
        "127.0.0.1:0",
    ));
    write_network_config(network, fixture, &hosts);
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, requests, publications),
        partial_rows,
        "real D reopen preserves partial material and every staged page revision"
    );

    let abc_network: PathBuf = temp_file(data_dir, "drain-abc.network");
    write_subset_network(&abc_network, fixture, &hosts, &[0, 1, 2]);
    let candidate: PathBuf = temp_file(data_dir, "drain.candidate");
    // Unlike submission, the offline builder consumes no network/deadline flags.
    let built: Output = edge_cli_command(
        [
            "economics",
            "drain-set-build",
            "--drain-selection-manifest",
            selection.to_str().unwrap(),
            "--drain-union-identity",
            identities[0].to_str().unwrap(),
            "--request-id",
            &to_hex(&DRAIN_SET_REQUEST),
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
            genesis.to_str().unwrap(),
            "--ordered-expected-genesis-digest",
            digest,
            "--out",
            candidate.to_str().unwrap(),
        ]
        .into_iter()
        .map(OsString::from),
    )
    .output()
    .unwrap();
    require_success(built, "build exact locally reconstructed DrainSet");
    let submission: PathBuf = temp_file(data_dir, "drain-network");
    require_success(
        ordered_command(
            fixture,
            &abc_network,
            genesis,
            "network-submit",
            &[
                "--candidate",
                candidate.to_str().unwrap(),
                "--out",
                submission.to_str().unwrap(),
            ],
        ),
        "normally commit DrainSet with the three complete proof holders",
    );
    assert_eq!(
        application_snapshots(fixture, pool, namespaces, ids, requests, publications),
        original_application,
        "readiness and ordered DrainSet must not apply any user member"
    );

    let target_store: Store = store(pool, &namespaces[3]);
    let target_context: DurableOperationContext = read_context(pool, &namespaces[3]);
    let member_key: Vec<u8> = node_core::fast_path::drain_publication::drain_publication_key(
        &fixture.chain_id,
        fixture.epoch,
        &UNAPPLIED_REQUEST,
    )
    .unwrap();
    assert!(
        target_store
            .get_versioned_durable(&target_context, fixture.domain, &member_key)
            .unwrap()
            .value()
            .is_none(),
        "D genuinely still lacks the sole-holder member before A fails"
    );

    // A is gone for the remainder. Its descriptor stays selected. Only B/C
    // are now artifact locators; their imported proofs must serve real HTTP.
    drop(hosts.remove(0));
    let relays: PathBuf = temp_file(data_dir, "drain-relays.network");
    let relay_text: String = [1_usize, 2]
        .iter()
        .map(|index| -> String {
            format!(
                "{} {} - -\n",
                fixture.validators[*index].validator_id,
                hosts[*index - 1].addr
            )
        })
        .collect();
    write_new(&relays, relay_text.as_bytes());
    require_success(
        ready_command(
            fixture,
            network,
            &relays,
            genesis,
            &selection,
            fixture.validators[3].validator_id,
            height,
            "512",
            &target_identity,
        ),
        "resume D after original holder failure using imported-proof relays",
    );
    assert_eq!(
        fs::read(&target_identity).unwrap(),
        fs::read(&identities[0]).unwrap()
    );
    let relay: Client<LoopbackHttpTransport> = publication_client(hosts[0].addr);
    let before_source: Vec<String> =
        all_snapshots(fixture, pool, namespaces, ids, requests, publications);
    let bundle: consensus::bundle::PublicationBundle = relay
        .source_retained_fastvote_publication(
            &trusted.certifier,
            &fixture.resolver,
            &[],
            unapplied_identity,
            None,
        )
        .unwrap();
    assert_eq!(
        bundle.signed_intent,
        encode_signed_paid_intent(unapplied).unwrap()
    );
    assert_eq!(&bundle.certificate, certificate);
    let relay_store: Store = store(pool, &namespaces[1]);
    let relay_context: DurableOperationContext = read_context(pool, &namespaces[1]);
    for key in [
        node_core::fast_path::publication::fastpath_publication_key(
            &fixture.chain_id,
            &UNAPPLIED_REQUEST,
        )
        .unwrap(),
        node_core::fast_path::publication::fastpath_availability_ack_key(
            &fixture.chain_id,
            &UNAPPLIED_REQUEST,
        )
        .unwrap(),
    ] {
        assert!(
            relay_store
                .get_versioned_durable(&relay_context, fixture.domain, &key)
                .unwrap()
                .value()
                .is_none(),
            "B's source is an imported proof, never a synthetic pre-Freeze publication or ACK"
        );
    }
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, requests, publications),
        before_source,
        "imported-proof source is read-only and does not manufacture a pre-Freeze ACK"
    );

    let d_network: PathBuf = temp_file(data_dir, "drain-d.network");
    write_new(
        &d_network,
        format!(
            "{} {} - -\n",
            fixture.validators[3].validator_id, hosts[2].addr
        )
        .as_bytes(),
    );
    require_success(
        ordered_command(
            fixture,
            &d_network,
            genesis,
            "network-replay",
            &[
                "--manifest",
                temp_file(data_dir, "drain-network.manifest")
                    .to_str()
                    .unwrap(),
                "--out",
                temp_file(data_dir, "drain-recovery").to_str().unwrap(),
            ],
        ),
        "signerless recovery installs the original committed DrainSet on D",
    );
    let signed_path: PathBuf = temp_file(data_dir, "drain-member.intent");
    write_new(&signed_path, &encode_signed_paid_intent(unapplied).unwrap());
    let result_path: PathBuf = temp_file(data_dir, "drain-member.result");
    let other_locks: Vec<(Vec<u8>, VersionedStateValue)> =
        locks_except_member(fixture, pool, &namespaces[3]);
    let prepared_key: Vec<u8> = node_core::local_instance_state::fastpath_prepared_record_key(
        &fixture.chain_id,
        &CONFLICTING_REQUEST,
    )
    .unwrap();
    let prepared_before: VersionedStateValue = target_store
        .get_versioned_durable(
            &read_context(pool, &namespaces[3]),
            fixture.domain,
            &prepared_key,
        )
        .unwrap();
    assert!(prepared_before.value().is_some());
    let apply_args: [&str; 6] = [
        "--validator-id",
        &validator_hex[3],
        "--signed-intent",
        signed_path.to_str().unwrap(),
        "--out-result",
        result_path.to_str().unwrap(),
    ];
    require_success(
        drain_command(
            fixture,
            network,
            genesis,
            "fastvote-drain-member",
            &apply_args,
        ),
        "explicitly apply the genuine missing certified member against D's conflicting partial locks",
    );
    assert_eq!(
        locks_except_member(fixture, pool, &namespaces[3]),
        other_locks,
        "all non-conflicting object/nonce reservations, including tombstones, remain exact"
    );
    assert_eq!(
        target_store
            .get_versioned_durable(
                &read_context(pool, &namespaces[3]),
                fixture.domain,
                &prepared_key
            )
            .unwrap(),
        prepared_before,
        "no arbitrary deletion of the displaced partial preparation"
    );
    assert!(
        matches!(
            node_core::query_request_receipt(
                &target_store,
                &read_context(pool, &namespaces[3]),
                fixture.domain,
                node_core::RequestId::new(CONFLICTING_REQUEST).unwrap()
            )
            .unwrap(),
            node_core::ReceiptQueryResult::Absent { .. }
        ),
        "uncertified partial request must never acquire a synthetic original receipt"
    );
    let result: Vec<u8> = fs::read(&result_path).unwrap();
    let after_apply: Vec<String> =
        all_snapshots(fixture, pool, namespaces, ids, requests, publications);
    let trapped_signed: SignedPaidIntent =
        decode_signed_paid_intent(&fs::read(temp_file(data_dir, "trap.intent")).unwrap()).unwrap();
    let trapped_receipt: runtime::DurableRequestReceipt = target_store
        .get_request_receipt(
            &read_context(pool, &namespaces[3]),
            fixture.domain,
            DurableRequestId::new(trapped_signed.intent.request_id).unwrap(),
        )
        .unwrap()
        .unwrap();
    let trapped_dedup: node_core::NodeDedupRecord =
        node_core::NodeDedupRecord::decode(trapped_receipt.canonical_bytes()).unwrap();
    let trapped_http: Vec<u8> = node_wire::HttpNodeResult::new(
        trapped_dedup.request_id(),
        trapped_dedup.responses().to_vec(),
    )
    .unwrap()
    .encode()
    .unwrap();
    // Ordinary submission saves the paid payload (0x6415), whereas member
    // application saves the full HTTP receipt (0xE101). Bind both formats to
    // the original durable receipt rather than comparing different wrappers.
    assert_eq!(
        trapped_dedup.responses()[0].payload().unwrap(),
        fs::read(temp_file(data_dir, "trap.result")).unwrap()
    );
    let trapped_result: PathBuf = temp_file(data_dir, "drain-trap-replay.result");
    require_success(
        drain_command(
            fixture,
            network,
            genesis,
            "fastvote-drain-member",
            &[
                "--validator-id",
                &validator_hex[3],
                "--signed-intent",
                temp_file(data_dir, "trap.intent").to_str().unwrap(),
                "--out-result",
                trapped_result.to_str().unwrap(),
            ],
        ),
        "completed charged trap returns its exact original receipt through drain replay",
    );
    assert_eq!(fs::read(trapped_result).unwrap(), trapped_http);
    let mut reused: execution::paid_execution::PaidIntent = unapplied.intent.clone();
    reused.nonce = reused.nonce.checked_add(1).unwrap();
    let PaidApplication::Call(call) = &mut reused.application else {
        unreachable!()
    };
    call.nonce = reused.nonce;
    let reused_path: PathBuf = temp_file(data_dir, "drain-conflicting-reuse.intent");
    write_new(&reused_path, &fixture.sign_intent(reused));
    let refused: Output = drain_command(
        fixture,
        network,
        genesis,
        "fastvote-drain-member",
        &[
            "--validator-id",
            &validator_hex[3],
            "--signed-intent",
            reused_path.to_str().unwrap(),
            "--out-result",
            temp_file(data_dir, "drain-conflicting-reuse.result")
                .to_str()
                .unwrap(),
        ],
    );
    assert!(
        !refused.status.success(),
        "a locator cannot bind a different signed intent to the original receipt"
    );
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, requests, publications),
        after_apply,
        "trap replay and conflicting request reuse preserve all application and local safety rows"
    );
    require_success(
        drain_command(
            fixture,
            network,
            genesis,
            "fastvote-drain-member",
            &apply_args,
        ),
        "same-boot exact drain replay",
    );
    assert_eq!(fs::read(&result_path).unwrap(), result);
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, requests, publications),
        after_apply,
        "same-boot replay changes no fee, nonce, receipt, object/history or local audit revision"
    );
    drop(hosts.pop().unwrap());
    let restarted: HostProcess = spawn_ordered_host(
        ca_path,
        dsn,
        &fixture.chain_id.to_string(),
        &validator_hex[3],
        &fixture.domain.to_string(),
        genesis,
        digest,
        key_paths[3],
        "127.0.0.1:0",
    );
    fs::write(
        &d_network,
        format!(
            "{} {} - -\n",
            fixture.validators[3].validator_id, restarted.addr
        ),
    )
    .unwrap();
    require_success(
        drain_command(
            fixture,
            &d_network,
            genesis,
            "fastvote-drain-member",
            &apply_args,
        ),
        "post-restart exact drain replay",
    );
    assert_eq!(fs::read(&result_path).unwrap(), result);
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, requests, publications),
        after_apply,
        "post-restart replay changes no application or signing-safety bytes/revisions"
    );
    let fresh_result: PathBuf = temp_file(data_dir, "drain-member-fresh-restart.result");
    require_success(
        drain_command(
            fixture,
            &d_network,
            genesis,
            "fastvote-drain-member",
            &[
                "--validator-id",
                &validator_hex[3],
                "--signed-intent",
                signed_path.to_str().unwrap(),
                "--out-result",
                fresh_result.to_str().unwrap(),
            ],
        ),
        "fresh output proves actual post-restart HTTP drain replay",
    );
    assert_eq!(fs::read(fresh_result).unwrap(), result);
    let trapped_restarted_result: PathBuf = temp_file(data_dir, "drain-trap-fresh-restart.result");
    require_success(
        drain_command(
            fixture,
            &d_network,
            genesis,
            "fastvote-drain-member",
            &[
                "--validator-id",
                &validator_hex[3],
                "--signed-intent",
                temp_file(data_dir, "trap.intent").to_str().unwrap(),
                "--out-result",
                trapped_restarted_result.to_str().unwrap(),
            ],
        ),
        "fresh output proves actual post-restart charged-trap HTTP replay",
    );
    assert_eq!(fs::read(trapped_restarted_result).unwrap(), trapped_http);
    assert_eq!(
        all_snapshots(fixture, pool, namespaces, ids, requests, publications),
        after_apply
    );
    super::ordered_history_acceptance::run(
        fixture,
        pool,
        namespaces,
        data_dir,
        ca_path,
        dsn,
        genesis,
        digest,
        key_paths[3],
        &hosts,
        restarted,
    );
    drop(hosts);
}
