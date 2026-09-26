//! DR-0150 missed-prepare evidence: three actual PostgreSQL HTTP hosts certify
//! dependent success/trap/success calls; a fourth actual process joins only
//! afterward and is recovered by the separately executed compiled Rust CLI.
//! The test requires scripts/check-fastvote-pg.sh to build that exact CLI first.
mod support;

use ed25519_zebra::{SigningKey, VerificationKey};
use execution::paid_execution::{
    PaidApplication, PaidIntent, SignedPaidIntent, decode_signed_paid_intent,
};
use node_core::ObjectQueryResult;
use objects::{ObjectId, ObjectRef, Owner};
use postgres::Config;
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{
    DurableDomainStateStore, DurableObjectVersion, DurableStateKeyScanner, PersistenceLayout,
    StateKeyScan, StructuredDurableDomainStateStore,
};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    process::{Command, Output},
    str::FromStr,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use sunrise_edge_client::{
    Client, FastVoteEndpoint, LoopbackHttpTransport, PaidExecutionResult, PaidExecutionStatus,
    apply_fastvote_to_all, collect_fastvote_certificate, encode_fast_certificate,
};
use support::cli::{
    CliContext, admin_pool, current_fee_coin_ref, install_genesis, namespace_init, proxied_dsn,
    read_context, single_tcp_backend_addr, temp_path, to_hex, write_signing_key_file,
};
use support::genesis_fixture::{FastVoteGenesisFixture, build_catch_up_network_fixture};
use support::host::{HostProcess, TempDir, spawn_host};
use support::http_relay::HttpRelay;

type AdminPool = Pool<PostgresConnectionManager<postgres::NoTls>>;
type Store = PostgresDurableStore<PostgresConnectionManager<postgres::NoTls>>;

fn store(pool: &AdminPool, namespace: &PostgresNamespace) -> Store {
    PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap(),
    )
}
fn persist(path: &Path, bytes: &[u8]) {
    let mut file: fs::File = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
fn endpoint(
    addr: SocketAddr,
    fixture: &FastVoteGenesisFixture,
    index: usize,
) -> FastVoteEndpoint<LoopbackHttpTransport> {
    FastVoteEndpoint {
        validator_id: fixture.validators[index].validator_id,
        endpoint_label: addr.to_string(),
        client: Client::new(
            LoopbackHttpTransport::new(
                addr,
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(5),
                NonZeroUsize::new(64 * 1024).unwrap(),
                NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
            )
            .unwrap(),
        ),
    }
}
fn cli_binary() -> PathBuf {
    let binary: PathBuf = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("sunrise-edge-cli");
    assert!(
        binary.is_file(),
        "build sunrise-edge-cli before the exact live catch-up test (scripts/check-fastvote-pg.sh does this)"
    );
    binary
}

fn current_ref(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    id: ObjectId,
) -> ObjectRef {
    let current: ObjectQueryResult = node_core::query_object(
        &store(pool, namespace),
        &read_context(pool, namespace),
        fixture.domain,
        &fixture.chain_id,
        id,
    )
    .unwrap();
    match current {
        ObjectQueryResult::CurrentInline {
            object_version,
            digest,
            ..
        } => ObjectRef {
            id,
            version: object_version.get(),
            digest,
        },
        other => panic!("expected a current application Coin: {other:?}"),
    }
}

fn owner(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    id: ObjectId,
) -> Owner {
    match node_core::query_object(
        &store(pool, namespace),
        &read_context(pool, namespace),
        fixture.domain,
        &fixture.chain_id,
        id,
    )
    .unwrap()
    {
        ObjectQueryResult::CurrentInline {
            canonical_object_bytes,
            ..
        } => {
            objects::decode_object(&canonical_object_bytes)
                .unwrap()
                .owner
        }
        other => panic!("expected a current owned Coin: {other:?}"),
    }
}
fn catch_up(
    directory: &Path,
    fixture: &FastVoteGenesisFixture,
    config: &Path,
    manifest: &Path,
    result_dir: &Path,
    extra: &[(&str, &str)],
) -> Output {
    let mut command: Command = Command::new(cli_binary());
    let mut flags: Vec<(String, String)> = vec![
        (
            "--expected-chain-id".to_owned(),
            fixture.chain_id.to_string(),
        ),
        ("--expected-protocol-version".to_owned(), "3".to_owned()),
        ("--expected-epoch".to_owned(), "0".to_owned()),
        ("--expected-hash-suite-id".to_owned(), "1".to_owned()),
        ("--expected-domain".to_owned(), fixture.domain.to_string()),
        (
            "--fastvote-network".to_owned(),
            config.to_str().unwrap().to_owned(),
        ),
        (
            "--fastvote-genesis-manifest".to_owned(),
            directory.join("genesis").to_str().unwrap().to_owned(),
        ),
        (
            "--fastvote-expected-genesis-digest".to_owned(),
            to_hex(&fixture.manifest_digest),
        ),
        ("--fastvote-deadline-seconds".to_owned(), "30".to_owned()),
        (
            "--fastvote-per-request-cap-seconds".to_owned(),
            "5".to_owned(),
        ),
        (
            "--manifest".to_owned(),
            manifest.to_str().unwrap().to_owned(),
        ),
        (
            "--result-dir".to_owned(),
            result_dir.to_str().unwrap().to_owned(),
        ),
    ];
    for (key, value) in extra {
        if let Some(flag) = flags.iter_mut().find(|flag| flag.0 == *key) {
            flag.1 = (*value).to_owned();
        } else {
            flags.push(((*key).to_owned(), (*value).to_owned()));
        }
    }
    command.args(["contract", "fastvote-catch-up"]);
    for (key, value) in flags {
        command.args([key, value]);
    }
    command.output().unwrap()
}

/// Complete generic rows + every known/declared/output object's exact typed
/// head, all retained versions and authority + nonce + every canonical receipt.
/// Physical writer-fence/attempt allocator metadata is intentionally excluded.
fn full_snapshot(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    requests: &[[u8; 32]],
    ids: &BTreeSet<ObjectId>,
) -> String {
    let store: Store = store(pool, namespace);
    let context = read_context(pool, namespace);
    let mut rows: Vec<(Vec<u8>, runtime::VersionedStateValue)> = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let page = store
            .scan_durable_keys(
                &context,
                fixture.domain,
                &StateKeyScan::new(b"se/".to_vec(), after, NonZeroUsize::new(128).unwrap())
                    .unwrap(),
            )
            .unwrap();
        for key in page.keys() {
            rows.push((
                key.clone(),
                store
                    .get_versioned_durable(&context, fixture.domain, key)
                    .unwrap(),
            ));
        }
        after = page.continuation_cursor().map(<[u8]>::to_vec);
        if after.is_none() {
            break;
        }
    }
    format!(
        "{rows:?}\n{}",
        convergence_snapshot(pool, namespace, fixture, requests, ids)
    )
}

fn convergence_snapshot(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    requests: &[[u8; 32]],
    ids: &BTreeSet<ObjectId>,
) -> String {
    let store: Store = store(pool, namespace);
    let context = read_context(pool, namespace);
    let mut snapshot: String = String::new();
    for id in ids {
        let head = store
            .get_object_head(&context, fixture.domain, *id)
            .unwrap();
        let verified: ObjectQueryResult =
            node_core::query_object(&store, &context, fixture.domain, &fixture.chain_id, *id)
                .unwrap();
        snapshot.push_str(&format!(
            "object={id} head={head:?} verified={verified:?}\n"
        ));
        if let Some(last) = head.object_version() {
            for version in 1..=last.get() {
                let value = store
                    .get_object_version(
                        &context,
                        fixture.domain,
                        *id,
                        DurableObjectVersion::new(version).unwrap(),
                    )
                    .unwrap();
                snapshot.push_str(&format!("version={version} value={value:?}\n"));
            }
        }
        let authority = store
            .get_versioned_durable(
                &context,
                fixture.domain,
                &node_core::local_instance_state::object_authority_key(*id),
            )
            .unwrap();
        snapshot.push_str(&format!("authority={:?}\n", authority.value()));
    }
    for request in requests {
        let receipt = node_core::query_request_receipt(
            &store,
            &context,
            fixture.domain,
            node_core::RequestId::new(*request).unwrap(),
        )
        .unwrap();
        snapshot.push_str(&format!("receipt={receipt:?}\n"));
        for key in [
            node_core::local_instance_state::fastpath_certificate_key(&fixture.chain_id, request)
                .unwrap(),
            node_core::local_instance_state::fastpath_commitment_witness_key(
                &fixture.chain_id,
                request,
            )
            .unwrap(),
            node_core::local_instance_state::fastpath_settlement_key(&fixture.chain_id, request)
                .unwrap(),
        ] {
            let row = store
                .get_versioned_durable(&context, fixture.domain, &key)
                .unwrap();
            snapshot.push_str(&format!("record={:?}\n", row.value()));
        }
    }
    let nonce: u64 = node_core::query_sender_next_nonce(
        &store,
        &context,
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        fixture.sender,
    )
    .unwrap();
    snapshot.push_str(&format!("sender_nonce={nonce}\n"));
    snapshot
}

#[test]
#[ignore = "run through scripts/check-fastvote-pg.sh"]
fn certified_catch_up_pg_missed_prepare_binary_cli_e2e() {
    let Some(database_url) = support::live_postgres_url() else {
        eprintln!("skipping PostgreSQL certified catch-up: fixture URL unset");
        return;
    };
    let _live_lock = support::LiveTestLock::acquire();
    let _binary: PathBuf = cli_binary();
    let config: Config = Config::from_str(&database_url).unwrap();
    let backend: SocketAddr = single_tcp_backend_addr(&config, support::LIVE_POSTGRES_URL_ENV);
    let (proxy, _, ca) = support::tls_relay::TlsPassthroughProxy::spawn(backend);
    let dsn: String = proxied_dsn(&config, proxy.local_addr().port());
    let directory: PathBuf = temp_path("certified-catch-up");
    fs::create_dir(&directory).unwrap();
    let _owned: TempDir = TempDir(directory.clone());
    let (fixture, application_coins): (FastVoteGenesisFixture, [ObjectId; 2]) =
        build_catch_up_network_fixture(directory.file_name().unwrap().to_str().unwrap());
    persist(&directory.join("ca.der"), &ca);
    persist(&directory.join("genesis"), &fixture.manifest_bytes);
    let cli = CliContext {
        ca_path: &directory.join("ca.der"),
        dsn: &dsn,
        chain_id: fixture.chain_id.to_string(),
        protocol_version: fixture.protocol_version,
        manifest_path: &directory.join("genesis"),
        digest_hex: to_hex(&fixture.manifest_digest),
    };
    let mut key_paths: Vec<PathBuf> = Vec::new();
    let mut key_guards = Vec::new();
    let mut namespaces: Vec<PostgresNamespace> = Vec::new();
    for validator in &fixture.validators {
        let (path, guard) = write_signing_key_file(&validator.seed);
        key_paths.push(path);
        key_guards.push(guard);
        namespace_init(
            &cli,
            &validator.validator_id.to_string(),
            &fixture.domain.to_string(),
        );
        install_genesis(
            &cli,
            &validator.validator_id.to_string(),
            &fixture.domain.to_string(),
            true,
        );
        namespaces.push(
            PostgresNamespace::new(&fixture.chain_id, validator.validator_id, fixture.domain)
                .unwrap(),
        );
    }
    let start = |index: usize, address: &str| -> HostProcess {
        spawn_host(
            cli.ca_path,
            &dsn,
            &cli.chain_id,
            &fixture.validators[index].validator_id.to_string(),
            &fixture.domain.to_string(),
            cli.manifest_path,
            &cli.digest_hex,
            &key_paths[index],
            address,
        )
    };
    // The fourth host is genuinely absent throughout all prepare and apply.
    let hosts: Vec<HostProcess> = (0..3).map(|index| start(index, "127.0.0.1:0")).collect();
    let endpoints: Vec<FastVoteEndpoint<LoopbackHttpTransport>> = hosts
        .iter()
        .enumerate()
        .map(|(index, host)| endpoint(host.addr, &fixture, index))
        .collect();
    let certifier = sunrise_edge_client::load_trusted_fastvote_genesis(
        cli.manifest_path,
        &fixture.resolver,
        fixture.manifest_digest,
        &fixture.context,
    )
    .unwrap();
    let pool: AdminPool = admin_pool(&config);
    let requests: [[u8; 32]; 3] = [[0xD1; 32], [0xD2; 32], [0xD3; 32]];
    let genesis = node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let mut ids: BTreeSet<ObjectId> = genesis
        .objects
        .iter()
        .map(|entry| entry.object.id)
        .collect();
    let initial_fourth: String = full_snapshot(&pool, &namespaces[3], &fixture, &requests, &ids);
    let mut results: Vec<PaidExecutionResult> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    let recipient: [u8; 32] = VerificationKey::from(&SigningKey::from([0x71; 32])).into();
    for (index, request) in requests.iter().enumerate() {
        let reference: ObjectRef = current_fee_coin_ref(&pool, &namespaces[0], &fixture);
        let mut intent: PaidIntent = decode_signed_paid_intent(&fixture.paid_intent_bytes)
            .unwrap()
            .intent;
        intent.request_id = *request;
        intent.nonce = u64::try_from(index).unwrap();
        intent.consent.source = reference.clone();
        intent.consent.refund_recipient = fixture.sender;
        let PaidApplication::Call(call) = &mut intent.application else {
            panic!("fixture is a Call");
        };
        call.request_id = *request;
        call.nonce = intent.nonce;
        call.access.entries[0].object_ref = current_ref(
            &pool,
            &namespaces[0],
            &fixture,
            application_coins[usize::from(index != 0)],
        );
        // Distinct application and fee sources. The trap must discard the
        // second transfer so the following success can use that exact Coin.
        call.arguments = public_standard_asset::transfer_arguments(if index == 1 {
            &[0x41; 32]
        } else {
            &recipient
        })
        .unwrap();
        let bytes: Vec<u8> = fixture.sign_intent(intent);
        let signed: SignedPaidIntent = decode_signed_paid_intent(&bytes).unwrap();
        let intent_path: PathBuf = directory.join(format!("call-{index}.intent"));
        let cert_path: PathBuf = directory.join(format!("call-{index}.cert"));
        persist(&intent_path, &bytes);
        let deadline: Instant = Instant::now().checked_add(Duration::from_secs(30)).unwrap();
        let (certificate, _) = collect_fastvote_certificate(
            &endpoints,
            &certifier,
            &fixture.resolver,
            &signed,
            deadline,
            Duration::from_secs(5),
        )
        .unwrap();
        persist(&cert_path, &encode_fast_certificate(&certificate).unwrap());
        let attempts = apply_fastvote_to_all(
            &endpoints,
            &certifier,
            &signed,
            &fixture.resolver,
            &certificate,
            deadline,
            Duration::from_secs(5),
        )
        .unwrap();
        let result: PaidExecutionResult = attempts[0].result.as_ref().unwrap().clone();
        assert_eq!(
            result.status,
            if index == 1 {
                PaidExecutionStatus::ApplicationFailed
            } else {
                PaidExecutionStatus::Success
            }
        );
        assert!(result.charged.is_some());
        for attempt in attempts {
            assert_eq!(attempt.result.unwrap(), result);
        }
        assert_eq!(
            owner(
                &pool,
                &namespaces[0],
                &fixture,
                application_coins[usize::from(index != 0)]
            ),
            Owner::Address(objects::Address::new(if index == 1 {
                fixture.sender
            } else {
                recipient
            }))
        );
        for effect in &result.effects.object_effects {
            ids.insert(match effect {
                execution::ObjectEffect::Created(object) => object.id,
                execution::ObjectEffect::Mutated { new_object, .. } => new_object.id,
                execution::ObjectEffect::Deleted { id, .. } => *id,
            });
        }
        let charged = result.charged.as_ref().unwrap();
        ids.insert(charged.fee_output.id);
        if let Some(refund) = &charged.refund_output {
            ids.insert(refund.id);
        }
        persist(
            &directory.join(format!("call-{index}.result")),
            &sunrise_edge_client::encode_paid_execution_result(&result).unwrap(),
        );
        results.push(result);
        lines.push(format!("call-{index}.intent call-{index}.cert\n"));
    }
    assert_eq!(
        full_snapshot(
            &pool,
            &namespaces[3],
            &fixture,
            &requests,
            &genesis
                .objects
                .iter()
                .map(|entry| entry.object.id)
                .collect()
        ),
        initial_fourth
    );
    let expected: String = convergence_snapshot(&pool, &namespaces[0], &fixture, &requests, &ids);
    for namespace in &namespaces[1..3] {
        assert_eq!(
            convergence_snapshot(&pool, namespace, &fixture, &requests, &ids),
            expected
        );
    }

    let mut fourth: HostProcess = start(3, "127.0.0.1:0");
    let address: SocketAddr = fourth.addr;
    let relay: HttpRelay = HttpRelay::new(address);
    let network: PathBuf = directory.join("returning.conf");
    persist(
        &network,
        format!(
            "{} {} - -\n",
            fixture.validators[3].validator_id, relay.addr
        )
        .as_bytes(),
    );
    let manifest: PathBuf = directory.join("batch");
    persist(&manifest, lines.concat().as_bytes());
    let all_snapshots = || -> Vec<String> {
        namespaces
            .iter()
            .map(|namespace| full_snapshot(&pool, namespace, &fixture, &requests, &ids))
            .collect()
    };
    let new_output = |label: &str| -> PathBuf {
        let path: PathBuf = directory.join(label);
        fs::create_dir(&path).unwrap();
        path
    };
    let before: Vec<String> = all_snapshots();

    // A corrupt LAST artifact must reject the entire otherwise valid prefix
    // before ANY POST, established by the real TCP relay's observed counter.
    let corrupt: PathBuf = directory.join("bad.cert");
    persist(&corrupt, b"corrupt");
    let bad_manifest: PathBuf = directory.join("bad-batch");
    persist(
        &bad_manifest,
        (lines[0].clone() + &lines[1] + "call-2.intent bad.cert\n").as_bytes(),
    );
    let count: usize = relay.posts.load(Ordering::SeqCst);
    let bad_output: PathBuf = new_output("corrupt-results");
    assert!(
        !catch_up(
            &directory,
            &fixture,
            &network,
            &bad_manifest,
            &bad_output,
            &[]
        )
        .status
        .success()
    );
    assert_eq!(fs::read_dir(&bad_output).unwrap().count(), 0);
    assert_eq!(relay.posts.load(Ordering::SeqCst), count);
    assert_eq!(all_snapshots(), before);
    for (label, extra) in [
        (
            "wrong-genesis",
            vec![(
                "--fastvote-expected-genesis-digest",
                "0000000000000000000000000000000000000000000000000000000000000000",
            )],
        ),
        ("wrong-epoch", vec![("--expected-epoch", "1")]),
        ("zero-deadline", vec![("--fastvote-deadline-seconds", "0")]),
        ("unknown-flag", vec![("--seed-file", "missing")]),
    ] {
        assert!(
            !catch_up(
                &directory,
                &fixture,
                &network,
                &manifest,
                &new_output(label),
                &extra
            )
            .status
            .success()
        );
        assert_eq!(relay.posts.load(Ordering::SeqCst), count);
        assert_eq!(all_snapshots(), before);
    }
    for (label, text) in [
        ("duplicate", lines[0].repeat(2)),
        ("too-many", lines[0].repeat(17)),
        ("long-line", "#".to_owned() + &"x".repeat(4096)),
        ("large-manifest", "#".repeat(65537)),
    ] {
        let path: PathBuf = directory.join(format!("{label}.manifest"));
        persist(&path, text.as_bytes());
        assert!(
            !catch_up(
                &directory,
                &fixture,
                &network,
                &path,
                &new_output(label),
                &[]
            )
            .status
            .success()
        );
        assert_eq!(relay.posts.load(Ordering::SeqCst), count);
        assert_eq!(all_snapshots(), before);
    }
    for alias in [false, true] {
        let output: PathBuf = new_output(if alias {
            "alias-results"
        } else {
            "existing-results"
        });
        let path: PathBuf = output.join(format!(
            "entry-0003-validator-{}.result",
            fixture.validators[3].validator_id
        ));
        if alias {
            fs::hard_link(directory.join("call-2.intent"), &path).unwrap();
        } else {
            persist(&path, b"keep");
        }
        assert!(
            !catch_up(&directory, &fixture, &network, &manifest, &output, &[])
                .status
                .success()
        );
        assert_eq!(relay.posts.load(Ordering::SeqCst), count);
        assert_eq!(all_snapshots(), before);
    }
    let reversed: PathBuf = directory.join("out-of-order");
    persist(
        &reversed,
        (lines[1].clone() + &lines[0] + &lines[2]).as_bytes(),
    );
    let out_of_order: PathBuf = new_output("out-of-order-results");
    assert!(
        !catch_up(
            &directory,
            &fixture,
            &network,
            &reversed,
            &out_of_order,
            &[]
        )
        .status
        .success()
    );
    assert_eq!(
        relay.posts.load(Ordering::SeqCst),
        count + 1,
        "missing predecessor rejects first real POST and stops suffix"
    );
    assert_eq!(all_snapshots(), before);

    // Deliberately tombstone the test-owned target application source via the
    // exact normalized namespace row (retaining immutable version history).
    // A genuine certificate cannot repair a divergent object head. Restore
    // only this controlled prerequisite after proving the attempt is inert.
    let namespace: &PostgresNamespace = &namespaces[3];
    let target_id: ObjectId = application_coins[0];
    let validator_id = namespace.validator_id();
    let domain = namespace.domain();
    let mut connection = pool.get().unwrap();
    let selector: [&(dyn postgres::types::ToSql + Sync); 4] = [
        &namespace.chain_id_bytes(),
        &validator_id.as_bytes().as_slice(),
        &domain.as_bytes().as_slice(),
        &target_id.as_bytes().as_slice(),
    ];
    let head = connection.query_one("SELECT current_version::text, digest_algorithm_id, digest_bytes, owner_projection, routing_projection FROM sunrise_edge.object_heads WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 AND object_id=$4", &selector).unwrap();
    assert_eq!(connection.execute("UPDATE sunrise_edge.object_heads SET current_version=NULL, digest_algorithm_id=NULL, digest_bytes=NULL, owner_projection=NULL, routing_projection=NULL, tombstone=true WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 AND object_id=$4", &selector).unwrap(), 1);
    let divergent_head: Vec<String> = all_snapshots();
    assert!(
        !catch_up(
            &directory,
            &fixture,
            &network,
            &manifest,
            &new_output("divergent-head-results"),
            &[]
        )
        .status
        .success()
    );
    assert_eq!(all_snapshots(), divergent_head);
    let version: String = head.get(0);
    let algorithm: i32 = head.get(1);
    let digest: Vec<u8> = head.get(2);
    let owner_projection: Option<Vec<u8>> = head.get(3);
    let routing_projection: Option<Vec<u8>> = head.get(4);
    let restore: [&(dyn postgres::types::ToSql + Sync); 9] = [
        selector[0],
        selector[1],
        selector[2],
        selector[3],
        &version,
        &algorithm,
        &digest,
        &owner_projection,
        &routing_projection,
    ];
    assert_eq!(connection.execute("UPDATE sunrise_edge.object_heads SET current_version=$5::text::numeric, digest_algorithm_id=$6, digest_bytes=$7, owner_projection=$8, routing_projection=$9, tombstone=false WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 AND object_id=$4", &restore).unwrap(), 1);
    drop(connection);
    assert_eq!(all_snapshots(), before);

    // A real, valid canonical advanced nonce copied from a certified peer is
    // a divergent target prerequisite. The negative attempt cannot mutate it.
    let target_store: Store = store(&pool, &namespaces[3]);
    let nonce_key: Vec<u8> =
        PersistenceLayout::new(fixture.chain_id.clone(), fixture.protocol_version)
            .sender_nonce_key(fixture.sender, fixture.epoch);
    let primary_store: Store = store(&pool, &namespaces[0]);
    let primary_nonce: Vec<u8> = primary_store
        .get_versioned_durable(
            &read_context(&pool, &namespaces[0]),
            fixture.domain,
            &nonce_key,
        )
        .unwrap()
        .value()
        .unwrap()
        .to_vec();
    support::durable_state::replace(
        &target_store,
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        nonce_key.clone(),
        primary_nonce.clone(),
    );
    let divergent: Vec<String> = all_snapshots();
    assert!(
        !catch_up(
            &directory,
            &fixture,
            &network,
            &manifest,
            &new_output("divergent-nonce-results"),
            &[]
        )
        .status
        .success()
    );
    assert_eq!(all_snapshots(), divergent);
    // Restore exactly the synthetic row introduced above, at its observed
    // revision/value, to the original never-created state. A nonce tombstone
    // would change the certified commitment's exact nonce revision. This
    // fixture-only SQL does not touch any prepared/lock/application rows.
    let mut connection = pool.get().unwrap();
    assert_eq!(connection.execute("DELETE FROM sunrise_edge.state_records WHERE chain_id_bytes=$1 AND validator_id=$2 AND atomicity_domain_id=$3 AND state_key=$4 AND canonical_bytes=$5 AND revision=1 AND tombstone=false", &[selector[0], selector[1], selector[2], &nonce_key, &primary_nonce]).unwrap(), 1);
    drop(connection);
    assert_eq!(all_snapshots(), before);

    let recovered: PathBuf = new_output("recovered");
    let output: Output = catch_up(&directory, &fixture, &network, &manifest, &recovered, &[]);
    assert!(
        output.status.success(),
        "compiled catch-up CLI rejected genuine recovery: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        convergence_snapshot(&pool, &namespaces[3], &fixture, &requests, &ids),
        expected
    );
    for (index, result) in results.iter().enumerate() {
        let path: PathBuf = recovered.join(format!(
            "entry-{:04}-validator-{}.result",
            index + 1,
            fixture.validators[3].validator_id
        ));
        assert_eq!(
            fs::read(path).unwrap(),
            sunrise_edge_client::encode_paid_execution_result(result).unwrap()
        );
        let prepared = target_store
            .get_versioned_durable(
                &read_context(&pool, &namespaces[3]),
                fixture.domain,
                &node_core::local_instance_state::fastpath_prepared_record_key(
                    &fixture.chain_id,
                    &requests[index],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            prepared.revision(),
            runtime::StateRevision::INITIAL,
            "recovery must never create a preparation or tombstone"
        );
    }
    let context = read_context(&pool, &namespaces[3]);
    for id in &ids {
        let lock = target_store
            .get_versioned_durable(
                &context,
                fixture.domain,
                &node_core::local_instance_state::fastpath_lock_key(&fixture.chain_id, *id)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            lock.revision(),
            runtime::StateRevision::INITIAL,
            "recovery must not create object lock tombstones"
        );
    }
    let nonce_lock = target_store
        .get_versioned_durable(
            &context,
            fixture.domain,
            &node_core::local_instance_state::fastpath_nonce_lock_key(
                &fixture.chain_id,
                &fixture.sender,
                fixture.epoch,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(nonce_lock.revision(), runtime::StateRevision::INITIAL);
    for namespace in &namespaces {
        let store: Store = store(&pool, namespace);
        let blobs = PostgresBlobStore::new(pool.clone(), namespace.clone()).unwrap();
        let verified = node_core::fee_claims::verify_fee_escrow_inventory_all(
            &store,
            &blobs,
            &read_context(&pool, namespace),
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.chain_id,
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
        assert_eq!(verified.verified_rows, 3);
        assert_eq!(verified.verified_claims, 0);
        assert_eq!(verified.verified_payouts, 0);
    }
    let before_same_boot_replay: Vec<String> = all_snapshots();
    let same_boot_replayed: PathBuf = new_output("same-boot-replay");
    let same_boot_replay: Output = catch_up(
        &directory,
        &fixture,
        &network,
        &manifest,
        &same_boot_replayed,
        &[],
    );
    assert!(
        same_boot_replay.status.success(),
        "same-boot exact catch-up replay failed: {}",
        String::from_utf8_lossy(&same_boot_replay.stderr)
    );
    assert_eq!(
        all_snapshots(),
        before_same_boot_replay,
        "same-boot whole-batch replay must not reapply nonce, fee, receipt, object or audit records"
    );
    for index in 1..=3 {
        let name: String = format!(
            "entry-{index:04}-validator-{}.result",
            fixture.validators[3].validator_id
        );
        assert_eq!(
            fs::read(same_boot_replayed.join(&name)).unwrap(),
            fs::read(recovered.join(name)).unwrap()
        );
    }
    let before_restart: Vec<String> = all_snapshots();
    fourth.child.kill().unwrap();
    fourth.child.wait().unwrap();
    fourth = start(3, &address.to_string());
    let replayed: PathBuf = new_output("reopened-replay");
    let replay: Output = catch_up(&directory, &fixture, &network, &manifest, &replayed, &[]);
    assert!(
        replay.status.success(),
        "reopened exact catch-up replay failed: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert_eq!(
        all_snapshots(),
        before_restart,
        "replay must not reapply nonce, fee, receipt, object or audit records"
    );
    for index in 1..=3 {
        let name: String = format!(
            "entry-{index:04}-validator-{}.result",
            fixture.validators[3].validator_id
        );
        assert_eq!(
            fs::read(replayed.join(&name)).unwrap(),
            fs::read(recovered.join(name)).unwrap()
        );
    }
    drop(relay);
    drop(fourth);
    drop(hosts);
}
