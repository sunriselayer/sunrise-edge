//! DR-0151 delivery 1: recovers a validator kept genuinely offline from
//! strictly before the first publish through the complete declared
//! dependency-ordered lifecycle (Publish -> Instantiate -> generic paid mint
//! -> a charged application trap), using the separately compiled
//! `sunrise-edge-cli` binary's signerless `contract fastvote-catch-up`, from
//! the exact saved signed-intent and certificate artifacts three real
//! `fastvote_host_pg` processes produced (also driven through the compiled
//! binary, never `sunrise_edge_cli::run` in-process). Also proves: exact
//! same-boot and real process-restart idempotent replay; prefix commits and
//! fail-closed rejection of a nonce gap and a genuinely tombstoned prerequisite
//! (never claiming whole-batch atomicity); stale-writer fencing; a pre-existing
//! output/reference collision and mismatched protocol pins both reject
//! before any POST.
mod support;

use abi::package_types::PackageOrigin;
use execution::paid_execution::{PaidExecutionStatus, SignedPaidIntent, decode_signed_paid_intent};
use node_core::ObjectQueryResult;
use objects::{ObjectId, ObjectRef};
use postgres::Config;
use public_standard_asset::StandardAssetPackage;
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
};
use std::time::Duration;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    process::Output,
    str::FromStr,
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};
use sunrise_edge_client::{Client, LoopbackHttpTransport};
use support::cli::{
    CliContext, admin_pool, edge_cli_command, install_genesis, namespace_init, proxied_dsn,
    read_context, single_tcp_backend_addr, to_hex, write_signing_key_file,
};
use support::durable_state::{convergence_snapshot, delete, protocol_convergence_snapshot};
use support::genesis_fixture::{self, FastVoteGenesisFixture};
use support::host::{
    HostProcess, TempDir, spawn_host, temp_file, write_network_config, write_new,
    write_new_secure_mode,
};
use support::http_relay::HttpRelay;
use support::paid_calls::{
    NetworkCall, current_object_ref, identify_coin, identify_definition_and_cap, run_asset_verb,
    run_contract_paid, run_generic_mint, track,
};

type AdminPool = Pool<PostgresConnectionManager<postgres::NoTls>>;
type Store = PostgresDurableStore<PostgresConnectionManager<postgres::NoTls>>;

const PUBLISH_ORIGIN_SEED: [u8; 32] = [0x64; 32];
const SECOND_PUBLISH_ORIGIN_SEED: [u8; 32] = [0x66; 32];

fn store(pool: &AdminPool, namespace: &PostgresNamespace) -> Store {
    PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap(),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_catch_up(
    chain_id: &str,
    domain_hex: &str,
    network: &Path,
    manifest_path: &Path,
    digest_hex: &str,
    batch: &Path,
    result_dir: &Path,
) -> Output {
    let mut flags: Vec<OsString> = vec![
        OsString::from("contract"),
        OsString::from("fastvote-catch-up"),
    ];
    flags.extend(
        [
            "--expected-chain-id",
            chain_id,
            "--expected-protocol-version",
            "3",
            "--expected-epoch",
            "0",
            "--expected-hash-suite-id",
            "1",
            "--expected-domain",
            domain_hex,
            "--fastvote-network",
            network.to_str().unwrap(),
            "--fastvote-genesis-manifest",
            manifest_path.to_str().unwrap(),
            "--fastvote-expected-genesis-digest",
            digest_hex,
            "--fastvote-deadline-seconds",
            "30",
            "--fastvote-per-request-cap-seconds",
            "10",
            "--manifest",
            batch.to_str().unwrap(),
            "--result-dir",
            result_dir.to_str().unwrap(),
        ]
        .into_iter()
        .map(OsString::from),
    );
    edge_cli_command(flags).output().unwrap()
}

#[test]
#[ignore = "run through scripts/check-fastvote-pg.sh"]
fn contract_lifecycle_catch_up_pg_missed_publish_instantiate_call_binary_cli_e2e() {
    let database_url_option = support::live_postgres_url();
    if database_url_option.is_none() {
        return;
    }
    let database_url = database_url_option.unwrap();
    let _live_test_lock = support::LiveTestLock::acquire();
    let original_config: Config = Config::from_str(&database_url).unwrap();
    let backend_addr: SocketAddr =
        single_tcp_backend_addr(&original_config, support::LIVE_POSTGRES_URL_ENV);
    let (proxy, _client_connector, ca_der) =
        support::tls_relay::TlsPassthroughProxy::spawn(backend_addr);
    let dsn: String = proxied_dsn(&original_config, proxy.local_addr().port());
    let unique: String = format!(
        "catchup-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let fixture: FastVoteGenesisFixture = genesis_fixture::build_network_fixture(&unique);
    let data_dir = std::env::temp_dir().join(format!(
        "sunrise-contract-lifecycle-catch-up-pg-e2e-{unique}"
    ));
    fs::create_dir(&data_dir).unwrap();
    let _owned = TempDir(data_dir.clone());
    let ca_path = temp_file(&data_dir, "ca.der");
    write_new(&ca_path, &ca_der);
    let manifest_path = temp_file(&data_dir, "genesis-manifest");
    write_new(&manifest_path, &fixture.manifest_bytes);
    let digest_hex = to_hex(&fixture.manifest_digest);
    let domain_hex = format!("{}", fixture.domain);
    let chain_id = format!("{}", fixture.chain_id);
    let cli_context = CliContext {
        protocol_version: fixture.protocol_version,
        ca_path: &ca_path,
        dsn: &dsn,
        chain_id: chain_id.clone(),
        manifest_path: &manifest_path,
        digest_hex: digest_hex.clone(),
    };
    let validator_hex: Vec<String> = fixture
        .validators
        .iter()
        .map(|validator| format!("{}", validator.validator_id))
        .collect();
    let (temp_key_0, temp_key_0_guard) = write_signing_key_file(&fixture.validators[0].seed);
    let key_path_0: PathBuf = temp_file(&data_dir, "signing-key-0");
    fs::copy(&temp_key_0, &key_path_0).unwrap();
    drop(temp_key_0_guard);
    let (temp_key_1, temp_key_1_guard) = write_signing_key_file(&fixture.validators[1].seed);
    let key_path_1: PathBuf = temp_file(&data_dir, "signing-key-1");
    fs::copy(&temp_key_1, &key_path_1).unwrap();
    drop(temp_key_1_guard);
    let (temp_key_2, temp_key_2_guard) = write_signing_key_file(&fixture.validators[2].seed);
    let key_path_2: PathBuf = temp_file(&data_dir, "signing-key-2");
    fs::copy(&temp_key_2, &key_path_2).unwrap();
    drop(temp_key_2_guard);
    let (temp_key_3, temp_key_3_guard) = write_signing_key_file(&fixture.validators[3].seed);
    let key_path_3: PathBuf = temp_file(&data_dir, "signing-key-3");
    fs::copy(&temp_key_3, &key_path_3).unwrap();
    drop(temp_key_3_guard);
    validator_hex.iter().for_each(|validator_id_hex: &String| {
        namespace_init(&cli_context, validator_id_hex, &domain_hex);
        install_genesis(&cli_context, validator_id_hex, &domain_hex, true);
    });
    let host0 = spawn_host(
        &ca_path,
        &dsn,
        &chain_id,
        &validator_hex[0],
        &domain_hex,
        &manifest_path,
        &digest_hex,
        &key_path_0,
        "127.0.0.1:0",
    );
    let host1 = spawn_host(
        &ca_path,
        &dsn,
        &chain_id,
        &validator_hex[1],
        &domain_hex,
        &manifest_path,
        &digest_hex,
        &key_path_1,
        "127.0.0.1:0",
    );
    let host2 = spawn_host(
        &ca_path,
        &dsn,
        &chain_id,
        &validator_hex[2],
        &domain_hex,
        &manifest_path,
        &digest_hex,
        &key_path_2,
        "127.0.0.1:0",
    );
    let hosts: Vec<HostProcess> = vec![host0, host1, host2];
    let network_config_path = temp_file(&data_dir, "fastvote-network.conf");
    write_network_config(&network_config_path, &fixture, &hosts);
    let namespaces: Vec<PostgresNamespace> = fixture
        .validators
        .iter()
        .map(|validator| {
            PostgresNamespace::new(&fixture.chain_id, validator.validator_id, fixture.domain)
                .unwrap()
        })
        .collect();
    let pool: AdminPool = admin_pool(&original_config);
    let seed_path = temp_file(&data_dir, "sender.seed");
    write_new_secure_mode(&seed_path, "21".repeat(32).as_bytes());
    let genesis = node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
    let mut ids: BTreeSet<ObjectId> = genesis
        .objects
        .iter()
        .map(|entry| entry.object.id)
        .collect();
    let mut requests: Vec<[u8; 32]> = Vec::new();
    let call = NetworkCall {
        endpoint: hosts[0].addr,
        chain_id: &chain_id,
        domain_hex: &domain_hex,
        seed_path: &seed_path,
        network_config_path: &network_config_path,
        manifest_path: &manifest_path,
        digest_hex: &digest_hex,
        fee_source: fixture.fee_coin,
    };

    // Publish -> Instantiate -> a real top-level `mint` -> a charged
    // application trap, exactly the declared dependency order validator
    // four's recovery batch below replays.
    let origin: PackageOrigin = PackageOrigin::unverified(
        fixture.chain_id.clone(),
        fixture.sender,
        PUBLISH_ORIGIN_SEED,
    )
    .unwrap();
    let package: StandardAssetPackage = public_standard_asset::build_package(&origin).unwrap();
    let wasm_path = temp_file(&data_dir, "package.wasm");
    write_new(&wasm_path, &package.wasm);
    let abi_path = temp_file(&data_dir, "package.abi");
    write_new(&abi_path, &package.encoded_abi);
    let publish_request_id: [u8; 32] = [0xC1; 32];
    let dependency_ref_out = temp_file(&data_dir, "publish.code-ref");
    let (publish_result, _publish_signed, _publish_cert) = run_contract_paid(
        &call,
        "paid-publish",
        &[
            ("--wasm", wasm_path.to_str().unwrap().to_owned()),
            ("--abi", abi_path.to_str().unwrap().to_owned()),
            ("--entrypoints", package.exports.join(",")),
            ("--origin-seed", to_hex(&PUBLISH_ORIGIN_SEED)),
            (
                "--dependency-ref-out",
                dependency_ref_out.to_str().unwrap().to_owned(),
            ),
        ],
        &data_dir,
        publish_request_id,
        0,
        "publish",
    );
    assert_eq!(publish_result.status, PaidExecutionStatus::Success);
    track(&mut ids, &publish_result);
    requests.push(publish_request_id);

    let init_args_path = temp_file(&data_dir, "init.args");
    write_new(
        &init_args_path,
        &public_standard_asset::no_arguments().unwrap(),
    );
    let instantiate_request_id: [u8; 32] = [0xC2; 32];
    let instance_ref_out = temp_file(&data_dir, "instance.ref");
    let (instantiate_result, _instantiate_signed, _instantiate_cert) = run_contract_paid(
        &call,
        "paid-instantiate",
        &[
            (
                "--code-ref",
                dependency_ref_out.to_str().unwrap().to_owned(),
            ),
            ("--instance-seed", to_hex(&[0x65; 32])),
            ("--args", init_args_path.to_str().unwrap().to_owned()),
            (
                "--instance-ref-out",
                instance_ref_out.to_str().unwrap().to_owned(),
            ),
        ],
        &data_dir,
        instantiate_request_id,
        1,
        "instantiate",
    );
    assert_eq!(instantiate_result.status, PaidExecutionStatus::Success);
    track(&mut ids, &instantiate_result);
    requests.push(instantiate_request_id);
    let (published_definition, published_cap): (ObjectId, ObjectId) = identify_definition_and_cap(
        &instantiate_result,
        &fixture.resolver,
        fixture.epoch,
        &origin,
    );

    let call_request_id: [u8; 32] = [0xC3; 32];
    let (call_result, _call_signed, _call_cert) = run_generic_mint(
        &call,
        &store(&pool, &namespaces[0]),
        &read_context(&pool, &namespaces[0]),
        fixture.domain,
        &fixture.chain_id,
        &instance_ref_out,
        published_definition,
        published_cap,
        9,
        &fixture.sender,
        &data_dir,
        call_request_id,
        2,
        "mint-published",
    );
    assert_eq!(call_result.status, PaidExecutionStatus::Success);
    track(&mut ids, &call_result);
    requests.push(call_request_id);

    let trap_request_id: [u8; 32] = [0xC4; 32];
    let trap_result = run_asset_verb(
        &call,
        "transfer",
        &[
            ("--coin", fixture.fee_coin.to_string()),
            ("--recipient", to_hex(&[0x41; 32])),
        ],
        &data_dir,
        trap_request_id,
        3,
        "trap",
        false,
    );
    assert_eq!(trap_result.status, PaidExecutionStatus::ApplicationFailed);
    assert!(trap_result.charged.is_some());
    track(&mut ids, &trap_result);
    requests.push(trap_request_id);

    let publications: Vec<PackageOrigin> = vec![origin.clone()];
    let expected_state: String = protocol_convergence_snapshot(
        &store(&pool, &namespaces[0]),
        &read_context(&pool, &namespaces[0]),
        &fixture,
        &ids,
        &requests,
        &publications,
    );
    for namespace in &namespaces[1..3] {
        assert_eq!(
            protocol_convergence_snapshot(
                &store(&pool, namespace),
                &read_context(&pool, namespace),
                &fixture,
                &ids,
                &requests,
                &publications,
            ),
            expected_state
        );
    }

    // Validator four is spawned only now: it was genuinely offline for every
    // preceding Publish/Instantiate/mint/trap.
    let fourth: HostProcess = spawn_host(
        &ca_path,
        &dsn,
        &chain_id,
        &validator_hex[3],
        &domain_hex,
        &manifest_path,
        &digest_hex,
        &key_path_3,
        "127.0.0.1:0",
    );
    let relay: HttpRelay = HttpRelay::new(fourth.addr);
    let recovery_network: PathBuf = temp_file(&data_dir, "recovery-network.conf");
    write_new(
        &recovery_network,
        format!(
            "{} {} - -\n",
            fixture.validators[3].validator_id, relay.addr
        )
        .as_bytes(),
    );
    let manifest_lines: String =
        "publish.intent publish.cert\ninstantiate.intent instantiate.cert\n\
mint-published.intent mint-published.cert\ntrap.intent trap.cert\n"
            .to_owned();
    let batch_manifest: PathBuf = temp_file(&data_dir, "batch");
    write_new(&batch_manifest, manifest_lines.as_bytes());
    let corrupt_cert: PathBuf = temp_file(&data_dir, "corrupt.cert");
    write_new(&corrupt_cert, b"not-a-certificate");
    let bad_manifest_lines: String =
        "publish.intent publish.cert\ninstantiate.intent instantiate.cert\n\
mint-published.intent mint-published.cert\ntrap.intent corrupt.cert\n"
            .to_owned();
    let bad_manifest: PathBuf = temp_file(&data_dir, "bad-batch");
    write_new(&bad_manifest, bad_manifest_lines.as_bytes());
    let bad_result_dir: PathBuf = temp_file(&data_dir, "bad-results");
    fs::create_dir(&bad_result_dir).unwrap();
    let before_bad_attempt: String = convergence_snapshot(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        &fixture,
        &ids,
        &requests,
        &publications,
    );
    let bad_output: Output = run_catch_up(
        &chain_id,
        &domain_hex,
        &recovery_network,
        &manifest_path,
        &digest_hex,
        &bad_manifest,
        &bad_result_dir,
    );
    assert!(
        !bad_output.status.success(),
        "a malformed last artifact must reject the entire batch before any POST"
    );
    assert_eq!(
        relay.posts.load(Ordering::SeqCst),
        0,
        "preflight authentication of every entry must reject before the first real POST"
    );
    assert_eq!(fs::read_dir(&bad_result_dir).unwrap().count(), 0);
    assert_eq!(
        convergence_snapshot(
            &store(&pool, &namespaces[3]),
            &read_context(&pool, &namespaces[3]),
            &fixture,
            &ids,
            &requests,
            &publications,
        ),
        before_bad_attempt
    );

    let recovered_result_dir: PathBuf = temp_file(&data_dir, "recovered-results");
    fs::create_dir(&recovered_result_dir).unwrap();
    let recovery_output: Output = run_catch_up(
        &chain_id,
        &domain_hex,
        &recovery_network,
        &manifest_path,
        &digest_hex,
        &batch_manifest,
        &recovered_result_dir,
    );
    assert!(
        recovery_output.status.success(),
        "compiled catch-up CLI rejected genuine recovery of the full declared \
         Publish->Instantiate->mint->trap lifecycle: {}",
        String::from_utf8_lossy(&recovery_output.stderr)
    );
    assert_eq!(
        protocol_convergence_snapshot(
            &store(&pool, &namespaces[3]),
            &read_context(&pool, &namespaces[3]),
            &fixture,
            &ids,
            &requests,
            &publications,
        ),
        expected_state,
        "the recovered validator must converge on the exact same publication/instance/authority \
         records, object heads/versions and query bytes, receipts, certificate/witness/\
         settlement records and sender nonce as every already-certified peer"
    );

    let before_same_boot: String = convergence_snapshot(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        &fixture,
        &ids,
        &requests,
        &publications,
    );
    let same_boot_result_dir: PathBuf = temp_file(&data_dir, "same-boot-results");
    fs::create_dir(&same_boot_result_dir).unwrap();
    let same_boot_output: Output = run_catch_up(
        &chain_id,
        &domain_hex,
        &recovery_network,
        &manifest_path,
        &digest_hex,
        &batch_manifest,
        &same_boot_result_dir,
    );
    assert!(
        same_boot_output.status.success(),
        "same-boot exact catch-up replay must still succeed: {}",
        String::from_utf8_lossy(&same_boot_output.stderr)
    );
    assert_eq!(
        convergence_snapshot(
            &store(&pool, &namespaces[3]),
            &read_context(&pool, &namespaces[3]),
            &fixture,
            &ids,
            &requests,
            &publications,
        ),
        before_same_boot,
        "same-boot replay must never reapply nonce, fee, receipt or object state"
    );

    // A real returning-host stop/reopen: the validator four process is
    // actually killed and a fresh process is actually spawned in its place,
    // reading the exact same durable namespace from a clean boot. The
    // original saved Publish/Instantiate/success/trap artifacts must still
    // replay as an exact no-op against the reopened process.
    drop(relay);
    drop(fourth);
    let fourth2: HostProcess = spawn_host(
        &ca_path,
        &dsn,
        &chain_id,
        &validator_hex[3],
        &domain_hex,
        &manifest_path,
        &digest_hex,
        &key_path_3,
        "127.0.0.1:0",
    );
    let reopen_network: PathBuf = temp_file(&data_dir, "reopen-network.conf");
    write_new(
        &reopen_network,
        format!(
            "{} {} - -\n",
            fixture.validators[3].validator_id, fourth2.addr
        )
        .as_bytes(),
    );
    let before_reopen: String = convergence_snapshot(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        &fixture,
        &ids,
        &requests,
        &publications,
    );
    let reopen_result_dir: PathBuf = temp_file(&data_dir, "reopen-results");
    fs::create_dir(&reopen_result_dir).unwrap();
    let reopen_output: Output = run_catch_up(
        &chain_id,
        &domain_hex,
        &reopen_network,
        &manifest_path,
        &digest_hex,
        &batch_manifest,
        &reopen_result_dir,
    );
    assert!(
        reopen_output.status.success(),
        "exact replay of the original saved artifacts against a genuinely restarted host \
         process must still succeed: {}",
        String::from_utf8_lossy(&reopen_output.stderr)
    );
    assert_eq!(
        convergence_snapshot(
            &store(&pool, &namespaces[3]),
            &read_context(&pool, &namespaces[3]),
            &fixture,
            &ids,
            &requests,
            &publications,
        ),
        before_reopen,
        "replay against a real restarted host must never reapply nonce, fee, receipt, \
         publication or object state"
    );

    // Before the second, never-yet-recovered package is even created,
    // independently re-verify the recovered validator's own fee escrow
    // inventory: it must account for exactly the four requests it has
    // actually applied so far, no more and no less.
    {
        let blobs = PostgresBlobStore::new(pool.clone(), namespaces[3].clone()).unwrap();
        let verified = node_core::fee_claims::verify_fee_escrow_inventory_all(
            &store(&pool, &namespaces[3]),
            &blobs,
            &read_context(&pool, &namespaces[3]),
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.chain_id,
            NonZeroUsize::new(4).unwrap(),
        )
        .unwrap();
        assert_eq!(
            usize::try_from(verified.verified_rows).unwrap(),
            requests.len(),
            "the recovered validator's own independently re-verified fee escrow inventory must \
             account for every request it has actually applied before any further recovery"
        );
    }

    // A second, never-yet-recovered package, used only to prove (a) a
    // pre-existing output/reference collision and (b) mismatched protocol
    // pins both reject before any POST, (c) an order/nonce-gap manifest
    // commits its valid prefix but fails closed on the entry that actually
    // breaks nonce order -- never claiming whole-batch atomicity -- and (d)
    // a deliberately corrupted (tombstoned) prerequisite publication makes a
    // later replay of an already-certified dependent certificate fail closed
    // rather than reconstruct anything.
    let origin2: PackageOrigin = PackageOrigin::unverified(
        fixture.chain_id.clone(),
        fixture.sender,
        SECOND_PUBLISH_ORIGIN_SEED,
    )
    .unwrap();
    let package2: StandardAssetPackage = public_standard_asset::build_package(&origin2).unwrap();
    let wasm2_path = temp_file(&data_dir, "package2.wasm");
    write_new(&wasm2_path, &package2.wasm);
    let abi2_path = temp_file(&data_dir, "package2.abi");
    write_new(&abi2_path, &package2.encoded_abi);
    let publish2_request_id: [u8; 32] = [0xC5; 32];
    let dependency2_ref_out = temp_file(&data_dir, "publish2.code-ref");
    let (publish2_result, publish2_signed_path, publish2_cert_path) = run_contract_paid(
        &call,
        "paid-publish",
        &[
            ("--wasm", wasm2_path.to_str().unwrap().to_owned()),
            ("--abi", abi2_path.to_str().unwrap().to_owned()),
            ("--entrypoints", package2.exports.join(",")),
            ("--origin-seed", to_hex(&SECOND_PUBLISH_ORIGIN_SEED)),
            (
                "--dependency-ref-out",
                dependency2_ref_out.to_str().unwrap().to_owned(),
            ),
        ],
        &data_dir,
        publish2_request_id,
        4,
        "publish2",
    );
    assert_eq!(publish2_result.status, PaidExecutionStatus::Success);
    track(&mut ids, &publish2_result);
    requests.push(publish2_request_id);

    // Writer-fence proof, performed BEFORE validator four ever recovers this
    // publish: decode the exact saved signed intent and prove its nonce and
    // declared fee source match what the not-yet-recovered validator (still
    // at nonce four) currently sees, then prove a rival process claiming a
    // fresh writer generation over the exact same namespace fences the
    // still-running `fourth2` out -- it must reject this authentic,
    // well-formed prepare and certified apply rather than serve or mutate
    // anything.
    let publish2_signed_bytes: Vec<u8> = fs::read(&publish2_signed_path).unwrap();
    let publish2_signed: SignedPaidIntent =
        decode_signed_paid_intent(&publish2_signed_bytes).unwrap();
    assert_eq!(publish2_signed.intent.nonce, 4);
    let returning_nonce: u64 = node_core::query_sender_next_nonce(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        fixture.sender,
    )
    .unwrap();
    assert_eq!(returning_nonce, publish2_signed.intent.nonce);
    let current_fee_ref: ObjectRef = current_object_ref(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        &fixture.chain_id,
        fixture.fee_coin,
    );
    assert_eq!(publish2_signed.intent.consent.source, current_fee_ref);

    let publish2_cert_bytes: Vec<u8> = fs::read(&publish2_cert_path).unwrap();
    let stale_fourth2_addr: SocketAddr = fourth2.addr;
    let rival: HostProcess = spawn_host(
        &ca_path,
        &dsn,
        &chain_id,
        &validator_hex[3],
        &domain_hex,
        &manifest_path,
        &digest_hex,
        &key_path_3,
        "127.0.0.1:0",
    );
    assert_ne!(
        rival.addr, stale_fourth2_addr,
        "the rival must be a genuinely separate live process, not the original"
    );
    let stale_client: Client<LoopbackHttpTransport> = Client::new(
        LoopbackHttpTransport::new(
            stale_fourth2_addr,
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            NonZeroUsize::new(64 * 1024).unwrap(),
            NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
        )
        .unwrap(),
    );
    let before_fence_probe: String = convergence_snapshot(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        &fixture,
        &ids,
        &requests,
        &publications,
    );
    let stale_prepare_result = stale_client.prepare_fastvote(&publish2_signed_bytes, None);
    assert!(
        stale_prepare_result.is_err(),
        "a prepare request against a fenced-out stale host must fail closed, not succeed: \
         {stale_prepare_result:?}"
    );
    let stale_apply_result = stale_client.apply_fastvote(
        &publish2_signed,
        &fixture.resolver,
        &publish2_cert_bytes,
        None,
    );
    assert!(
        stale_apply_result.is_err(),
        "a certified apply against a fenced-out stale host must fail closed, not succeed: \
         {stale_apply_result:?}"
    );
    assert_eq!(
        convergence_snapshot(
            &store(&pool, &namespaces[3]),
            &read_context(&pool, &namespaces[3]),
            &fixture,
            &ids,
            &requests,
            &publications,
        ),
        before_fence_probe,
        "a fenced-out stale host must never mutate state while rejecting"
    );

    // The rival is now the current writer generation for validator four's
    // namespace: drop the stale process and build a fresh relay/network
    // config pointing only at the live rival, so no later negative in this
    // test ever addresses a dead address.
    drop(fourth2);
    let fourth2: HostProcess = rival;
    let relay2: HttpRelay = HttpRelay::new(fourth2.addr);
    let live_network: PathBuf = temp_file(&data_dir, "live-network.conf");
    write_new(
        &live_network,
        format!(
            "{} {} - -\n",
            fixture.validators[3].validator_id, relay2.addr
        )
        .as_bytes(),
    );

    let instantiate2_request_id: [u8; 32] = [0xC6; 32];
    let instance2_ref_out = temp_file(&data_dir, "instance2.ref");
    let (instantiate2_result, instantiate2_signed_path, _instantiate2_cert) = run_contract_paid(
        &call,
        "paid-instantiate",
        &[
            (
                "--code-ref",
                dependency2_ref_out.to_str().unwrap().to_owned(),
            ),
            ("--instance-seed", to_hex(&[0x67; 32])),
            ("--args", init_args_path.to_str().unwrap().to_owned()),
            (
                "--instance-ref-out",
                instance2_ref_out.to_str().unwrap().to_owned(),
            ),
        ],
        &data_dir,
        instantiate2_request_id,
        5,
        "instantiate2",
    );
    assert_eq!(instantiate2_result.status, PaidExecutionStatus::Success);
    track(&mut ids, &instantiate2_result);
    requests.push(instantiate2_request_id);
    let (definition2, _cap2): (ObjectId, ObjectId) = identify_definition_and_cap(
        &instantiate2_result,
        &fixture.resolver,
        fixture.epoch,
        &origin2,
    );

    let prefix_mint_request_id: [u8; 32] = [0xC7; 32];
    let (prefix_mint_result, _prefix_mint_signed, _prefix_mint_cert) = run_generic_mint(
        &call,
        &store(&pool, &namespaces[0]),
        &read_context(&pool, &namespaces[0]),
        fixture.domain,
        &fixture.chain_id,
        &instance_ref_out,
        published_definition,
        published_cap,
        3,
        &fixture.sender,
        &data_dir,
        prefix_mint_request_id,
        6,
        "prefix-mint",
    );
    assert_eq!(prefix_mint_result.status, PaidExecutionStatus::Success);
    track(&mut ids, &prefix_mint_result);
    requests.push(prefix_mint_request_id);
    let prefix_coin: ObjectId = identify_coin(
        &prefix_mint_result,
        &fixture.resolver,
        fixture.epoch,
        &origin,
        published_definition,
    );

    let publish_instantiate_lines: String =
        "publish2.intent publish2.cert\ninstantiate2.intent instantiate2.cert\n".to_owned();
    let publish_then_instantiate_manifest: PathBuf = temp_file(&data_dir, "second-package-batch");
    write_new(
        &publish_then_instantiate_manifest,
        publish_instantiate_lines.as_bytes(),
    );

    // (a) Output/reference collision: a file already occupies the exact
    // first result path this run would reserve, so it must reject before
    // any POST, and the pre-existing file's own content must survive
    // untouched.
    let collision_dir: PathBuf = temp_file(&data_dir, "collision-results");
    fs::create_dir(&collision_dir).unwrap();
    let colliding_result_path: PathBuf =
        collision_dir.join(format!("entry-0001-validator-{}.result", validator_hex[3]));
    fs::hard_link(&ca_path, &colliding_result_path).unwrap();
    let original_collision_contents: Vec<u8> = fs::read(&colliding_result_path).unwrap();
    let posts_before_collision: usize = relay2.posts.load(Ordering::SeqCst);
    let collision_output: Output = run_catch_up(
        &chain_id,
        &domain_hex,
        &live_network,
        &manifest_path,
        &digest_hex,
        &publish_then_instantiate_manifest,
        &collision_dir,
    );
    assert!(
        !collision_output.status.success(),
        "a pre-existing output/reference collision must reject before any POST"
    );
    assert_eq!(
        relay2.posts.load(Ordering::SeqCst),
        posts_before_collision,
        "a pre-existing output/reference collision must make zero additional POSTs"
    );
    assert_eq!(fs::read_dir(&collision_dir).unwrap().count(), 1);
    assert_eq!(
        fs::read(&colliding_result_path).unwrap(),
        original_collision_contents,
        "a rejected output collision must never overwrite the pre-existing file"
    );
    assert!(
        node_core::publication::query_publication(
            &store(&pool, &namespaces[3]),
            &read_context(&pool, &namespaces[3]),
            fixture.domain,
            &fixture.resolver,
            &origin2,
        )
        .unwrap()
        .is_none()
    );

    // (b) Order/nonce-gap failure: `publish2` (nonce four) is the valid
    // prefix that really commits (`instantiate2` genuinely depends on it);
    // `prefix-mint` (nonce six, no dependency on package two at all) is the
    // gap entry -- nonce five was never applied on validator four, so it
    // must reject on nonce order, not on a missing definition; the
    // never-reached `instantiate2` (nonce five) must leave a
    // reserved-but-empty report and result. This is an order/nonce-gap
    // failure, never whole-batch atomicity.
    let nonce_gap_lines: String = "publish2.intent publish2.cert\n\
prefix-mint.intent prefix-mint.cert\ninstantiate2.intent instantiate2.cert\n"
        .to_owned();
    let nonce_gap_manifest: PathBuf = temp_file(&data_dir, "nonce-gap-batch");
    write_new(&nonce_gap_manifest, nonce_gap_lines.as_bytes());
    let nonce_gap_dir: PathBuf = temp_file(&data_dir, "nonce-gap-results");
    fs::create_dir(&nonce_gap_dir).unwrap();
    let posts_before_gap: usize = relay2.posts.load(Ordering::SeqCst);
    let nonce_gap_output: Output = run_catch_up(
        &chain_id,
        &domain_hex,
        &live_network,
        &manifest_path,
        &digest_hex,
        &nonce_gap_manifest,
        &nonce_gap_dir,
    );
    assert!(
        !nonce_gap_output.status.success(),
        "an order/nonce-gap manifest must fail closed, not silently reorder or skip"
    );
    assert!(
        relay2.posts.load(Ordering::SeqCst) > posts_before_gap,
        "the valid publish2 prefix must have actually been POSTed before the gap entry rejected"
    );
    let publish2_publication_live: Option<node_core::publication::PublicationQueryResult> =
        node_core::publication::query_publication(
            &store(&pool, &namespaces[0]),
            &read_context(&pool, &namespaces[0]),
            fixture.domain,
            &fixture.resolver,
            &origin2,
        )
        .unwrap();
    let publish2_publication_recovered: Option<node_core::publication::PublicationQueryResult> =
        node_core::publication::query_publication(
            &store(&pool, &namespaces[3]),
            &read_context(&pool, &namespaces[3]),
            fixture.domain,
            &fixture.resolver,
            &origin2,
        )
        .unwrap();
    assert!(
        publish2_publication_recovered.is_some(),
        "publish2 is the valid prefix entry and must have actually committed on the recovered \
         validator"
    );
    assert_eq!(
        publish2_publication_recovered, publish2_publication_live,
        "the recovered validator's committed publish2 prefix must match the original canonical \
         publication record exactly"
    );
    let publish2_receipt_live = node_core::query_request_receipt(
        &store(&pool, &namespaces[0]),
        &read_context(&pool, &namespaces[0]),
        fixture.domain,
        node_core::RequestId::new(publish2_request_id).unwrap(),
    )
    .unwrap();
    let publish2_receipt_recovered = node_core::query_request_receipt(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        node_core::RequestId::new(publish2_request_id).unwrap(),
    )
    .unwrap();
    assert_eq!(
        publish2_receipt_recovered, publish2_receipt_live,
        "the recovered validator's own canonical receipt for the committed publish2 prefix must \
         match every already-certified peer"
    );
    let nonce_after_gap: u64 = node_core::query_sender_next_nonce(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        fixture.sender,
    )
    .unwrap();
    assert_eq!(
        nonce_after_gap, 5,
        "only publish2 (nonce four) may have actually advanced the recovered validator's nonce; \
         the gap entry and the unreached entry must not"
    );
    assert!(
        fs::read(nonce_gap_dir.join("entry-0002.report"))
            .unwrap()
            .starts_with(b"entry=2"),
        "the nonce-gap entry's own report must record its failure"
    );
    assert!(
        fs::read(nonce_gap_dir.join(format!("entry-0003-validator-{}.result", validator_hex[3])))
            .unwrap()
            .is_empty(),
        "an entry stopped before its own turn must have a reserved but empty result"
    );
    assert!(
        fs::read(nonce_gap_dir.join("entry-0003.report"))
            .unwrap()
            .is_empty(),
        "an entry never reached must have a reserved but empty report; this is a prefix commit, \
         not whole-batch atomicity"
    );
    let definition2_query: ObjectQueryResult = node_core::query_object(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        &fixture.chain_id,
        definition2,
    )
    .unwrap();
    assert!(
        matches!(definition2_query, ObjectQueryResult::Absent { .. }),
        "instantiate2 was never reached and must not exist: {definition2_query:?}"
    );
    let prefix_query: ObjectQueryResult = node_core::query_object(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        &fixture.chain_id,
        prefix_coin,
    )
    .unwrap();
    assert!(
        matches!(prefix_query, ObjectQueryResult::Absent { .. }),
        "the nonce-gap entry must reject without committing, even though it has no dependency on \
         package two: {prefix_query:?}"
    );

    // (c) Divergent-publication proof: prove Inst2's own saved signed intent
    // still agrees with the recovered validator's current nonce/fee
    // reference (nonce five, now that publish2 has actually committed),
    // then deliberately tombstone the just-committed publish2 publication
    // record directly against validator four's own store (never through a
    // real protocol path) and require that replaying the already-certified
    // Inst2 alone, as a one-entry signerless catch-up batch, rejects closed
    // and leaves the corrupted snapshot exactly unchanged -- no speculative
    // Definition/instance/fee/nonce/receipt state, publish2's own retained
    // receipt undisturbed, and the tombstone itself retained. The original,
    // already-certified peers already accepted this exact Inst2 certificate
    // for real above, a positive control proving the certificate itself was
    // always valid.
    let instantiate2_signed_bytes: Vec<u8> = fs::read(&instantiate2_signed_path).unwrap();
    let instantiate2_signed: SignedPaidIntent =
        decode_signed_paid_intent(&instantiate2_signed_bytes).unwrap();
    assert_eq!(instantiate2_signed.intent.nonce, 5);
    assert_eq!(instantiate2_signed.intent.nonce, nonce_after_gap);
    let fee_ref_before_corruption: ObjectRef = current_object_ref(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        &fixture.chain_id,
        fixture.fee_coin,
    );
    assert_eq!(
        instantiate2_signed.intent.consent.source,
        fee_ref_before_corruption
    );

    let publication_key: Vec<u8> =
        node_core::publication::publication_record_key(&origin2).unwrap();
    let tombstoned: runtime::VersionedStateValue = delete(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        publication_key,
    );
    assert!(
        tombstoned.value().is_some(),
        "the deliberately corrupted publication record must have actually been present before \
         deletion"
    );
    assert!(
        node_core::publication::query_publication(
            &store(&pool, &namespaces[3]),
            &read_context(&pool, &namespaces[3]),
            fixture.domain,
            &fixture.resolver,
            &origin,
        )
        .unwrap()
        .is_some(),
        "the healthy first-origin publication must remain queryable after an unrelated origin's \
         deliberate corruption"
    );
    let corrupted_snapshot: String = convergence_snapshot(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        &fixture,
        &ids,
        &requests,
        &publications,
    );

    let inst2_only_lines: String = "instantiate2.intent instantiate2.cert\n".to_owned();
    let inst2_only_manifest: PathBuf = temp_file(&data_dir, "inst2-only-batch");
    write_new(&inst2_only_manifest, inst2_only_lines.as_bytes());
    let inst2_only_dir: PathBuf = temp_file(&data_dir, "inst2-only-results");
    fs::create_dir(&inst2_only_dir).unwrap();
    let inst2_only_output: Output = run_catch_up(
        &chain_id,
        &domain_hex,
        &live_network,
        &manifest_path,
        &digest_hex,
        &inst2_only_manifest,
        &inst2_only_dir,
    );
    assert!(
        !inst2_only_output.status.success(),
        "replaying an already-certified Inst2 alone must reject once its own prerequisite \
         publication has been deliberately tombstoned, never reconstructing it"
    );
    assert_eq!(
        convergence_snapshot(
            &store(&pool, &namespaces[3]),
            &read_context(&pool, &namespaces[3]),
            &fixture,
            &ids,
            &requests,
            &publications,
        ),
        corrupted_snapshot,
        "a rejected replay against deliberately corrupted durable state must never mutate \
         anything, speculative or otherwise, and must never re-tombstone or heal the corrupted \
         record"
    );
    let definition2_after_corruption: ObjectQueryResult = node_core::query_object(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        &fixture.chain_id,
        definition2,
    )
    .unwrap();
    assert!(matches!(
        definition2_after_corruption,
        ObjectQueryResult::Absent { .. }
    ));
    let publish2_receipt_after_corruption = node_core::query_request_receipt(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        fixture.domain,
        node_core::RequestId::new(publish2_request_id).unwrap(),
    )
    .unwrap();
    assert_eq!(
        publish2_receipt_after_corruption, publish2_receipt_recovered,
        "publish2's own retained canonical receipt must survive an unrelated deliberate \
         corruption of the publication record it produced"
    );

    // (d) A well-formed, wrong signed protocol-context chain pin must reject
    // before any POST or result reservation, including an otherwise valid
    // historical replay. Atomicity domain is a separate local store scope,
    // not a member of the signed publication/genesis protocol context.
    let pins_dir: PathBuf = temp_file(&data_dir, "wrong-pins-results");
    fs::create_dir(&pins_dir).unwrap();
    let before_pins: String = convergence_snapshot(
        &store(&pool, &namespaces[3]),
        &read_context(&pool, &namespaces[3]),
        &fixture,
        &ids,
        &requests,
        &publications,
    );
    let posts_before_pins: usize = relay2.posts.load(Ordering::SeqCst);
    let pins_output: Output = run_catch_up(
        "sunrise-edge-wrong-network",
        &domain_hex,
        &live_network,
        &manifest_path,
        &digest_hex,
        &publish_then_instantiate_manifest,
        &pins_dir,
    );
    assert!(
        !pins_output.status.success(),
        "a mismatched signed protocol-context pin must reject before any POST"
    );
    assert_eq!(relay2.posts.load(Ordering::SeqCst), posts_before_pins);
    assert_eq!(fs::read_dir(&pins_dir).unwrap().count(), 0);
    assert_eq!(
        convergence_snapshot(
            &store(&pool, &namespaces[3]),
            &read_context(&pool, &namespaces[3]),
            &fixture,
            &ids,
            &requests,
            &publications,
        ),
        before_pins,
        "a mismatched signed protocol-context pin must never mutate durable state"
    );

    drop(fourth2);
    drop(hosts);
}
