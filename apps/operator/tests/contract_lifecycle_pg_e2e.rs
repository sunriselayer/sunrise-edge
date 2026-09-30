//! DR-0151 delivery 1: real four-host PostgreSQL integrated functional
//! acceptance for the generic network contract lifecycle -- a genuinely
//! user-selected real Standard Asset WASM/ABI paid-publish -> paid-instantiate
//! -> paid-call, plus ordinary Standard Asset creation and its real top-level
//! `create-asset`/`transfer`/`split`/`merge`/`mint`/`burn` verbs, all driven
//! through the separately compiled `sunrise-edge-cli` binary (never
//! `sunrise_edge_cli::run` in-process) with `--fastvote-network`, against
//! three real `fastvote_host_pg` processes. In the Logical profile the fourth
//! host subsequently retains each publication without execution and recovers
//! the entire lifecycle using saved intent/certificate/availability proofs,
//! never preparing or signing an execution vote. Historical multi-entry
//! recovery remains `contract_lifecycle_catch_up_pg_e2e`'s separate job.
mod support;

#[path = "support/frozen_frontier_acceptance.rs"]
mod frozen_frontier_acceptance;

use abi::package_types::PackageOrigin;
use consensus::bundle::encode_publication_bundle;
use consensus::{
    AvailabilityCertificate, AvailabilityCertifier, AvailabilityVote, FastCertificate,
    decode_availability_certificate, decode_fast_certificate,
};
use execution::paid_execution::PaidExecutionStatus;
use execution::paid_execution::{SignedPaidIntent, decode_signed_paid_intent};
use objects::ObjectId;
use postgres::Config;
use public_standard_asset::StandardAssetPackage;
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{DurableOperationContext, DurableStateKeyScanner, StateKeyScan};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use sunrise_edge_client::{Client, LoopbackHttpTransport, TrustedFastVoteGenesis};
use support::cli::{
    CliContext, admin_pool, install_genesis, namespace_init, proxied_dsn, read_context,
    single_tcp_backend_addr, to_hex, write_signing_key_file,
};
use support::durable_state::{
    convergence_snapshot, execution_snapshot, protocol_convergence_snapshot,
};
use support::genesis_fixture::{self, FastVoteGenesisFixture};
use support::host::{
    HostProcess, TempDir, spawn_host, temp_file, write_network_config, write_new,
    write_new_secure_mode,
};
use support::paid_calls::{
    NetworkCall, identify_coin, identify_definition_and_cap, run_asset_verb,
    run_asset_verb_expect_rejected, run_contract_paid, run_generic_mint, track,
};

type AdminPool = Pool<PostgresConnectionManager<postgres::NoTls>>;
type Store = PostgresDurableStore<PostgresConnectionManager<postgres::NoTls>>;
type HostSpawner = fn(&Path, &str, &str, &str, &str, &Path, &str, &Path, &str) -> HostProcess;

const PUBLISH_ORIGIN_SEED: [u8; 32] = [0x61; 32];

fn store(pool: &AdminPool, namespace: &PostgresNamespace) -> Store {
    PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap(),
    )
}

#[allow(clippy::too_many_arguments)]
fn replay_flags(
    chain_id: &str,
    domain_hex: &str,
    network_path: &Path,
    manifest_path: &Path,
    digest_hex: &str,
    submission: &Path,
    certificate: &Path,
    availability: &Path,
    result_out: &Path,
) -> Vec<OsString> {
    [
        "contract",
        "fastvote-replay",
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
        network_path.to_str().unwrap(),
        "--fastvote-genesis-manifest",
        manifest_path.to_str().unwrap(),
        "--fastvote-expected-genesis-digest",
        digest_hex,
        "--submission",
        submission.to_str().unwrap(),
        "--certificate",
        certificate.to_str().unwrap(),
        "--availability-certificate",
        availability.to_str().unwrap(),
        "--result-out",
        result_out.to_str().unwrap(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn publication_client(addr: SocketAddr) -> Client<LoopbackHttpTransport> {
    let timeout: Duration = Duration::from_secs(10);
    Client::new(
        LoopbackHttpTransport::new(
            addr,
            timeout,
            timeout,
            timeout,
            NonZeroUsize::new(64 * 1024).unwrap(),
            NonZeroUsize::new(sunrise_edge_client::MAX_ENCODED_BUNDLE_BYTES).unwrap(),
        )
        .unwrap(),
    )
}

#[allow(clippy::too_many_arguments)]
fn recover_logical_lifecycle(
    call: &NetworkCall<'_>,
    fixture: &FastVoteGenesisFixture,
    data_dir: &Path,
    source_addr: SocketAddr,
    follower: &HostProcess,
    follower_store: &Store,
    follower_context: &DurableOperationContext,
    ids: &BTreeSet<ObjectId>,
    requests: &[[u8; 32]],
    publications: &[PackageOrigin],
    expected: &str,
) {
    let trusted: TrustedFastVoteGenesis =
        sunrise_edge_client::load_trusted_fastvote_genesis_with_profile(
            call.manifest_path,
            &fixture.resolver,
            fixture.manifest_digest,
            &fixture.context,
        )
        .unwrap();
    assert!(trusted.commitment_profile.is_logical());
    let availability_certifier: AvailabilityCertifier = AvailabilityCertifier::new(
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        trusted.certifier.validator_set().clone(),
    )
    .unwrap();
    let source: Client<LoopbackHttpTransport> = publication_client(source_addr);
    let target: Client<LoopbackHttpTransport> = publication_client(follower.addr);
    let follower_config: PathBuf = temp_file(data_dir, "follower-network.conf");
    write_new(
        &follower_config,
        format!(
            "{} {} - -\n",
            fixture.validators[3].validator_id, follower.addr
        )
        .as_bytes(),
    );
    for label in [
        "publish",
        "instantiate",
        "mint-published",
        "trap",
        "create",
        "mint-a",
        "mint-b",
        "merge",
        "split",
        "transfer",
        "burn",
    ] {
        let submission: PathBuf = temp_file(data_dir, &format!("{label}.intent"));
        let certificate: PathBuf = temp_file(data_dir, &format!("{label}.cert"));
        let availability_path: PathBuf = temp_file(data_dir, &format!("{label}.avail"));
        let signed: SignedPaidIntent =
            decode_signed_paid_intent(&fs::read(&submission).unwrap()).unwrap();
        let full: FastCertificate =
            decode_fast_certificate(&fs::read(&certificate).unwrap()).unwrap();
        let availability: AvailabilityCertificate =
            decode_availability_certificate(&fs::read(&availability_path).unwrap()).unwrap();
        availability_certifier
            .verify_certificate(
                &availability,
                &node_core::fast_path::FastPathEd25519Verifier,
            )
            .unwrap();
        let before_retention: String = execution_snapshot(
            follower_store,
            follower_context,
            fixture,
            ids,
            requests,
            publications,
        );
        let (bundle, identity) = source
            .source_fastvote_publication(
                &signed,
                &full,
                &trusted.certifier,
                &fixture.resolver,
                &[],
                fixture.domain,
                None,
            )
            .unwrap();
        assert_eq!(identity, availability.identity);
        let bundle_bytes: Vec<u8> = encode_publication_bundle(&bundle).unwrap();
        let ack: AvailabilityVote = target
            .retain_fastvote_publication(&bundle_bytes, None)
            .unwrap();
        availability_certifier
            .verify_vote(&ack, &node_core::fast_path::FastPathEd25519Verifier)
            .unwrap();
        assert_eq!(ack.validator, fixture.validators[3].validator_id);
        assert_eq!(ack.identity, availability.identity);
        assert_eq!(
            execution_snapshot(
                follower_store,
                follower_context,
                fixture,
                ids,
                requests,
                publications
            ),
            before_retention,
            "retaining {label} must not execute, change objects, write a receipt or charge a fee"
        );
        let result_out: PathBuf = temp_file(data_dir, &format!("follower-{label}.result"));
        let output: std::process::Output = support::cli::edge_cli_command(replay_flags(
            call.chain_id,
            call.domain_hex,
            &follower_config,
            call.manifest_path,
            call.digest_hex,
            &submission,
            &certificate,
            &availability_path,
            &result_out,
        ))
        .output()
        .unwrap();
        assert_eq!(
            output.status.success(),
            label != "trap",
            "{label} recovery must return its original success or charged-failure status: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(result_out).unwrap(),
            fs::read(temp_file(data_dir, &format!("{label}.result"))).unwrap(),
            "missed-prepare {label} recovery must return the exact canonical result bytes"
        );
    }
    for prefix in [
        b"se/instances/v1/fastpath/prepared/".as_slice(),
        b"se/instances/v1/fastpath/prepared-witness/".as_slice(),
        b"se/instances/v1/fastpath/prepared-artifact/".as_slice(),
    ] {
        let scan: StateKeyScan =
            StateKeyScan::new(prefix.to_vec(), None, NonZeroUsize::new(1).unwrap()).unwrap();
        assert!(
            follower_store
                .scan_durable_keys(follower_context, fixture.domain, &scan)
                .unwrap()
                .keys()
                .is_empty()
        );
    }
    assert_eq!(
        protocol_convergence_snapshot(
            follower_store,
            follower_context,
            fixture,
            ids,
            requests,
            publications
        ),
        expected,
        "the missed-prepare fourth replica must converge on all application and authenticated history rows"
    );
}

#[test]
#[ignore = "run through scripts/check-fastvote-pg.sh"]
fn contract_lifecycle_pg_publish_instantiate_call_and_asset_verbs_multivalidator_e2e() {
    contract_lifecycle_pg_e2e_case(false, false, false);
}

#[test]
#[ignore = "run through scripts/check-fastvote-pg.sh"]
fn contract_lifecycle_pg_logical_publish_instantiate_call_and_asset_verbs_multivalidator_e2e() {
    contract_lifecycle_pg_e2e_case(true, false, false);
}

#[test]
#[ignore = "run through scripts/check-fastvote-pg.sh"]
fn contract_lifecycle_pg_ordered_freeze_and_frontier_binary_cli_e2e() {
    contract_lifecycle_pg_e2e_case(true, true, false);
}

#[test]
#[ignore = "run through scripts/check-fastvote-pg.sh"]
fn contract_lifecycle_pg_drainset_member_drain_binary_cli_e2e() {
    contract_lifecycle_pg_e2e_case(true, true, true);
}

fn contract_lifecycle_pg_e2e_case(logical: bool, frozen_frontier: bool, member_drain: bool) {
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
        "lifecycle-{}-{}-{}",
        if member_drain {
            "drain"
        } else if frozen_frontier {
            "frozen"
        } else if logical {
            "logical"
        } else {
            "hist"
        },
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let fixture: FastVoteGenesisFixture = if frozen_frontier {
        genesis_fixture::build_frozen_frontier_network_fixture(&unique)
    } else if logical {
        genesis_fixture::build_logical_network_fixture(&unique)
    } else {
        genesis_fixture::build_network_fixture(&unique)
    };
    let data_dir = std::env::temp_dir().join(format!("sunrise-contract-lifecycle-pg-e2e-{unique}"));
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
    validator_hex.iter().for_each(|validator_id_hex: &String| {
        namespace_init(&cli_context, validator_id_hex, &domain_hex);
        install_genesis(&cli_context, validator_id_hex, &domain_hex, true);
    });
    let spawn_profile: HostSpawner = if frozen_frontier {
        support::host::spawn_ordered_host
    } else {
        spawn_host
    };
    let host0 = spawn_profile(
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
    let host1 = spawn_profile(
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
    let host2 = spawn_profile(
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

    // A genuinely user-selected package: built fresh from the public
    // `public-standard-asset` source under an independent origin seed, never
    // seeded directly into genesis or the durable store.
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
    let publish_request_id: [u8; 32] = [0xB1; 32];
    let dependency_ref_out = temp_file(&data_dir, "publish.code-ref");
    let (publish_result, publish_signed, publish_cert) = run_contract_paid(
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
    assert!(publish_result.charged.is_some());
    track(&mut ids, &publish_result);
    requests.push(publish_request_id);
    assert!(dependency_ref_out.exists());

    let init_args_path = temp_file(&data_dir, "init.args");
    write_new(
        &init_args_path,
        &public_standard_asset::no_arguments().unwrap(),
    );
    let instantiate_request_id: [u8; 32] = [0xB2; 32];
    let instance_ref_out = temp_file(&data_dir, "published-instance.ref");
    let (instantiate_result, _instantiate_signed, _instantiate_cert) = run_contract_paid(
        &call,
        "paid-instantiate",
        &[
            (
                "--code-ref",
                dependency_ref_out.to_str().unwrap().to_owned(),
            ),
            ("--instance-seed", to_hex(&[0x62; 32])),
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

    // The independently published, user-selected package's real generic
    // `contract paid-call` mint -- never a top-level asset verb, which
    // intentionally only binds to the active locally trusted Standard Asset
    // code (`standard_asset::validate_application_instance_pin`).
    let (mint_published_result, _mint_published_signed, _mint_published_cert) = run_generic_mint(
        &call,
        &store(&pool, &namespaces[0]),
        &read_context(&pool, &namespaces[0]),
        fixture.domain,
        &fixture.chain_id,
        &instance_ref_out,
        published_definition,
        published_cap,
        7,
        &fixture.sender,
        &data_dir,
        [0xB3; 32],
        2,
        "mint-published",
    );
    assert_eq!(mint_published_result.status, PaidExecutionStatus::Success);
    track(&mut ids, &mint_published_result);
    requests.push([0xB3; 32]);

    // A charged application trap: the genesis fee coin used simultaneously
    // as the transfer's own coin input and its fee source. The reservation
    // has already been taken before the WASM trap, so this is a committed,
    // charged failure, not a rejected submission.
    let invalid_recipient: [u8; 32] = [0x41; 32];
    let trap_request_id: [u8; 32] = [0xB4; 32];
    let trap_result = run_asset_verb(
        &call,
        "transfer",
        &[
            ("--coin", fixture.fee_coin.to_string()),
            ("--recipient", to_hex(&invalid_recipient)),
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

    // Real top-level `create-asset`: ordinary Standard Asset creation over
    // the genesis code, replacing any manual `paid-instantiate --code-ref`
    // construction.
    let created_instance_ref_out = temp_file(&data_dir, "created-instance.ref");
    let create_result = run_asset_verb(
        &call,
        "create-asset",
        &[
            ("--instance-seed", to_hex(&[0x63; 32])),
            (
                "--instance-ref-out",
                created_instance_ref_out.to_str().unwrap().to_owned(),
            ),
        ],
        &data_dir,
        [0xB5; 32],
        4,
        "create",
        true,
    );
    assert_eq!(create_result.status, PaidExecutionStatus::Success);
    track(&mut ids, &create_result);
    requests.push([0xB5; 32]);
    let genesis_origin: PackageOrigin = fixture.code().origin().clone();
    let (created_definition, created_cap): (ObjectId, ObjectId) = identify_definition_and_cap(
        &create_result,
        &fixture.resolver,
        fixture.epoch,
        &genesis_origin,
    );
    let asset_extra: Vec<(&str, String)> = vec![
        ("--asset", created_definition.to_string()),
        (
            "--instance-ref",
            created_instance_ref_out.to_str().unwrap().to_owned(),
        ),
    ];

    let recipient: [u8; 32] = {
        use ed25519_zebra::{SigningKey, VerificationKey};
        VerificationKey::from(&SigningKey::from([0x71; 32])).into()
    };
    let mut mint_a_extra: Vec<(&str, String)> = vec![
        ("--treasury-cap", created_cap.to_string()),
        ("--amount", "30".to_owned()),
        ("--recipient", to_hex(&fixture.sender)),
    ];
    mint_a_extra.extend(asset_extra.iter().cloned());
    let mint_a_result = run_asset_verb(
        &call,
        "mint",
        &mint_a_extra,
        &data_dir,
        [0xB6; 32],
        5,
        "mint-a",
        true,
    );
    track(&mut ids, &mint_a_result);
    requests.push([0xB6; 32]);
    let coin_a: ObjectId = identify_coin(
        &mint_a_result,
        &fixture.resolver,
        fixture.epoch,
        &genesis_origin,
        created_definition,
    );

    let mut mint_b_extra: Vec<(&str, String)> = vec![
        ("--treasury-cap", created_cap.to_string()),
        ("--amount", "15".to_owned()),
        ("--recipient", to_hex(&fixture.sender)),
    ];
    mint_b_extra.extend(asset_extra.iter().cloned());
    let mint_b_result = run_asset_verb(
        &call,
        "mint",
        &mint_b_extra,
        &data_dir,
        [0xB7; 32],
        6,
        "mint-b",
        true,
    );
    track(&mut ids, &mint_b_result);
    requests.push([0xB7; 32]);
    let coin_b: ObjectId = identify_coin(
        &mint_b_result,
        &fixture.resolver,
        fixture.epoch,
        &genesis_origin,
        created_definition,
    );

    let mut merge_extra: Vec<(&str, String)> = vec![
        ("--into", coin_a.to_string()),
        ("--from", coin_b.to_string()),
    ];
    merge_extra.extend(asset_extra.iter().cloned());
    let merge_result = run_asset_verb(
        &call,
        "merge",
        &merge_extra,
        &data_dir,
        [0xB8; 32],
        7,
        "merge",
        true,
    );
    track(&mut ids, &merge_result);
    requests.push([0xB8; 32]);

    let mut split_extra: Vec<(&str, String)> = vec![
        ("--coin", coin_a.to_string()),
        ("--amount", "10".to_owned()),
        ("--recipient", to_hex(&fixture.sender)),
    ];
    split_extra.extend(asset_extra.iter().cloned());
    let split_result = run_asset_verb(
        &call,
        "split",
        &split_extra,
        &data_dir,
        [0xB9; 32],
        8,
        "split",
        true,
    );
    track(&mut ids, &split_result);
    requests.push([0xB9; 32]);
    let coin_c: ObjectId = identify_coin(
        &split_result,
        &fixture.resolver,
        fixture.epoch,
        &genesis_origin,
        created_definition,
    );

    let transfer_request_id: [u8; 32] = [0xBA; 32];
    let mut transfer_extra: Vec<(&str, String)> = vec![
        ("--coin", coin_c.to_string()),
        ("--recipient", to_hex(&recipient)),
    ];
    transfer_extra.extend(asset_extra.iter().cloned());
    let transfer_result = run_asset_verb(
        &call,
        "transfer",
        &transfer_extra,
        &data_dir,
        transfer_request_id,
        9,
        "transfer",
        true,
    );
    track(&mut ids, &transfer_result);
    requests.push(transfer_request_id);

    let mut burn_extra: Vec<(&str, String)> = vec![
        ("--treasury-cap", created_cap.to_string()),
        ("--coin", coin_a.to_string()),
    ];
    burn_extra.extend(asset_extra.iter().cloned());
    let burn_result = run_asset_verb(
        &call,
        "burn",
        &burn_extra,
        &data_dir,
        [0xBB; 32],
        10,
        "burn",
        true,
    );
    track(&mut ids, &burn_result);
    requests.push([0xBB; 32]);

    let publications: Vec<PackageOrigin> = vec![origin.clone(), genesis_origin.clone()];
    let before_conflict = convergence_snapshot(
        &store(&pool, &namespaces[0]),
        &read_context(&pool, &namespaces[0]),
        &fixture,
        &ids,
        &requests,
        &publications,
    );

    // Reusing an already-committed request id under a fresh nonce, with
    // different content, must be rejected -- and must leave every tracked
    // object, receipt and nonce exactly unchanged.
    run_asset_verb_expect_rejected(
        &call,
        "transfer",
        &[
            ("--coin", fixture.fee_coin.to_string()),
            ("--recipient", to_hex(&fixture.sender)),
        ],
        &data_dir,
        transfer_request_id,
        11,
        "conflict",
    );
    assert_eq!(
        convergence_snapshot(
            &store(&pool, &namespaces[0]),
            &read_context(&pool, &namespaces[0]),
            &fixture,
            &ids,
            &requests,
            &publications,
        ),
        before_conflict,
        "a rejected conflicting request-id reuse must leave every tracked object, receipt and nonce unchanged"
    );

    let expected: String = protocol_convergence_snapshot(
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
            expected,
            "every online peer must converge on the exact same publication/instance/authority \
             records, object heads/versions and query bytes, receipts, certificate/witness/\
             settlement records and sender nonce"
        );
    }

    for namespace in &namespaces[0..3] {
        let blobs = PostgresBlobStore::new(pool.clone(), namespace.clone()).unwrap();
        let verified = node_core::fee_claims::verify_fee_escrow_inventory_all(
            &store(&pool, namespace),
            &blobs,
            &read_context(&pool, namespace),
            fixture.domain,
            &fixture.resolver,
            &[],
            &fixture.chain_id,
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            usize::try_from(verified.verified_rows).unwrap(),
            requests.len(),
            "every online peer's independently re-verified fee escrow inventory must account for \
             every settled request"
        );
    }
    if logical {
        let snapshot_online = || -> Vec<String> {
            namespaces[..3]
                .iter()
                .map(|namespace: &PostgresNamespace| -> String {
                    convergence_snapshot(
                        &store(&pool, namespace),
                        &read_context(&pool, namespace),
                        &fixture,
                        &ids,
                        &requests,
                        &publications,
                    )
                })
                .collect()
        };
        let snapshot_before_replay: Vec<String> = snapshot_online();

        let publish_avail = temp_file(&data_dir, "publish.avail");

        // Missing/bad availability-proof refusal: corrupted availability certificate must fail and leave state unchanged.
        let bad_avail = temp_file(&data_dir, "publish-bad.avail");
        write_new(&bad_avail, b"corrupted-availability-certificate-bytes");
        let bad_result_out = temp_file(&data_dir, "publish-replay-bad.result");
        let bad_output = support::cli::edge_cli_command(replay_flags(
            &chain_id,
            &domain_hex,
            &network_config_path,
            &manifest_path,
            &digest_hex,
            &publish_signed,
            &publish_cert,
            &bad_avail,
            &bad_result_out,
        ))
        .output()
        .unwrap();
        assert!(
            !bad_output.status.success(),
            "replay with corrupted availability proof must fail"
        );
        assert!(!bad_result_out.exists() || fs::read(&bad_result_out).unwrap().is_empty());
        assert_eq!(
            snapshot_online(),
            snapshot_before_replay,
            "failed replay must leave every online replica unchanged"
        );

        let wrong_result_out: PathBuf = temp_file(&data_dir, "publish-replay-wrong.result");
        let wrong_output: std::process::Output = support::cli::edge_cli_command(replay_flags(
            &chain_id,
            &domain_hex,
            &network_config_path,
            &manifest_path,
            &digest_hex,
            &publish_signed,
            &publish_cert,
            &temp_file(&data_dir, "burn.avail"),
            &wrong_result_out,
        ))
        .output()
        .unwrap();
        assert!(
            !wrong_output.status.success(),
            "a genuine proof for a different request must fail local preflight"
        );
        assert!(!wrong_result_out.exists() || fs::read(&wrong_result_out).unwrap().is_empty());
        assert_eq!(snapshot_online(), snapshot_before_replay);

        // Same-boot exact replay with saved intent, certificate and genuine availability certificate.
        let replay_result_1 = temp_file(&data_dir, "publish-replay-1.result");
        support::run_expect_success(
            support::cli::edge_cli_command(replay_flags(
                &chain_id,
                &domain_hex,
                &network_config_path,
                &manifest_path,
                &digest_hex,
                &publish_signed,
                &publish_cert,
                &publish_avail,
                &replay_result_1,
            )),
            "publish-replay-same-boot",
        );
        assert_eq!(
            fs::read(&replay_result_1).unwrap(),
            fs::read(temp_file(&data_dir, "publish.result")).unwrap(),
            "same-boot replay must return byte-identical result"
        );
        assert_eq!(
            snapshot_online(),
            snapshot_before_replay,
            "same-boot replay must leave every online replica unchanged"
        );

        // Kill actual host processes and restart them.
        drop(hosts);
        let host0 = spawn_profile(
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
        let host1 = spawn_profile(
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
        let host2 = spawn_profile(
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
        let restarted_hosts: Vec<HostProcess> = vec![host0, host1, host2];
        write_network_config(&network_config_path, &fixture, &restarted_hosts);

        let replay_result_2 = temp_file(&data_dir, "publish-replay-2.result");
        support::run_expect_success(
            support::cli::edge_cli_command(replay_flags(
                &chain_id,
                &domain_hex,
                &network_config_path,
                &manifest_path,
                &digest_hex,
                &publish_signed,
                &publish_cert,
                &publish_avail,
                &replay_result_2,
            )),
            "publish-replay-post-restart",
        );
        assert_eq!(
            fs::read(&replay_result_2).unwrap(),
            fs::read(temp_file(&data_dir, "publish.result")).unwrap(),
            "post-restart replay must return byte-identical result"
        );
        assert_eq!(
            snapshot_online(),
            snapshot_before_replay,
            "post-restart replay must leave every online replica unchanged"
        );
        let (follower_key, _follower_key_guard) =
            write_signing_key_file(&fixture.validators[3].seed);
        let follower: HostProcess = spawn_profile(
            &ca_path,
            &dsn,
            &chain_id,
            &validator_hex[3],
            &domain_hex,
            &manifest_path,
            &digest_hex,
            &follower_key,
            "127.0.0.1:0",
        );
        let follower_store: Store = store(&pool, &namespaces[3]);
        let follower_context: DurableOperationContext = read_context(&pool, &namespaces[3]);
        recover_logical_lifecycle(
            &call,
            &fixture,
            &data_dir,
            restarted_hosts[0].addr,
            &follower,
            &follower_store,
            &follower_context,
            &ids,
            &requests,
            &publications,
            &expected,
        );
        assert_eq!(
            snapshot_online(),
            snapshot_before_replay,
            "sourcing old bundles after restart must remain read-only"
        );
        if frozen_frontier {
            frozen_frontier_acceptance::run(
                &fixture,
                &pool,
                &namespaces,
                &data_dir,
                &ca_path,
                &dsn,
                &manifest_path,
                &digest_hex,
                &network_config_path,
                &validator_hex,
                [&key_path_0, &key_path_1, &key_path_2, &follower_key],
                restarted_hosts,
                follower,
                &ids,
                &requests,
                &publications,
                member_drain,
            );
        } else {
            drop(follower);
            drop(restarted_hosts);
        }
    } else {
        drop(hosts);
    }
}
