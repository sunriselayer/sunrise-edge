//! Genuine signed causal genesis, ordinary user-selected WASM publication and
//! shared economic execution, audited by separate compiled processes. Raw
//! writes below the acceptance helper are deliberate disposable corruption
//! negatives, never substitutes for signed material or committed history.
#[path = "support/business_audit_acceptance.rs"]
mod acceptance;
#[path = "support/ordered_economics_bond.rs"]
mod bond;
#[path = "support/causal_genesis_fixture.rs"]
mod causal;
#[path = "support/ordered_economics_evidence.rs"]
mod evidence;
mod support;
use support::genesis_fixture;

use abi::call_values::{CallValue, encode_call_value};
use abi::package_types::PackageOrigin;
use abi::{AccessEntry, AccessManifest, encode_access_manifest};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy, SignedLocalExecutionIntent,
    encode_signed_local_execution, local_execution_signing_frame,
};
use execution::paid_execution::{PaidExecutionResult, PaidExecutionStatus};
use node_core::fee_claims;
use node_core::ordered_economics::{
    OrderedCandidate, OrderedOperationKind, encode_ordered_candidate,
};
use objects::{AccessMode, Address, ObjectId};
use postgres::{Config, NoTls};
use protocol_types::ValidatorId;
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{DurableDomainStateStore, StructuredDurableDomainStateStore};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
};
use std::{
    ffi::OsString,
    fs,
    num::NonZeroU32,
    path::{Path, PathBuf},
    process::Output,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use support::cli::{self, CliContext};
use support::genesis_fixture::FastVoteGenesisFixture;
use support::host::{self, HostProcess};
use support::paid_calls::{self, NetworkCall};

type AdminPool = Pool<PostgresConnectionManager<NoTls>>;
type Store = PostgresDurableStore<PostgresConnectionManager<NoTls>>;
type Snapshot = support::durable_state::PostgresRowsSnapshot;

/// Preserve only this test's exclusively created directory on failure. Hosts
/// still terminate through their independent guards; retained files contain
/// disposable fixture material, never production signing keys or credentials.
struct BusinessAuditDirectory {
    path: PathBuf,
    preserve_on_success: bool,
}

impl Drop for BusinessAuditDirectory {
    fn drop(&mut self) {
        if std::thread::panicking() || self.preserve_on_success {
            eprintln!(
                "business-audit diagnostic artifacts preserved: {}",
                self.path.display()
            );
        } else {
            let _ignored: std::io::Result<()> = fs::remove_dir_all(&self.path);
        }
    }
}

fn store(pool: &AdminPool, namespace: &PostgresNamespace) -> Store {
    PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
    )
}

fn snapshots(pool: &AdminPool, namespaces: &[PostgresNamespace]) -> Vec<Snapshot> {
    namespaces
        .iter()
        .map(|namespace| support::durable_state::postgres_rows_snapshot(pool, namespace))
        .collect()
}

fn require_success(output: Output, label: &str) -> String {
    assert!(
        output.status.success(),
        "{label}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn ordered_command(
    fixture: &FastVoteGenesisFixture,
    network: &Path,
    genesis: &Path,
    action: &str,
    extra: &[&str],
) -> Output {
    let mut args: Vec<OsString> = [
        "economics",
        action,
        "--ordered-network",
        network.to_str().unwrap(),
        "--ordered-genesis-manifest",
        genesis.to_str().unwrap(),
        "--ordered-expected-genesis-digest",
        &cli::to_hex(&fixture.manifest_digest),
        "--expected-chain-id",
        &fixture.chain_id.to_string(),
        "--expected-protocol-version",
        &fixture.protocol_version.get().to_string(),
        "--expected-epoch",
        &fixture.epoch.get().to_string(),
        "--domain",
        &fixture.domain.to_string(),
        "--deadline-seconds",
        "90",
        "--per-request-cap-seconds",
        "10",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.extend(extra.iter().map(OsString::from));
    cli::edge_cli_command(args).output().unwrap()
}

fn submit(
    fixture: &FastVoteGenesisFixture,
    network: &Path,
    genesis: &Path,
    dir: &Path,
    candidate: &OrderedCandidate,
    label: &str,
) {
    let path: PathBuf = dir.join(format!("{label}.candidate"));
    let out: PathBuf = dir.join(label);
    host::write_new(&path, &encode_ordered_candidate(candidate).unwrap());
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
                out.to_str().unwrap(),
            ],
        ),
        label,
    );
}

fn inspect_escrow(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
) -> fee_claims::FeeEscrowInspection {
    fee_claims::inspect_fee_escrow(
        &store(pool, namespace),
        &PostgresBlobStore::new(pool.clone(), namespace.clone()).unwrap(),
        &cli::read_context(pool, namespace),
        fixture.domain,
        &fixture.resolver,
        &[],
        &fixture.context,
        fixture.request_id,
    )
    .unwrap()
}

fn prepare_claim(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    claimant: ValidatorId,
    request: [u8; 32],
) -> OrderedCandidate {
    support::fee_claim_candidate::prepare(
        pool,
        namespace,
        fixture,
        support::fee_claim_candidate::ClaimRequest {
            escrow: fixture.request_id,
            claimant,
            request,
            recipient: Address::new(fixture.sender),
            checkpoint: None,
        },
    )
}

fn claimant_nonce(
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    validator: ValidatorId,
) -> u64 {
    let key: &SigningKey = &fixture
        .validators
        .iter()
        .find(|v| v.validator_id == validator)
        .unwrap()
        .signing_key;
    let public: [u8; 32] = VerificationKey::from(key).into();
    node_core::query_sender_next_nonce(
        &store(pool, namespace),
        &cli::read_context(pool, namespace),
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        public,
    )
    .unwrap()
}

/// A charged overflow trap against the actual independently published package.
/// The same production CLI creates its intent, quorum certificate, availability
/// and original result; a failed application is not an admission failure.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn charged_trap(
    call: &NetworkCall<'_>,
    fixture: &FastVoteGenesisFixture,
    pool: &AdminPool,
    namespace: &PostgresNamespace,
    instance: &Path,
    definition: ObjectId,
    cap: ObjectId,
    dir: &Path,
) {
    let args: PathBuf = dir.join("trap.args");
    let types: PathBuf = dir.join("trap.types");
    let access: PathBuf = dir.join("trap.access");
    host::write_new(
        &args,
        &public_standard_asset::mint_arguments(u64::MAX, &fixture.sender).unwrap(),
    );
    host::write_new(
        &types,
        &abi::package_types::encode_scoped_type_arguments(
            &fixture.chain_id,
            &[public_standard_asset::asset_type_argument(&definition)],
        )
        .unwrap(),
    );
    host::write_new(
        &access,
        &encode_access_manifest(&AccessManifest {
            entries: vec![AccessEntry {
                object_ref: paid_calls::current_object_ref(
                    &store(pool, namespace),
                    &cli::read_context(pool, namespace),
                    fixture.domain,
                    &fixture.chain_id,
                    cap,
                ),
                mode: AccessMode::Write,
            }],
        })
        .unwrap(),
    );
    let signed: PathBuf = dir.join("trap.intent");
    let certificate: PathBuf = dir.join("trap.cert");
    let availability: PathBuf = dir.join("trap.avail");
    let result: PathBuf = dir.join("trap.result");
    let mut flags: Vec<OsString> = vec!["contract".into(), "paid-call".into()];
    flags.extend(call.preamble([0x44; 32], 4));
    flags.extend(
        [
            "--fee-access",
            "write",
            "--instance-ref",
            instance.to_str().unwrap(),
            "--entrypoint",
            "mint",
            "--access",
            access.to_str().unwrap(),
            "--args",
            args.to_str().unwrap(),
            "--type-args",
            types.to_str().unwrap(),
            "--fastvote-signed-intent-out",
            signed.to_str().unwrap(),
            "--fastvote-certificate-out",
            certificate.to_str().unwrap(),
            "--fastvote-availability-certificate-out",
            availability.to_str().unwrap(),
            "--result-out",
            result.to_str().unwrap(),
        ]
        .into_iter()
        .map(OsString::from),
    );
    let output: Output = cli::edge_cli_command(flags).output().unwrap();
    assert!(
        !output.status.success(),
        "overflow must be a charged application trap"
    );
    paid_calls::verify_saved_availability_certificate(call, &availability, &signed, &certificate);
    let decoded: PaidExecutionResult = paid_calls::decode_result(&result);
    assert_eq!(decoded.status, PaidExecutionStatus::ApplicationFailed);
    assert!(decoded.charged.is_some());
}

#[test]
#[ignore = "requires disposable PostgreSQL and separately compiled CLI; mandatory business-audit live gate"]
#[allow(clippy::too_many_lines)]
fn business_audit_pg_genuine_causal_history_reopen_and_corruption_e2e() {
    let Some(url) = support::live_postgres_url() else {
        return;
    };
    eprintln!("business-audit-e2e stage=fixture event=start");
    let _lock: support::LiveTestLock = support::LiveTestLock::acquire();
    let config: Config = Config::from_str(&url).unwrap();
    let backend: std::net::SocketAddr =
        cli::single_tcp_backend_addr(&config, support::LIVE_POSTGRES_URL_ENV);
    let (proxy, _connector, ca_der) = support::tls_relay::TlsPassthroughProxy::spawn(backend);
    let dsn: String = cli::proxied_dsn(&config, proxy.local_addr().port());
    let unique: String = format!(
        "business-audit-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let causal::CausalGenesisFixture {
        mut network,
        zero_fee_coin,
    } = causal::build(&unique);
    let funded: node_core::GenesisObjectEntry = bond::fund_source(&mut network);
    let fixture: FastVoteGenesisFixture = network;
    let dir: PathBuf = std::env::temp_dir().join(format!("sunrise-edge-{unique}"));
    fs::create_dir(&dir).unwrap();
    let _owned: BusinessAuditDirectory = BusinessAuditDirectory {
        path: dir.clone(),
        preserve_on_success: false,
    };
    let ca: PathBuf = dir.join("ca.der");
    let genesis: PathBuf = dir.join("genesis.v4");
    let seed: PathBuf = dir.join("sender.seed");
    let network_path: PathBuf = dir.join("network.conf");
    host::write_new(&ca, &ca_der);
    host::write_new(&genesis, &fixture.manifest_bytes);
    host::write_new_secure_mode(&seed, "21".repeat(32).as_bytes());
    let chain: String = fixture.chain_id.to_string();
    let domain: String = fixture.domain.to_string();
    let digest: String = cli::to_hex(&fixture.manifest_digest);
    let bootstrap: CliContext<'_> = CliContext {
        ca_path: &ca,
        dsn: &dsn,
        chain_id: chain.clone(),
        protocol_version: fixture.protocol_version,
        manifest_path: &genesis,
        digest_hex: digest.clone(),
    };
    let pool: AdminPool = cli::admin_pool(&config);
    let namespaces: Vec<PostgresNamespace> = fixture
        .validators
        .iter()
        .map(|validator| {
            PostgresNamespace::new(&fixture.chain_id, validator.validator_id, fixture.domain)
                .unwrap()
        })
        .collect();
    let keys: Vec<PathBuf> = fixture
        .validators
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            let path: PathBuf = dir.join(format!("validator-{index}.seed"));
            host::write_new_secure_mode(&path, &validator.seed);
            path
        })
        .collect();
    for validator in &fixture.validators {
        let id: String = validator.validator_id.to_string();
        cli::assert_stdout_contains(
            &cli::namespace_init(&bootstrap, &id, &domain),
            "complete=true",
        );
        cli::assert_stdout_contains(
            &cli::install_genesis(&bootstrap, &id, &domain, true),
            "outcome=fresh_install",
        );
    }
    let mut hosts: Vec<HostProcess> = fixture
        .validators
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            host::spawn_ordered_host(
                &ca,
                &dsn,
                &chain,
                &validator.validator_id.to_string(),
                &domain,
                &genesis,
                &digest,
                &keys[index],
                "127.0.0.1:0",
            )
        })
        .collect();
    host::write_network_config(&network_path, &fixture, &hosts);
    let call: NetworkCall<'_> = NetworkCall {
        endpoint: hosts[0].addr,
        chain_id: &chain,
        domain_hex: &domain,
        seed_path: &seed,
        network_config_path: &network_path,
        manifest_path: &genesis,
        digest_hex: &digest,
        fee_source: fixture.fee_coin,
    };
    let initial: PaidExecutionResult = paid_calls::run_asset_verb(
        &call,
        "transfer",
        &[
            ("--coin", fixture.fee_coin.to_string()),
            ("--recipient", cli::to_hex(&fixture.sender)),
        ],
        &dir,
        fixture.request_id,
        0,
        "owned-base",
        true,
    );
    assert_eq!(initial.status, PaidExecutionStatus::Success);
    let origin: PackageOrigin =
        PackageOrigin::unverified(fixture.chain_id.clone(), fixture.sender, [0x61; 32]).unwrap();
    let package: public_standard_asset::StandardAssetPackage =
        public_standard_asset::build_package(&origin).unwrap();
    let wasm: PathBuf = dir.join("package.wasm");
    let abi_path: PathBuf = dir.join("package.abi");
    let code: PathBuf = dir.join("package.code");
    host::write_new(&wasm, &package.wasm);
    host::write_new(&abi_path, &package.encoded_abi);
    let (published, _, _) = paid_calls::run_contract_paid(
        &call,
        "paid-publish",
        &[
            ("--wasm", wasm.to_str().unwrap().into()),
            ("--abi", abi_path.to_str().unwrap().into()),
            ("--entrypoints", package.exports.join(",")),
            ("--origin-seed", cli::to_hex(&[0x61; 32])),
            ("--dependency-ref-out", code.to_str().unwrap().into()),
        ],
        &dir,
        [0x41; 32],
        1,
        "publish",
    );
    assert_eq!(published.status, PaidExecutionStatus::Success);
    let init: PathBuf = dir.join("init.args");
    let instance: PathBuf = dir.join("instance.ref");
    host::write_new(&init, &public_standard_asset::no_arguments().unwrap());
    let (instantiated, _, _) = paid_calls::run_contract_paid(
        &call,
        "paid-instantiate",
        &[
            ("--code-ref", code.to_str().unwrap().into()),
            ("--instance-seed", cli::to_hex(&[0x62; 32])),
            ("--args", init.to_str().unwrap().into()),
            ("--instance-ref-out", instance.to_str().unwrap().into()),
        ],
        &dir,
        [0x42; 32],
        2,
        "instantiate",
    );
    assert_eq!(instantiated.status, PaidExecutionStatus::Success);
    let (definition, cap): (ObjectId, ObjectId) = paid_calls::identify_definition_and_cap(
        &instantiated,
        &fixture.resolver,
        fixture.epoch,
        &origin,
    );
    let (minted, _, _) = paid_calls::run_generic_mint(
        &call,
        &store(&pool, &namespaces[0]),
        &cli::read_context(&pool, &namespaces[0]),
        fixture.domain,
        &fixture.chain_id,
        &instance,
        definition,
        cap,
        7,
        &fixture.sender,
        &dir,
        [0x43; 32],
        3,
        "mint",
    );
    assert_eq!(minted.status, PaidExecutionStatus::Success);
    charged_trap(
        &call,
        &fixture,
        &pool,
        &namespaces[0],
        &instance,
        definition,
        cap,
        &dir,
    );
    let zero_call: NetworkCall<'_> = NetworkCall {
        fee_source: zero_fee_coin,
        ..call
    };
    let zero: PaidExecutionResult = paid_calls::run_asset_verb(
        &zero_call,
        "transfer",
        &[
            ("--coin", zero_fee_coin.to_string()),
            ("--recipient", cli::to_hex(&fixture.sender)),
        ],
        &dir,
        [0x45; 32],
        5,
        "zero",
        false,
    );
    assert!(
        zero.charged.is_none(),
        "genuine quoted-fee refusal must charge nothing"
    );
    assert_eq!(zero.status, PaidExecutionStatus::ReservationFailed);
    assert!(zero.effects.object_effects.is_empty());
    let wrong_lane_call: NetworkCall<'_> = NetworkCall {
        fee_source: fixture.fee_coin,
        ..zero_call
    };
    let before_wrong_lane: Vec<Snapshot> = snapshots(&pool, &namespaces);
    paid_calls::run_asset_verb_expect_rejected(
        &wrong_lane_call,
        "transfer",
        &[
            ("--coin", fixture.fee_coin.to_string()),
            ("--recipient", cli::to_hex(&fixture.sender)),
        ],
        &dir,
        [0x81; 32],
        6,
        "wrong-owned-lane",
    );
    assert_eq!(
        snapshots(&pool, &namespaces),
        before_wrong_lane,
        "wrong Owned lane must refuse before any source/observer row, nonce, reservation, vote or receipt"
    );

    // Distinct claimants share an old logical settlement generation, not a
    // sender nonce. Both previews use only genuine installed/material state.
    let inspected: fee_claims::FeeEscrowInspection =
        inspect_escrow(&pool, &namespaces[0], &fixture);
    let positive: Vec<ValidatorId> = inspected
        .claimants
        .iter()
        .filter(|entry| entry.amount > 0)
        .map(|entry| entry.validator_id)
        .collect();
    assert!(
        positive.len() >= 2,
        "fixture must have distinct positive claimants"
    );
    let before_preview: Vec<Snapshot> = snapshots(&pool, &namespaces);
    let first: OrderedCandidate =
        prepare_claim(&pool, &namespaces[0], &fixture, positive[0], [0xE1; 32]);
    let stale: OrderedCandidate =
        prepare_claim(&pool, &namespaces[0], &fixture, positive[1], [0xE2; 32]);
    assert_eq!(
        snapshots(&pool, &namespaces),
        before_preview,
        "claim preview reserves nothing"
    );
    submit(
        &fixture,
        &network_path,
        &genesis,
        &dir,
        &first,
        "claim-first",
    );
    let nonce_before_stale: u64 = claimant_nonce(&pool, &namespaces[0], &fixture, positive[1]);
    submit(
        &fixture,
        &network_path,
        &genesis,
        &dir,
        &stale,
        "claim-stale",
    );
    assert_eq!(
        claimant_nonce(&pool, &namespaces[0], &fixture, positive[1]),
        nonce_before_stale
    );
    let receipt: runtime::DurableRequestReceipt = store(&pool, &namespaces[0])
        .get_request_receipt(
            &cli::read_context(&pool, &namespaces[0]),
            fixture.domain,
            runtime::DurableRequestId::new(stale.request_id).unwrap(),
        )
        .unwrap()
        .unwrap();
    let record: node_core::NodeDedupRecord =
        node_core::NodeDedupRecord::decode(receipt.canonical_bytes()).unwrap();
    assert_eq!(
        node_core::ordered_economics::decode_ordered_refusal_payload(
            record.responses()[0].payload().unwrap()
        )
        .unwrap(),
        node_core::ordered_economics::OrderedRefusal::StaleGeneration
    );
    let fresh: OrderedCandidate =
        prepare_claim(&pool, &namespaces[0], &fixture, positive[1], [0xE3; 32]);
    submit(
        &fixture,
        &network_path,
        &genesis,
        &dir,
        &fresh,
        "claim-fresh",
    );

    // Real generic custody deposit/release, signed conflict evidence, and
    // evidence-authorized forfeiture. Evidence is not epoch activation.
    let malicious: ValidatorId = fixture.validators[0].validator_id;
    let (replace, expected_bond, released) =
        bond::prepare_replace(&pool, &namespaces[0], &fixture, &funded, malicious);
    submit(
        &fixture,
        &network_path,
        &genesis,
        &dir,
        &replace,
        "bond-replace",
    );
    assert_eq!(
        bond::current_bond(&pool, &namespaces[0], &fixture, malicious),
        expected_bond
    );
    let proofs: Vec<evidence::Proof> = evidence::proofs(&fixture, malicious);
    for (index, proof) in proofs.iter().enumerate() {
        assert_eq!(
            node_core::equivocation::evidence_identity_digest(
                &fixture.resolver,
                &proof.evidence_bytes
            )
            .unwrap(),
            proof.identity,
        );
        submit(
            &fixture,
            &network_path,
            &genesis,
            &dir,
            &proof.candidate,
            &format!("evidence-{index}"),
        );
    }
    let slash: OrderedCandidate = evidence::prepare_slash(
        &pool,
        &namespaces[0],
        &fixture,
        malicious,
        proofs[0].identity,
    );
    submit(
        &fixture,
        &network_path,
        &genesis,
        &dir,
        &slash,
        "bond-slash",
    );
    let (reactivate, expected_active) =
        bond::prepare_reactivate(&pool, &namespaces[0], &fixture, &released, malicious);
    submit(
        &fixture,
        &network_path,
        &genesis,
        &dir,
        &reactivate,
        "bond-reactivate",
    );
    assert_eq!(
        bond::current_bond(&pool, &namespaces[0], &fixture, malicious),
        expected_active
    );

    let harness: acceptance::Harness<'_> = acceptance::Harness {
        fixture: &fixture,
        pool: &pool,
        namespaces: &namespaces,
        ca: &ca,
        dsn: &dsn,
        genesis: &genesis,
        network: &network_path,
        keys: &keys,
        dir: &dir,
    };
    eprintln!("business-audit-e2e stage=fixture event=end");
    acceptance::commit_freeze_and_drainset(&harness, &hosts);
    acceptance::run(&harness, &mut hosts);
}

/// Diagnostic only: recover authentic materials from an already completed
/// disposable fixture without installing genesis, advancing a writer fence,
/// reopening hosts, or repeating its lifecycle. This is never a substitute
/// for the mandatory fresh end-to-end acceptance above.
#[test]
#[ignore = "requires exact previous disposable fixture unique/genesis/through-digest pins and live PostgreSQL"]
fn business_audit_pg_readonly_retained_fixture_diagnostic() {
    let unique: String = std::env::var("SUNRISE_EDGE_BUSINESS_AUDIT_RECOVER_UNIQUE")
        .expect("explicit previous disposable fixture unique required");
    let suffix: &str = unique
        .strip_prefix("business-audit-")
        .expect("only this test's disposable fixture namespace is allowed");
    assert!(!suffix.is_empty() && suffix.len() <= 40 && suffix.bytes().all(|b| b.is_ascii_digit()));
    let genesis_text: String = std::env::var("SUNRISE_EDGE_BUSINESS_AUDIT_RECOVER_GENESIS_DIGEST")
        .expect("explicit previous signed genesis pin required");
    let through_text: String = std::env::var("SUNRISE_EDGE_BUSINESS_AUDIT_RECOVER_THROUGH_DIGEST")
        .expect("explicit previous fixed height-31 digest required");
    let genesis_pin: [u8; 32] = sunrise_edge_operator::common::parse_hex_32(
        &genesis_text,
        "SUNRISE_EDGE_BUSINESS_AUDIT_RECOVER_GENESIS_DIGEST",
    )
    .unwrap();
    let through_pin: [u8; 32] = sunrise_edge_operator::common::parse_hex_32(
        &through_text,
        "SUNRISE_EDGE_BUSINESS_AUDIT_RECOVER_THROUGH_DIGEST",
    )
    .unwrap();
    let url: String = std::env::var(support::LIVE_POSTGRES_URL_ENV)
        .expect("diagnostic requires explicit disposable PostgreSQL URL");
    let config: Config = Config::from_str(&url).unwrap();
    let backend: std::net::SocketAddr =
        cli::single_tcp_backend_addr(&config, support::LIVE_POSTGRES_URL_ENV);
    let (proxy, _connector, ca_der) = support::tls_relay::TlsPassthroughProxy::spawn(backend);
    let dsn: String = cli::proxied_dsn(&config, proxy.local_addr().port());
    let mut fixture: FastVoteGenesisFixture = causal::build(&unique).network;
    let _funded: node_core::GenesisObjectEntry = bond::fund_source(&mut fixture);
    assert_eq!(
        fixture.manifest_digest, genesis_pin,
        "original signed genesis must match exactly"
    );
    let pool: AdminPool = cli::admin_pool(&config);
    let namespaces: Vec<PostgresNamespace> = fixture
        .validators
        .iter()
        .map(|validator| {
            PostgresNamespace::new(&fixture.chain_id, validator.validator_id, fixture.domain)
                .unwrap()
        })
        .collect();
    let before: Vec<Snapshot> = snapshots(&pool, &namespaces);
    let stamp: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir: PathBuf =
        std::env::temp_dir().join(format!("sunrise-edge-{unique}-readonly-recovery-{stamp}"));
    fs::create_dir(&dir).unwrap();
    let _owned: BusinessAuditDirectory = BusinessAuditDirectory {
        path: dir.clone(),
        preserve_on_success: true,
    };
    let ca: PathBuf = dir.join("ca.der");
    let genesis: PathBuf = dir.join("genesis.v4");
    let network: PathBuf = dir.join("unused-network.conf");
    host::write_new(&ca, &ca_der);
    host::write_new(&genesis, &fixture.manifest_bytes);
    let harness: acceptance::Harness<'_> = acceptance::Harness {
        fixture: &fixture,
        pool: &pool,
        namespaces: &namespaces,
        ca: &ca,
        dsn: &dsn,
        genesis: &genesis,
        network: &network,
        keys: &[],
        dir: &dir,
    };
    acceptance::recover_retained_fixture(&harness, through_pin);
    assert_eq!(
        snapshots(&pool, &namespaces),
        before,
        "diagnostic must preserve every PG row/revision/sequence/fence across all four namespaces"
    );
}
