//! Live, multi-process, multi-validator PostgreSQL E2E for the `fastvote_pg`
//! operator CLI (DR-0126/DR-0129/DR-0130).
//!
//! Skips (with a diagnostic on stderr) unless `SUNRISE_EDGE_TEST_POSTGRES_URL`
//! is configured, exactly like every other live PostgreSQL test in this
//! repository. Drives the actual compiled `fastvote_pg` binary, never a
//! reimplementation of it, as four independent subprocesses (one per real
//! Ed25519 validator identity, each in its own PostgreSQL namespace) through
//! the shared ephemeral-CA TLS relay (`support::tls_relay`), using the real,
//! exactly-signed four-validator genesis manifest and real sender-signed
//! paid intent built by `support::genesis_fixture`.

mod support;

use ed25519_zebra::{SigningKey, VerificationKey};
use node_core::{ObjectQueryResult, query_object, query_sender_next_nonce};
use postgres::{
    Config,
    config::{Host, SslMode},
};
use protocol_types::ValidatorId;
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{
    DurableDomainStateStore, DurableOperationContext, StorageCorrelationId, StorageDeadline,
    WriterFenceGeneration,
};
use runtime_postgres::{
    PostgresNamespace, PostgresPoolConfig, build_postgres_pool, inspect_namespace,
};
use std::{
    env, fs,
    net::{SocketAddr, ToSocketAddrs},
    num::NonZeroU32,
    path::{Path, PathBuf},
    process::{Command, Output},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::genesis_fixture::{self, FastVoteGenesisFixture, SUITE_FLAG};

const DSN_ENV: &str = "SUNRISE_EDGE_OPERATOR_POSTGRES_DSN";
const CHECKPOINT: &str = "1";
const TIMEOUT_SECONDS: &str = "60";

/// Deletes its temp file on drop, best-effort, regardless of test outcome.
struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// A fresh, bounded, unique temp path this process exclusively owns; never
/// created on disk. The caller decides whether/how to populate it.
fn temp_path(label: &str) -> PathBuf {
    env::temp_dir().join(format!(
        "sunrise-edge-operator-fastvote-pg-e2e-{label}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_TEMP_PATH.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ))
}

static NEXT_TEMP_PATH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn bounded_temp_file(label: &str, bytes: &[u8]) -> (PathBuf, TempFileGuard) {
    let path: PathBuf = temp_path(label);
    fs::write(&path, bytes).unwrap();
    (path.clone(), TempFileGuard(path))
}

/// Writes a raw 32-byte Ed25519 seed to a bounded, `0600` temp file, exactly
/// the shape `fastvote_pg --signing-key-file` requires.
fn write_signing_key_file(seed: &[u8; 32]) -> (PathBuf, TempFileGuard) {
    let (path, guard) = bounded_temp_file("signing-key", seed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    (path, guard)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut text: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

fn single_tcp_backend_addr(config: &Config) -> SocketAddr {
    let [Host::Tcp(host)] = config.get_hosts() else {
        panic!(
            "{} must resolve to exactly one TCP host",
            support::LIVE_POSTGRES_URL_ENV
        );
    };
    let port: u16 = config.get_ports().first().copied().unwrap_or(5432);
    format!("{host}:{port}")
        .to_socket_addrs()
        .unwrap_or_else(|error| panic!("failed to resolve backend host {host}: {error}"))
        .next()
        .unwrap_or_else(|| panic!("no resolved address for backend host {host}"))
}

fn proxied_dsn(original: &Config, proxy_port: u16) -> String {
    let user: &str = original.get_user().unwrap_or("postgres");
    let dbname: &str = original.get_dbname().unwrap_or(user);
    let password: Option<String> = original
        .get_password()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    match password {
        Some(password) => format!("postgresql://{user}:{password}@localhost:{proxy_port}/{dbname}"),
        None => format!("postgresql://{user}@localhost:{proxy_port}/{dbname}"),
    }
}

/// Every flag shared by every subcommand in one E2E run, derived once from
/// the fixture.
struct CliContext<'a> {
    ca_path: &'a Path,
    dsn: &'a str,
    chain_id: String,
    manifest_path: &'a Path,
    digest_hex: String,
}

fn base_command(context: &CliContext<'_>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fastvote_pg"));
    command.env(DSN_ENV, context.dsn);
    command
}

fn namespace_init(context: &CliContext<'_>, validator_hex: &str, domain_hex: &str) -> Output {
    let mut command = base_command(context);
    command.args([
        "namespace-init",
        "--tls-root-der",
        context.ca_path.to_str().unwrap(),
        "--chain-id",
        context.chain_id.as_str(),
        "--validator-id",
        validator_hex,
        "--domain",
        domain_hex,
        "--confirm-namespace-bootstrap",
    ]);
    support::run_expect_success(command, "namespace-init")
}

fn install_genesis(
    context: &CliContext<'_>,
    validator_hex: &str,
    domain_hex: &str,
    expect_success: bool,
) -> Output {
    let mut command = base_command(context);
    command.args([
        "install-genesis",
        "--tls-root-der",
        context.ca_path.to_str().unwrap(),
        "--chain-id",
        context.chain_id.as_str(),
        "--validator-id",
        validator_hex,
        "--domain",
        domain_hex,
        "--protocol-version",
        "1",
        "--epoch",
        "0",
        "--suite",
        SUITE_FLAG,
        "--genesis-manifest",
        context.manifest_path.to_str().unwrap(),
        "--expected-genesis-digest",
        &context.digest_hex,
        "--checkpoint",
        CHECKPOINT,
        "--timeout-seconds",
        TIMEOUT_SECONDS,
        "--confirm-offline-fence-advance",
    ]);
    if expect_success {
        support::run_expect_success(command, "install-genesis")
    } else {
        command.output().unwrap()
    }
}

fn prepare_vote(
    context: &CliContext<'_>,
    validator_hex: &str,
    domain_hex: &str,
    key_path: &Path,
    intent_path: &Path,
    vote_output: &Path,
    expect_success: bool,
) -> Output {
    let mut command = base_command(context);
    command.args([
        "prepare-vote",
        "--tls-root-der",
        context.ca_path.to_str().unwrap(),
        "--chain-id",
        context.chain_id.as_str(),
        "--validator-id",
        validator_hex,
        "--domain",
        domain_hex,
        "--protocol-version",
        "1",
        "--epoch",
        "0",
        "--suite",
        SUITE_FLAG,
        "--genesis-manifest",
        context.manifest_path.to_str().unwrap(),
        "--expected-genesis-digest",
        &context.digest_hex,
        "--signing-key-file",
        key_path.to_str().unwrap(),
        "--paid-intent",
        intent_path.to_str().unwrap(),
        "--created-checkpoint",
        CHECKPOINT,
        "--vote-output",
        vote_output.to_str().unwrap(),
        "--timeout-seconds",
        TIMEOUT_SECONDS,
        "--confirm-offline-fence-advance",
    ]);
    if expect_success {
        support::run_expect_success(command, "prepare-vote")
    } else {
        command.output().unwrap()
    }
}

fn assemble_certificate(
    context: &CliContext<'_>,
    vote_paths: &[PathBuf],
    certificate_output: &Path,
) -> Output {
    let mut command = base_command(context);
    command.args([
        "assemble-certificate",
        "--validator-set-source",
        "genesis-manifest",
        "--chain-id",
        context.chain_id.as_str(),
        "--protocol-version",
        "1",
        "--epoch",
        "0",
        "--suite",
        SUITE_FLAG,
        "--genesis-manifest",
        context.manifest_path.to_str().unwrap(),
        "--expected-genesis-digest",
        &context.digest_hex,
        "--certificate-output",
        certificate_output.to_str().unwrap(),
        "--timeout-seconds",
        TIMEOUT_SECONDS,
    ]);
    for vote_path in vote_paths {
        command.arg("--vote").arg(vote_path);
    }
    command.output().unwrap()
}

fn apply_certificate(
    context: &CliContext<'_>,
    validator_hex: &str,
    domain_hex: &str,
    intent_path: &Path,
    certificate_path: &Path,
    expect_success: bool,
) -> Output {
    let mut command = base_command(context);
    command.args([
        "apply-certificate",
        "--tls-root-der",
        context.ca_path.to_str().unwrap(),
        "--chain-id",
        context.chain_id.as_str(),
        "--validator-id",
        validator_hex,
        "--domain",
        domain_hex,
        "--protocol-version",
        "1",
        "--epoch",
        "0",
        "--suite",
        SUITE_FLAG,
        "--genesis-manifest",
        context.manifest_path.to_str().unwrap(),
        "--expected-genesis-digest",
        &context.digest_hex,
        "--paid-intent",
        intent_path.to_str().unwrap(),
        "--certificate",
        certificate_path.to_str().unwrap(),
        "--timeout-seconds",
        TIMEOUT_SECONDS,
        "--confirm-offline-fence-advance",
    ]);
    if expect_success {
        support::run_expect_success(command, "apply-certificate")
    } else {
        command.output().unwrap()
    }
}

fn assert_stdout_contains(output: &Output, field: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(field),
        "operator stdout lacks {field:?}: {stdout}"
    );
}

/// Direct, NoTls admin connection to the real backend (bypassing the TLS
/// relay), for out-of-band durable-state assertions the CLI itself has no
/// subcommand for: reading the current writer fence, and independently
/// re-verifying committed object/nonce state via `node_core`'s own public
/// query helpers.
fn admin_pool(original: &Config) -> Pool<PostgresConnectionManager<postgres::NoTls>> {
    let pool_config: PostgresPoolConfig = PostgresPoolConfig::new(
        NonZeroU32::new(2).unwrap(),
        Duration::from_secs(5),
        Duration::from_secs(30),
        Duration::from_secs(300),
    )
    .unwrap();
    let mut config: Config = original.clone();
    config.ssl_mode(SslMode::Disable);
    build_postgres_pool(config, postgres::NoTls, pool_config).unwrap()
}

fn current_fence(
    pool: &Pool<PostgresConnectionManager<postgres::NoTls>>,
    namespace: &PostgresNamespace,
) -> WriterFenceGeneration {
    let mut connection = pool.get().unwrap();
    inspect_namespace(&mut *connection, namespace)
        .unwrap()
        .unwrap()
        .writer_fence()
}

/// Builds a read-only `DurableOperationContext` at the namespace's exact
/// current writer fence, so a plain structured read never trips
/// `WriterFenced` against live, already-advanced state.
fn read_context(
    pool: &Pool<PostgresConnectionManager<postgres::NoTls>>,
    namespace: &PostgresNamespace,
) -> DurableOperationContext {
    DurableOperationContext::new(
        current_fence(pool, namespace),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x22; 16]).unwrap(),
    )
}

/// One independently re-verified snapshot of the durable state a real
/// applied transfer certificate leaves behind: the receipt-equivalent
/// permanent certificate-apply audit record, the mutated fee-coin object,
/// and the sender's next nonce.
#[derive(Debug, PartialEq, Eq)]
struct DurableSnapshot {
    certificate_record: Option<Vec<u8>>,
    object: ObjectQueryResult,
    next_nonce: u64,
}

fn snapshot(
    pool: &Pool<PostgresConnectionManager<postgres::NoTls>>,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
) -> DurableSnapshot {
    let store = runtime_postgres::PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        runtime_postgres::PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap(),
    );
    let context: DurableOperationContext = read_context(pool, namespace);
    let certificate_key: Vec<u8> = node_core::local_instance_state::fastpath_certificate_key(
        &fixture.chain_id,
        &fixture.request_id,
    )
    .unwrap();
    let certificate_record: Option<Vec<u8>> = store
        .get_versioned_durable(&context, fixture.domain, &certificate_key)
        .unwrap()
        .value()
        .map(<[u8]>::to_vec);
    let object: ObjectQueryResult = query_object(
        &store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        fixture.fee_coin,
    )
    .unwrap();
    let next_nonce: u64 = query_sender_next_nonce(
        &store,
        &context,
        fixture.domain,
        fixture.chain_id.clone(),
        fixture.protocol_version,
        fixture.epoch,
        fixture.sender,
    )
    .unwrap();
    DurableSnapshot {
        certificate_record,
        object,
        next_nonce,
    }
}

#[test]
#[ignore = "run through scripts/check-fastvote-pg.sh"]
fn fastvote_pg_operator_multivalidator_e2e() {
    let Some(database_url) = support::live_postgres_url() else {
        eprintln!(
            "skipping live PostgreSQL fastvote_pg multi-validator operator E2E: {} is unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };

    // Acquired before any live-database work, shared with every other live
    // PostgreSQL test family in this repository.
    let _live_test_lock = support::LiveTestLock::acquire();

    let original_config: Config = Config::from_str(&database_url).unwrap();
    let backend_addr: SocketAddr = single_tcp_backend_addr(&original_config);
    let (proxy, _client_connector, ca_der) =
        support::tls_relay::TlsPassthroughProxy::spawn(backend_addr);
    let (ca_path, _ca_guard) = bounded_temp_file("ca", &ca_der);
    let dsn: String = proxied_dsn(&original_config, proxy.local_addr().port());

    let unique: String = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let fixture: FastVoteGenesisFixture = genesis_fixture::build_fixture(&unique);
    let (manifest_path, _manifest_guard) =
        bounded_temp_file("genesis-manifest", &fixture.manifest_bytes);
    let (paid_intent_path, _paid_intent_guard) =
        bounded_temp_file("paid-intent", &fixture.paid_intent_bytes);
    let digest_hex: String = to_hex(&fixture.manifest_digest);
    let domain_hex: String = format!("{}", fixture.domain);
    let cli: CliContext<'_> = CliContext {
        ca_path: &ca_path,
        dsn: &dsn,
        chain_id: format!("{}", fixture.chain_id),
        manifest_path: &manifest_path,
        digest_hex: digest_hex.clone(),
    };

    let validator_hex: Vec<String> = fixture
        .validators
        .iter()
        .map(|validator| format!("{}", validator.validator_id))
        .collect();
    let key_files: Vec<(PathBuf, TempFileGuard)> = fixture
        .validators
        .iter()
        .map(|validator| write_signing_key_file(&validator.seed))
        .collect();

    // ---- namespace-init + install-genesis, four independent CLI processes ----
    for validator_id_hex in &validator_hex {
        let first: Output = namespace_init(&cli, validator_id_hex, &domain_hex);
        for field in [
            "complete=true",
            &format!("chain_id={}", cli.chain_id),
            &format!("validator_id={validator_id_hex}"),
            &format!("domain={domain_hex}"),
            "writer_fence=1",
        ] {
            assert_stdout_contains(&first, field);
        }

        let installed: Output = install_genesis(&cli, validator_id_hex, &domain_hex, true);
        for field in [
            "complete=true",
            "outcome=fresh_install",
            "writer_generation=2",
            &format!("manifest_digest={digest_hex}"),
        ] {
            assert_stdout_contains(&installed, field);
        }
    }

    // ---- prepare, four separate CLI processes, one real paid intent ----
    let mut vote_paths: Vec<PathBuf> = Vec::with_capacity(4);
    let mut vote_guards: Vec<TempFileGuard> = Vec::with_capacity(4);
    let mut vote_fields: Vec<(String, String, String)> = Vec::with_capacity(4);
    for index in 0..4 {
        let vote_output: PathBuf = temp_path(&format!("vote-{index}"));
        let prepared: Output = prepare_vote(
            &cli,
            &validator_hex[index],
            &domain_hex,
            &key_files[index].0,
            &paid_intent_path,
            &vote_output,
            true,
        );
        assert_stdout_contains(&prepared, "complete=true");
        assert_stdout_contains(&prepared, "writer_generation=3");
        let stdout: String = String::from_utf8_lossy(&prepared.stdout).into_owned();
        let field = |name: &str| -> String {
            stdout
                .split_whitespace()
                .find_map(|token| token.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("missing {name} in prepare-vote stdout: {stdout}"))
                .to_owned()
        };
        vote_fields.push((
            field("tx_hash"),
            field("execution_effects_hash"),
            field("locked_objects_digest"),
        ));
        vote_paths.push(vote_output.clone());
        vote_guards.push(TempFileGuard(vote_output));
    }
    // Deterministic execution: all four validators, independently executing
    // the identical real paid intent against their own independently
    // installed copy of the identical genesis, derive byte-identical vote
    // headers.
    for fields in &vote_fields[1..] {
        assert_eq!(fields, &vote_fields[0]);
    }

    // ---- assemble one 3-of-4 certificate (offline, genesis-manifest source) ----
    let certificate_path: PathBuf = temp_path("certificate");
    let assembled: Output = assemble_certificate(&cli, &vote_paths[..3], &certificate_path);
    assert!(
        assembled.status.success(),
        "assemble-certificate (3-of-4) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&assembled.stdout),
        String::from_utf8_lossy(&assembled.stderr)
    );
    for field in [
        "complete=true",
        "votes_supplied=3",
        "votes_in_certificate=3",
    ] {
        assert_stdout_contains(&assembled, field);
    }
    let _certificate_guard = TempFileGuard(certificate_path.clone());

    // ---- apply the 3-of-4 certificate independently on all four namespaces ----
    for validator_id_hex in &validator_hex {
        let applied: Output = apply_certificate(
            &cli,
            validator_id_hex,
            &domain_hex,
            &paid_intent_path,
            &certificate_path,
            true,
        );
        for field in ["complete=true", "writer_generation=4"] {
            assert_stdout_contains(&applied, field);
        }
    }

    // ---- independently re-verify durable state, then repeat apply after a
    //      process restart and require byte-identical durable evidence ----
    let admin_pool: Pool<PostgresConnectionManager<postgres::NoTls>> = admin_pool(&original_config);
    let namespaces: Vec<PostgresNamespace> = fixture
        .validators
        .iter()
        .map(|validator| {
            PostgresNamespace::new(&fixture.chain_id, validator.validator_id, fixture.domain)
                .unwrap()
        })
        .collect();
    let first_snapshots: Vec<DurableSnapshot> = namespaces
        .iter()
        .map(|namespace| snapshot(&admin_pool, namespace, &fixture))
        .collect();
    for snapshot in &first_snapshots {
        assert!(
            snapshot.certificate_record.is_some(),
            "applied certificate must leave a permanent audit record"
        );
        assert!(
            matches!(
                snapshot.object,
                ObjectQueryResult::CurrentInline { .. }
                    | ObjectQueryResult::CurrentBlobReference { .. }
            ),
            "the transferred fee coin must have a current, independently re-verified head: {:?}",
            snapshot.object
        );
    }

    for validator_id_hex in &validator_hex {
        let applied_again: Output = apply_certificate(
            &cli,
            validator_id_hex,
            &domain_hex,
            &paid_intent_path,
            &certificate_path,
            true,
        );
        assert_stdout_contains(&applied_again, "complete=true");
        assert_stdout_contains(&applied_again, "writer_generation=5");
    }
    let second_snapshots: Vec<DurableSnapshot> = namespaces
        .iter()
        .map(|namespace| snapshot(&admin_pool, namespace, &fixture))
        .collect();
    assert_eq!(
        first_snapshots, second_snapshots,
        "an idempotent replay after a fresh operator process restart must leave byte-identical \
         durable receipt/object/nonce state"
    );

    // ==================== negatives ====================

    // ---- insufficient quorum: 2 of 4 votes never forms a certificate ----
    let short_certificate_path: PathBuf = temp_path("short-certificate");
    let insufficient: Output =
        assemble_certificate(&cli, &vote_paths[..2], &short_certificate_path);
    assert!(
        !insufficient.status.success(),
        "2-of-4 votes must never form a certificate"
    );
    assert!(insufficient.stdout.is_empty());
    assert!(
        !short_certificate_path.exists(),
        "no certificate file may be written on insufficient quorum"
    );

    // ---- one scratch validator/namespace for DB-touching negatives ----
    let scratch_seed: [u8; 32] = [0xB0; 32];
    let scratch_key: SigningKey = SigningKey::from(scratch_seed);
    let scratch_public: [u8; 32] = VerificationKey::from(&scratch_key).into();
    let scratch_id: ValidatorId = ValidatorId::new(scratch_public);
    let scratch_hex: String = format!("{scratch_id}");
    let scratch_namespace: PostgresNamespace =
        PostgresNamespace::new(&fixture.chain_id, scratch_id, fixture.domain).unwrap();
    namespace_init(&cli, &scratch_hex, &domain_hex);
    let fence_before_negatives: WriterFenceGeneration =
        current_fence(&admin_pool, &scratch_namespace);
    assert_eq!(fence_before_negatives.get(), 1);

    // ---- wrong genesis digest: rejected before any durable mutation ----
    let mut wrong_digest: String = digest_hex.clone();
    wrong_digest.replace_range(
        0..2,
        if &wrong_digest[0..2] == "00" {
            "ff"
        } else {
            "00"
        },
    );
    let cli_wrong_digest: CliContext<'_> = CliContext {
        ca_path: &ca_path,
        dsn: &dsn,
        chain_id: cli.chain_id.clone(),
        manifest_path: &manifest_path,
        digest_hex: wrong_digest,
    };
    let bad_digest: Output = install_genesis(&cli_wrong_digest, &scratch_hex, &domain_hex, false);
    assert!(!bad_digest.status.success());
    assert!(bad_digest.stdout.is_empty());
    assert_eq!(
        current_fence(&admin_pool, &scratch_namespace),
        fence_before_negatives,
        "a rejected genesis digest must never advance the namespace writer fence"
    );

    // ---- wrong context (epoch mismatch): also rejected before mutation ----
    let mut wrong_epoch_command = base_command(&cli);
    wrong_epoch_command.args([
        "install-genesis",
        "--tls-root-der",
        ca_path.to_str().unwrap(),
        "--chain-id",
        cli.chain_id.as_str(),
        "--validator-id",
        &scratch_hex,
        "--domain",
        &domain_hex,
        "--protocol-version",
        "1",
        "--epoch",
        "1",
        "--suite",
        SUITE_FLAG,
        "--genesis-manifest",
        manifest_path.to_str().unwrap(),
        "--expected-genesis-digest",
        &digest_hex,
        "--checkpoint",
        CHECKPOINT,
        "--timeout-seconds",
        TIMEOUT_SECONDS,
        "--confirm-offline-fence-advance",
    ]);
    let wrong_context: Output = wrong_epoch_command.output().unwrap();
    assert!(!wrong_context.status.success());
    assert!(wrong_context.stdout.is_empty());
    assert_eq!(
        current_fence(&admin_pool, &scratch_namespace),
        fence_before_negatives,
        "a rejected genesis context must never advance the namespace writer fence"
    );

    // ---- wrong validator key: prepare-vote with a mismatched signing key ----
    install_genesis(&cli, &scratch_hex, &domain_hex, true);
    let mismatched_vote_output: PathBuf = temp_path("mismatched-vote");
    let fence_before_key_mismatch: WriterFenceGeneration =
        current_fence(&admin_pool, &scratch_namespace);
    let wrong_key: Output = prepare_vote(
        &cli,
        &scratch_hex,
        &domain_hex,
        &key_files[0].0, // validator[0]'s key, never the scratch validator's
        &paid_intent_path,
        &mismatched_vote_output,
        false,
    );
    assert!(!wrong_key.status.success());
    assert!(wrong_key.stdout.is_empty());
    assert!(!mismatched_vote_output.exists());
    // `prepare-vote` claims its writer fence before checking the local
    // signing key against the committed validator set (an ordinary
    // reservation, not fast-path business state), so the fence legitimately
    // advances by exactly one here; the invariant this negative actually
    // proves is that no fast-path business record is written and no vote is
    // ever produced for a signing key that fails that check.
    assert_eq!(
        current_fence(&admin_pool, &scratch_namespace).get(),
        fence_before_key_mismatch.get() + 1,
        "prepare-vote must claim exactly one fresh writer fence generation, win or lose"
    );
    let scratch_store = runtime_postgres::PostgresDurableStore::new(
        admin_pool.clone(),
        scratch_namespace.clone(),
        runtime_postgres::PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap(),
    );
    let scratch_prepared_key: Vec<u8> =
        node_core::local_instance_state::fastpath_prepared_record_key(
            &fixture.chain_id,
            &fixture.request_id,
        )
        .unwrap();
    let scratch_read_context: DurableOperationContext =
        read_context(&admin_pool, &scratch_namespace);
    assert!(
        scratch_store
            .get_versioned_durable(&scratch_read_context, fixture.domain, &scratch_prepared_key)
            .unwrap()
            .value()
            .is_none(),
        "a rejected wrong-key prepare-vote must leave no fast-path prepared record behind"
    );

    // ---- replay conflict: a different intent under the same request id ----
    let conflicting_bytes: Vec<u8> = fixture.sign_transfer(
        fixture.request_id,
        1,
        VerificationKey::from(&SigningKey::from([0x55; 32])).into(),
    );
    let (conflicting_intent_path, _conflicting_intent_guard) =
        bounded_temp_file("conflicting-intent", &conflicting_bytes);
    let conflict_vote_output: PathBuf = temp_path("conflict-vote");
    let conflict: Output = prepare_vote(
        &cli,
        &validator_hex[0],
        &domain_hex,
        &key_files[0].0,
        &conflicting_intent_path,
        &conflict_vote_output,
        false,
    );
    assert!(
        !conflict.status.success(),
        "a conflicting prepared replay under the same request id must fail closed"
    );
    assert!(conflict.stdout.is_empty());
    assert!(!conflict_vote_output.exists());
    // The already-committed durable state for validator[0]'s namespace is
    // completely unaffected by the rejected conflicting attempt.
    assert_eq!(
        snapshot(&admin_pool, &namespaces[0], &fixture),
        second_snapshots[0]
    );

    // ---- stale writer fence: a reader pinned to a superseded generation ----
    let stale_context: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(2).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x33; 16]).unwrap(),
    );
    let store = runtime_postgres::PostgresDurableStore::new(
        admin_pool.clone(),
        namespaces[0].clone(),
        runtime_postgres::PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap(),
    );
    let certificate_key: Vec<u8> = node_core::local_instance_state::fastpath_certificate_key(
        &fixture.chain_id,
        &fixture.request_id,
    )
    .unwrap();
    assert!(matches!(
        store.get_versioned_durable(&stale_context, fixture.domain, &certificate_key),
        Err(runtime::DurableReadError::WriterFenced { active_generation })
            if active_generation.get() == current_fence(&admin_pool, &namespaces[0]).get()
    ));

    drop(proxy);
}
