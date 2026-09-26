//! Shared helpers for driving the real, compiled `fastvote_pg` operator CLI
//! as a subprocess and independently re-verifying its durable PostgreSQL
//! state out of band.
//!
//! Factored out of the original single-database `fastvote_pg_e2e.rs` so the
//! credential-isolation E2E (`fastvote_pg_credential_isolation_e2e.rs`) can
//! reuse the exact same CLI-invocation and durable-state-assertion logic
//! against per-validator databases instead of duplicating it.
#![allow(dead_code)]

use super::genesis_fixture::FastVoteGenesisFixture;
use node_core::{ObjectQueryResult, query_object, query_sender_next_nonce};
use objects::ObjectRef;
use postgres::{
    Config,
    config::{Host, SslMode},
};
use protocol_types::ProtocolVersion;
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
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const DSN_ENV: &str = "SUNRISE_EDGE_OPERATOR_POSTGRES_DSN";
pub const CHECKPOINT: &str = "1";
pub const TIMEOUT_SECONDS: &str = "60";

/// Deletes its temp file on drop, best-effort, regardless of test outcome.
pub struct TempFileGuard(pub PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

static NEXT_TEMP_PATH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A fresh, bounded, unique temp path this process exclusively owns; never
/// created on disk. The caller decides whether/how to populate it.
pub fn temp_path(label: &str) -> PathBuf {
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

pub fn bounded_temp_file(label: &str, bytes: &[u8]) -> (PathBuf, TempFileGuard) {
    let path: PathBuf = temp_path(label);
    fs::write(&path, bytes).unwrap();
    (path.clone(), TempFileGuard(path))
}

/// Writes a raw 32-byte Ed25519 seed to a bounded, `0600` temp file, exactly
/// the shape `fastvote_pg --signing-key-file` requires.
pub fn write_signing_key_file(seed: &[u8; 32]) -> (PathBuf, TempFileGuard) {
    let (path, guard) = bounded_temp_file("signing-key", seed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    (path, guard)
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut text: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

pub fn single_tcp_backend_addr(config: &Config, url_env: &str) -> SocketAddr {
    let [Host::Tcp(host)] = config.get_hosts() else {
        panic!("{url_env} must resolve to exactly one TCP host");
    };
    let port: u16 = config.get_ports().first().copied().unwrap_or(5432);
    format!("{host}:{port}")
        .to_socket_addrs()
        .unwrap_or_else(|error| panic!("failed to resolve backend host {host}: {error}"))
        .next()
        .unwrap_or_else(|| panic!("no resolved address for backend host {host}"))
}

/// Builds a `postgresql://` DSN through the TLS relay at `proxy_port`, using
/// `original`'s user/password/dbname unchanged.
pub fn proxied_dsn(original: &Config, proxy_port: u16) -> String {
    let user: &str = original.get_user().unwrap_or("postgres");
    let dbname: &str = original.get_dbname().unwrap_or(user);
    let password: Option<String> = original
        .get_password()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    proxied_dsn_for(user, password.as_deref(), dbname, proxy_port)
}

/// Builds a `postgresql://` DSN through the TLS relay at `proxy_port` for an
/// explicitly chosen user/password/dbname, independent of any existing
/// `Config` -- used to address a specific isolated validator's own role and
/// database.
pub fn proxied_dsn_for(
    user: &str,
    password: Option<&str>,
    dbname: &str,
    proxy_port: u16,
) -> String {
    match password {
        Some(password) => format!("postgresql://{user}:{password}@localhost:{proxy_port}/{dbname}"),
        None => format!("postgresql://{user}@localhost:{proxy_port}/{dbname}"),
    }
}

/// Every flag shared by every subcommand in one E2E run, derived once from
/// the fixture.
pub struct CliContext<'a> {
    pub ca_path: &'a Path,
    pub dsn: &'a str,
    pub chain_id: String,
    pub protocol_version: ProtocolVersion,
    pub manifest_path: &'a Path,
    pub digest_hex: String,
}

pub fn base_command(context: &CliContext<'_>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fastvote_pg"));
    command.env(DSN_ENV, context.dsn);
    command
}

/// Every protocol-sensitive operator command uses the fixture's exact pin.
fn protocol_command(context: &CliContext<'_>, subcommand: &str) -> Command {
    let mut command: Command = base_command(context);
    command
        .arg(subcommand)
        .arg("--protocol-version")
        .arg(context.protocol_version.get().to_string());
    command
}

#[cfg(test)]
mod protocol_pin_tests {
    use super::*;

    #[test]
    fn legacy_and_network_operator_commands_use_the_exact_fixture_protocol() {
        let legacy: FastVoteGenesisFixture =
            super::super::genesis_fixture::build_fixture("operator-protocol-v1");
        let network: FastVoteGenesisFixture =
            super::super::genesis_fixture::build_network_fixture("operator-protocol-v3");
        assert_eq!(legacy.protocol_version, ProtocolVersion::new(1));
        assert_eq!(network.protocol_version, ProtocolVersion::new(3));
        for fixture in [legacy, network] {
            let manifest: node_core::GenesisManifest =
                node_core::decode_genesis_manifest(&fixture.manifest_bytes).unwrap();
            assert_eq!(
                manifest.context().protocol_version(),
                fixture.protocol_version
            );
            let context: CliContext<'_> = CliContext {
                ca_path: Path::new("unused-ca"),
                dsn: "unused-dsn",
                chain_id: fixture.chain_id.to_string(),
                protocol_version: fixture.protocol_version,
                manifest_path: Path::new("unused-manifest"),
                digest_hex: to_hex(&fixture.manifest_digest),
            };
            for subcommand in [
                "install-genesis",
                "prepare-vote",
                "assemble-certificate",
                "apply-certificate",
            ] {
                // This is the actual command factory used by every helper
                // above, without executing a subprocess or contacting PG.
                let command: Command = protocol_command(&context, subcommand);
                let arguments: Vec<std::ffi::OsString> = command
                    .get_args()
                    .map(std::ffi::OsStr::to_os_string)
                    .collect();
                assert_eq!(
                    arguments,
                    vec![
                        std::ffi::OsString::from(subcommand),
                        std::ffi::OsString::from("--protocol-version"),
                        std::ffi::OsString::from(fixture.protocol_version.get().to_string()),
                    ]
                );
            }
        }
    }
}

pub fn namespace_init(context: &CliContext<'_>, validator_hex: &str, domain_hex: &str) -> Output {
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
    super::run_expect_success(command, "namespace-init")
}

/// Same as [`namespace_init`], but never panics on a non-success exit --
/// used by negatives that expect a connection/authorization failure.
pub fn namespace_init_allow_failure(
    context: &CliContext<'_>,
    validator_hex: &str,
    domain_hex: &str,
) -> Output {
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
    command.output().unwrap()
}

pub fn install_genesis(
    context: &CliContext<'_>,
    validator_hex: &str,
    domain_hex: &str,
    expect_success: bool,
) -> Output {
    let mut command = protocol_command(context, "install-genesis");
    command.args([
        "--tls-root-der",
        context.ca_path.to_str().unwrap(),
        "--chain-id",
        context.chain_id.as_str(),
        "--validator-id",
        validator_hex,
        "--domain",
        domain_hex,
        "--epoch",
        "0",
        "--suite",
        super::genesis_fixture::SUITE_FLAG,
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
        super::run_expect_success(command, "install-genesis")
    } else {
        command.output().unwrap()
    }
}

pub fn prepare_vote(
    context: &CliContext<'_>,
    validator_hex: &str,
    domain_hex: &str,
    key_path: &Path,
    intent_path: &Path,
    vote_output: &Path,
    expect_success: bool,
) -> Output {
    let mut command = protocol_command(context, "prepare-vote");
    command.args([
        "--tls-root-der",
        context.ca_path.to_str().unwrap(),
        "--chain-id",
        context.chain_id.as_str(),
        "--validator-id",
        validator_hex,
        "--domain",
        domain_hex,
        "--epoch",
        "0",
        "--suite",
        super::genesis_fixture::SUITE_FLAG,
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
        super::run_expect_success(command, "prepare-vote")
    } else {
        command.output().unwrap()
    }
}

pub fn assemble_certificate(
    context: &CliContext<'_>,
    vote_paths: &[PathBuf],
    certificate_output: &Path,
) -> Output {
    let mut command = protocol_command(context, "assemble-certificate");
    command.args([
        "--validator-set-source",
        "genesis-manifest",
        "--chain-id",
        context.chain_id.as_str(),
        "--epoch",
        "0",
        "--suite",
        super::genesis_fixture::SUITE_FLAG,
        "--genesis-manifest",
        context.manifest_path.to_str().unwrap(),
        "--expected-genesis-digest",
        &context.digest_hex,
        "--certificate-output",
        certificate_output.to_str().unwrap(),
    ]);
    for vote_path in vote_paths {
        command.arg("--vote").arg(vote_path);
    }
    command.output().unwrap()
}

pub fn apply_certificate(
    context: &CliContext<'_>,
    validator_hex: &str,
    domain_hex: &str,
    intent_path: &Path,
    certificate_path: &Path,
    response_output: &Path,
    expect_success: bool,
) -> Output {
    let mut command = protocol_command(context, "apply-certificate");
    command.args([
        "--tls-root-der",
        context.ca_path.to_str().unwrap(),
        "--chain-id",
        context.chain_id.as_str(),
        "--validator-id",
        validator_hex,
        "--domain",
        domain_hex,
        "--epoch",
        "0",
        "--suite",
        super::genesis_fixture::SUITE_FLAG,
        "--genesis-manifest",
        context.manifest_path.to_str().unwrap(),
        "--expected-genesis-digest",
        &context.digest_hex,
        "--paid-intent",
        intent_path.to_str().unwrap(),
        "--certificate",
        certificate_path.to_str().unwrap(),
        "--response-output",
        response_output.to_str().unwrap(),
        "--timeout-seconds",
        TIMEOUT_SECONDS,
        "--confirm-offline-fence-advance",
    ]);
    if expect_success {
        super::run_expect_success(command, "apply-certificate")
    } else {
        command.output().unwrap()
    }
}

pub fn assert_stdout_contains(output: &Output, field: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(field),
        "operator stdout lacks {field:?}: {stdout}"
    );
}

/// Direct, NoTls admin connection to a real backend (bypassing the TLS
/// relay), for out-of-band durable-state assertions the CLI itself has no
/// subcommand for: reading the current writer fence, and independently
/// re-verifying committed object/nonce state via `node_core`'s own public
/// query helpers.
pub fn admin_pool(config: &Config) -> Pool<PostgresConnectionManager<postgres::NoTls>> {
    let pool_config: PostgresPoolConfig = PostgresPoolConfig::new(
        NonZeroU32::new(2).unwrap(),
        Duration::from_secs(5),
        Duration::from_secs(30),
        Duration::from_secs(300),
    )
    .unwrap();
    let mut config: Config = config.clone();
    config.ssl_mode(SslMode::Disable);
    build_postgres_pool(config, postgres::NoTls, pool_config).unwrap()
}

pub fn current_fence(
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
pub fn read_context(
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
pub struct DurableSnapshot {
    pub certificate_record: Option<Vec<u8>>,
    pub object: ObjectQueryResult,
    pub next_nonce: u64,
}

pub fn snapshot(
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

/// The fee coin's exact current `ObjectRef` (id, live version, live digest),
/// independently re-queried out of band. A CLI-built call's `--access`/
/// `--fee-source` must reference this, not the object's original genesis
/// version, once any prior call (successful or a charged trap) has mutated
/// it: an owned object's version/digest advances on every settlement,
/// including a discarded-effects `ApplicationFailed` charge.
pub fn current_fee_coin_ref(
    pool: &Pool<PostgresConnectionManager<postgres::NoTls>>,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
) -> ObjectRef {
    let store = runtime_postgres::PostgresDurableStore::new(
        pool.clone(),
        namespace.clone(),
        runtime_postgres::PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap(),
    );
    let context: DurableOperationContext = read_context(pool, namespace);
    match query_object(
        &store,
        &context,
        fixture.domain,
        &fixture.chain_id,
        fixture.fee_coin,
    )
    .unwrap()
    {
        ObjectQueryResult::CurrentInline {
            object_id,
            object_version,
            digest,
            ..
        } => ObjectRef {
            id: object_id,
            version: object_version.get(),
            digest,
        },
        other => panic!("expected the fee coin to be a current inline object, got {other:?}"),
    }
}
