//! Certified, nonempty, live-PostgreSQL E2E for the `fee_escrow_inventory_pg`
//! operator binary (DR-0143's "prove the PostgreSQL operator on a nonempty
//! quorum-certified escrow fixture" gate).
//!
//! Skips (with a diagnostic on stderr) unless `SUNRISE_EDGE_TEST_POSTGRES_URL`
//! is configured, exactly like every other live PostgreSQL test in this
//! repository. Requires the fixture directory populated by node-core's
//! `export_certified_operator_fixture_postgres` (see
//! `crates/node-core/src/fee_claims/tests.rs`); both are driven together by
//! `scripts/check-fee-escrow-inventory-pg.sh`.
//!
//! The real CI/live PostgreSQL service exposes only a plaintext port, but the
//! operator binary hard-requires TLS with a validated certificate. This test
//! bridges the two with an in-process, ephemeral-CA TLS-terminating relay
//! (`support::tls_relay`) so the actual compiled binary -- not a
//! reimplementation of it -- is exercised end-to-end, including its own TLS
//! enforcement.

mod support;

use postgres::{
    Config,
    config::{Host, SslMode},
};
use protocol_types::{AtomicityDomainId, ChainId, ValidatorId};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{
    DurableDomainStateStore, DurableOperationContext, DurableReadError, StorageCorrelationId,
    StorageDeadline, WriterFenceGeneration,
};
use runtime_postgres::{
    PostgresDurableStore, PostgresNamespace, PostgresPoolConfig, PostgresTransactionPolicy,
    build_postgres_pool,
};
use std::{
    env, fs,
    net::{SocketAddr, ToSocketAddrs},
    num::NonZeroU32,
    path::{Path, PathBuf},
    process::{Command, Output},
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CHAIN_ID: &str = "paid-durable";
const DOMAIN_HEX: &str = "0808080808080808080808080808080808080808080808080808080808080808";
const PROTOCOL_VERSION: &str = "3";
const SUITE: &str = "0:1:1:1:1:1:1:1";

/// Deletes its temp file on drop, best-effort, regardless of test outcome.
struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn parse_hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "expected 64 hex digits, got {value:?}");
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .unwrap_or_else(|error| panic!("invalid hex in {value:?}: {error}"));
    }
    bytes
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

/// Builds the plain `postgresql://` URL string the operator binary itself
/// parses via `Config::from_str`, pointed at the TLS proxy's `localhost`
/// port with the same credentials and database as the real backend. The
/// binary always forces `sslmode=require` internally, so this string need
/// not (and, since it must remain a plain unencoded test credential, does
/// not attempt to) specify TLS options itself.
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

fn operator_command(ca_path: &Path, validator_id_hex: &str, dsn: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fee_escrow_inventory_pg"));
    command
        .env("SUNRISE_EDGE_OPERATOR_POSTGRES_DSN", dsn)
        .args([
            "--tls-root-der",
            ca_path.to_str().unwrap(),
            "--chain-id",
            CHAIN_ID,
            "--validator-id",
            validator_id_hex,
            "--domain",
            DOMAIN_HEX,
            "--protocol-version",
            PROTOCOL_VERSION,
            "--suite",
            SUITE,
            "--page-size",
            "1",
            "--timeout-seconds",
            "60",
        ]);
    command
}

fn assert_stdout_contains(output: &Output, field: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(field),
        "operator stdout lacks {field:?}: {stdout}"
    );
}

#[test]
#[ignore = "run through scripts/check-fee-escrow-inventory-pg.sh"]
fn fee_escrow_inventory_pg_operator_e2e() {
    let Some(database_url) = support::live_postgres_url() else {
        eprintln!(
            "skipping live PostgreSQL fee-escrow inventory operator E2E: {} is unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };
    let fixture_dir: PathBuf = support::fixture_dir();
    let validator_id_hex: String = fs::read_to_string(fixture_dir.join("validator_id.hex"))
        .expect("run the paired node-core export_certified_operator_fixture_postgres test first")
        .trim()
        .to_owned();

    // Acquired before any live-database work, shared with `runtime-postgres`'s
    // own live test family and the paired node-core fixture export.
    let _live_test_lock = support::LiveTestLock::acquire();

    let original_config: Config = Config::from_str(&database_url).unwrap();
    let backend_addr: SocketAddr = single_tcp_backend_addr(&original_config);

    let (proxy, _client_connector, ca_der) =
        support::tls_relay::TlsPassthroughProxy::spawn(backend_addr);
    let ca_path: PathBuf = env::temp_dir().join(format!(
        "sunrise-edge-operator-e2e-ca-{}-{}.der",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    fs::write(&ca_path, &ca_der).unwrap();
    let _ca_guard = TempFileGuard(ca_path.clone());
    let dsn: String = proxied_dsn(&original_config, proxy.local_addr().port());

    // ---- first real operator run: nonempty certified fixture, two pages ----
    let first_started: Instant = Instant::now();
    let first: Output = support::run_expect_success(
        {
            let mut command = operator_command(&ca_path, &validator_id_hex, &dsn);
            command.arg("--confirm-offline-fence-advance");
            command
        },
        "fee_escrow_inventory_pg (first run)",
    );
    for field in [
        "complete=true",
        "backend=postgres",
        &format!("chain_id={CHAIN_ID}"),
        &format!("validator_id={validator_id_hex}"),
        &format!("domain={DOMAIN_HEX}"),
        &format!("protocol_version={PROTOCOL_VERSION}"),
        "writer_generation=2",
        "pages=2",
        "verified_rows=2",
        "verified_claims=5",
        "verified_payouts=2",
    ] {
        assert_stdout_contains(&first, field);
    }
    let first_elapsed: Duration = first_started.elapsed();

    // ---- second real operator run: fence keeps advancing, same evidence ----
    let second_started: Instant = Instant::now();
    let second: Output = support::run_expect_success(
        {
            let mut command = operator_command(&ca_path, &validator_id_hex, &dsn);
            command.arg("--confirm-offline-fence-advance");
            command
        },
        "fee_escrow_inventory_pg (second run)",
    );
    for field in [
        "complete=true",
        "writer_generation=3",
        "pages=2",
        "verified_rows=2",
        "verified_claims=5",
        "verified_payouts=2",
    ] {
        assert_stdout_contains(&second, field);
    }
    let second_elapsed: Duration = second_started.elapsed();
    eprintln!(
        "certified PostgreSQL escrow inventory: rows=2 claims=5 payouts=2 pages=2 first_complete_sweep={first_elapsed:?} restarted_complete_sweep={second_elapsed:?}; disposable service, not representative recovery capacity"
    );

    // ---- negative: missing offline confirmation never advances the fence ----
    let unconfirmed: Output = operator_command(&ca_path, &validator_id_hex, &dsn)
        .output()
        .unwrap();
    assert!(
        !unconfirmed.status.success(),
        "operator must refuse to run without --confirm-offline-fence-advance"
    );
    assert!(
        unconfirmed.stdout.is_empty(),
        "no partial complete result is permitted on the confirmation failure path"
    );

    drop(proxy);

    // ---- negative: a stale writer-fence context is rejected fail-closed ----
    // Two real operator runs above advanced the namespace's writer fence to
    // generation 3 in the real backend database (not the proxy, which is
    // dropped above). A reader still holding the first operator run's
    // generation 2 must fail closed, just as a competing stale writer would.
    let admin_pool_config: PostgresPoolConfig = PostgresPoolConfig::new(
        NonZeroU32::new(2).unwrap(),
        Duration::from_secs(5),
        Duration::from_secs(30),
        Duration::from_secs(300),
    )
    .unwrap();
    let mut admin_config: Config = original_config;
    admin_config.ssl_mode(SslMode::Disable);
    let pool: Pool<PostgresConnectionManager<postgres::NoTls>> =
        build_postgres_pool(admin_config, postgres::NoTls, admin_pool_config).unwrap();
    let namespace: PostgresNamespace = PostgresNamespace::new(
        &ChainId::new(CHAIN_ID).unwrap(),
        ValidatorId::new(parse_hex_32(&validator_id_hex)),
        AtomicityDomainId::new(parse_hex_32(DOMAIN_HEX)).unwrap(),
    )
    .unwrap();
    let transaction_policy: PostgresTransactionPolicy =
        PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap();
    let store: PostgresDurableStore<PostgresConnectionManager<postgres::NoTls>> =
        PostgresDurableStore::new(pool, namespace, transaction_policy);
    let stale_context: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(2).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([2; 16]).unwrap(),
    );
    let escrow_key: Vec<u8> = node_core::local_instance_state::fastpath_settlement_key(
        &ChainId::new(CHAIN_ID).unwrap(),
        &[0xB1; 32],
    )
    .unwrap();
    let domain: AtomicityDomainId = AtomicityDomainId::new(parse_hex_32(DOMAIN_HEX)).unwrap();
    assert!(
        matches!(
            store.get_versioned_durable(&stale_context, domain, &escrow_key),
            Err(DurableReadError::WriterFenced { active_generation })
                if active_generation.get() == 3
        ),
        "a stale writer-fence context must fail closed against the real, currently \
         advanced PostgreSQL writer fence"
    );
}
