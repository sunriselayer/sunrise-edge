//! DR-0146 Track B: the recovery reader half of the bounded certified
//! PostgreSQL load and recovery harness.
//!
//! This file owns exactly one live, `#[ignore]`d E2E
//! (`fee_escrow_soak_recovery_pg_operator_e2e`) plus a set of non-ignored,
//! no-database-required adversarial tests of `support::soak`'s strict
//! `handoff.kv` parser and fixture-context validator.
//!
//! The paired core workload test (owned by a separate change,
//! `fast_path::soak_tests::live_postgres_certified_load_exports_recovery_handoff`
//! in `node-core`) creates the planned certified escrows, exercises one
//! split, one final and two zero-share claims per escrow, closes and
//! reopens the PostgreSQL primary under an advanced writer generation, and
//! publishes `handoff.kv` into `SUNRISE_EDGE_SOAK_DIR` only after its own
//! full lifecycle and restart checks succeed. This test never treats that
//! file as authoritative: every field is independently re-validated here,
//! including a direct out-of-band read of the live, currently persisted
//! namespace writer fence, before any real `fee_escrow_inventory_pg`
//! invocation proceeds. `scripts/check-postgres-soak.sh` is the only
//! intended driver: it owns `SUNRISE_EDGE_SOAK_DIR`, runs the core workload
//! test first, then this operator test, under one whole-run wall-deadline
//! timeout.

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
    build_postgres_pool, inspect_namespace,
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
use support::soak;

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
            soak::FIXTURE_CHAIN_ID,
            "--validator-id",
            validator_id_hex,
            "--domain",
            soak::FIXTURE_DOMAIN_HEX,
            "--protocol-version",
            "3",
            "--suite",
            soak::FIXTURE_SUITE,
            "--page-size",
            "16",
            "--timeout-seconds",
            "120",
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

fn soak_dir() -> PathBuf {
    PathBuf::from(env::var_os(soak::SOAK_DIR_ENV).unwrap_or_else(|| {
        panic!(
            "{} must be supplied by scripts/check-postgres-soak.sh",
            soak::SOAK_DIR_ENV
        )
    }))
}

fn recovery_cycles() -> u32 {
    let raw: String = env::var(soak::RECOVERY_CYCLES_ENV).unwrap_or_else(|_| {
        panic!(
            "{} must be supplied by scripts/check-postgres-soak.sh",
            soak::RECOVERY_CYCLES_ENV
        )
    });
    let value: u32 = raw
        .parse()
        .unwrap_or_else(|_| panic!("invalid {}: {raw:?}", soak::RECOVERY_CYCLES_ENV));
    assert!(
        (soak::RECOVERY_CYCLES_MIN..=soak::RECOVERY_CYCLES_MAX).contains(&value),
        "{} out of bounds [{}, {}]: {value}",
        soak::RECOVERY_CYCLES_ENV,
        soak::RECOVERY_CYCLES_MIN,
        soak::RECOVERY_CYCLES_MAX
    );
    value
}

fn require_disposable_confirmation() {
    let value: String = env::var(soak::CONFIRM_DISPOSABLE_ENV).unwrap_or_default();
    assert_eq!(
        value,
        "1",
        "{} must be exactly \"1\", confirming this run targets only a disposable loopback \
         sunrise_edge_test service",
        soak::CONFIRM_DISPOSABLE_ENV
    );
}

#[test]
#[ignore = "run through scripts/check-postgres-soak.sh"]
fn fee_escrow_soak_recovery_pg_operator_e2e() {
    let Some(database_url) = support::live_postgres_url() else {
        eprintln!(
            "skipping live PostgreSQL certified load/recovery operator E2E: {} is unset",
            support::LIVE_POSTGRES_URL_ENV
        );
        return;
    };

    // Acquired before any live-database work, shared with every other live
    // PostgreSQL test family in this repository.
    let _live_test_lock = support::LiveTestLock::acquire();

    require_disposable_confirmation();
    let dir: PathBuf = soak_dir();
    let cycles: u32 = recovery_cycles();
    let handoff: soak::Handoff = soak::read_and_validate_handoff(&dir)
        .unwrap_or_else(|error| panic!("invalid or incomplete handoff.kv: {error}"));

    let original_config: Config = Config::from_str(&database_url).unwrap();
    let backend_addr: SocketAddr = single_tcp_backend_addr(&original_config);

    let admin_pool_config: PostgresPoolConfig = PostgresPoolConfig::new(
        NonZeroU32::new(2).unwrap(),
        Duration::from_secs(5),
        Duration::from_secs(30),
        Duration::from_secs(300),
    )
    .unwrap();
    let mut admin_config: Config = original_config.clone();
    admin_config.ssl_mode(SslMode::Disable);
    let admin_pool: Pool<PostgresConnectionManager<postgres::NoTls>> =
        build_postgres_pool(admin_config, postgres::NoTls, admin_pool_config).unwrap();

    let current_database: String = {
        let mut connection = admin_pool.get().unwrap();
        connection
            .query_one("SELECT current_database()", &[])
            .unwrap()
            .get(0)
    };
    assert_eq!(
        current_database, "sunrise_edge_test",
        "refusing to run the certified PostgreSQL soak recovery reader against a non-test database"
    );

    let chain: ChainId = ChainId::new(soak::FIXTURE_CHAIN_ID).unwrap();
    let validator: ValidatorId = ValidatorId::new(parse_hex_32(&handoff.validator_id));
    let domain: AtomicityDomainId = AtomicityDomainId::new(parse_hex_32(&handoff.domain)).unwrap();
    let namespace: PostgresNamespace = PostgresNamespace::new(&chain, validator, domain).unwrap();

    // The handoff is not authority: independently re-read the live,
    // currently persisted writer fence and require it to equal exactly what
    // the workload's own restart check left behind.
    let persisted: WriterFenceGeneration = {
        let mut connection = admin_pool.get().unwrap();
        inspect_namespace(&mut *connection, &namespace)
            .unwrap()
            .unwrap_or_else(|| panic!("PostgreSQL namespace not bootstrapped"))
            .writer_fence()
    };
    assert_eq!(
        persisted.get(),
        handoff.writer_generation,
        "persisted PostgreSQL writer fence does not match handoff.kv; refusing a stale handoff"
    );

    let (proxy, _client_connector, ca_der) =
        support::tls_relay::TlsPassthroughProxy::spawn(backend_addr);
    let ca_path: PathBuf = env::temp_dir().join(format!(
        "sunrise-edge-soak-recovery-e2e-ca-{}-{}.der",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    fs::write(&ca_path, &ca_der).unwrap();
    let _ca_guard = TempFileGuard(ca_path.clone());
    let dsn: String = proxied_dsn(&original_config, proxy.local_addr().port());

    // ---- repeated real operator recovery cycles: fence advances by
    // exactly one each time, evidence stays exactly the planned totals ----
    for cycle in 1..=cycles {
        let started: Instant = Instant::now();
        let mut command = operator_command(&ca_path, &handoff.validator_id, &dsn);
        command.arg("--confirm-offline-fence-advance");
        let output: Output = support::run_expect_success(
            command,
            &format!("fee_escrow_inventory_pg (recovery cycle {cycle})"),
        );
        let expected_generation: u64 = handoff.writer_generation + u64::from(cycle);
        for field in [
            "complete=true".to_owned(),
            "backend=postgres".to_owned(),
            format!("chain_id={}", soak::FIXTURE_CHAIN_ID),
            format!("validator_id={}", handoff.validator_id),
            format!("domain={}", handoff.domain),
            "protocol_version=3".to_owned(),
            format!("writer_generation={expected_generation}"),
            format!("verified_rows={}", handoff.expected_rows),
            format!("verified_claims={}", handoff.expected_claims),
            format!("verified_payouts={}", handoff.expected_payouts),
        ] {
            assert_stdout_contains(&output, &field);
        }
        let elapsed_ms: u128 = started.elapsed().as_millis();
        eprintln!(
            "sunrise_edge_soak_v1 kind=recovery cycle={cycle} writer_generation={expected_generation} \
             elapsed_ms={elapsed_ms} rows={} claims={} payouts={}",
            handoff.expected_rows, handoff.expected_claims, handoff.expected_payouts,
        );
    }
    let final_generation: u64 = handoff.writer_generation + u64::from(cycles);

    // ---- negative: missing offline confirmation never advances the fence
    // or emits any partial complete result ----
    let unconfirmed: Output = operator_command(&ca_path, &handoff.validator_id, &dsn)
        .output()
        .unwrap();
    assert!(
        !unconfirmed.status.success(),
        "operator must refuse to run without --confirm-offline-fence-advance"
    );
    assert!(
        unconfirmed.stdout.is_empty(),
        "no partial complete totals are permitted on the confirmation failure path"
    );

    drop(proxy);

    // ---- negative: the original handoff generation is now stale and must
    // fail closed against the real, currently advanced writer fence ----
    let stale_context: DurableOperationContext = DurableOperationContext::new(
        WriterFenceGeneration::new(handoff.writer_generation).unwrap(),
        StorageDeadline::new(u64::MAX).unwrap(),
        StorageCorrelationId::new([0x77; 16]).unwrap(),
    );
    let policy: PostgresTransactionPolicy =
        PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap();
    let store: PostgresDurableStore<PostgresConnectionManager<postgres::NoTls>> =
        PostgresDurableStore::new(admin_pool, namespace, policy);
    let arbitrary_key: Vec<u8> =
        node_core::local_instance_state::fastpath_settlement_key(&chain, &[0x51; 32]).unwrap();
    assert!(
        matches!(
            store.get_versioned_durable(&stale_context, domain, &arbitrary_key),
            Err(DurableReadError::WriterFenced { active_generation })
                if active_generation.get() == final_generation
        ),
        "a stale writer-fence context (the original handoff generation) must fail closed against \
         the real, currently advanced PostgreSQL writer fence"
    );
}

#[cfg(test)]
mod parser_tests {
    use super::soak::{
        FIXTURE_CHAIN_ID, FIXTURE_DOMAIN_HEX, FIXTURE_EPOCH, FIXTURE_PROTOCOL_VERSION,
        FIXTURE_SUITE, Handoff, parse_handoff, validate_against_fixture,
    };

    fn valid_lines() -> Vec<String> {
        vec![
            "schema_version=1".to_owned(),
            format!("validator_id={}", "11".repeat(32)),
            format!("chain_id={FIXTURE_CHAIN_ID}"),
            format!("domain={FIXTURE_DOMAIN_HEX}"),
            format!("protocol_version={FIXTURE_PROTOCOL_VERSION}"),
            format!("epoch={FIXTURE_EPOCH}"),
            format!("suite={FIXTURE_SUITE}"),
            "expected_rows=8".to_owned(),
            "expected_claims=32".to_owned(),
            "expected_payouts=8".to_owned(),
            "writer_generation=2".to_owned(),
            "workload_elapsed_ms=12345".to_owned(),
        ]
    }

    fn valid_text() -> String {
        let mut text: String = valid_lines().join("\n");
        text.push('\n');
        text
    }

    fn parse_ok(text: &str) -> Handoff {
        parse_handoff(text).unwrap_or_else(|error| panic!("expected valid handoff, got {error}"))
    }

    #[test]
    fn valid_handoff_parses_and_validates() {
        let handoff: Handoff = parse_ok(&valid_text());
        validate_against_fixture(&handoff).unwrap();
        assert_eq!(handoff.expected_rows, 8);
        assert_eq!(handoff.expected_claims, 32);
        assert_eq!(handoff.expected_payouts, 8);
        assert_eq!(handoff.writer_generation, 2);
    }

    #[test]
    fn missing_key_is_rejected() {
        let mut lines: Vec<String> = valid_lines();
        lines.remove(4); // protocol_version
        let mut text: String = lines.join("\n");
        text.push('\n');
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let mut lines: Vec<String> = valid_lines();
        lines.push("epoch=0".to_owned());
        let mut text: String = lines.join("\n");
        text.push('\n');
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn unknown_key_is_rejected() {
        let mut lines: Vec<String> = valid_lines();
        lines.pop();
        lines.push("unknown_field=1".to_owned());
        lines.push("workload_elapsed_ms=12345".to_owned());
        let mut text: String = lines.join("\n");
        text.push('\n');
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn non_newline_terminated_is_rejected() {
        let text: String = valid_lines().join("\n");
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn blank_line_is_rejected() {
        let mut text: String = valid_text();
        text.push('\n');
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn bad_schema_version_is_rejected() {
        let text: String = valid_text().replace("schema_version=1", "schema_version=2");
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn bad_hex_validator_id_is_rejected() {
        let text: String = valid_text().replace(&"11".repeat(32), &"GG".repeat(32));
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn leading_zero_decimal_is_rejected() {
        let text: String = valid_text().replace("expected_rows=8", "expected_rows=08");
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn rows_out_of_bounds_is_rejected() {
        let too_many: String = valid_text().replace("expected_rows=8", "expected_rows=4097");
        assert!(parse_handoff(&too_many).is_err());
        let zero: String = valid_text()
            .replace("expected_rows=8", "expected_rows=0")
            .replace("expected_claims=32", "expected_claims=0")
            .replace("expected_payouts=8", "expected_payouts=0");
        assert!(parse_handoff(&zero).is_err());
    }

    #[test]
    fn zero_writer_generation_is_rejected() {
        let text: String = valid_text().replace("writer_generation=2", "writer_generation=0");
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn oversized_value_is_rejected() {
        let text: String = valid_text().replace(
            "workload_elapsed_ms=12345",
            &format!("workload_elapsed_ms={}", "9".repeat(300)),
        );
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn non_ascii_graphic_value_is_rejected() {
        let text: String = valid_text().replace("chain_id=paid-durable", "chain_id=paid\tdurable");
        assert!(parse_handoff(&text).is_err());
    }

    #[test]
    fn claims_payouts_mismatch_is_rejected_by_fixture_validation() {
        let text: String = valid_text().replace("expected_claims=32", "expected_claims=31");
        let handoff: Handoff = parse_ok(&text);
        assert!(validate_against_fixture(&handoff).is_err());

        let text: String = valid_text().replace("expected_payouts=8", "expected_payouts=7");
        let handoff: Handoff = parse_ok(&text);
        assert!(validate_against_fixture(&handoff).is_err());
    }

    #[test]
    fn stale_context_fields_are_rejected_by_fixture_validation() {
        let chain: String = valid_text().replace("chain_id=paid-durable", "chain_id=other-chain");
        assert!(validate_against_fixture(&parse_ok(&chain)).is_err());

        let bad_domain: String = valid_text().replace(FIXTURE_DOMAIN_HEX, &"09".repeat(32));
        assert!(validate_against_fixture(&parse_ok(&bad_domain)).is_err());

        let protocol: String = valid_text().replace("protocol_version=3", "protocol_version=4");
        assert!(validate_against_fixture(&parse_ok(&protocol)).is_err());

        let epoch: String = valid_text().replace("epoch=0", "epoch=1");
        assert!(validate_against_fixture(&parse_ok(&epoch)).is_err());

        let suite: String = valid_text().replace(FIXTURE_SUITE, "0:2:1:1:1:1:1:1");
        assert!(validate_against_fixture(&parse_ok(&suite)).is_err());
    }
}
