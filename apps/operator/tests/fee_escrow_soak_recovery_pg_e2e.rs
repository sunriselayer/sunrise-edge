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
    collections::BTreeMap,
    env, fs,
    io::Write,
    net::{SocketAddr, ToSocketAddrs},
    num::NonZeroU32,
    path::{Path, PathBuf},
    process::{Command, Output},
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::soak;

/// Deliberately small relative to the smoke profile's 8 planned rows, so
/// even the fixed CI profile genuinely exercises multi-page pagination
/// (`ceil(8 / 4) == 2` pages) instead of fitting everything on one page.
const PAGE_SIZE: u32 = 4;

/// The exact, ordered set of `key=value` tokens the real
/// `fee_escrow_inventory_pg` binary's single success line prints. Any
/// missing, extra, duplicated or unknown key is a malformed record.
const OPERATOR_RECORD_KEYS: [&str; 11] = [
    "complete",
    "backend",
    "chain_id",
    "validator_id",
    "domain",
    "protocol_version",
    "writer_generation",
    "pages",
    "verified_rows",
    "verified_claims",
    "verified_payouts",
];

fn expected_pages(rows: u32) -> u32 {
    rows.div_ceil(PAGE_SIZE)
}

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
            "4",
            "--timeout-seconds",
            "120",
        ]);
    command
}

/// Parses the operator binary's stdout as an exact, single-line, bounded
/// `key=value` record: newline-terminated with no trailing partial line, no
/// duplicate/unknown/missing keys, no empty tokens from a repeated space,
/// no more than one line of output. Never accepts a value that merely
/// starts with an expected prefix (e.g. `verified_rows=80` must never be
/// mistaken for `verified_rows=8`): callers compare the returned map's
/// values for exact string equality, never substring containment.
fn parse_operator_record(stdout: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let text: String = String::from_utf8(stdout.to_vec())
        .map_err(|error| format!("stdout is not UTF-8: {error}"))?;
    let mut lines: Vec<&str> = text.split('\n').collect();
    let trailer: &str = lines.pop().unwrap_or("");
    if !trailer.is_empty() {
        return Err(format!(
            "stdout must be newline-terminated with no trailing partial line: {text:?}"
        ));
    }
    if lines.len() != 1 {
        return Err(format!(
            "stdout must be exactly one record line, found {}: {text:?}",
            lines.len()
        ));
    }
    let line: &str = lines[0];
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    for token in line.split(' ') {
        if token.is_empty() {
            return Err(format!(
                "stdout has an empty token (repeated space): {line:?}"
            ));
        }
        let Some((key, value)) = token.split_once('=') else {
            return Err(format!("stdout token is missing '=': {token:?}"));
        };
        if key.is_empty() || value.is_empty() {
            return Err(format!("stdout token has an empty key or value: {token:?}"));
        }
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("stdout has a duplicate key {key:?}: {line:?}"));
        }
    }
    if fields.len() != OPERATOR_RECORD_KEYS.len() {
        return Err(format!(
            "stdout must have exactly {} keys, found {}: {line:?}",
            OPERATOR_RECORD_KEYS.len(),
            fields.len()
        ));
    }
    for key in OPERATOR_RECORD_KEYS {
        if !fields.contains_key(key) {
            return Err(format!("stdout is missing key {key:?}: {line:?}"));
        }
    }
    Ok(fields)
}

fn field_eq(fields: &BTreeMap<String, String>, key: &str, expected: &str) -> bool {
    fields.get(key).map(String::as_str) == Some(expected)
}

fn assert_field_eq(fields: &BTreeMap<String, String>, key: &str, expected: &str) {
    let actual: Option<&str> = fields.get(key).map(String::as_str);
    assert!(
        field_eq(fields, key, expected),
        "operator stdout field {key:?} mismatch: got {actual:?}, want {expected:?}"
    );
}

/// Independently reads the live, currently persisted namespace writer fence
/// out of band, never trusting the operator binary's own stdout claim.
fn current_generation(
    pool: &Pool<PostgresConnectionManager<postgres::NoTls>>,
    namespace: &PostgresNamespace,
) -> WriterFenceGeneration {
    let mut connection = pool.get().unwrap();
    inspect_namespace(&mut *connection, namespace)
        .unwrap()
        .unwrap_or_else(|| panic!("PostgreSQL namespace missing"))
        .writer_fence()
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
    let persisted: WriterFenceGeneration = current_generation(&admin_pool, &namespace);
    assert_eq!(
        persisted.get(),
        handoff.writer_generation,
        "persisted PostgreSQL writer fence does not match handoff.kv; refusing a stale handoff"
    );

    let (proxy, _client_connector, ca_der) =
        support::tls_relay::TlsPassthroughProxy::spawn(backend_addr);
    // Placed inside the driver's own fresh, exclusively-owned soak
    // directory (never the shared, world-writable system temp directory),
    // and opened with `create_new` so an existing file or symlink at this
    // path is refused rather than overwritten or followed.
    let ca_path: PathBuf = dir.join(format!(
        "recovery-ca-{}-{}.der",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&ca_path)
            .unwrap_or_else(|error| {
                panic!(
                    "failed to create fresh CA file at {}: {error}",
                    ca_path.display()
                )
            });
        file.write_all(&ca_der).unwrap();
        file.sync_all().unwrap();
    }
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
        let expected_generation: u64 = handoff
            .writer_generation
            .checked_add(u64::from(cycle))
            .unwrap_or_else(|| panic!("handoff writer_generation + cycle {cycle} overflowed"));
        let fields: BTreeMap<String, String> = parse_operator_record(&output.stdout)
            .unwrap_or_else(|error| panic!("malformed operator stdout record: {error}"));
        assert_field_eq(&fields, "complete", "true");
        assert_field_eq(&fields, "backend", "postgres");
        assert_field_eq(&fields, "chain_id", soak::FIXTURE_CHAIN_ID);
        assert_field_eq(&fields, "validator_id", &handoff.validator_id);
        assert_field_eq(&fields, "domain", &handoff.domain);
        assert_field_eq(&fields, "protocol_version", "3");
        assert_field_eq(
            &fields,
            "writer_generation",
            &expected_generation.to_string(),
        );
        assert_field_eq(
            &fields,
            "pages",
            &expected_pages(handoff.expected_rows).to_string(),
        );
        assert_field_eq(&fields, "verified_rows", &handoff.expected_rows.to_string());
        assert_field_eq(
            &fields,
            "verified_claims",
            &handoff.expected_claims.to_string(),
        );
        assert_field_eq(
            &fields,
            "verified_payouts",
            &handoff.expected_payouts.to_string(),
        );

        // Never trust the binary's own stdout claim about the fence it
        // says it advanced to: independently re-read the real, currently
        // persisted namespace generation after every single cycle.
        let observed: WriterFenceGeneration = current_generation(&admin_pool, &namespace);
        assert_eq!(
            observed.get(),
            expected_generation,
            "persisted PostgreSQL writer fence after cycle {cycle} does not match the expected advance"
        );
        let elapsed_ms: u128 = started.elapsed().as_millis();
        eprintln!(
            "sunrise_edge_soak_v1 kind=recovery cycle={cycle} writer_generation={expected_generation} \
             elapsed_ms={elapsed_ms} rows={} claims={} payouts={}",
            handoff.expected_rows, handoff.expected_claims, handoff.expected_payouts,
        );
    }
    let final_generation: u64 = handoff
        .writer_generation
        .checked_add(u64::from(cycles))
        .unwrap_or_else(|| panic!("handoff writer_generation + cycles {cycles} overflowed"));

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
    let after_unconfirmed: WriterFenceGeneration = current_generation(&admin_pool, &namespace);
    assert_eq!(
        after_unconfirmed.get(),
        final_generation,
        "the writer fence must not advance when the operator refuses to run without confirmation"
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

#[cfg(test)]
mod record_tests {
    use super::{field_eq, parse_operator_record};
    use std::collections::BTreeMap;

    fn valid_record() -> String {
        "complete=true backend=postgres chain_id=paid-durable \
         validator_id=1111111111111111111111111111111111111111111111111111111111111111 \
         domain=0808080808080808080808080808080808080808080808080808080808080808 \
         protocol_version=3 writer_generation=3 pages=2 verified_rows=8 \
         verified_claims=32 verified_payouts=8\n"
            .to_owned()
    }

    #[test]
    fn valid_record_parses_with_exact_fields() {
        let fields: BTreeMap<String, String> = parse_operator_record(valid_record().as_bytes())
            .expect("a well-formed single-line record must parse");
        assert!(field_eq(&fields, "verified_rows", "8"));
        assert!(!field_eq(&fields, "verified_rows", "80"));
        assert!(!field_eq(&fields, "verified_rows", ""));
    }

    #[test]
    fn prefix_collision_value_is_never_accepted_as_a_match() {
        let text: String = valid_record().replace("verified_rows=8", "verified_rows=80");
        let fields: BTreeMap<String, String> = parse_operator_record(text.as_bytes()).unwrap();
        assert!(
            !field_eq(&fields, "verified_rows", "8"),
            "verified_rows=80 must never satisfy an expected value of 8"
        );
        assert!(field_eq(&fields, "verified_rows", "80"));
    }

    #[test]
    fn non_newline_terminated_record_is_rejected() {
        let text: String = valid_record().trim_end().to_owned();
        assert!(parse_operator_record(text.as_bytes()).is_err());
    }

    #[test]
    fn extra_line_is_rejected() {
        let mut text: String = valid_record();
        text.push_str("complete=true backend=postgres chain_id=paid-durable\n");
        assert!(parse_operator_record(text.as_bytes()).is_err());
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let text: String = valid_record().replace(
            "verified_payouts=8",
            "verified_payouts=8 verified_payouts=8",
        );
        assert!(parse_operator_record(text.as_bytes()).is_err());
    }

    #[test]
    fn missing_key_is_rejected() {
        let text: String = valid_record().replace("pages=2 ", "");
        assert!(parse_operator_record(text.as_bytes()).is_err());
    }

    #[test]
    fn unknown_key_is_rejected() {
        let mut text: String = valid_record();
        text.truncate(text.len() - 1);
        text.push_str(" unknown_field=1\n");
        assert!(parse_operator_record(text.as_bytes()).is_err());
    }

    #[test]
    fn repeated_space_empty_token_is_rejected() {
        let text: String = valid_record().replace(' ', "  ");
        assert!(parse_operator_record(text.as_bytes()).is_err());
    }

    #[test]
    fn non_utf8_stdout_is_rejected() {
        let bytes: Vec<u8> = vec![0xFF, 0xFE, 0xFD];
        assert!(parse_operator_record(&bytes).is_err());
    }

    #[test]
    fn empty_stdout_is_rejected() {
        assert!(parse_operator_record(b"").is_err());
    }
}
