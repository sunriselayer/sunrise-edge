//! DR-0146: bounded certified PostgreSQL load and recovery harness (see
//! `docs/architecture/decisions/0146-postgres-certified-load-and-recovery-harness.md`).
//!
//! This module owns exactly the node-core test surface of that decision: a
//! pure, fail-closed config/handoff parser and writer (exercised by the
//! ordinary, non-ignored tests below) plus one deliberately `#[ignore]`d
//! manual driver that creates a bounded number of genuinely paid, quorum-
//! certified fee escrows against one live PostgreSQL primary, drains every
//! one of them through the real fee-claim pipeline, and proves the result
//! survives one close/reopen under an advanced writer generation.
//!
//! This core driver performs exactly one writer-generation transition
//! (fence `1` -> `2`) and never prints `kind=totals complete=true`: an
//! ordered operator script owns repeating this driver across
//! `RECOVERY_CYCLES` and owns the single authoritative complete-run
//! declaration, so this module never claims that authority on its own.
//!
//! Out of scope here, by construction: the real TLS `fee_escrow_inventory_pg`
//! operator executable and any operator/script/docs surface. This module's
//! own in-process calls to [`verify_fee_escrow_inventory_all`] exercise the
//! identical library verification path that binary wraps, but never spawns
//! or TLS-dials the compiled executable itself -- that remains a separate,
//! operator-owned obligation.
use super::*;
use crate::fee_claims::tests::certified_multi_escrow_inventory::{
    SplitClaim, Voter, apply_escrow, apply_escrow_with_blob, build_final_claim_for_lane,
    build_split_claim_for_lane, build_validator_set, build_zero_claim, certify, install_all,
    prepare_vote, prepare_vote_with_blob,
};
use crate::fee_claims::{
    FeeClaimError, FeeEscrowInventorySweep, handle_fee_claim, verify_fee_escrow_inventory_all,
};
use crate::paid_execution::tests::{
    FIRST_PAID_NONCE, Fixture, LanePaidTransfer, base_policy, context, domain, install_extra_coin,
    lane_paid_transfer, memory_store, protocol, receipt, resolver,
};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::LocalWasmExecutionEngine;
use execution::paid_execution::PaidExecutionStatus;
use postgres::{Client, NoTls};
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime::{DurableRequestReceipt, MemoryDurableStateStore, StateRevision};
use runtime_postgres::{
    POSTGRES_SCHEMA_GENERATION, PostgresBlobStore, PostgresDurableStore, PostgresNamespace,
    PostgresPoolConfig, PostgresTransactionPolicy, advance_writer_fence, apply_initial_schema,
    bootstrap_namespace, build_postgres_pool,
};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ── DR-0146 bounds ──────────────────────────────────────────────────────

const MIN_ESCROWS: u32 = 1;
const MAX_ESCROWS: u32 = 4096;
const MIN_SENDERS: u32 = 1;
const MAX_SENDERS: u32 = 64;
const MIN_CLAIM_WRITERS: u32 = 1;
const MAX_CLAIM_WRITERS: u32 = 16;
const MIN_MAX_CLAIM_RATE_PER_SEC: u32 = 1;
const MAX_MAX_CLAIM_RATE_PER_SEC: u32 = 1000;
const MIN_DURATION_SECONDS: u64 = 1;
const MAX_DURATION_SECONDS: u64 = 21_600;
const MIN_WALL_DEADLINE_SECONDS: u64 = 1;
const MAX_WALL_DEADLINE_SECONDS: u64 = 25_200;
const MIN_RECOVERY_CYCLES: u32 = 1;
const MAX_RECOVERY_CYCLES: u32 = 32;

/// Every bounded live-run knob, `SUNRISE_EDGE_SOAK_`-prefixed per DR-0146.
/// `recovery_cycles` is parsed and bounded here (so a malformed value still
/// fails config validation) but this core driver itself never loops on it:
/// repeating the whole driver `recovery_cycles` times is the ordered
/// operator script's job, not this in-process test's.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SoakConfig {
    directory: PathBuf,
    escrows: u32,
    senders: u32,
    claim_writers: u32,
    max_claim_rate_per_sec: u32,
    duration_seconds: u64,
    wall_deadline_seconds: u64,
    recovery_cycles: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoakConfigError {
    MissingVar(&'static str),
    NonCanonicalInteger(&'static str),
    OutOfBounds(&'static str),
    SendersExceedEscrows,
    WallDeadlineDoesNotExceedDuration,
    DirectoryMissing,
    ConfirmDisposableRequired,
}

impl fmt::Display for SoakConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVar(name) => write!(f, "missing required env var {name}"),
            Self::NonCanonicalInteger(name) => {
                write!(f, "env var {name} is not a canonical unsigned decimal integer")
            }
            Self::OutOfBounds(name) => write!(f, "env var {name} is out of its DR-0146 bounds"),
            Self::SendersExceedEscrows => {
                f.write_str("SUNRISE_EDGE_SOAK_SENDERS must not exceed SUNRISE_EDGE_SOAK_ESCROWS")
            }
            Self::WallDeadlineDoesNotExceedDuration => f.write_str(
                "SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS must exceed SUNRISE_EDGE_SOAK_DURATION_SECONDS",
            ),
            Self::DirectoryMissing => {
                f.write_str("SUNRISE_EDGE_SOAK_DIR must name an existing directory")
            }
            Self::ConfirmDisposableRequired => f.write_str(
                "SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE must be exactly the literal `1`",
            ),
        }
    }
}

/// Accepts only a canonical unsigned decimal integer: no leading `+`, no
/// leading zero (other than the literal `0`), no surrounding whitespace, no
/// non-ASCII-digit byte. Rejects `"+1"`, `"01"`, `" 1"`, `"1 "`, `""`.
fn canonical_decimal_digits(raw: &str) -> Option<&str> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if raw.len() > 1 && raw.as_bytes()[0] == b'0' {
        return None;
    }
    Some(raw)
}

fn required_u32(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    min: u32,
    max: u32,
) -> Result<u32, SoakConfigError> {
    let raw: String = lookup(name).ok_or(SoakConfigError::MissingVar(name))?;
    let canonical: &str =
        canonical_decimal_digits(&raw).ok_or(SoakConfigError::NonCanonicalInteger(name))?;
    let value: u32 = canonical
        .parse()
        .map_err(|_| SoakConfigError::NonCanonicalInteger(name))?;
    if value < min || value > max {
        return Err(SoakConfigError::OutOfBounds(name));
    }
    Ok(value)
}

fn required_u64(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    min: u64,
    max: u64,
) -> Result<u64, SoakConfigError> {
    let raw: String = lookup(name).ok_or(SoakConfigError::MissingVar(name))?;
    let canonical: &str =
        canonical_decimal_digits(&raw).ok_or(SoakConfigError::NonCanonicalInteger(name))?;
    let value: u64 = canonical
        .parse()
        .map_err(|_| SoakConfigError::NonCanonicalInteger(name))?;
    if value < min || value > max {
        return Err(SoakConfigError::OutOfBounds(name));
    }
    Ok(value)
}

/// Parses every `SUNRISE_EDGE_SOAK_*` knob from an injected lookup function
/// (never `std::env` directly), so the bound checks below are exercised as
/// ordinary, fast, non-ignored unit tests. Also requires the exact literal
/// `SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE=1` disposable-test confirmation
/// DR-0146 mandates for the manual runner.
fn parse_soak_config(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<SoakConfig, SoakConfigError> {
    let confirm_disposable: String = lookup("SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE").ok_or(
        SoakConfigError::MissingVar("SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE"),
    )?;
    if confirm_disposable != "1" {
        return Err(SoakConfigError::ConfirmDisposableRequired);
    }
    let escrows: u32 = required_u32(
        &lookup,
        "SUNRISE_EDGE_SOAK_ESCROWS",
        MIN_ESCROWS,
        MAX_ESCROWS,
    )?;
    let senders: u32 = required_u32(
        &lookup,
        "SUNRISE_EDGE_SOAK_SENDERS",
        MIN_SENDERS,
        MAX_SENDERS,
    )?;
    if senders > escrows {
        return Err(SoakConfigError::SendersExceedEscrows);
    }
    let claim_writers: u32 = required_u32(
        &lookup,
        "SUNRISE_EDGE_SOAK_CLAIM_WRITERS",
        MIN_CLAIM_WRITERS,
        MAX_CLAIM_WRITERS,
    )?;
    let max_claim_rate_per_sec: u32 = required_u32(
        &lookup,
        "SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC",
        MIN_MAX_CLAIM_RATE_PER_SEC,
        MAX_MAX_CLAIM_RATE_PER_SEC,
    )?;
    let duration_seconds: u64 = required_u64(
        &lookup,
        "SUNRISE_EDGE_SOAK_DURATION_SECONDS",
        MIN_DURATION_SECONDS,
        MAX_DURATION_SECONDS,
    )?;
    let wall_deadline_seconds: u64 = required_u64(
        &lookup,
        "SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS",
        MIN_WALL_DEADLINE_SECONDS,
        MAX_WALL_DEADLINE_SECONDS,
    )?;
    if wall_deadline_seconds <= duration_seconds {
        return Err(SoakConfigError::WallDeadlineDoesNotExceedDuration);
    }
    let recovery_cycles: u32 = required_u32(
        &lookup,
        "SUNRISE_EDGE_SOAK_RECOVERY_CYCLES",
        MIN_RECOVERY_CYCLES,
        MAX_RECOVERY_CYCLES,
    )?;
    let directory_raw: String = lookup("SUNRISE_EDGE_SOAK_DIR")
        .ok_or(SoakConfigError::MissingVar("SUNRISE_EDGE_SOAK_DIR"))?;
    let directory: PathBuf = PathBuf::from(directory_raw);
    if !directory.is_dir() {
        return Err(SoakConfigError::DirectoryMissing);
    }
    Ok(SoakConfig {
        directory,
        escrows,
        senders,
        claim_writers,
        max_claim_rate_per_sec,
        duration_seconds,
        wall_deadline_seconds,
        recovery_cycles,
    })
}

// ── disposable-database URL validation ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisposableDatabaseUrlError {
    Unparseable,
    NotExactlyOneTcpHost,
    HostNotLoopback,
    WrongDatabaseName,
}

impl fmt::Display for DisposableDatabaseUrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unparseable => f.write_str(
                "SUNRISE_EDGE_TEST_POSTGRES_URL is not a valid PostgreSQL connection string",
            ),
            Self::NotExactlyOneTcpHost => {
                f.write_str("SUNRISE_EDGE_TEST_POSTGRES_URL must name exactly one TCP host")
            }
            Self::HostNotLoopback => f.write_str(
                "SUNRISE_EDGE_TEST_POSTGRES_URL's host must resolve only to loopback addresses",
            ),
            Self::WrongDatabaseName => f.write_str(
                "SUNRISE_EDGE_TEST_POSTGRES_URL must name the sunrise_edge_test database",
            ),
        }
    }
}

/// Enforces, from the connection string alone and before any socket is
/// opened, that this run can only ever reach a single disposable loopback
/// PostgreSQL service named `sunrise_edge_test`: exactly one TCP host, every
/// address that host resolves to a loopback address, and the exact
/// configured database name. This is defense in depth alongside (not a
/// replacement for) the real post-connect `SELECT current_database()` check.
fn validate_disposable_test_database_url(url: &str) -> Result<(), DisposableDatabaseUrlError> {
    let config: postgres::Config = url
        .parse()
        .map_err(|_| DisposableDatabaseUrlError::Unparseable)?;
    let hosts: &[postgres::config::Host] = config.get_hosts();
    let [postgres::config::Host::Tcp(host_name)] = hosts else {
        return Err(DisposableDatabaseUrlError::NotExactlyOneTcpHost);
    };
    let resolved: Vec<std::net::IpAddr> = if let Ok(ip) = host_name.parse::<std::net::IpAddr>() {
        vec![ip]
    } else {
        use std::net::ToSocketAddrs;
        (host_name.as_str(), 0_u16)
            .to_socket_addrs()
            .map_err(|_| DisposableDatabaseUrlError::HostNotLoopback)?
            .map(|address| address.ip())
            .collect()
    };
    if resolved.is_empty() || !resolved.iter().all(std::net::IpAddr::is_loopback) {
        return Err(DisposableDatabaseUrlError::HostNotLoopback);
    }
    if config.get_dbname() != Some("sunrise_edge_test") {
        return Err(DisposableDatabaseUrlError::WrongDatabaseName);
    }
    Ok(())
}

// ── handoff.kv ───────────────────────────────────────────────────────────

/// The exact twelve keys DR-0146 requires, in the order it documents them.
/// `writer_generation` is always `2` from this core driver (one fence
/// `1 -> 2` transition); an operator script that repeats this driver across
/// several writer generations owns interpreting/aggregating that sequence.
struct HandoffFields {
    validator_id: String,
    chain_id: String,
    domain: String,
    protocol_version: u32,
    epoch: u64,
    suite: String,
    expected_rows: u32,
    expected_claims: u32,
    expected_payouts: u32,
    writer_generation: u64,
    workload_elapsed_ms: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum SoakHandoffError {
    AlreadyExists,
    Io(std::io::ErrorKind),
}

/// Writes `handoff.kv` fresh: refuses to overwrite an existing file, a
/// dangling symlink, or anything else already present at that exact path.
fn write_handoff(directory: &Path, fields: &HandoffFields) -> Result<(), SoakHandoffError> {
    let path: PathBuf = directory.join("handoff.kv");
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(SoakHandoffError::AlreadyExists);
    }
    let mut body: String = String::new();
    for (key, value) in [
        ("schema_version".to_owned(), "1".to_owned()),
        ("validator_id".to_owned(), fields.validator_id.clone()),
        ("chain_id".to_owned(), fields.chain_id.clone()),
        ("domain".to_owned(), fields.domain.clone()),
        (
            "protocol_version".to_owned(),
            fields.protocol_version.to_string(),
        ),
        ("epoch".to_owned(), fields.epoch.to_string()),
        ("suite".to_owned(), fields.suite.clone()),
        ("expected_rows".to_owned(), fields.expected_rows.to_string()),
        (
            "expected_claims".to_owned(),
            fields.expected_claims.to_string(),
        ),
        (
            "expected_payouts".to_owned(),
            fields.expected_payouts.to_string(),
        ),
        (
            "writer_generation".to_owned(),
            fields.writer_generation.to_string(),
        ),
        (
            "workload_elapsed_ms".to_owned(),
            fields.workload_elapsed_ms.to_string(),
        ),
    ] {
        body.push_str(&key);
        body.push('=');
        body.push_str(&value);
        body.push('\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| SoakHandoffError::Io(error.kind()))?;
    file.write_all(body.as_bytes())
        .map_err(|error| SoakHandoffError::Io(error.kind()))?;
    file.sync_all()
        .map_err(|error| SoakHandoffError::Io(error.kind()))
}

// ── non-ignored config/handoff/DSN tests ────────────────────────────────

#[cfg(test)]
mod config_and_handoff_tests {
    use super::*;

    fn valid_map() -> BTreeMap<&'static str, String> {
        let mut map: BTreeMap<&'static str, String> = BTreeMap::new();
        map.insert("SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE", "1".to_owned());
        map.insert("SUNRISE_EDGE_SOAK_ESCROWS", "4".to_owned());
        map.insert("SUNRISE_EDGE_SOAK_SENDERS", "2".to_owned());
        map.insert("SUNRISE_EDGE_SOAK_CLAIM_WRITERS", "2".to_owned());
        map.insert("SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC", "10".to_owned());
        map.insert("SUNRISE_EDGE_SOAK_DURATION_SECONDS", "60".to_owned());
        map.insert("SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS", "120".to_owned());
        map.insert("SUNRISE_EDGE_SOAK_RECOVERY_CYCLES", "1".to_owned());
        map.insert(
            "SUNRISE_EDGE_SOAK_DIR",
            std::env::temp_dir().to_string_lossy().into_owned(),
        );
        map
    }

    fn lookup(map: &BTreeMap<&'static str, String>) -> impl Fn(&str) -> Option<String> {
        let owned: BTreeMap<&'static str, String> = map.clone();
        move |name: &str| owned.get(name).cloned()
    }

    #[test]
    fn accepts_a_fully_bounded_configuration() {
        let map: BTreeMap<&'static str, String> = valid_map();
        let config: SoakConfig = parse_soak_config(lookup(&map)).unwrap();
        assert_eq!(config.escrows, 4);
        assert_eq!(config.senders, 2);
        assert_eq!(config.claim_writers, 2);
        assert_eq!(config.max_claim_rate_per_sec, 10);
        assert_eq!(config.duration_seconds, 60);
        assert_eq!(config.wall_deadline_seconds, 120);
        assert_eq!(config.recovery_cycles, 1);
    }

    #[test]
    fn rejects_a_missing_confirm_disposable() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.remove("SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE");
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::MissingVar("SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE"),
        );
    }

    #[test]
    fn rejects_a_non_exact_confirm_disposable() {
        for value in ["0", "true", "yes", "01", "+1", "1 ", " 1", "11"] {
            let mut map: BTreeMap<&'static str, String> = valid_map();
            map.insert("SUNRISE_EDGE_SOAK_CONFIRM_DISPOSABLE", value.to_owned());
            assert_eq!(
                parse_soak_config(lookup(&map)).unwrap_err(),
                SoakConfigError::ConfirmDisposableRequired,
                "value {value:?} must be rejected",
            );
        }
    }

    #[test]
    fn rejects_a_missing_variable() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.remove("SUNRISE_EDGE_SOAK_ESCROWS");
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::MissingVar("SUNRISE_EDGE_SOAK_ESCROWS"),
        );
    }

    #[test]
    fn rejects_a_non_integer_value() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert("SUNRISE_EDGE_SOAK_ESCROWS", "not-a-number".to_owned());
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::NonCanonicalInteger("SUNRISE_EDGE_SOAK_ESCROWS"),
        );
    }

    #[test]
    fn rejects_noncanonical_integers() {
        for value in ["+4", "04", " 4", "4 ", "4.0", "-4"] {
            let mut map: BTreeMap<&'static str, String> = valid_map();
            map.insert("SUNRISE_EDGE_SOAK_ESCROWS", value.to_owned());
            assert_eq!(
                parse_soak_config(lookup(&map)).unwrap_err(),
                SoakConfigError::NonCanonicalInteger("SUNRISE_EDGE_SOAK_ESCROWS"),
                "value {value:?} must be rejected",
            );
        }
    }

    #[test]
    fn accepts_the_canonical_zero() {
        assert_eq!(canonical_decimal_digits("0"), Some("0"));
        assert_eq!(canonical_decimal_digits("00"), None);
    }

    #[test]
    fn rejects_escrows_below_the_minimum() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert("SUNRISE_EDGE_SOAK_ESCROWS", "0".to_owned());
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::OutOfBounds("SUNRISE_EDGE_SOAK_ESCROWS"),
        );
    }

    #[test]
    fn rejects_escrows_above_the_maximum() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert("SUNRISE_EDGE_SOAK_ESCROWS", "4097".to_owned());
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::OutOfBounds("SUNRISE_EDGE_SOAK_ESCROWS"),
        );
    }

    #[test]
    fn rejects_senders_above_escrows() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert("SUNRISE_EDGE_SOAK_ESCROWS", "2".to_owned());
        map.insert("SUNRISE_EDGE_SOAK_SENDERS", "3".to_owned());
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::SendersExceedEscrows,
        );
    }

    #[test]
    fn rejects_senders_above_the_maximum() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert("SUNRISE_EDGE_SOAK_ESCROWS", "4096".to_owned());
        map.insert("SUNRISE_EDGE_SOAK_SENDERS", "65".to_owned());
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::OutOfBounds("SUNRISE_EDGE_SOAK_SENDERS"),
        );
    }

    #[test]
    fn rejects_claim_writers_above_the_maximum() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert("SUNRISE_EDGE_SOAK_CLAIM_WRITERS", "17".to_owned());
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::OutOfBounds("SUNRISE_EDGE_SOAK_CLAIM_WRITERS"),
        );
    }

    #[test]
    fn rejects_claim_rate_above_the_maximum() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert(
            "SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC",
            "1001".to_owned(),
        );
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::OutOfBounds("SUNRISE_EDGE_SOAK_MAX_CLAIM_RATE_PER_SEC"),
        );
    }

    #[test]
    fn rejects_duration_above_the_maximum() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert("SUNRISE_EDGE_SOAK_DURATION_SECONDS", "21601".to_owned());
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::OutOfBounds("SUNRISE_EDGE_SOAK_DURATION_SECONDS"),
        );
    }

    #[test]
    fn rejects_wall_deadline_above_the_maximum() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert(
            "SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS",
            "25201".to_owned(),
        );
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::OutOfBounds("SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS"),
        );
    }

    #[test]
    fn rejects_a_wall_deadline_that_does_not_exceed_the_duration() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert("SUNRISE_EDGE_SOAK_DURATION_SECONDS", "120".to_owned());
        map.insert("SUNRISE_EDGE_SOAK_WALL_DEADLINE_SECONDS", "120".to_owned());
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::WallDeadlineDoesNotExceedDuration,
        );
    }

    #[test]
    fn rejects_recovery_cycles_above_the_maximum() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert("SUNRISE_EDGE_SOAK_RECOVERY_CYCLES", "33".to_owned());
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::OutOfBounds("SUNRISE_EDGE_SOAK_RECOVERY_CYCLES"),
        );
    }

    #[test]
    fn rejects_a_missing_directory() {
        let mut map: BTreeMap<&'static str, String> = valid_map();
        map.insert(
            "SUNRISE_EDGE_SOAK_DIR",
            "/nonexistent/sunrise-edge-soak-dir".to_owned(),
        );
        assert_eq!(
            parse_soak_config(lookup(&map)).unwrap_err(),
            SoakConfigError::DirectoryMissing,
        );
    }

    #[test]
    fn accepts_a_loopback_ipv4_literal_naming_the_test_database() {
        assert_eq!(
            validate_disposable_test_database_url(
                "host=127.0.0.1 port=5432 dbname=sunrise_edge_test"
            ),
            Ok(()),
        );
    }

    #[test]
    fn accepts_the_localhost_hostname_naming_the_test_database() {
        assert_eq!(
            validate_disposable_test_database_url("host=localhost dbname=sunrise_edge_test"),
            Ok(()),
        );
    }

    #[test]
    fn rejects_a_non_loopback_host() {
        assert_eq!(
            validate_disposable_test_database_url("host=8.8.8.8 dbname=sunrise_edge_test"),
            Err(DisposableDatabaseUrlError::HostNotLoopback),
        );
    }

    #[test]
    fn rejects_more_than_one_host() {
        assert_eq!(
            validate_disposable_test_database_url(
                "host=127.0.0.1,127.0.0.2 dbname=sunrise_edge_test"
            ),
            Err(DisposableDatabaseUrlError::NotExactlyOneTcpHost),
        );
    }

    #[test]
    fn rejects_the_wrong_database_name() {
        assert_eq!(
            validate_disposable_test_database_url("host=127.0.0.1 dbname=other_database"),
            Err(DisposableDatabaseUrlError::WrongDatabaseName),
        );
    }

    #[test]
    fn rejects_a_missing_database_name() {
        assert_eq!(
            validate_disposable_test_database_url("host=127.0.0.1"),
            Err(DisposableDatabaseUrlError::WrongDatabaseName),
        );
    }

    #[test]
    fn rejects_an_unparseable_url() {
        assert_eq!(
            validate_disposable_test_database_url("not a connection string### "),
            Err(DisposableDatabaseUrlError::Unparseable),
        );
    }

    fn sample_fields() -> HandoffFields {
        HandoffFields {
            validator_id: "ab".repeat(32),
            chain_id: "paid-durable".to_owned(),
            domain: "08".repeat(32),
            protocol_version: 3,
            epoch: 0,
            suite: "0:1:1:1:1:1:1:1".to_owned(),
            expected_rows: 4,
            expected_claims: 16,
            expected_payouts: 4,
            writer_generation: 2,
            workload_elapsed_ms: 1234,
        }
    }

    fn fresh_directory(tag: &str) -> PathBuf {
        let unique: u128 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-edge-soak-handoff-{tag}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn writes_exactly_the_twelve_documented_keys_in_order() {
        let directory: PathBuf = fresh_directory("keys");
        write_handoff(&directory, &sample_fields()).unwrap();
        let body: String = std::fs::read_to_string(directory.join("handoff.kv")).unwrap();
        let keys: Vec<&str> = body
            .lines()
            .map(|line| line.split('=').next().unwrap())
            .collect();
        assert_eq!(
            keys,
            vec![
                "schema_version",
                "validator_id",
                "chain_id",
                "domain",
                "protocol_version",
                "epoch",
                "suite",
                "expected_rows",
                "expected_claims",
                "expected_payouts",
                "writer_generation",
                "workload_elapsed_ms",
            ],
        );
        assert!(body.ends_with('\n'));
        assert_eq!(
            keys.len(),
            std::collections::BTreeSet::from_iter(keys.clone()).len()
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn refuses_to_overwrite_an_existing_handoff_file() {
        let directory: PathBuf = fresh_directory("existing");
        write_handoff(&directory, &sample_fields()).unwrap();
        assert_eq!(
            write_handoff(&directory, &sample_fields()).unwrap_err(),
            SoakHandoffError::AlreadyExists,
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn refuses_to_overwrite_a_dangling_symlink() {
        let directory: PathBuf = fresh_directory("symlink");
        let target: PathBuf = directory.join("does-not-exist");
        std::os::unix::fs::symlink(&target, directory.join("handoff.kv")).unwrap();
        assert_eq!(
            write_handoff(&directory, &sample_fields()).unwrap_err(),
            SoakHandoffError::AlreadyExists,
        );
        assert!(!target.exists());
        std::fs::remove_dir_all(&directory).unwrap();
    }
}

// ── outer #[test]/#[ignore] wrapper: exact required libtest name ────────

/// Deliberately ignored: a manual, explicitly bounded operator run, never
/// invoked by ordinary `cargo test`. All real logic lives in
/// [`live_postgres::run_workload`]; this wrapper exists only so the libtest
/// name is exactly `fast_path::soak_tests::live_postgres_certified_load_exports_recovery_handoff`,
/// with no extra module path component.
#[test]
#[ignore = "requires SUNRISE_EDGE_TEST_POSTGRES_URL and every bounded SUNRISE_EDGE_SOAK_* env var against a live PostgreSQL sunrise_edge_test database"]
fn live_postgres_certified_load_exports_recovery_handoff() {
    live_postgres::run_workload();
}

// ── live-PostgreSQL driver helpers (no #[test] in this module) ─────────

mod live_postgres {
    use super::*;
    use crate::query::query_sender_next_nonce;
    use runtime::{
        DurableDomainStateStore, DurableObjectHead, DurableObjectPayload, DurableOperationContext,
        DurableReadError, DurableRequestId, StorageCorrelationId, StorageDeadline,
        WriterFenceGeneration,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    type LiveManager = PostgresConnectionManager<NoTls>;

    /// Cross-process file lock shared with every other live-PostgreSQL test
    /// family in this repo (see the identically named lock in
    /// `crate::fee_claims::tests::certified_multi_escrow_inventory` and
    /// `crate::fast_path::capacity_tests::live_postgres`): `cargo test` may
    /// run each crate's live-database tests as independent concurrent
    /// processes against the same shared database, so they must all
    /// serialize on the same file. `Drop` only removes the file if it still
    /// records this exact acquisition, mirroring those modules' abandoned-
    /// lock rationale.
    struct PostgresLiveLock {
        path: PathBuf,
        owner: String,
    }

    impl PostgresLiveLock {
        fn acquire() -> Self {
            let path: PathBuf =
                std::env::temp_dir().join("sunrise-edge-runtime-postgres-live-test.lock");
            let owner: String = format!(
                "{}:{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            );
            let deadline: Instant = Instant::now() + Duration::from_secs(600);
            loop {
                let created = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path);
                match created {
                    Ok(mut file) => {
                        file.write_all(owner.as_bytes()).unwrap();
                        file.sync_all().unwrap();
                        return Self { path, owner };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        if Instant::now() >= deadline {
                            panic!(
                                "timed out waiting for the exclusive live PostgreSQL test lock \
                                 at {}; if no other live test is actually running, delete this \
                                 file",
                                path.display()
                            );
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(error) => panic!(
                        "failed to create live PostgreSQL test lock at {}: {error}",
                        path.display()
                    ),
                }
            }
        }
    }

    impl Drop for PostgresLiveLock {
        fn drop(&mut self) {
            if std::fs::read_to_string(&self.path).ok().as_deref() == Some(self.owner.as_str()) {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    fn live_pool(url: &str, size: u32) -> Pool<LiveManager> {
        let config: postgres::Config = url.parse().unwrap();
        build_postgres_pool(
            config,
            NoTls,
            PostgresPoolConfig::new(
                NonZeroU32::new(size).unwrap(),
                Duration::from_secs(5),
                Duration::from_secs(30),
                Duration::from_secs(300),
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// Whole-relation physical size in bytes, including indexes and TOAST.
    /// Every namespace in `sunrise_edge_test` shares these tables, so this is
    /// never an isolated per-namespace measurement: only a before/after
    /// delta around this exact run's own writes, diagnostic only.
    fn relation_bytes(admin: &mut Client, qualified_table: &str) -> i64 {
        admin
            .query_one(
                "SELECT pg_total_relation_size(to_regclass($1))",
                &[&qualified_table],
            )
            .unwrap()
            .get(0)
    }

    /// A fresh, time-and-process-derived storage identity: not a real
    /// signing key, only the opaque partition key selecting this run's
    /// namespace, so repeated runs against the shared test database never
    /// reuse another run's rows or writer fence.
    fn fresh_storage_validator_id(tag: u8) -> ValidatorId {
        let nanos: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut id: [u8; 32] = [0; 32];
        id[..16].copy_from_slice(&nanos.to_be_bytes());
        id[16..20].copy_from_slice(&std::process::id().to_be_bytes());
        id[20] = tag;
        ValidatorId::new(id)
    }

    /// Connects the admin client, refuses to run against anything but the
    /// dedicated test database, applies the schema, and bootstraps one fresh
    /// namespace at writer fence 1.
    fn open_fresh_namespace(
        database_url: &str,
        tag: u8,
    ) -> (Client, PostgresNamespace, ValidatorId) {
        let mut admin: Client = Client::connect(database_url, NoTls).unwrap();
        let current_database: String = admin
            .query_one("SELECT current_database()", &[])
            .unwrap()
            .get(0);
        assert_eq!(
            current_database, "sunrise_edge_test",
            "refusing to run the soak load harness against a non-test database"
        );
        apply_initial_schema(&mut admin).unwrap();
        let storage_validator_id: ValidatorId = fresh_storage_validator_id(tag);
        let namespace: PostgresNamespace =
            PostgresNamespace::new(protocol().chain_id(), storage_validator_id, domain()).unwrap();
        bootstrap_namespace(
            &mut admin,
            &namespace,
            POSTGRES_SCHEMA_GENERATION,
            WriterFenceGeneration::new(1).unwrap(),
        )
        .unwrap();
        (admin, namespace, storage_validator_id)
    }

    fn pg_server_version_num(admin: &mut Client) -> i32 {
        let raw: String = admin
            .query_one("SHOW server_version_num", &[])
            .unwrap()
            .get(0);
        raw.trim().parse().unwrap()
    }

    fn context_at(generation: u64) -> DurableOperationContext {
        DurableOperationContext::new(
            WriterFenceGeneration::new(generation).unwrap(),
            StorageDeadline::new(u64::MAX).unwrap(),
            StorageCorrelationId::new([0xF0; 16]).unwrap(),
        )
    }

    fn assert_before_deadline(deadline: Instant, label: &str) {
        assert!(
            Instant::now() < deadline,
            "{label}: deadline exceeded, this run grants no complete result",
        );
    }

    /// A non-bursting ("no catch-up") pacer: each call is spaced at least
    /// `1/rate` seconds after the previous one, measured from the previous
    /// call's own scheduled slot (never from a fixed run-start reference).
    /// A caller that falls behind schedule never gets to "catch up" with a
    /// burst; it simply gets the very next slot.
    struct ClaimPacer {
        interval: Duration,
        next_allowed: Mutex<Instant>,
    }

    impl ClaimPacer {
        fn new(rate_per_sec: u32, start: Instant) -> Self {
            Self {
                interval: Duration::from_secs(1) / rate_per_sec,
                next_allowed: Mutex::new(start),
            }
        }

        /// Blocks until this caller's paced slot, first asserting that slot
        /// does not fall past either deadline: a proposed sleep that would
        /// cross a deadline fails immediately rather than sleeping past it.
        fn wait(&self, wall_deadline: Instant, workload_deadline: Instant) {
            let target: Instant = {
                let mut guard = self.next_allowed.lock().unwrap();
                let target: Instant = (*guard).max(Instant::now());
                *guard = target + self.interval;
                target
            };
            assert!(
                target < wall_deadline,
                "the next paced claim slot would exceed the wall deadline",
            );
            assert!(
                target < workload_deadline,
                "the next paced claim slot would exceed the workload duration deadline",
            );
            let now: Instant = Instant::now();
            if target > now {
                std::thread::sleep(target - now);
            }
        }
    }

    fn fresh_soak_voters() -> Vec<Voter> {
        let nanos: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut voters: Vec<Voter> = (0_u8..4)
            .map(|index| {
                let mut seed: [u8; 32] = [0xA6; 32];
                seed[..16].copy_from_slice(&nanos.to_be_bytes());
                seed[16..20].copy_from_slice(&std::process::id().to_be_bytes());
                seed[20] = index;
                let signing_key: SigningKey = SigningKey::from(seed);
                let public: [u8; 32] = VerificationKey::from(&signing_key).into();
                Voter {
                    entry: FastPathValidatorEntry {
                        id: ValidatorId::new(public),
                        voting_power: 1,
                        signature_scheme: SignatureSchemeId::Ed25519,
                        public_key: public.to_vec(),
                    },
                    signing_key,
                }
            })
            .collect();
        voters.sort_by_key(|voter| voter.entry.id);
        voters
    }

    fn lane_signing_key(prefix: u8, index: u32) -> SigningKey {
        let mut seed: [u8; 32] = [prefix; 32];
        seed[28..].copy_from_slice(&index.to_be_bytes());
        SigningKey::from(seed)
    }

    fn escrow_request_id(index: u32) -> [u8; 32] {
        let mut id: [u8; 32] = [0xE5; 32];
        id[28..].copy_from_slice(&index.to_be_bytes());
        id
    }
    fn mint_request_id(index: u32) -> [u8; 32] {
        let mut id: [u8; 32] = [0xE6; 32];
        id[28..].copy_from_slice(&index.to_be_bytes());
        id
    }
    fn split_claim_request_id(index: u32) -> [u8; 32] {
        let mut id: [u8; 32] = [0xE7; 32];
        id[28..].copy_from_slice(&index.to_be_bytes());
        id
    }
    fn final_claim_request_id(index: u32) -> [u8; 32] {
        let mut id: [u8; 32] = [0xE8; 32];
        id[28..].copy_from_slice(&index.to_be_bytes());
        id
    }
    fn zero_claim_request_id_a(index: u32) -> [u8; 32] {
        let mut id: [u8; 32] = [0xE9; 32];
        id[28..].copy_from_slice(&index.to_be_bytes());
        id
    }
    fn zero_claim_request_id_b(index: u32) -> [u8; 32] {
        let mut id: [u8; 32] = [0xEA; 32];
        id[28..].copy_from_slice(&index.to_be_bytes());
        id
    }

    /// Every claim leg (`split`/`transfer`) gets its own escrow-scoped,
    /// leg-scoped signer, nonce always `0`: genuinely independent signing/
    /// nonce lanes per DR-0146, never shared across escrows or leg types, so
    /// concurrent claim writers across distinct escrows never race on a
    /// shared sender's nonce chain.
    fn split_leg_signer(index: u32) -> SigningKey {
        lane_signing_key(0xEC, index)
    }
    fn final_leg_signer(index: u32) -> SigningKey {
        lane_signing_key(0xED, index)
    }

    fn leg_sender(signing_key: &SigningKey) -> [u8; 32] {
        VerificationKey::from(signing_key).into()
    }

    const LANE_COIN_AMOUNT: u64 = 1_000;

    /// Byte-exact durable state DR-0146 requires surviving close/reopen for
    /// one fully drained escrow: the final (generation-5) settlement row,
    /// all four retained claim envelopes, the final escrow object, the split
    /// payout object, and all four outer request receipts.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct EscrowSnapshot {
        escrow_object_id: ObjectId,
        payout_object_id: ObjectId,
        row_bytes: Vec<u8>,
        row_revision: StateRevision,
        claim_bytes: [Vec<u8>; 4],
        escrow_object_version: u64,
        escrow_object_bytes: Vec<u8>,
        payout_object_version: u64,
        payout_object_bytes: Vec<u8>,
        receipts: [DurableRequestReceipt; 4],
    }

    impl EscrowSnapshot {
        fn retained_bytes(&self) -> u64 {
            let claims: u64 = self
                .claim_bytes
                .iter()
                .map(|bytes| u64::try_from(bytes.len()).unwrap())
                .sum();
            u64::try_from(self.row_bytes.len()).unwrap()
                + claims
                + u64::try_from(self.escrow_object_bytes.len()).unwrap()
                + u64::try_from(self.payout_object_bytes.len()).unwrap()
        }
    }

    /// Reads back exactly the durable bytes [`EscrowSnapshot`] documents,
    /// for one escrow, under the given context. Called once right after the
    /// escrow's four claims commit (the "before close" reading) and again
    /// after reopen under the advanced writer generation (the "after
    /// reopen" reading); DR-0146 requires both to be byte-exact.
    fn capture_escrow_state<S: StructuredDurableDomainStateStore>(
        store: &S,
        context: &DurableOperationContext,
        index: u32,
        escrow_object_id: ObjectId,
        payout_object_id: ObjectId,
    ) -> EscrowSnapshot {
        let chain: ChainId = protocol().chain_id().clone();
        let row_key: Vec<u8> =
            crate::local_instance_state::fastpath_settlement_key(&chain, &escrow_request_id(index))
                .unwrap();
        let row_value: VersionedStateValue = store
            .get_versioned_durable(context, domain(), &row_key)
            .unwrap();
        let row_bytes: Vec<u8> = row_value
            .value()
            .expect("escrow settlement row must be retained")
            .to_vec();
        let row_revision: StateRevision = row_value.revision();
        assert_eq!(
            row_revision,
            StateRevision::new(5),
            "escrow {index} must be fully drained (generation 5) before this snapshot",
        );

        let claim_bytes: [Vec<u8>; 4] = [2_u64, 3, 4, 5].map(|generation| {
            let key: Vec<u8> = crate::local_instance_state::fastpath_fee_claim_key(
                &chain,
                &escrow_request_id(index),
                generation,
            )
            .unwrap();
            store
                .get_versioned_durable(context, domain(), &key)
                .unwrap()
                .value()
                .expect("retained claim envelope")
                .to_vec()
        });

        let escrow_head: DurableObjectHead = store
            .get_object_head(context, domain(), escrow_object_id)
            .unwrap();
        let DurableObjectHead::Current {
            object_version: escrow_version,
            ..
        } = escrow_head
        else {
            panic!("escrow {index} object must remain current");
        };
        let escrow_record: DurableObjectVersionRecord = store
            .get_object_version(context, domain(), escrow_object_id, escrow_version)
            .unwrap()
            .unwrap();
        let DurableObjectPayload::Inline(escrow_inline) = escrow_record.payload() else {
            panic!("escrow {index} object must stay inline");
        };
        let escrow_object_bytes: Vec<u8> = escrow_inline.canonical_bytes().to_vec();

        let payout_head: DurableObjectHead = store
            .get_object_head(context, domain(), payout_object_id)
            .unwrap();
        let DurableObjectHead::Current {
            object_version: payout_version,
            ..
        } = payout_head
        else {
            panic!("escrow {index} payout object must remain current");
        };
        let payout_record: DurableObjectVersionRecord = store
            .get_object_version(context, domain(), payout_object_id, payout_version)
            .unwrap()
            .unwrap();
        let DurableObjectPayload::Inline(payout_inline) = payout_record.payload() else {
            panic!("escrow {index} payout object must stay inline");
        };
        let payout_object_bytes: Vec<u8> = payout_inline.canonical_bytes().to_vec();

        let receipts: [DurableRequestReceipt; 4] = [
            split_claim_request_id(index),
            final_claim_request_id(index),
            zero_claim_request_id_a(index),
            zero_claim_request_id_b(index),
        ]
        .map(|request_id| {
            store
                .get_request_receipt(
                    context,
                    domain(),
                    DurableRequestId::new(request_id).unwrap(),
                )
                .unwrap()
                .expect("escrow claim outer receipt must be retained")
        });

        EscrowSnapshot {
            escrow_object_id,
            payout_object_id,
            row_bytes,
            row_revision,
            claim_bytes,
            escrow_object_version: escrow_version.get(),
            escrow_object_bytes,
            payout_object_version: payout_version.get(),
            payout_object_bytes,
            receipts,
        }
    }

    /// Submits one claim through the real [`handle_fee_claim`] pipeline as
    /// counted, paced workload: paces and checks both deadlines immediately
    /// before every attempt (including retries), counts every attempted
    /// call, retries only a definite serialization non-commit with the
    /// caller's exact unchanged signed bytes, and asserts the terminal
    /// response is `Accepted`. Never used for a replay-idempotency
    /// validation call -- those are deliberately unpaced and uncounted.
    #[allow(clippy::too_many_arguments)]
    fn submit_claim_paced(
        writer: &PostgresDurableStore<LiveManager>,
        writer_blobs: &PostgresBlobStore<LiveManager>,
        signed_bytes: &[u8],
        pacer: &ClaimPacer,
        wall_deadline: Instant,
        workload_deadline: Instant,
        attempted: &AtomicU64,
        completed: &AtomicU64,
        retries: &AtomicU64,
        writer_slot: usize,
    ) -> NodeOutput {
        const MAX_ATTEMPTS: u64 = 32;
        let slot_delay_ms: u64 = u64::try_from(writer_slot % 4).unwrap();
        for attempt in 1_u64..=MAX_ATTEMPTS {
            assert_before_deadline(wall_deadline, "claim submission");
            assert_before_deadline(workload_deadline, "claim submission");
            pacer.wait(wall_deadline, workload_deadline);
            attempted.fetch_add(1, Ordering::Relaxed);
            let result: Result<NodeOutput, FeeClaimError> = handle_fee_claim(
                writer,
                writer_blobs,
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                &base_policy(),
                &LocalWasmExecutionEngine::new(),
                signed_bytes,
                12,
            );
            assert_before_deadline(wall_deadline, "claim submission");
            assert_before_deadline(workload_deadline, "claim submission");
            match result {
                Ok(output) => {
                    assert_eq!(
                        output.responses()[0].status(),
                        NodeResponseStatus::Accepted,
                        "every workload claim must be accepted",
                    );
                    completed.fetch_add(1, Ordering::Relaxed);
                    return output;
                }
                Err(FeeClaimError::Node(NodeCoreError::DurableCommitRejected(
                    DurableCommitRejection::SerializationFailure,
                ))) if attempt < MAX_ATTEMPTS => {
                    retries.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(attempt.min(10) + slot_delay_ms));
                }
                Err(error) => panic!("fee claim failed after {attempt} attempts: {error}"),
            }
        }
        unreachable!("the last attempt either succeeds or panics")
    }

    /// DR-0146: creates `config.escrows` genuinely paid, quorum-certified fee
    /// escrows against a live PostgreSQL primary (with two independent
    /// memory-backed co-voters supplying the other two of four votes), drains
    /// every one of them through the real fee-claim pipeline (one positive
    /// split, one positive final transfer, two zero-share claims), then
    /// closes and reopens the primary under exactly one advanced writer
    /// generation (fence `1 -> 2`), verifying every escrow's exact retained
    /// row/claim/object/payout/receipt bytes and rejecting the stale
    /// generation. Never prints `kind=totals complete=true`: see this
    /// module's doc comment.
    pub(super) fn run_workload() {
        let wall_start: Instant = Instant::now();
        let config: SoakConfig = parse_soak_config(|name| std::env::var(name).ok())
            .expect("every bounded SUNRISE_EDGE_SOAK_* env var must be set and in range");
        let database_url: String = std::env::var("SUNRISE_EDGE_TEST_POSTGRES_URL")
            .expect("the live PostgreSQL soak load requires SUNRISE_EDGE_TEST_POSTGRES_URL");
        validate_disposable_test_database_url(&database_url).expect(
            "SUNRISE_EDGE_TEST_POSTGRES_URL must name exactly one loopback host and the \
             sunrise_edge_test database, checked before any connection is opened",
        );
        let wall_deadline: Instant = wall_start + Duration::from_secs(config.wall_deadline_seconds);

        let _lock: PostgresLiveLock = PostgresLiveLock::acquire();
        assert_before_deadline(wall_deadline, "acquiring the live PostgreSQL lock");

        let (mut admin, namespace, storage_validator_id): (Client, PostgresNamespace, ValidatorId) =
            open_fresh_namespace(&database_url, 0xF0);
        let pg_version_num: i32 = pg_server_version_num(&mut admin);
        let baseline_state_records_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.state_records");

        let voters: Vec<Voter> = fresh_soak_voters();
        let entries: Vec<FastPathValidatorEntry> =
            voters.iter().map(|voter| voter.entry.clone()).collect();
        let validator_set: ValidatorSet = build_validator_set(&entries);

        let pool_size: u32 = 32;
        // Exactly one internal transaction attempt: every serialization
        // rejection must surface to (and be counted/retried by) this
        // driver's own bounded caller-level retry, never silently absorbed
        // by the adapter's own internal retry loop.
        let transaction_policy: PostgresTransactionPolicy =
            PostgresTransactionPolicy::new(NonZeroU32::new(1).unwrap()).unwrap();
        let pool: Pool<LiveManager> = live_pool(&database_url, pool_size);
        let primary: PostgresDurableStore<LiveManager> =
            PostgresDurableStore::new(pool.clone(), namespace.clone(), transaction_policy);
        let blobs: PostgresBlobStore<LiveManager> =
            PostgresBlobStore::new(pool.clone(), namespace.clone()).unwrap();
        let (fixture, policy): (Fixture, PaidFeePolicy) = install_all(&primary, &entries);
        let voter_store_1: MemoryDurableStateStore = memory_store();
        let (voter1_fixture, _): (Fixture, PaidFeePolicy) = install_all(&voter_store_1, &entries);
        let voter_store_2: MemoryDurableStateStore = memory_store();
        let (voter2_fixture, _): (Fixture, PaidFeePolicy) = install_all(&voter_store_2, &entries);
        let resource_id: BondResourceId = fee_resource_id(&policy).unwrap();

        assert_before_deadline(wall_deadline, "escrow creation setup");
        let creation_start: Instant = Instant::now();
        let workload_deadline: Instant =
            creation_start + Duration::from_secs(config.duration_seconds);

        let lane_keys: Vec<SigningKey> = (0..config.senders)
            .map(|lane| lane_signing_key(0xEB, lane))
            .collect();
        let mut primary_cap: Object = fixture.cap.clone();
        let mut voter1_cap: Object = voter1_fixture.cap.clone();
        let mut voter2_cap: Object = voter2_fixture.cap.clone();
        let mut installer_nonce: u64 = FIRST_PAID_NONCE;
        let mut escrow_object_ids: Vec<ObjectId> = Vec::with_capacity(config.escrows as usize);

        // The installer's own zero-fee nonce chain must strictly continue
        // `FIRST_PAID_NONCE`; a `zip`-style iterator would obscure that.
        #[allow(clippy::explicit_counter_loop)]
        for index in 0..config.escrows {
            assert_before_deadline(wall_deadline, "escrow creation");
            assert_before_deadline(workload_deadline, "escrow creation");
            let lane: u32 = index % config.senders;
            let lane_nonce: u64 = u64::from(index / config.senders);
            let owner_key: &SigningKey = &lane_keys[lane as usize];
            let owner: [u8; 32] = leg_sender(owner_key);
            let mint_id: [u8; 32] = mint_request_id(index);

            let (primary_coin, new_primary_cap): (Object, Object) = install_extra_coin(
                &primary,
                &fixture,
                &primary_cap,
                mint_id,
                installer_nonce,
                owner,
                LANE_COIN_AMOUNT,
            );
            primary_cap = new_primary_cap;
            let (_voter1_coin, new_voter1_cap): (Object, Object) = install_extra_coin(
                &voter_store_1,
                &voter1_fixture,
                &voter1_cap,
                mint_id,
                installer_nonce,
                owner,
                LANE_COIN_AMOUNT,
            );
            voter1_cap = new_voter1_cap;
            let (_voter2_coin, new_voter2_cap): (Object, Object) = install_extra_coin(
                &voter_store_2,
                &voter2_fixture,
                &voter2_cap,
                mint_id,
                installer_nonce,
                owner,
                LANE_COIN_AMOUNT,
            );
            voter2_cap = new_voter2_cap;
            installer_nonce += 1;
            escrow_object_ids.push(primary_coin.id);

            let signed_bytes: Vec<u8> = lane_paid_transfer(LanePaidTransfer {
                fixture: &fixture,
                policy: &policy,
                request_id: escrow_request_id(index),
                nonce: lane_nonce,
                source: &primary_coin,
                sender: owner,
                signing_key: owner_key,
            });
            let votes: Vec<FastVote> = vec![
                prepare_vote_with_blob(&primary, &blobs, &policy, &voters[0], &signed_bytes),
                prepare_vote(&voter_store_1, &policy, &voters[1], &signed_bytes),
                prepare_vote(&voter_store_2, &policy, &voters[2], &signed_bytes),
            ];
            let certificate: Vec<u8> = certify(&validator_set, &votes);
            let applied: NodeOutput =
                apply_escrow_with_blob(&primary, &blobs, &policy, &signed_bytes, &certificate);
            assert_eq!(receipt(&applied).status, PaidExecutionStatus::Success);
            assert_eq!(
                apply_escrow(&voter_store_1, &policy, &signed_bytes, &certificate),
                applied,
            );
            assert_eq!(
                apply_escrow(&voter_store_2, &policy, &signed_bytes, &certificate),
                applied,
            );
            assert_before_deadline(wall_deadline, "escrow creation");
            assert_before_deadline(workload_deadline, "escrow creation");
        }
        let creation_elapsed_ms: u64 = u64::try_from(creation_start.elapsed().as_millis()).unwrap();
        eprintln!(
            "sunrise_edge_soak_v1 kind=creation escrows={} senders={} creation_elapsed_ms={creation_elapsed_ms} \
             pg_version_num={pg_version_num}",
            config.escrows, config.senders,
        );

        // ── claim phase: the rate limiter and every attempted/completed
        //    counter start here, never before creation ──
        let claim_start: Instant = Instant::now();
        let pacer: ClaimPacer = ClaimPacer::new(config.max_claim_rate_per_sec, claim_start);
        let attempted: AtomicU64 = AtomicU64::new(0);
        let completed: AtomicU64 = AtomicU64::new(0);
        let retries: AtomicU64 = AtomicU64::new(0);
        let snapshots: Vec<Mutex<Option<EscrowSnapshot>>> =
            (0..config.escrows).map(|_| Mutex::new(None)).collect();

        // ── escrow 0, claimed sequentially and directly on the primary, so
        //    the same-boot replay-idempotency proof has a captured original
        //    output to compare against. Its four claims are still counted,
        //    paced workload; only the replay calls immediately below are
        //    validation, deliberately unpaced and uncounted. ──
        let split0: SplitClaim = build_split_claim_for_lane(
            &primary,
            &fixture,
            &voters[0],
            resource_id,
            escrow_request_id(0),
            split_claim_request_id(0),
            leg_sender(&split_leg_signer(0)),
            &split_leg_signer(0),
            0,
            0xF1,
        );
        let split0_output: NodeOutput = submit_claim_paced(
            &primary,
            &blobs,
            &split0.signed_bytes,
            &pacer,
            wall_deadline,
            workload_deadline,
            &attempted,
            &completed,
            &retries,
            0,
        );

        assert_before_deadline(wall_deadline, "same-boot replay validation");
        let representative_row_before_replay: Vec<u8> =
            crate::fee_claims::tests::certified_multi_escrow_inventory::current_row(
                &primary,
                escrow_request_id(0),
            )
            .0;
        let representative_nonce_before_replay: u64 = query_sender_next_nonce(
            &primary,
            &context_at(1),
            domain(),
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            protocol().epoch(),
            leg_sender(&split_leg_signer(0)),
        )
        .unwrap();
        // Deliberately not `submit_claim_paced`: a same-boot replay of an
        // already-applied claim is validation, not new workload.
        assert_eq!(
            handle_fee_claim(
                &primary,
                &blobs,
                &context(),
                domain(),
                &resolver(),
                &[],
                &protocol(),
                &base_policy(),
                &LocalWasmExecutionEngine::new(),
                &split0.signed_bytes,
                12,
            )
            .unwrap(),
            split0_output,
            "same-boot replay of an already-applied claim must be a byte-exact no-op",
        );
        assert_eq!(
            crate::fee_claims::tests::certified_multi_escrow_inventory::current_row(
                &primary,
                escrow_request_id(0),
            )
            .0,
            representative_row_before_replay,
            "same-boot replay must leave the settlement row byte-exact",
        );
        assert_eq!(
            query_sender_next_nonce(
                &primary,
                &context_at(1),
                domain(),
                protocol().chain_id().clone(),
                protocol().protocol_version(),
                protocol().epoch(),
                leg_sender(&split_leg_signer(0)),
            )
            .unwrap(),
            representative_nonce_before_replay,
            "same-boot replay must leave the leg sender's nonce unchanged",
        );

        let final_bytes_0: Vec<u8> = build_final_claim_for_lane(
            &primary,
            &fixture,
            &voters[1],
            resource_id,
            escrow_request_id(0),
            final_claim_request_id(0),
            leg_sender(&final_leg_signer(0)),
            &final_leg_signer(0),
            0,
            0xF2,
        );
        submit_claim_paced(
            &primary,
            &blobs,
            &final_bytes_0,
            &pacer,
            wall_deadline,
            workload_deadline,
            &attempted,
            &completed,
            &retries,
            0,
        );
        let zero_a_0: Vec<u8> = build_zero_claim(
            &primary,
            &voters[2],
            resource_id,
            escrow_request_id(0),
            zero_claim_request_id_a(0),
        );
        submit_claim_paced(
            &primary,
            &blobs,
            &zero_a_0,
            &pacer,
            wall_deadline,
            workload_deadline,
            &attempted,
            &completed,
            &retries,
            0,
        );
        let zero_b_0: Vec<u8> = build_zero_claim(
            &primary,
            &voters[3],
            resource_id,
            escrow_request_id(0),
            zero_claim_request_id_b(0),
        );
        submit_claim_paced(
            &primary,
            &blobs,
            &zero_b_0,
            &pacer,
            wall_deadline,
            workload_deadline,
            &attempted,
            &completed,
            &retries,
            0,
        );
        *snapshots[0].lock().unwrap() = Some(capture_escrow_state(
            &primary,
            &context_at(1),
            0,
            escrow_object_ids[0],
            split0.payout.id,
        ));

        // ── every remaining escrow, drained by concurrent bounded writers ──
        let mut shards: Vec<Vec<u32>> = vec![Vec::new(); config.claim_writers as usize];
        for index in 1..config.escrows {
            shards[(index % config.claim_writers) as usize].push(index);
        }

        std::thread::scope(|scope| {
            for (writer_slot, shard) in shards.iter().enumerate() {
                let writer_pool: Pool<LiveManager> = pool.clone();
                let writer_namespace: PostgresNamespace = namespace.clone();
                let attempted_ref: &AtomicU64 = &attempted;
                let completed_ref: &AtomicU64 = &completed;
                let retry_counter: &AtomicU64 = &retries;
                let pacer_ref: &ClaimPacer = &pacer;
                let fixture_ref: &Fixture = &fixture;
                let voters_ref: &[Voter] = &voters;
                let escrow_object_ids_ref: &[ObjectId] = &escrow_object_ids;
                let snapshots_ref: &[Mutex<Option<EscrowSnapshot>>] = &snapshots;
                scope.spawn(move || {
                    let writer: PostgresDurableStore<LiveManager> = PostgresDurableStore::new(
                        writer_pool.clone(),
                        writer_namespace.clone(),
                        transaction_policy,
                    );
                    let writer_blobs: PostgresBlobStore<LiveManager> =
                        PostgresBlobStore::new(writer_pool, writer_namespace).unwrap();
                    for &index in shard {
                        let split: SplitClaim = build_split_claim_for_lane(
                            &writer,
                            fixture_ref,
                            &voters_ref[0],
                            resource_id,
                            escrow_request_id(index),
                            split_claim_request_id(index),
                            leg_sender(&split_leg_signer(index)),
                            &split_leg_signer(index),
                            0,
                            0xF1,
                        );
                        submit_claim_paced(
                            &writer,
                            &writer_blobs,
                            &split.signed_bytes,
                            pacer_ref,
                            wall_deadline,
                            workload_deadline,
                            attempted_ref,
                            completed_ref,
                            retry_counter,
                            writer_slot,
                        );

                        let final_bytes: Vec<u8> = build_final_claim_for_lane(
                            &writer,
                            fixture_ref,
                            &voters_ref[1],
                            resource_id,
                            escrow_request_id(index),
                            final_claim_request_id(index),
                            leg_sender(&final_leg_signer(index)),
                            &final_leg_signer(index),
                            0,
                            0xF2,
                        );
                        submit_claim_paced(
                            &writer,
                            &writer_blobs,
                            &final_bytes,
                            pacer_ref,
                            wall_deadline,
                            workload_deadline,
                            attempted_ref,
                            completed_ref,
                            retry_counter,
                            writer_slot,
                        );

                        let zero_a: Vec<u8> = build_zero_claim(
                            &writer,
                            &voters_ref[2],
                            resource_id,
                            escrow_request_id(index),
                            zero_claim_request_id_a(index),
                        );
                        submit_claim_paced(
                            &writer,
                            &writer_blobs,
                            &zero_a,
                            pacer_ref,
                            wall_deadline,
                            workload_deadline,
                            attempted_ref,
                            completed_ref,
                            retry_counter,
                            writer_slot,
                        );

                        let zero_b: Vec<u8> = build_zero_claim(
                            &writer,
                            &voters_ref[3],
                            resource_id,
                            escrow_request_id(index),
                            zero_claim_request_id_b(index),
                        );
                        submit_claim_paced(
                            &writer,
                            &writer_blobs,
                            &zero_b,
                            pacer_ref,
                            wall_deadline,
                            workload_deadline,
                            attempted_ref,
                            completed_ref,
                            retry_counter,
                            writer_slot,
                        );

                        *snapshots_ref[index as usize].lock().unwrap() =
                            Some(capture_escrow_state(
                                &writer,
                                &context_at(1),
                                index,
                                escrow_object_ids_ref[index as usize],
                                split.payout.id,
                            ));
                    }
                });
            }
        });

        let claim_elapsed_ms: u64 = u64::try_from(claim_start.elapsed().as_millis()).unwrap();
        let workload_elapsed_ms: u64 = creation_elapsed_ms.checked_add(claim_elapsed_ms).unwrap();
        assert!(
            workload_elapsed_ms <= config.duration_seconds.checked_mul(1000).unwrap(),
            "the full planned workload of {} escrows must complete within the configured \
             duration window, not merely be paced under its rate limit",
            config.escrows,
        );

        let expected_rows: u64 = u64::from(config.escrows);
        let expected_claims: u64 = expected_rows.checked_mul(4).unwrap();
        let expected_payouts: u64 = expected_rows;
        let attempted_calls: u64 = attempted.load(Ordering::Relaxed);
        let completed_claims: u64 = completed.load(Ordering::Relaxed);
        assert_eq!(
            completed_claims, expected_claims,
            "every planned claim must reach a completed Accepted response",
        );
        let retained_logical_bytes: u64 = snapshots
            .iter()
            .map(|slot| slot.lock().unwrap().as_ref().unwrap().retained_bytes())
            .sum();

        eprintln!(
            "sunrise_edge_soak_v1 kind=claims escrows={} senders={} claim_writers={} \
             max_claim_rate_per_sec={} attempted_calls={attempted_calls} \
             completed_claims={completed_claims} planned_claims={expected_claims} \
             planned_payouts={expected_payouts} serialization_retries={} \
             claim_elapsed_ms={claim_elapsed_ms} workload_elapsed_ms={workload_elapsed_ms} \
             retained_logical_bytes={retained_logical_bytes}",
            config.escrows,
            config.senders,
            config.claim_writers,
            config.max_claim_rate_per_sec,
            retries.load(Ordering::Relaxed),
        );

        drop(blobs);
        drop(primary);
        drop(pool);

        // ── exactly one recovery transition: close/reopen under an
        //    advanced writer generation (fence 1 -> 2), verifying every
        //    escrow's exact retained bytes and rejecting the stale
        //    generation. Repeating this across several generations is the
        //    ordered operator script's job, not this core driver's. ──
        assert_before_deadline(wall_deadline, "recovery");
        let recovery_start: Instant = Instant::now();
        let advanced_fence: WriterFenceGeneration = WriterFenceGeneration::new(2).unwrap();
        advance_writer_fence(
            &mut admin,
            &namespace,
            WriterFenceGeneration::new(1).unwrap(),
            advanced_fence,
        )
        .unwrap();

        let reopened_pool: Pool<LiveManager> = live_pool(&database_url, pool_size);
        let reopened: PostgresDurableStore<LiveManager> =
            PostgresDurableStore::new(reopened_pool.clone(), namespace.clone(), transaction_policy);
        let reopened_blobs: PostgresBlobStore<LiveManager> =
            PostgresBlobStore::new(reopened_pool, namespace.clone()).unwrap();
        let fresh_context: DurableOperationContext = context_at(2);

        let stale_row_key: Vec<u8> = crate::local_instance_state::fastpath_settlement_key(
            protocol().chain_id(),
            &escrow_request_id(0),
        )
        .unwrap();
        let stale_error: DurableReadError = reopened
            .get_versioned_durable(&context_at(1), domain(), &stale_row_key)
            .unwrap_err();
        assert_eq!(
            stale_error,
            DurableReadError::WriterFenced {
                active_generation: advanced_fence,
            },
        );

        assert_before_deadline(wall_deadline, "post-reopen replay validation");
        let representative_nonce_before_reopen_replay: u64 = query_sender_next_nonce(
            &reopened,
            &fresh_context,
            domain(),
            protocol().chain_id().clone(),
            protocol().protocol_version(),
            protocol().epoch(),
            leg_sender(&split_leg_signer(0)),
        )
        .unwrap();
        // Deliberately not `submit_claim_paced`: a post-reopen replay of an
        // already-applied claim is validation, not new workload.
        assert_eq!(
            handle_fee_claim(
                &reopened,
                &reopened_blobs,
                &fresh_context,
                domain(),
                &resolver(),
                &[],
                &protocol(),
                &base_policy(),
                &LocalWasmExecutionEngine::new(),
                &split0.signed_bytes,
                12,
            )
            .unwrap(),
            split0_output,
            "post-reopen replay of an already-applied claim must be a byte-exact no-op",
        );
        assert_eq!(
            query_sender_next_nonce(
                &reopened,
                &fresh_context,
                domain(),
                protocol().chain_id().clone(),
                protocol().protocol_version(),
                protocol().epoch(),
                leg_sender(&split_leg_signer(0)),
            )
            .unwrap(),
            representative_nonce_before_reopen_replay,
            "post-reopen replay must leave the leg sender's nonce unchanged",
        );

        for index in 0..config.escrows {
            assert_before_deadline(wall_deadline, "post-reopen escrow verification");
            let expected: EscrowSnapshot = snapshots[index as usize]
                .lock()
                .unwrap()
                .take()
                .expect("every escrow must have a captured pre-close snapshot");
            let actual: EscrowSnapshot = capture_escrow_state(
                &reopened,
                &fresh_context,
                index,
                expected.escrow_object_id,
                expected.payout_object_id,
            );
            assert_eq!(
                actual, expected,
                "escrow {index} durable state must survive close/reopen byte-exact",
            );
        }

        let verified: FeeEscrowInventorySweep = verify_fee_escrow_inventory_all(
            &reopened,
            &reopened_blobs,
            &fresh_context,
            domain(),
            &resolver(),
            &[],
            protocol().chain_id(),
            NonZeroUsize::new(64).unwrap(),
        )
        .unwrap();
        assert_eq!(verified.verified_rows, expected_rows);
        assert_eq!(verified.verified_claims, expected_claims);
        assert_eq!(verified.verified_payouts, expected_payouts);

        let final_state_records_bytes: i64 =
            relation_bytes(&mut admin, "sunrise_edge.state_records");
        let recovery_elapsed_ms: u64 = u64::try_from(recovery_start.elapsed().as_millis()).unwrap();

        eprintln!(
            "sunrise_edge_soak_v1 kind=recovery writer_generation=2 verified_rows={} \
             verified_claims={} verified_payouts={} verified_pages={} recovery_elapsed_ms={recovery_elapsed_ms} \
             physical_state_records_relation_bytes_whole_shared_table[baseline={baseline_state_records_bytes},final={final_state_records_bytes}]",
            verified.verified_rows,
            verified.verified_claims,
            verified.verified_payouts,
            verified.pages,
        );

        assert_before_deadline(wall_deadline, "handoff export");
        let suite = resolver()
            .suite_for_epoch(protocol().epoch())
            .unwrap()
            .clone();
        let handoff: HandoffFields = HandoffFields {
            validator_id: storage_validator_id.to_string(),
            chain_id: protocol().chain_id().to_string(),
            domain: domain().to_string(),
            protocol_version: protocol().protocol_version().get(),
            epoch: protocol().epoch().get(),
            suite: format!(
                "{}:{}:{}:{}:{}:{}:{}:{}",
                protocol().epoch().get(),
                suite.id.get(),
                suite.transaction_hash.as_u16(),
                suite.object_digest.as_u16(),
                suite.effects_hash.as_u16(),
                suite.code_hash.as_u16(),
                suite.config_hash.as_u16(),
                suite.certificate_hash.as_u16(),
            ),
            expected_rows: config.escrows,
            expected_claims: u32::try_from(expected_claims).unwrap(),
            expected_payouts: u32::try_from(expected_payouts).unwrap(),
            writer_generation: 2,
            workload_elapsed_ms,
        };
        write_handoff(&config.directory, &handoff)
            .expect("a fresh SUNRISE_EDGE_SOAK_DIR must accept a fresh handoff.kv");

        drop(reopened);
        drop(reopened_blobs);
        drop(admin);
    }
}
