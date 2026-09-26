//! DR-0146: bounded certified PostgreSQL load and recovery harness (see
//! `docs/architecture/decisions/0146-postgres-certified-load-and-recovery-harness.md`).
//!
//! This module owns exactly the node-core test surface of that decision: a
//! pure, fail-closed config/handoff parser and writer (exercised by the
//! ordinary, non-ignored tests below) plus one deliberately `#[ignore]`d
//! manual driver that creates a bounded number of genuinely paid, quorum-
//! certified fee escrows against one live PostgreSQL primary, drains every
//! one of them through the real fee-claim pipeline, and proves the result
//! survives repeated close/reopen under an advancing writer generation.
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
    prepare_vote, prepare_vote_with_blob, submit_claim_with_blob,
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
use runtime::MemoryDurableStateStore;
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
    InvalidInteger(&'static str),
    OutOfBounds(&'static str),
    SendersExceedEscrows,
    WallDeadlineDoesNotExceedDuration,
    DirectoryMissing,
}

impl fmt::Display for SoakConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVar(name) => write!(f, "missing required env var {name}"),
            Self::InvalidInteger(name) => write!(f, "env var {name} is not a valid integer"),
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
        }
    }
}

fn required_u32(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    min: u32,
    max: u32,
) -> Result<u32, SoakConfigError> {
    let raw: String = lookup(name).ok_or(SoakConfigError::MissingVar(name))?;
    let value: u32 = raw
        .parse()
        .map_err(|_| SoakConfigError::InvalidInteger(name))?;
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
    let value: u64 = raw
        .parse()
        .map_err(|_| SoakConfigError::InvalidInteger(name))?;
    if value < min || value > max {
        return Err(SoakConfigError::OutOfBounds(name));
    }
    Ok(value)
}

/// Parses every `SUNRISE_EDGE_SOAK_*` knob from an injected lookup function
/// (never `std::env` directly), so the bound checks below are exercised as
/// ordinary, fast, non-ignored unit tests.
fn parse_soak_config(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<SoakConfig, SoakConfigError> {
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

// ── handoff.kv ───────────────────────────────────────────────────────────

/// The exact twelve keys DR-0146 requires, in the order it documents them.
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

// ── non-ignored config/handoff tests ────────────────────────────────────

#[cfg(test)]
mod config_and_handoff_tests {
    use super::*;

    fn valid_map() -> BTreeMap<&'static str, String> {
        let mut map: BTreeMap<&'static str, String> = BTreeMap::new();
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
            SoakConfigError::InvalidInteger("SUNRISE_EDGE_SOAK_ESCROWS"),
        );
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

// ── ignored live-PostgreSQL driver ──────────────────────────────────────

mod live_postgres {
    use super::*;
    use crate::query::query_sender_next_nonce;
    use runtime::{
        DurableDomainStateStore, DurableOperationContext, DurableReadError, StorageCorrelationId,
        StorageDeadline, WriterFenceGeneration,
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

    /// Retry only a definite serialization non-commit with unchanged signed
    /// bytes. The caller bound and per-writer delay avoid retry storms.
    fn claim_with_bounded_retry(
        mut attempt_claim: impl FnMut() -> Result<NodeOutput, FeeClaimError>,
        writer_slot: usize,
        retry_counter: &AtomicU64,
    ) -> NodeOutput {
        const MAX_CALLER_ATTEMPTS: u64 = 32;
        let slot_delay_ms: u64 = u64::try_from(writer_slot % 4).unwrap();
        for attempt in 1_u64..=MAX_CALLER_ATTEMPTS {
            match attempt_claim() {
                Ok(output) => return output,
                Err(FeeClaimError::Node(NodeCoreError::DurableCommitRejected(
                    DurableCommitRejection::SerializationFailure,
                ))) if attempt < MAX_CALLER_ATTEMPTS => {
                    retry_counter.fetch_add(1, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(attempt.min(10) + slot_delay_ms));
                }
                Err(error) => panic!("fee claim failed after {attempt} attempts: {error}"),
            }
        }
        unreachable!("the last attempt either succeeds or panics")
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

    /// DR-0146: creates `config.escrows` genuinely paid, quorum-certified fee
    /// escrows against a live PostgreSQL primary (with two independent
    /// memory-backed co-voters supplying the other two of four votes), drains
    /// every one of them through the real fee-claim pipeline (one positive
    /// split, one positive final transfer, two zero-share claims), then
    /// closes and reopens the primary under `config.recovery_cycles`
    /// successive advanced writer generations, verifying the exact retained
    /// row/claim/payout counts and rejecting the stale generation at each
    /// step. Deliberately ignored: a manual, explicitly bounded operator
    /// run, never invoked by ordinary `cargo test`.
    #[test]
    #[ignore = "requires SUNRISE_EDGE_TEST_POSTGRES_URL and every bounded SUNRISE_EDGE_SOAK_* env var against a live PostgreSQL sunrise_edge_test database"]
    fn live_postgres_certified_load_exports_recovery_handoff() {
        let wall_start: Instant = Instant::now();
        let config: SoakConfig = parse_soak_config(|name| std::env::var(name).ok())
            .expect("every bounded SUNRISE_EDGE_SOAK_* env var must be set and in range");
        let database_url: String = std::env::var("SUNRISE_EDGE_TEST_POSTGRES_URL")
            .expect("the live PostgreSQL soak load requires SUNRISE_EDGE_TEST_POSTGRES_URL");
        let wall_deadline: Duration = Duration::from_secs(config.wall_deadline_seconds);
        let check_wall_deadline = |label: &str| {
            assert!(
                wall_start.elapsed() < wall_deadline,
                "wall deadline exceeded during {label}: this run grants no complete result",
            );
        };

        let _lock: PostgresLiveLock = PostgresLiveLock::acquire();
        let (mut admin, namespace, storage_validator_id): (Client, PostgresNamespace, ValidatorId) =
            open_fresh_namespace(&database_url, 0xF0);
        let pg_version_num: i32 = pg_server_version_num(&mut admin);

        let voters: Vec<Voter> = fresh_soak_voters();
        let entries: Vec<FastPathValidatorEntry> =
            voters.iter().map(|voter| voter.entry.clone()).collect();
        let validator_set: ValidatorSet = build_validator_set(&entries);

        let pool_size: u32 = 32;
        let transaction_policy: PostgresTransactionPolicy =
            PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap();
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

        check_wall_deadline("escrow creation setup");
        let workload_start: Instant = Instant::now();

        let lane_keys: Vec<SigningKey> = (0..config.senders)
            .map(|lane| lane_signing_key(0xEB, lane))
            .collect();
        let mut primary_cap: Object = fixture.cap.clone();
        let mut voter1_cap: Object = voter1_fixture.cap.clone();
        let mut voter2_cap: Object = voter2_fixture.cap.clone();
        let mut installer_nonce: u64 = FIRST_PAID_NONCE;

        // The installer's own zero-fee nonce chain must strictly continue
        // `FIRST_PAID_NONCE`; a `zip`-style iterator would obscure that.
        #[allow(clippy::explicit_counter_loop)]
        for index in 0..config.escrows {
            check_wall_deadline("escrow creation");
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
        }

        // ── one representative escrow, claimed sequentially and directly on
        //    the primary, so the same-boot replay-idempotency proof below has
        //    a captured original output to compare against ──
        check_wall_deadline("representative claim sequence");
        let representative_split: SplitClaim = build_split_claim_for_lane(
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
        let representative_split_output: NodeOutput =
            submit_claim_with_blob(&primary, &blobs, &representative_split.signed_bytes);
        assert_eq!(
            representative_split_output.responses()[0].status(),
            NodeResponseStatus::Accepted
        );
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
        assert_eq!(
            submit_claim_with_blob(&primary, &blobs, &representative_split.signed_bytes),
            representative_split_output,
            "same-boot replay of an already-applied claim must be a byte-exact no-op",
        );
        assert_eq!(
            crate::fee_claims::tests::certified_multi_escrow_inventory::current_row(
                &primary,
                escrow_request_id(0),
            )
            .0,
            representative_row_before_replay,
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
        assert_eq!(
            submit_claim_with_blob(&primary, &blobs, &final_bytes_0).responses()[0].status(),
            NodeResponseStatus::Accepted,
        );
        let zero_a_0: Vec<u8> = build_zero_claim(
            &primary,
            &voters[2],
            resource_id,
            escrow_request_id(0),
            zero_claim_request_id_a(0),
        );
        assert_eq!(
            submit_claim_with_blob(&primary, &blobs, &zero_a_0).responses()[0].status(),
            NodeResponseStatus::Accepted,
        );
        let zero_b_0: Vec<u8> = build_zero_claim(
            &primary,
            &voters[3],
            resource_id,
            escrow_request_id(0),
            zero_claim_request_id_b(0),
        );
        assert_eq!(
            submit_claim_with_blob(&primary, &blobs, &zero_b_0).responses()[0].status(),
            NodeResponseStatus::Accepted,
        );

        // ── every remaining escrow, drained by concurrent bounded writers ──
        let retries: AtomicU64 = AtomicU64::new(0);
        let claims_submitted: Mutex<u64> = Mutex::new(0);
        let rate: u32 = config.max_claim_rate_per_sec;
        let pace = |claims_submitted: &Mutex<u64>| {
            let earliest_allowed: Instant = {
                let mut guard = claims_submitted.lock().unwrap();
                let already: u64 = *guard;
                *guard += 1;
                workload_start + Duration::from_secs_f64(already as f64 / f64::from(rate))
            };
            let now: Instant = Instant::now();
            if now < earliest_allowed {
                std::thread::sleep(earliest_allowed - now);
            }
        };

        let mut shards: Vec<Vec<u32>> = vec![Vec::new(); config.claim_writers as usize];
        for index in 1..config.escrows {
            shards[(index % config.claim_writers) as usize].push(index);
        }

        std::thread::scope(|scope| {
            for (writer_slot, shard) in shards.iter().enumerate() {
                let writer_pool: Pool<LiveManager> = pool.clone();
                let writer_namespace: PostgresNamespace = namespace.clone();
                let retry_counter: &AtomicU64 = &retries;
                let claims_submitted: &Mutex<u64> = &claims_submitted;
                let fixture_ref: &Fixture = &fixture;
                let voters_ref: &[Voter] = &voters;
                let check_wall_deadline_ref = &check_wall_deadline;
                scope.spawn(move || {
                    let writer: PostgresDurableStore<LiveManager> = PostgresDurableStore::new(
                        writer_pool.clone(),
                        writer_namespace.clone(),
                        transaction_policy,
                    );
                    let writer_blobs: PostgresBlobStore<LiveManager> =
                        PostgresBlobStore::new(writer_pool, writer_namespace).unwrap();
                    for &index in shard {
                        check_wall_deadline_ref("concurrent claim submission");

                        pace(claims_submitted);
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
                        claim_with_bounded_retry(
                            || {
                                handle_fee_claim(
                                    &writer,
                                    &writer_blobs,
                                    &context(),
                                    domain(),
                                    &resolver(),
                                    &[],
                                    &protocol(),
                                    &base_policy(),
                                    &LocalWasmExecutionEngine::new(),
                                    &split.signed_bytes,
                                    12,
                                )
                            },
                            writer_slot,
                            retry_counter,
                        );

                        pace(claims_submitted);
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
                        claim_with_bounded_retry(
                            || {
                                handle_fee_claim(
                                    &writer,
                                    &writer_blobs,
                                    &context(),
                                    domain(),
                                    &resolver(),
                                    &[],
                                    &protocol(),
                                    &base_policy(),
                                    &LocalWasmExecutionEngine::new(),
                                    &final_bytes,
                                    12,
                                )
                            },
                            writer_slot,
                            retry_counter,
                        );

                        pace(claims_submitted);
                        let zero_a: Vec<u8> = build_zero_claim(
                            &writer,
                            &voters_ref[2],
                            resource_id,
                            escrow_request_id(index),
                            zero_claim_request_id_a(index),
                        );
                        claim_with_bounded_retry(
                            || {
                                handle_fee_claim(
                                    &writer,
                                    &writer_blobs,
                                    &context(),
                                    domain(),
                                    &resolver(),
                                    &[],
                                    &protocol(),
                                    &base_policy(),
                                    &LocalWasmExecutionEngine::new(),
                                    &zero_a,
                                    12,
                                )
                            },
                            writer_slot,
                            retry_counter,
                        );

                        pace(claims_submitted);
                        let zero_b: Vec<u8> = build_zero_claim(
                            &writer,
                            &voters_ref[3],
                            resource_id,
                            escrow_request_id(index),
                            zero_claim_request_id_b(index),
                        );
                        claim_with_bounded_retry(
                            || {
                                handle_fee_claim(
                                    &writer,
                                    &writer_blobs,
                                    &context(),
                                    domain(),
                                    &resolver(),
                                    &[],
                                    &protocol(),
                                    &base_policy(),
                                    &LocalWasmExecutionEngine::new(),
                                    &zero_b,
                                    12,
                                )
                            },
                            writer_slot,
                            retry_counter,
                        );
                    }
                });
            }
        });

        let workload_elapsed_ms: u64 = u64::try_from(workload_start.elapsed().as_millis()).unwrap();
        assert!(
            workload_elapsed_ms <= config.duration_seconds.checked_mul(1000).unwrap(),
            "the full planned workload of {} escrows must complete within the configured \
             duration window, not merely be paced under its rate limit",
            config.escrows,
        );

        let expected_rows: u64 = u64::from(config.escrows);
        let expected_claims: u64 = expected_rows.checked_mul(4).unwrap();
        let expected_payouts: u64 = expected_rows;

        eprintln!(
            "sunrise_edge_soak_v1 kind=workload escrows={} senders={} claim_writers={} \
             max_claim_rate_per_sec={} planned_claims={expected_claims} \
             planned_payouts={expected_payouts} serialization_retries={} \
             workload_elapsed_ms={workload_elapsed_ms} pg_version_num={pg_version_num}",
            config.escrows,
            config.senders,
            config.claim_writers,
            config.max_claim_rate_per_sec,
            retries.load(Ordering::Relaxed),
        );

        drop(blobs);
        drop(primary);
        drop(pool);

        // ── recovery: repeated close/reopen under an advancing writer
        //    generation, each cycle re-verifying the exact retained counts
        //    and rejecting the now-stale prior generation ──
        let mut current_generation: u64 = 1;
        for cycle in 1..=config.recovery_cycles {
            check_wall_deadline("recovery cycle");
            let recovery_start: Instant = Instant::now();
            let stale_generation: u64 = current_generation;
            let advanced_fence: WriterFenceGeneration =
                WriterFenceGeneration::new(current_generation + 1).unwrap();
            advance_writer_fence(
                &mut admin,
                &namespace,
                WriterFenceGeneration::new(current_generation).unwrap(),
                advanced_fence,
            )
            .unwrap();
            current_generation += 1;

            let reopened_pool: Pool<LiveManager> = live_pool(&database_url, pool_size);
            let reopened: PostgresDurableStore<LiveManager> = PostgresDurableStore::new(
                reopened_pool.clone(),
                namespace.clone(),
                transaction_policy,
            );
            let reopened_blobs: PostgresBlobStore<LiveManager> =
                PostgresBlobStore::new(reopened_pool, namespace.clone()).unwrap();
            let fresh_context: DurableOperationContext = context_at(current_generation);

            let stale_row_key: Vec<u8> = crate::local_instance_state::fastpath_settlement_key(
                protocol().chain_id(),
                &escrow_request_id(0),
            )
            .unwrap();
            let stale_error: DurableReadError = reopened
                .get_versioned_durable(&context_at(stale_generation), domain(), &stale_row_key)
                .unwrap_err();
            assert_eq!(
                stale_error,
                DurableReadError::WriterFenced {
                    active_generation: advanced_fence,
                },
            );

            // post-reopen replay of the same representative claim must still
            // be a byte-exact no-op under the fresh writer generation.
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
                    &representative_split.signed_bytes,
                    12,
                )
                .unwrap(),
                representative_split_output,
                "post-reopen replay of an already-applied claim must be a byte-exact no-op",
            );

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

            let recovery_elapsed: Duration = recovery_start.elapsed();
            eprintln!(
                "sunrise_edge_soak_v1 kind=recovery cycle={cycle} writer_generation={current_generation} \
                 verified_rows={} verified_claims={} verified_payouts={} verified_pages={} \
                 recovery_elapsed_ms={}",
                verified.verified_rows,
                verified.verified_claims,
                verified.verified_payouts,
                verified.pages,
                recovery_elapsed.as_millis(),
            );

            drop(reopened);
            drop(reopened_blobs);
        }

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
            writer_generation: current_generation,
            workload_elapsed_ms,
        };
        write_handoff(&config.directory, &handoff)
            .expect("a fresh SUNRISE_EDGE_SOAK_DIR must accept a fresh handoff.kv");

        eprintln!(
            "sunrise_edge_soak_v1 kind=totals complete=true escrows={} recovery_cycles={} \
             final_writer_generation={current_generation} wall_elapsed_ms={}",
            config.escrows,
            config.recovery_cycles,
            wall_start.elapsed().as_millis(),
        );
    }
}
