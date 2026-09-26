//! Shared support for the PostgreSQL operator's live-database E2E test.
//!
//! Mirrors `crates/runtime-postgres/tests/support/mod.rs`'s live-test
//! conventions (self-skip unless configured, bounded cross-process lock) in
//! miniature: this crate cannot import that module (it is private to
//! `runtime-postgres`'s own test binaries), so the minimum needed is
//! duplicated here, deliberately sharing the exact same lock file path so
//! both crates' live PostgreSQL tests still serialize against each other.
#![allow(dead_code)]

pub mod cli;
pub mod durable_state;
pub mod genesis_fixture;
pub mod isolated_databases;
pub mod observed_io;
pub mod soak;
pub mod tls_relay;

use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
    process::{Command, Output},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Environment variable naming the live database this test connects to.
/// Unset means the whole E2E test skips, exactly like every other live
/// PostgreSQL test in this repository.
pub const LIVE_POSTGRES_URL_ENV: &str = "SUNRISE_EDGE_TEST_POSTGRES_URL";

/// Environment variable naming the directory the paired node-core certified
/// fixture-export test (`export_certified_operator_fixture_postgres`) wrote
/// `validator_id.hex` into. Supplied by `scripts/check-fee-escrow-inventory-pg.sh`.
pub const FIXTURE_DIR_ENV: &str = "SUNRISE_EDGE_ESCROW_FIXTURE_DIR";

const LOCK_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(600);
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(50);

fn live_lock_path() -> PathBuf {
    env::temp_dir().join("sunrise-edge-runtime-postgres-live-test.lock")
}

/// Held, bounded, cross-process exclusive lock over the shared live
/// PostgreSQL database. See `runtime-postgres`'s own `LiveTestLock` for the
/// full abandoned-lock rationale this mirrors.
pub struct LiveTestLock {
    path: PathBuf,
    owner: String,
}

impl LiveTestLock {
    pub fn acquire() -> Self {
        let path = live_lock_path();
        let owner = format!(
            "{}:{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos(),
        );
        let deadline = Instant::now() + LOCK_ACQUIRE_TIMEOUT;
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(owner.as_bytes()).unwrap();
                    file.sync_all().unwrap();
                    return Self { path, owner };
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if Instant::now() >= deadline {
                        panic!(
                            "timed out after {LOCK_ACQUIRE_TIMEOUT:?} waiting for the exclusive \
                             live PostgreSQL test lock at {}; if no other live test is actually \
                             running, delete this file",
                            path.display()
                        );
                    }
                    thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(error) => panic!(
                    "failed to create live PostgreSQL test lock at {}: {error}",
                    path.display()
                ),
            }
        }
    }
}

impl Drop for LiveTestLock {
    fn drop(&mut self) {
        if fs::read_to_string(&self.path).ok().as_deref() == Some(self.owner.as_str()) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Resolves the live database URL, returning `None` (never panicking) when
/// unset so the caller can print a skip message and return early, exactly
/// like every other live PostgreSQL test in this repository.
pub fn live_postgres_url() -> Option<String> {
    env::var_os(LIVE_POSTGRES_URL_ENV).map(|value| value.to_string_lossy().into_owned())
}

/// Reads the fixture directory the paired node-core export test populated.
pub fn fixture_dir() -> PathBuf {
    PathBuf::from(env::var_os(FIXTURE_DIR_ENV).unwrap_or_else(|| {
        panic!("{FIXTURE_DIR_ENV} must be supplied by scripts/check-fee-escrow-inventory-pg.sh")
    }))
}

/// Runs `command` to completion, panicking with its captured stderr on a
/// non-success exit so a failing operator invocation fails loudly with
/// actionable context instead of a bare "assertion failed".
pub fn run_expect_success(mut command: Command, label: &str) -> Output {
    let output = command.output().unwrap_or_else(|error| {
        panic!("failed to spawn {label}: {error}");
    });
    assert!(
        output.status.success(),
        "{label} failed (status {:?}): stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}
