//! Real compiled-process evidence for DR-0195: the actual `sqlite_genesis`
//! `prepare`/`preflight` binaries against genuinely independent fresh
//! local SQLite namespaces, built from a genuine signed multi-validator
//! fixture. No raw fixture row is ever inserted into a prepared store;
//! every row present was installed by the real core installers through
//! the compiled `prepare` subprocess itself.
#![allow(dead_code)]

#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn byte_hex(byte: u8) -> [u8; 2] {
    [
        HEX_DIGITS[usize::from(byte >> 4)],
        HEX_DIGITS[usize::from(byte & 0x0f)],
    ]
}

fn hex(bytes: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.extend_from_slice(&byte_hex(*byte));
    }
    String::from_utf8(out).unwrap()
}

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Directory(PathBuf);
fn directory_name(label: &str) -> String {
    std::env::temp_dir()
        .join(label)
        .to_string_lossy()
        .into_owned()
}
impl Directory {
    fn new(label: &str) -> Self {
        let sequence: u64 = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let mut unique: String = String::from(label);
        unique.push('-');
        unique.push_str(&std::process::id().to_string());
        unique.push('-');
        unique.push_str(&sequence.to_string());
        let name: String = directory_name(&unique);
        let path: PathBuf = PathBuf::from(name);
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

use compiled_source_host_process::spawn_bounded_output;
use ed25519_zebra::VerificationKey;
use runtime::{
    Clock, DurableOperationContext, StorageCorrelationId, StorageDeadline, SystemClock,
    WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::{
    ffi::OsString,
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

struct Built {
    directory: Directory,
    network: genesis_fixture::FastVoteGenesisFixture,
    genesis_path: PathBuf,
}
