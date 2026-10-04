//! Closed snapshots of the real Cargo-built children used by this fixture.
//! A separate worktree build must not replace a later child mid-workflow.

use super::fixture::Directory;
use std::{path::PathBuf, sync::Arc};

#[derive(Clone)]
pub struct CompiledExecutableSnapshot {
    _owner: Arc<Directory>,
    pub business_cut: PathBuf,
    pub business_import: PathBuf,
    pub conditional_readiness: PathBuf,
    pub ordered_seal: PathBuf,
    pub successor_activation: PathBuf,
    pub successor_host: PathBuf,
    pub sqlite_source_host: PathBuf,
}

impl CompiledExecutableSnapshot {
    pub fn capture() -> Self {
        let owner: Arc<Directory> = Arc::new(Directory::new("compiled-operator-snapshot"));
        let copy = |source: &str, name: &str| -> PathBuf {
            let destination: PathBuf = owner.0.join(name);
            std::fs::copy(source, &destination).unwrap();
            let permissions: std::fs::Permissions =
                std::fs::metadata(source).unwrap().permissions();
            std::fs::set_permissions(&destination, permissions).unwrap();
            destination
        };
        let business_cut: PathBuf = copy(env!("CARGO_BIN_EXE_business_cut"), "business_cut");
        let business_import: PathBuf =
            copy(env!("CARGO_BIN_EXE_business_import"), "business_import");
        let conditional_readiness: PathBuf = copy(
            env!("CARGO_BIN_EXE_conditional_readiness"),
            "conditional_readiness",
        );
        let ordered_seal: PathBuf = copy(env!("CARGO_BIN_EXE_ordered_seal"), "ordered_seal");
        let successor_activation: PathBuf = copy(
            env!("CARGO_BIN_EXE_successor_activation"),
            "successor_activation",
        );
        let successor_host: PathBuf = copy(env!("CARGO_BIN_EXE_successor_host"), "successor_host");
        let sqlite_source_host: PathBuf = copy(
            env!("CARGO_BIN_EXE_sqlite_source_host"),
            "sqlite_source_host",
        );
        Self {
            _owner: owner,
            business_cut,
            business_import,
            conditional_readiness,
            ordered_seal,
            successor_activation,
            successor_host,
            sqlite_source_host,
        }
    }
}
