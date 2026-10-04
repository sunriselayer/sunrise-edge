//! Actual compiled import command over a genuinely frozen/drained SQLite source.
//! This is inactive installation evidence, not provider or activation acceptance.

#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "business_cut/fixture.rs"]
mod fixture;
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;

use fixture::{Directory, Fixture, copy_files, files};
use node_core::business_reconstruction::SourceBusinessSnapshot;
use protocol_types::ValidatorId;
use runtime_sqlite::{SqliteDurableStore, SqliteNamespace};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use sunrise_edge_operator::{
    business_cut::{CutArchiveLimits, export_source_business_cut},
    business_snapshot::capture_source_business_snapshot,
    immutable_archive::ImmutableArchive,
};

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

fn command(
    fixture: &Fixture,
    history: &Path,
    cut: &Path,
    destination: &Path,
    mode: &str,
    validator: ValidatorId,
    maximum_batches: &str,
) -> Command {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_business_import"));
    command.arg(mode).args([
        "--chain-id",
        fixture.network.chain_id.as_str(),
        "--protocol-version",
        &fixture.network.protocol_version.get().to_string(),
        "--epoch",
        &fixture.network.epoch.get().to_string(),
        "--domain",
        &hex(fixture.network.domain.as_bytes()),
        "--suite",
        "0:1:1:1:1:1:1:1",
        "--genesis-manifest",
        fixture.directory.0.join("genesis.bin").to_str().unwrap(),
        "--expected-genesis-digest",
        &hex(&fixture.network.manifest_digest),
        "--ordered-history-dir",
        history.to_str().unwrap(),
        "--cut-dir",
        cut.to_str().unwrap(),
        "--state-db",
        destination.join("state.sqlite").to_str().unwrap(),
        "--blob-db",
        destination.join("blobs.sqlite").to_str().unwrap(),
        "--validator-id",
        &hex(validator.as_bytes()),
        "--max-new-batches",
        maximum_batches,
    ]);
    command
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn identity_fields(text: &str) -> Vec<&str> {
    text.split_whitespace()
        .filter(|word| {
            word.starts_with("cut=") || word.starts_with("package=") || word.starts_with("plan=")
        })
        .collect()
}

fn history_files(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut files: BTreeMap<PathBuf, Option<Vec<u8>>> = BTreeMap::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path: PathBuf = entry.unwrap().path();
            let metadata: std::fs::Metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let relative: PathBuf = path.strip_prefix(root).unwrap().to_path_buf();
            let contents: Option<Vec<u8>> = if metadata.is_dir() {
                pending.push(path);
                None
            } else {
                assert!(metadata.is_file());
                Some(std::fs::read(&path).unwrap())
            };
            assert!(files.insert(relative, contents).is_none());
        }
    }
    files
}

#[test]
fn compiled_verified_import_creates_reopens_and_reverifies_without_ordinary_serving() {
    let fixture: Fixture = Fixture::new();
    fixture.freeze_and_complete();
    std::fs::write(
        fixture.directory.0.join("genesis.bin"),
        &fixture.network.manifest_bytes,
    )
    .unwrap();
    let (identity, ordered) = fixture.history();
    let before: SourceBusinessSnapshot = fixture.snapshot();
    let history: Directory = Directory::new("import-history-parent");
    let history_root = history.0.join("history");
    fixture.write_history(&history_root, &identity, &ordered);
    let cut: Directory = Directory::new("import-saved-cut");
    let archive: ImmutableArchive = ImmutableArchive::open(&cut.0).unwrap();
    assert!(
        export_source_business_cut(
            fixture.plan(&identity, fixture.operation),
            &fixture.stores[0],
            &fixture.blobs,
            &ordered,
            &archive,
            CutArchiveLimits::new(128, 1048576, 4096).unwrap(),
        )
        .unwrap()
        .complete
    );
    let original_files = files(&cut.0);
    let original_history_files = history_files(&history_root);
    let destination: Directory = Directory::new("import-destination");
    let incoming: ValidatorId = ValidatorId::new([0xE7; 32]);
    assert!(
        fixture.policy.registered_validator(incoming).is_none(),
        "a namespace identifier is not eligibility proof"
    );
    let invalid: Output = command(
        &fixture,
        &history_root,
        &cut.0,
        &destination.0,
        "create-sqlite",
        incoming,
        "0",
    )
    .output()
    .unwrap();
    assert!(!invalid.status.success());
    assert!(!destination.0.join("state.sqlite").exists());
    assert!(!destination.0.join("blobs.sqlite").exists());
    for input_root in [&cut.0, &history_root] {
        for mode in ["create-sqlite", "resume-sqlite"] {
            for (flag, filename) in [
                ("--state-db", "state.sqlite"),
                ("--blob-db", "blobs.sqlite"),
            ] {
                let original: Command = command(
                    &fixture,
                    &history_root,
                    &cut.0,
                    &destination.0,
                    mode,
                    incoming,
                    "1",
                );
                let mut arguments: Vec<OsString> =
                    original.get_args().map(OsString::from).collect();
                let position: usize = arguments.iter().position(|value| value == flag).unwrap();
                arguments[position + 1] = input_root.join(filename).into_os_string();
                let misplaced: Output = Command::new(env!("CARGO_BIN_EXE_business_import"))
                    .args(arguments)
                    .output()
                    .unwrap();
                assert!(!misplaced.status.success());
                assert!(
                    String::from_utf8_lossy(&misplaced.stderr)
                        .contains("destination database must be outside pinned input archive")
                );
                assert!(!input_root.join(filename).exists());
                assert!(!destination.0.join("state.sqlite").exists());
                assert!(!destination.0.join("blobs.sqlite").exists());
                assert_eq!(files(&cut.0), original_files);
                assert!(
                    history_files(&history_root) == original_history_files,
                    "refused placement preserves all original history files and directories"
                );
            }
        }
    }
    let corrupt_cut: Directory = Directory::new("import-corrupt-cut");
    copy_files(&cut.0, &corrupt_cut.0);
    let corrupt_identity: std::path::PathBuf = corrupt_cut.0.join("identity.bin");
    let mut identity_bytes: Vec<u8> = std::fs::read(&corrupt_identity).unwrap();
    let last: usize = identity_bytes.len() - 1;
    identity_bytes[last] ^= 1;
    std::fs::write(&corrupt_identity, identity_bytes).unwrap();
    let corrupt: Output = command(
        &fixture,
        &history_root,
        &corrupt_cut.0,
        &destination.0,
        "create-sqlite",
        incoming,
        "1",
    )
    .output()
    .unwrap();
    assert!(
        !corrupt.status.success(),
        "an altered saved identity is not an import capability"
    );
    assert!(!destination.0.join("state.sqlite").exists());
    assert!(!destination.0.join("blobs.sqlite").exists());
    let first: String = success(
        command(
            &fixture,
            &history_root,
            &cut.0,
            &destination.0,
            "create-sqlite",
            incoming,
            "1",
        )
        .output()
        .unwrap(),
    );
    eprintln!("compiled import first result: {first}");
    assert!(
        first.contains("business_import=partial")
            || first.contains("business_import=complete-inactive")
    );
    assert!(!first.contains("business_import=active"));
    let namespace: SqliteNamespace = SqliteNamespace::new(
        fixture.network.chain_id.clone(),
        incoming,
        fixture.network.domain,
    );
    assert!(
        SqliteDurableStore::open_existing(destination.0.join("state.sqlite"), namespace).is_err()
    );
    let complete: String = success(
        command(
            &fixture,
            &history_root,
            &cut.0,
            &destination.0,
            "resume-sqlite",
            incoming,
            "4096",
        )
        .output()
        .unwrap(),
    );
    assert!(complete.contains("business_import=complete-inactive"));
    assert_eq!(identity_fields(&first), identity_fields(&complete));
    let replay: String = success(
        command(
            &fixture,
            &history_root,
            &cut.0,
            &destination.0,
            "resume-sqlite",
            incoming,
            "1",
        )
        .output()
        .unwrap(),
    );
    assert!(replay.contains("business_import=complete-inactive"));
    assert!(replay.contains("new_batches=0"));
    assert_eq!(identity_fields(&complete), identity_fields(&replay));
    assert_eq!(
        files(&cut.0),
        original_files,
        "import never rewrites the saved cut"
    );
    assert!(
        history_files(&history_root) == original_history_files,
        "successful import and resume preserve all original history files and directories"
    );
    assert_eq!(
        fixture.snapshot(),
        before,
        "import never writes or fences its source"
    );
}
