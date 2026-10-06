//! Real compiled-process evidence for DR-0195: the actual `sqlite_genesis`
//! `prepare`/`preflight` binaries against genuinely independent fresh
//! local SQLite namespaces, built from a genuine signed multi-validator
//! fixture. No raw fixture row is ever inserted into a prepared store;
//! every row present was installed by the real core installers through
//! the compiled `prepare` subprocess itself.

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
        unique.push('-');
        unique.push_str(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .to_string(),
        );
        let name: String = directory_name(&unique);
        let path: PathBuf = PathBuf::from(name);
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

use compiled_source_host_process::{spawn_bounded_output, spawn_bounded_status_line};
use ed25519_zebra::VerificationKey;
use execution::LocalWasmExecutionEngine;
use execution::local_execution::LocalExecutionPolicy;
use node_core::business_reconstruction::SourceBusinessSnapshot;
use node_core::genesis::VerifiedGenesisRoot;
use node_core::ordered_economics::{
    OrderedEconomicsEnvironment, OrderedEconomicsPolicy, query_status,
};
use protocol_types::AtomicityDomainId;
use runtime::{
    Clock, DurableDomainStateStore, DurableOperationContext, StorageCorrelationId, StorageDeadline,
    StructuredDurableDomainStateStore, SystemClock, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    ffi::OsString,
    fs,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use sunrise_edge_operator::business_snapshot::capture_source_business_snapshot;
use sunrise_edge_operator::host_runtime::{
    fast_path_committee_matches, require_committed_genesis_fee_policy,
};

struct Built {
    directory: Directory,
    network: genesis_fixture::FastVoteGenesisFixture,
    genesis_path: PathBuf,
}

fn build() -> Built {
    let directory: Directory = Directory::new("sqlite-genesis");
    let unique: String = directory
        .0
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let network: genesis_fixture::FastVoteGenesisFixture =
        causal_genesis_fixture::build(&unique).network;
    let genesis_path: PathBuf = directory.0.join("genesis.bin");
    fs::write(&genesis_path, &network.manifest_bytes).unwrap();
    Built {
        directory,
        network,
        genesis_path,
    }
}

fn verified_root(built: &Built) -> VerifiedGenesisRoot {
    VerifiedGenesisRoot::verify_bytes(
        &built.network.resolver,
        &built.network.manifest_bytes,
        built.network.manifest_digest,
        &built.network.context,
    )
    .unwrap()
}

fn namespace(built: &Built, validator_index: usize) -> SqliteNamespace {
    SqliteNamespace::new(
        built.network.chain_id.clone(),
        built.network.validators[validator_index].validator_id,
        built.network.domain,
    )
}

fn operation_context(fence: WriterFenceGeneration, tag: u8) -> DurableOperationContext {
    let now: u64 = SystemClock.now_unix_millis().unwrap();
    DurableOperationContext::new(
        fence,
        StorageDeadline::new(now.checked_add(60_000).unwrap()).unwrap(),
        StorageCorrelationId::new([tag; 16]).unwrap(),
    )
}

fn snapshot(
    store: &SqliteDurableStore,
    blobs: &SqliteBlobStore,
    context: &DurableOperationContext,
    domain: AtomicityDomainId,
) -> SourceBusinessSnapshot {
    capture_source_business_snapshot(
        store,
        blobs,
        context,
        domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap()
}

fn prepare_args(
    built: &Built,
    validator_index: usize,
    state_db: &Path,
    blob_db: &Path,
) -> Vec<OsString> {
    vec![
        OsString::from("prepare"),
        OsString::from("--chain-id"),
        OsString::from(built.network.chain_id.as_str()),
        OsString::from("--validator-id"),
        OsString::from(hex(built.network.validators[validator_index]
            .validator_id
            .as_bytes())),
        OsString::from("--domain"),
        OsString::from(hex(built.network.domain.as_bytes())),
        OsString::from("--protocol-version"),
        OsString::from(built.network.protocol_version.get().to_string()),
        OsString::from("--epoch"),
        OsString::from(built.network.epoch.get().to_string()),
        OsString::from("--suite"),
        OsString::from(genesis_fixture::SUITE_FLAG),
        OsString::from("--genesis-manifest"),
        built.genesis_path.as_os_str().to_owned(),
        OsString::from("--expected-genesis-digest"),
        OsString::from(hex(&built.network.manifest_digest)),
        OsString::from("--state-db"),
        state_db.as_os_str().to_owned(),
        OsString::from("--blob-db"),
        blob_db.as_os_str().to_owned(),
        OsString::from("--created-checkpoint"),
        OsString::from("10"),
    ]
}

fn preflight_args(
    built: &Built,
    validator_index: usize,
    state_db: &Path,
    blob_db: &Path,
) -> Vec<OsString> {
    let public_key: [u8; 32] =
        VerificationKey::from(&built.network.validators[validator_index].signing_key).into();
    vec![
        OsString::from("preflight"),
        OsString::from("--chain-id"),
        OsString::from(built.network.chain_id.as_str()),
        OsString::from("--validator-id"),
        OsString::from(hex(built.network.validators[validator_index]
            .validator_id
            .as_bytes())),
        OsString::from("--domain"),
        OsString::from(hex(built.network.domain.as_bytes())),
        OsString::from("--protocol-version"),
        OsString::from(built.network.protocol_version.get().to_string()),
        OsString::from("--epoch"),
        OsString::from(built.network.epoch.get().to_string()),
        OsString::from("--suite"),
        OsString::from(genesis_fixture::SUITE_FLAG),
        OsString::from("--genesis-manifest"),
        built.genesis_path.as_os_str().to_owned(),
        OsString::from("--expected-genesis-digest"),
        OsString::from(hex(&built.network.manifest_digest)),
        OsString::from("--state-db"),
        state_db.as_os_str().to_owned(),
        OsString::from("--blob-db"),
        blob_db.as_os_str().to_owned(),
        OsString::from("--validator-public-key"),
        OsString::from(hex(&public_key)),
    ]
}

fn run_sqlite_genesis(args: Vec<OsString>) -> Output {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_genesis"));
    command.args(&args);
    spawn_bounded_output(command, Duration::from_secs(30))
}

fn stdout_line(output: &Output) -> String {
    let stdout: String = String::from_utf8(output.stdout.clone()).unwrap();
    assert_eq!(
        stdout.lines().count(),
        1,
        "expected one closed completion line"
    );
    stdout.trim_end().to_owned()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Logical rows, not unstable SQLite page/WAL bytes. Includes every table,
/// including empty receipt/nonce/blob tables and unreferenced blob inventory.
fn logical_tables(path: &Path) -> Vec<(String, Vec<String>)> {
    let connection: rusqlite::Connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut names: rusqlite::Statement<'_> = connection.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap();
    let tables: Vec<String> = names
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<String>, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|name: String| {
            let query: String = format!("SELECT * FROM \"{}\"", name.replace('"', "\"\""));
            let mut statement: rusqlite::Statement<'_> = connection.prepare(&query).unwrap();
            let columns: usize = statement.column_count();
            let mut rows: Vec<String> = statement
                .query_map([], |row| {
                    let values: Vec<rusqlite::types::Value> = (0..columns)
                        .map(|column: usize| row.get(column))
                        .collect::<Result<Vec<rusqlite::types::Value>, _>>()?;
                    Ok(format!("{values:?}"))
                })
                .unwrap()
                .collect::<Result<Vec<String>, _>>()
                .unwrap();
            rows.sort();
            (name, rows)
        })
        .collect()
}

fn flag_value_index(args: &[OsString], flag: &str) -> usize {
    args.iter()
        .position(|value: &OsString| value == flag)
        .unwrap_or_else(|| panic!("missing {flag} in {args:?}"))
        + 1
}

fn field(line: &str, key: &str) -> String {
    line.split_whitespace()
        .find_map(|token: &str| token.strip_prefix(key))
        .unwrap_or_else(|| panic!("line lacks {key}: {line}"))
        .to_owned()
}

#[test]
fn prepare_installs_four_independent_pairs_with_markers_objects_fee_committee_and_ordered_state() {
    let built: Built = build();
    assert_eq!(
        built.network.validators.len(),
        4,
        "the fixture names four committee validators"
    );
    let root: VerifiedGenesisRoot = verified_root(&built);

    for index in 0..built.network.validators.len() {
        let state_db: PathBuf = built.directory.0.join(format!("pair-{index}-state.sqlite"));
        let blob_db: PathBuf = built.directory.0.join(format!("pair-{index}-blob.sqlite"));
        let output: Output = run_sqlite_genesis(prepare_args(&built, index, &state_db, &blob_db));
        assert!(
            output.status.success(),
            "validator {index}: {}",
            stderr_text(&output)
        );
        let line: String = stdout_line(&output);
        assert!(line.contains("complete=true mode=prepare"), "{line}");
        assert_eq!(field(&line, "writer_fence="), "1");

        let store: SqliteDurableStore =
            SqliteDurableStore::open_existing(&state_db, namespace(&built, index)).unwrap();
        let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_db).unwrap();
        let fence: WriterFenceGeneration = store.writer_fence().unwrap();
        assert_eq!(fence.get(), 1);
        let context: DurableOperationContext =
            operation_context(fence, 0x10u8.wrapping_add(index as u8));

        // Marker + fee policy, exactly as the original host checks them.
        let fee_policy: execution::paid_execution::PaidFeePolicy =
            require_committed_genesis_fee_policy(
                &store,
                &context,
                built.network.domain,
                &built.network.context,
                &root,
            )
            .unwrap();
        assert_eq!(fee_policy, root.manifest().fee_policy);

        // Genesis objects were installed by the real installer, not seeded.
        assert!(!store.object_store_is_empty().unwrap());
        for entry in &root.manifest().objects {
            let version: runtime::DurableObjectVersion =
                runtime::DurableObjectVersion::new(entry.object.version).unwrap();
            let record: runtime::DurableObjectVersionRecord = store
                .get_object_version(&context, built.network.domain, entry.object.id, version)
                .unwrap()
                .expect("every genesis object is installed");
            let canonical: Vec<u8> = objects::encode_object(&entry.object).unwrap();
            assert_eq!(
                record.payload().inline().unwrap().canonical_bytes(),
                canonical
            );
        }

        // Committed fast-path committee matches the trusted root's own committee.
        let key: Vec<u8> =
            node_core::local_instance_state::fastpath_validator_set_key(&built.network.context)
                .unwrap();
        let observed = store
            .get_versioned_durable(&context, built.network.domain, &key)
            .unwrap();
        let record = node_core::fast_path::records::decode_fastpath_validator_set_record(
            observed.value().unwrap(),
        )
        .unwrap();
        assert!(fast_path_committee_matches(
            &record,
            &root.manifest().validator_set
        ));

        // Ordered consensus state was installed at genesis, not left missing.
        let policy: OrderedEconomicsPolicy =
            OrderedEconomicsPolicy::from_genesis_root(&root, built.network.domain).unwrap();
        let local_policy: LocalExecutionPolicy =
            LocalExecutionPolicy::generic_object_results(built.network.context.clone());
        let engine: LocalWasmExecutionEngine = LocalWasmExecutionEngine::new();
        let env: OrderedEconomicsEnvironment<'_> = OrderedEconomicsEnvironment {
            policy: &policy,
            history: &[],
            leg_policy: &local_policy,
            engine: &engine,
            blobs: &blobs,
            seal: None,
        };
        let status = query_status(&store, &context, &env).unwrap();
        assert_eq!(status.committed_height, 0);
    }

    // Independence: each pair is bound to its own validator's namespace.
    for a in 0..built.network.validators.len() {
        for b in (a + 1)..built.network.validators.len() {
            assert_ne!(
                built.network.validators[a].validator_id,
                built.network.validators[b].validator_id
            );
        }
    }
}

#[test]
fn prepare_repeated_attempt_refuses_without_changing_existing_state() {
    let built: Built = build();
    let state_db: PathBuf = built.directory.0.join("state.sqlite");
    let blob_db: PathBuf = built.directory.0.join("blob.sqlite");
    let first: Output = run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db));
    assert!(first.status.success(), "{}", stderr_text(&first));

    let store: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_db, namespace(&built, 0)).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_db).unwrap();
    let fence: WriterFenceGeneration = store.writer_fence().unwrap();
    let before: SourceBusinessSnapshot = snapshot(
        &store,
        &blobs,
        &operation_context(fence, 0x20),
        built.network.domain,
    );
    drop(store);
    drop(blobs);

    let second: Output = run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db));
    assert!(
        !second.status.success(),
        "a repeated prepare into the same destinations must refuse"
    );
    assert!(
        stderr_text(&second).contains("already exists"),
        "{}",
        stderr_text(&second)
    );

    let reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_db, namespace(&built, 0)).unwrap();
    let reopened_blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_db).unwrap();
    let after_fence: WriterFenceGeneration = reopened.writer_fence().unwrap();
    assert_eq!(after_fence, fence);
    let after: SourceBusinessSnapshot = snapshot(
        &reopened,
        &reopened_blobs,
        &operation_context(after_fence, 0x21),
        built.network.domain,
    );
    assert_eq!(
        before.records, after.records,
        "a refused repeat must not change any row"
    );
    assert_eq!(before.referenced_blobs, after.referenced_blobs);
    assert_eq!(before.token, after.token);
}

#[test]
fn prepare_refuses_wrong_digest_context_and_non_committee_validator_before_any_file_creation() {
    let built: Built = build();
    let cases: Vec<(&str, &str, String)> = vec![
        ("--expected-genesis-digest", "wrong digest", "99".repeat(32)),
        (
            "--chain-id",
            "wrong chain",
            "sqlite-genesis-wrong-chain".to_owned(),
        ),
        (
            "--protocol-version",
            "wrong protocol version",
            "9".to_owned(),
        ),
        ("--epoch", "wrong epoch", "7".to_owned()),
        (
            "--validator-id",
            "validator outside the committee",
            "55".repeat(32),
        ),
    ];
    for (flag, label, value) in cases {
        let state_db: PathBuf = built
            .directory
            .0
            .join(format!("refuse-{flag}-state.sqlite").replace("--", ""));
        let blob_db: PathBuf = built
            .directory
            .0
            .join(format!("refuse-{flag}-blob.sqlite").replace("--", ""));
        let mut args: Vec<OsString> = prepare_args(&built, 0, &state_db, &blob_db);
        let index: usize = flag_value_index(&args, flag);
        args[index] = OsString::from(value);
        let output: Output = run_sqlite_genesis(args);
        assert!(
            !output.status.success(),
            "{label} was unexpectedly accepted"
        );
        assert!(
            !state_db.exists(),
            "{label}: state file created despite refusal"
        );
        assert!(
            !blob_db.exists(),
            "{label}: blob file created despite refusal"
        );
    }
}

#[test]
fn prepare_refuses_preexisting_destinations_sidecars_and_cross_file_aliases_without_creating_main()
{
    let built: Built = build();

    {
        let state_db: PathBuf = built.directory.0.join("existing-main-state.sqlite");
        let blob_db: PathBuf = built.directory.0.join("existing-main-blob.sqlite");
        fs::write(&state_db, []).unwrap();
        let output: Output = run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db));
        assert!(!output.status.success());
        assert_eq!(fs::read(&state_db).unwrap(), Vec::<u8>::new());
        assert!(!blob_db.exists());
    }

    {
        let shared: PathBuf = built.directory.0.join("shared.sqlite");
        let output: Output = run_sqlite_genesis(prepare_args(&built, 0, &shared, &shared));
        assert!(!output.status.success());
        assert!(!shared.exists());
    }

    {
        let blob_db: PathBuf = built.directory.0.join("normalized.sqlite");
        let mut spelled: OsString = built.directory.0.as_os_str().to_owned();
        spelled.push("/./normalized.sqlite");
        let state_db: PathBuf = PathBuf::from(spelled);
        let output: Output = run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db));
        assert!(
            !output.status.success(),
            "a redundant '.' component must still collide after normalization"
        );
        assert!(!blob_db.exists());
    }

    for target in ["state", "blob"] {
        for suffix in ["-wal", "-shm", "-journal"] {
            let state_db: PathBuf = built
                .directory
                .0
                .join(format!("{target}{suffix}-state.sqlite"));
            let blob_db: PathBuf = built
                .directory
                .0
                .join(format!("{target}{suffix}-blob.sqlite"));
            let mut sidecar: OsString = if target == "state" {
                state_db.as_os_str()
            } else {
                blob_db.as_os_str()
            }
            .to_owned();
            sidecar.push(suffix);
            let sidecar: PathBuf = PathBuf::from(sidecar);
            fs::write(&sidecar, b"preserve sidecar").unwrap();
            let output: Output = run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db));
            assert!(!output.status.success());
            assert!(
                !state_db.exists(),
                "main must never be created once a sidecar already exists"
            );
            assert!(!blob_db.exists());
            assert_eq!(fs::read(&sidecar).unwrap(), b"preserve sidecar");
        }
    }

    for suffix in ["-wal", "-shm", "-journal"] {
        for reversed in [false, true] {
            let first: PathBuf = built
                .directory
                .0
                .join(format!("cross-{suffix}-{reversed}.sqlite"));
            let mut second: OsString = first.as_os_str().to_owned();
            second.push(suffix);
            let second: PathBuf = PathBuf::from(second);
            let (state_db, blob_db): (PathBuf, PathBuf) = if reversed {
                (second, first)
            } else {
                (first, second)
            };
            let output: Output = run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db));
            assert!(
                !output.status.success(),
                "cross-file sidecar alias {suffix} reversed={reversed}"
            );
            assert!(!state_db.exists());
            assert!(!blob_db.exists());
        }
    }

    #[cfg(unix)]
    {
        let real: PathBuf = built.directory.0.join("real-target.sqlite");
        let link: PathBuf = built.directory.0.join("symlink-state.sqlite");
        fs::write(&real, b"keep").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let blob_db: PathBuf = built.directory.0.join("symlink-blob.sqlite");
        let output: Output = run_sqlite_genesis(prepare_args(&built, 0, &link, &blob_db));
        assert!(!output.status.success());
        assert_eq!(fs::read(&real).unwrap(), b"keep");
        assert!(!blob_db.exists());
    }
}

#[test]
fn prepare_checks_both_parents_before_reserving_either_destination() {
    let built: Built = build();
    for bad_target in ["state", "blob"] {
        for fault in ["missing", "file", "parent-traversal"] {
            let safe: PathBuf = built
                .directory
                .0
                .join(format!("safe-{bad_target}-{fault}.sqlite"));
            let parent: PathBuf = built.directory.0.join(format!("bad-{bad_target}-{fault}"));
            if fault == "file" {
                fs::write(&parent, b"preserve parent").unwrap();
            }
            let bad: PathBuf = if fault == "parent-traversal" {
                built.directory.0.join("../not-allowed.sqlite")
            } else {
                parent.join("db.sqlite")
            };
            let (state, blob): (&Path, &Path) = if bad_target == "state" {
                (&bad, &safe)
            } else {
                (&safe, &bad)
            };
            let output: Output = run_sqlite_genesis(prepare_args(&built, 0, state, blob));
            assert!(!output.status.success());
            assert!(
                !safe.exists(),
                "neither main may be reserved when either parent is invalid"
            );
            if fault == "file" {
                assert_eq!(fs::read(&parent).unwrap(), b"preserve parent");
            }
        }
    }
    #[cfg(unix)]
    {
        let link: PathBuf = built.directory.0.join("parent-link");
        std::os::unix::fs::symlink(&built.directory.0, &link).unwrap();
        let state: PathBuf = built.directory.0.join("valid-state.sqlite");
        let blob: PathBuf = link.join("invalid-blob.sqlite");
        assert!(
            !run_sqlite_genesis(prepare_args(&built, 0, &state, &blob))
                .status
                .success()
        );
        assert!(!state.exists());
        assert!(!blob.exists());
    }
}

#[test]
fn prepare_refuses_a_verified_non_causal_genesis_before_creating_either_destination() {
    let directory: Directory = Directory::new("sqlite-genesis-non-causal");
    let unique: String = directory
        .0
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let network: genesis_fixture::FastVoteGenesisFixture =
        genesis_fixture::build_network_fixture(&unique);
    let genesis_path: PathBuf = directory.0.join("genesis.bin");
    fs::write(&genesis_path, &network.manifest_bytes).unwrap();
    let built: Built = Built {
        directory,
        network,
        genesis_path,
    };

    // Root verification (signature/digest/context) must succeed on its own
    // terms; only the causal-admission gate is exercised below.
    let root: VerifiedGenesisRoot = verified_root(&built);
    assert!(
        !root.admission_profile().is_causal(),
        "this regression requires a genuinely non-causal verified root"
    );

    let state_db: PathBuf = built.directory.0.join("non-causal-state.sqlite");
    let blob_db: PathBuf = built.directory.0.join("non-causal-blob.sqlite");
    let output: Output = run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db));

    assert!(
        !output.status.success(),
        "a verified but non-causal genesis must still be refused"
    );
    assert!(
        stderr_text(&output).contains("sqlite-genesis requires a causal-admission genesis"),
        "{}",
        stderr_text(&output)
    );
    assert!(output.stdout.is_empty());
    assert!(!state_db.exists());
    assert!(!blob_db.exists());
}

#[test]
fn preflight_reports_success_and_leaves_rows_objects_receipts_blobs_fence_and_sequence_unchanged() {
    let built: Built = build();
    let state_db: PathBuf = built.directory.0.join("state.sqlite");
    let blob_db: PathBuf = built.directory.0.join("blob.sqlite");
    assert!(
        run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db))
            .status
            .success()
    );

    let store: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_db, namespace(&built, 0)).unwrap();
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_db).unwrap();
    let fence: WriterFenceGeneration = store.writer_fence().unwrap();
    let before: SourceBusinessSnapshot = snapshot(
        &store,
        &blobs,
        &operation_context(fence, 0x30),
        built.network.domain,
    );
    drop(store);
    drop(blobs);
    let before_all = (logical_tables(&state_db), logical_tables(&blob_db));

    let output: Output = run_sqlite_genesis(preflight_args(&built, 0, &state_db, &blob_db));
    assert!(output.status.success(), "{}", stderr_text(&output));
    let line: String = stdout_line(&output);
    assert!(
        line.contains("complete=true mode=preflight advisory=true"),
        "{line}"
    );

    let reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_db, namespace(&built, 0)).unwrap();
    let reopened_blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_db).unwrap();
    let after_fence: WriterFenceGeneration = reopened.writer_fence().unwrap();
    assert_eq!(
        after_fence, fence,
        "advisory preflight must never advance the writer fence"
    );
    let after: SourceBusinessSnapshot = snapshot(
        &reopened,
        &reopened_blobs,
        &operation_context(after_fence, 0x31),
        built.network.domain,
    );
    assert_eq!(before.records, after.records);
    assert_eq!(before.referenced_blobs, after.referenced_blobs);
    assert_eq!(before.token, after.token);
    assert_eq!(
        before_all,
        (logical_tables(&state_db), logical_tables(&blob_db))
    );
}

#[test]
fn preflight_refuses_wrong_digest_context_and_mismatched_public_key() {
    let built: Built = build();
    let state_db: PathBuf = built.directory.0.join("state.sqlite");
    let blob_db: PathBuf = built.directory.0.join("blob.sqlite");
    assert!(
        run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db))
            .status
            .success()
    );

    let before_all = (logical_tables(&state_db), logical_tables(&blob_db));
    let cases: [(&str, String); 3] = [
        ("--expected-genesis-digest", "77".repeat(32)),
        ("--epoch", "3".to_owned()),
        ("--validator-public-key", "66".repeat(32)),
    ];
    for (flag, value) in cases {
        let mut args: Vec<OsString> = preflight_args(&built, 0, &state_db, &blob_db);
        let index: usize = flag_value_index(&args, flag);
        args[index] = OsString::from(value);
        let output: Output = run_sqlite_genesis(args);
        assert!(
            !output.status.success(),
            "{flag} mismatch was unexpectedly accepted"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(
            before_all,
            (logical_tables(&state_db), logical_tables(&blob_db))
        );
    }

    let reopened: SqliteDurableStore =
        SqliteDurableStore::open_existing(&state_db, namespace(&built, 0)).unwrap();
    assert_eq!(
        reopened.writer_fence().unwrap().get(),
        1,
        "every refusal above must leave the fence untouched"
    );
}

#[test]
fn preflight_refuses_deleted_and_malformed_ordered_state_without_repair() {
    use consensus::decode_consensus_state;
    use runtime::portable::DurableRecordKey;
    use runtime::{
        AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
        StateMutation, StateMutationEntry, StateReadAssertion,
    };

    for case in ["missing", "deleted", "malformed"] {
        let built: Built = build();
        let state_db: PathBuf = built.directory.0.join("state.sqlite");
        let blob_db: PathBuf = built.directory.0.join("blob.sqlite");
        assert!(
            run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db))
                .status
                .success()
        );

        let store: SqliteDurableStore =
            SqliteDurableStore::open_existing(&state_db, namespace(&built, 0)).unwrap();
        let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_db).unwrap();
        let fence: WriterFenceGeneration = store.writer_fence().unwrap();
        let context: DurableOperationContext = operation_context(fence, 0x40);
        let before: SourceBusinessSnapshot =
            snapshot(&store, &blobs, &context, built.network.domain);
        let key: Vec<u8> = before
            .records
            .iter()
            .find_map(|record| match record.descriptor.key() {
                DurableRecordKey::State(key)
                    if record
                        .value
                        .as_deref()
                        .is_some_and(|bytes| decode_consensus_state(bytes).is_ok()) =>
                {
                    Some(key.clone())
                }
                _ => None,
            })
            .expect("a fresh prepare installs exactly one consensus row");
        let observed = store
            .get_versioned_durable(&context, built.network.domain, &key)
            .unwrap();
        let mutation: StateMutation = if case == "deleted" {
            StateMutation::Delete
        } else {
            StateMutation::Put(vec![0])
        };
        let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
            built.network.domain,
            AtomicStateReadSet::new(vec![
                StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
            ])
            .unwrap(),
            AtomicStateMutationSet::new(vec![
                StateMutationEntry::new(key.clone(), mutation).unwrap(),
            ])
            .unwrap(),
        )
        .unwrap();
        if case == "missing" {
            // Deliberate physical fault to an actually installed row, not a
            // hand-seeded positive namespace or an authorized deletion.
            let connection: rusqlite::Connection = rusqlite::Connection::open(&state_db).unwrap();
            assert_eq!(
                connection.execute(
                    "DELETE FROM durable_state WHERE key=?1",
                    rusqlite::params![key]
                ),
                Ok(1)
            );
        } else {
            assert_eq!(
                store.commit_durable(&context, transaction),
                DurableCommitOutcome::Committed
            );
        }
        let corrupted: SourceBusinessSnapshot =
            snapshot(&store, &blobs, &context, built.network.domain);
        drop(store);
        drop(blobs);
        let corrupted_all = (logical_tables(&state_db), logical_tables(&blob_db));

        let output: Output = run_sqlite_genesis(preflight_args(&built, 0, &state_db, &blob_db));
        assert!(!output.status.success(), "{case}: {}", stderr_text(&output));

        let reopened: SqliteDurableStore =
            SqliteDurableStore::open_existing(&state_db, namespace(&built, 0)).unwrap();
        let reopened_blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blob_db).unwrap();
        let reopened_fence: WriterFenceGeneration = reopened.writer_fence().unwrap();
        assert_eq!(
            reopened_fence, fence,
            "preflight never advances the fence, even on refusal"
        );
        let after: SourceBusinessSnapshot = snapshot(
            &reopened,
            &reopened_blobs,
            &operation_context(reopened_fence, 0x41),
            built.network.domain,
        );
        assert_eq!(
            corrupted.records, after.records,
            "{case}: refusal must not repair the corrupted row"
        );
        assert_eq!(corrupted.token, after.token);
        assert_eq!(
            corrupted_all,
            (logical_tables(&state_db), logical_tables(&blob_db))
        );
    }
}

#[test]
fn preflight_refuses_an_imported_origin_namespace() {
    use protocol_types::{Digest32, ExecutionGeneration, HashAlgorithmId};
    use runtime::{ImportBinding, ImportContext};
    use runtime_sqlite::SqliteImportTarget;

    let built: Built = build();
    let state_db: PathBuf = built.directory.0.join("state.sqlite");
    let blob_db: PathBuf = built.directory.0.join("blob.sqlite");
    let binding: ImportBinding = ImportBinding {
        context: ImportContext {
            chain_id: built.network.chain_id.clone(),
            protocol_version: built.network.protocol_version,
            epoch: built.network.epoch,
        },
        domain: built.network.domain,
        genesis_digest: Digest32::new(HashAlgorithmId::Sha2_256, [1; 32]),
        validator_set_digest: Digest32::new(HashAlgorithmId::Sha2_256, [2; 32]),
        cut_digest: Digest32::new(HashAlgorithmId::Sha2_256, [3; 32]),
        package_digest: Digest32::new(HashAlgorithmId::Sha2_256, [4; 32]),
        plan_digest: Digest32::new(HashAlgorithmId::Sha2_256, [5; 32]),
        row_count: 0,
        blob_count: 0,
        generation_floor: ExecutionGeneration::new(1),
    };
    SqliteImportTarget::create(
        &state_db,
        namespace(&built, 0),
        WriterFenceGeneration::new(1).unwrap(),
        &binding,
    )
    .unwrap();
    let before = logical_tables(&state_db);

    let output: Output = run_sqlite_genesis(preflight_args(&built, 0, &state_db, &blob_db));
    assert!(!output.status.success());
    assert!(
        stderr_text(&output).to_lowercase().contains("import"),
        "{}",
        stderr_text(&output)
    );
    assert_eq!(before, logical_tables(&state_db));
    assert!(!blob_db.exists());
}

#[test]
fn preflight_refuses_a_sealed_origin_namespace() {
    use protocol_types::{Digest32, Epoch, HashAlgorithmId};
    use runtime::{OutgoingBarrier, SealBarrier, TransitionHistoryState, encode_outgoing_barrier};
    use rusqlite::Connection;

    let built: Built = build();
    let state_db: PathBuf = built.directory.0.join("state.sqlite");
    let blob_db: PathBuf = built.directory.0.join("blob.sqlite");
    assert!(
        run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db))
            .status
            .success()
    );

    let barrier: OutgoingBarrier = OutgoingBarrier::Sealed(SealBarrier {
        outgoing_epoch: Epoch::new(1),
        request: [0x80; 32],
        height: 1,
        block_digest: Digest32::new(HashAlgorithmId::Sha2_256, [9; 32]),
        target_digest: Digest32::new(HashAlgorithmId::Sha2_256, [10; 32]),
        transition_history: TransitionHistoryState::Virgin,
    });
    let encoded: Vec<u8> = encode_outgoing_barrier(&barrier).unwrap();
    let connection: Connection = Connection::open(&state_db).unwrap();
    connection
        .execute(
            "UPDATE durable_outgoing_barrier SET barrier = ?1 WHERE id = 1",
            rusqlite::params![encoded],
        )
        .unwrap();
    drop(connection);
    let before = (logical_tables(&state_db), logical_tables(&blob_db));

    let output: Output = run_sqlite_genesis(preflight_args(&built, 0, &state_db, &blob_db));
    assert!(!output.status.success());
    assert!(
        stderr_text(&output).to_lowercase().contains("sealed"),
        "{}",
        stderr_text(&output)
    );
    assert_eq!(
        before,
        (logical_tables(&state_db), logical_tables(&blob_db))
    );
}

#[test]
fn preflight_refuses_missing_or_wrong_fee_committee_and_marker_without_repair() {
    use runtime::{
        AtomicStateMutationSet, AtomicStateReadSet, AtomicStateTransaction, DurableCommitOutcome,
        StateMutation, StateMutationEntry, StateReadAssertion,
    };
    for which in ["fee", "committee", "marker"] {
        for wrong_value in [false, true] {
            let built: Built = build();
            let state: PathBuf = built.directory.0.join("state.sqlite");
            let blobs: PathBuf = built.directory.0.join("blobs.sqlite");
            assert!(
                run_sqlite_genesis(prepare_args(&built, 0, &state, &blobs))
                    .status
                    .success()
            );
            let store: SqliteDurableStore =
                SqliteDurableStore::open_existing(&state, namespace(&built, 0)).unwrap();
            let context: DurableOperationContext =
                operation_context(store.writer_fence().unwrap(), 0x63);
            let key: Vec<u8> = match which {
                "fee" => {
                    node_core::local_instance_state::paid_fee_policy_key(&built.network.context)
                        .unwrap()
                }
                "committee" => node_core::local_instance_state::fastpath_validator_set_key(
                    &built.network.context,
                )
                .unwrap(),
                _ => node_core::genesis_marker_key(&built.network.context).unwrap(),
            };
            let observed: runtime::VersionedStateValue = store
                .get_versioned_durable(&context, built.network.domain, &key)
                .unwrap();
            assert!(observed.value().is_some());
            let mutation: StateMutation = if wrong_value {
                let bytes: Vec<u8> = match which {
                    "fee" => {
                        let mut policy: execution::paid_execution::PaidFeePolicy =
                            execution::paid_execution::decode_paid_fee_policy(
                                observed.value().unwrap(),
                            )
                            .unwrap();
                        policy.fee_recipient =
                            VerificationKey::from(&built.network.validators[1].signing_key).into();
                        execution::paid_execution::encode_paid_fee_policy(&policy).unwrap()
                    }
                    "committee" => {
                        let mut record: node_core::fast_path::FastPathValidatorSetRecord =
                            node_core::fast_path::records::decode_fastpath_validator_set_record(
                                observed.value().unwrap(),
                            )
                            .unwrap();
                        record.validators[0].voting_power =
                            record.validators[0].voting_power.checked_add(1).unwrap();
                        node_core::fast_path::records::encode_fastpath_validator_set_record(&record)
                            .unwrap()
                    }
                    _ => {
                        let mut marker: node_core::genesis::GenesisInstallMarker =
                            node_core::decode_genesis_install_marker(observed.value().unwrap())
                                .unwrap();
                        marker.manifest_digest = protocol_types::Digest32::new(
                            protocol_types::HashAlgorithmId::Sha2_256,
                            [0x71; 32],
                        );
                        node_core::encode_genesis_install_marker(&marker).unwrap()
                    }
                };
                StateMutation::Put(bytes)
            } else {
                StateMutation::Delete
            };
            let transaction: AtomicStateTransaction = AtomicStateTransaction::new(
                built.network.domain,
                AtomicStateReadSet::new(vec![
                    StateReadAssertion::new(key.clone(), observed.revision()).unwrap(),
                ])
                .unwrap(),
                AtomicStateMutationSet::new(vec![StateMutationEntry::new(key, mutation).unwrap()])
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                store.commit_durable(&context, transaction),
                DurableCommitOutcome::Committed
            );
            drop(store);
            let before = (logical_tables(&state), logical_tables(&blobs));
            let output: Output = run_sqlite_genesis(preflight_args(&built, 0, &state, &blobs));
            assert!(
                !output.status.success(),
                "{which} wrong={wrong_value} accepted"
            );
            assert!(output.stdout.is_empty());
            let error: String = stderr_text(&output);
            let expected: &str = match which {
                "fee" => "fee policy",
                "committee" => "validator",
                _ => "genesis",
            };
            assert!(
                error.contains(expected),
                "{which} wrong={wrong_value}: {error}"
            );
            assert_eq!(before, (logical_tables(&state), logical_tables(&blobs)));
        }
    }
}

struct HostProcess {
    _child: compiled_source_host_process::ChildGuard,
    address: std::net::SocketAddr,
    generation: u64,
}

fn start_sqlite_source_host(
    built: &Built,
    state_db: &Path,
    blob_db: &Path,
    key_file: &Path,
    index: usize,
) -> HostProcess {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_source_host"));
    command.args([
        "--chain-id",
        built.network.chain_id.as_str(),
        "--validator-id",
        &hex(built.network.validators[index].validator_id.as_bytes()),
        "--domain",
        &hex(built.network.domain.as_bytes()),
        "--protocol-version",
        &built.network.protocol_version.get().to_string(),
        "--epoch",
        &built.network.epoch.get().to_string(),
        "--suite",
        genesis_fixture::SUITE_FLAG,
        "--genesis-manifest",
        built.genesis_path.to_str().unwrap(),
        "--expected-genesis-digest",
        &hex(&built.network.manifest_digest),
        "--signing-key-file",
        key_file.to_str().unwrap(),
        "--state-db",
        state_db.to_str().unwrap(),
        "--blob-db",
        blob_db.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--created-checkpoint",
        "1000",
        "--timeout-seconds",
        "30",
        "--max-concurrent",
        "4",
        "--confirm-offline-fence-advance",
    ]);
    let (mut guard, line) = spawn_bounded_status_line(command, Duration::from_secs(30));
    if line.is_empty() {
        panic!(
            "sqlite-source-host exited before serving: {:?}",
            guard.try_wait()
        );
    }
    assert!(line.contains("complete=true mode=serving"), "{line}");
    HostProcess {
        address: field(&line, "listen=").parse().unwrap(),
        generation: field(&line, "writer_generation=").parse().unwrap(),
        _child: guard,
    }
}

fn query_status_over_loopback(
    address: std::net::SocketAddr,
) -> node_core::ordered_economics::OrderedStatus {
    use sunrise_edge_client::{LoopbackHttpTransport, Method, Transport, WireRequest};

    let transport: LoopbackHttpTransport = LoopbackHttpTransport::new(
        address,
        Duration::from_secs(3),
        Duration::from_secs(3),
        Duration::from_secs(3),
        NonZeroUsize::new(8 * 1024).unwrap(),
        NonZeroUsize::new(1024 * 1024).unwrap(),
    )
    .unwrap();
    let response = transport
        .send(&WireRequest {
            method: Method::Get,
            path: node_wire::ordered_economics::ORDERED_ECONOMICS_STATUS_PATH.to_owned(),
            content_type: None,
            body: Vec::new(),
            deadline: None,
        })
        .unwrap();
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    node_core::ordered_economics::decode_ordered_status(&response.body).unwrap()
}

#[test]
fn prepared_host_loopback_query_survives_stop_and_reopen_with_a_strictly_newer_fence() {
    let built: Built = build();
    let state_db: PathBuf = built.directory.0.join("state.sqlite");
    let blob_db: PathBuf = built.directory.0.join("blob.sqlite");
    assert!(
        run_sqlite_genesis(prepare_args(&built, 0, &state_db, &blob_db))
            .status
            .success()
    );
    let key_file: PathBuf = built.directory.0.join("validator-0.key");
    fs::write(&key_file, built.network.validators[0].seed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let first: HostProcess = start_sqlite_source_host(&built, &state_db, &blob_db, &key_file, 0);
    assert_eq!(
        first.generation, 2,
        "the freshly prepared store closes at writer fence 1, so the first real claim is exactly generation 2"
    );
    let initial = query_status_over_loopback(first.address);
    assert_eq!(initial.committed_height, 0);
    drop(first);

    let second: HostProcess = start_sqlite_source_host(&built, &state_db, &blob_db, &key_file, 0);
    assert_eq!(
        second.generation, 3,
        "reopening a real process claims exactly the next writer fence"
    );
    let reopened_status = query_status_over_loopback(second.address);
    assert_eq!(
        reopened_status, initial,
        "the reopened host observes the same persisted ordered status"
    );
    drop(second);
}
