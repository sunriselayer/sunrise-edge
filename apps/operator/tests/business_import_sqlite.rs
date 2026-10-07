//! Actual compiled import command over a genuinely frozen/drained SQLite source.
//! This is inactive installation evidence, not provider or activation acceptance.

#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "business_cut/fixture.rs"]
mod fixture;
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;

use fixture::{Directory, Fixture, copy_files, files};
use node_core::business_reconstruction::cut::{BusinessCutIdentity, decode_business_cut_identity};
use node_core::business_reconstruction::{BusinessReconstructionPlan, SourceBusinessSnapshot};
use node_core::ordered_economics::{OrderedHistoryHeightMaterial, OrderedHistoryIdentity};
use protocol_types::ValidatorId;
use runtime::portable::{
    DurableCollection, DurablePortableSnapshotRepository, DurableRecordPage, DurableRecordScan,
    PortableSnapshotToken,
};
use runtime::{
    Clock, DurableDomainStateStore, DurableOperationContext, ImportBinding, NamespaceLifecycle,
    StorageCorrelationId, StorageDeadline, SystemClock, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteDurableStore, SqliteDurableStoreError, SqliteNamespace};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use sunrise_edge_operator::{
    business_snapshot::capture_source_business_snapshot, source_sqlite::ExistingSqliteSource,
};

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

fn pinned_arguments(
    fixture: &Fixture,
    identity: &OrderedHistoryIdentity,
    history: &Path,
) -> Vec<OsString> {
    let plan: BusinessReconstructionPlan<'_> = fixture.plan(identity, fixture.operation);
    let context: &execution::publication::PublicationContext = plan.genesis_root.genesis_context();
    let mut arguments: Vec<OsString> = [
        "--chain-id",
        context.chain_id().as_str(),
        "--protocol-version",
        &context.protocol_version().get().to_string(),
        "--epoch",
        &context.epoch().get().to_string(),
        "--domain",
        &hex(plan.domain.as_bytes()),
        "--genesis-manifest",
        fixture.directory.0.join("genesis.bin").to_str().unwrap(),
        "--expected-genesis-digest",
        &hex(&plan.genesis_root.digest().bytes()),
        "--ordered-history-dir",
        history.to_str().unwrap(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    for schedule in plan.genesis_root.genesis_resolver().schedules() {
        arguments.push(OsString::from("--suite"));
        arguments.push(OsString::from(format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            schedule.activation_epoch.get(),
            schedule.suite.id.get(),
            schedule.suite.transaction_hash.as_u16(),
            schedule.suite.object_digest.as_u16(),
            schedule.suite.effects_hash.as_u16(),
            schedule.suite.code_hash.as_u16(),
            schedule.suite.config_hash.as_u16(),
            schedule.suite.certificate_hash.as_u16(),
        )));
    }
    arguments
}

fn cut_command(pins: &[OsString], cut: &Path, mode: &str) -> Command {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_business_cut"));
    command
        .arg(mode)
        .args(pins)
        .args(["--out-dir", cut.to_str().unwrap()]);
    command
}

fn command(
    pins: &[OsString],
    cut: &Path,
    state: &Path,
    blobs: &Path,
    mode: &str,
    validator: ValidatorId,
    maximum_batches: &str,
) -> Command {
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_business_import"));
    command.arg(mode).args(pins).args([
        "--cut-dir",
        cut.to_str().unwrap(),
        "--state-db",
        state.to_str().unwrap(),
        "--blob-db",
        blobs.to_str().unwrap(),
        "--validator-id",
        &hex(validator.as_bytes()),
        "--max-new-batches",
        maximum_batches,
        "--timeout-seconds",
        "300",
    ]);
    command
}

fn assert_unavailable(paths: [&Path; 2]) {
    for path in paths {
        assert!(
            matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "offline command recreated a source attachment: {}",
            path.display(),
        );
    }
}

fn offline_output(mut command: Command, source_paths: [&Path; 2]) -> Output {
    assert_unavailable(source_paths);
    let output: Output = command.output().unwrap();
    assert_unavailable(source_paths);
    output
}

fn observation_context(writer_fence: WriterFenceGeneration) -> DurableOperationContext {
    let deadline: u64 = SystemClock
        .now_unix_millis()
        .unwrap()
        .checked_add(300_000)
        .unwrap();
    DurableOperationContext::new(
        writer_fence,
        StorageDeadline::new(deadline).unwrap(),
        StorageCorrelationId::new([0xBD; 16]).unwrap(),
    )
}

fn inspect_fresh_residue(
    state: &Path,
    namespace: &SqliteNamespace,
) -> (ImportBinding, PortableSnapshotToken) {
    let residue: SqliteDurableStore =
        SqliteDurableStore::open_historical(state, namespace.clone()).unwrap();
    let own_writer: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    assert_eq!(residue.writer_fence().unwrap(), own_writer);
    let context: DurableOperationContext = observation_context(own_writer);
    let lifecycle: NamespaceLifecycle = residue
        .get_namespace_lifecycle(&context, namespace.domain())
        .unwrap();
    let NamespaceLifecycle::FreshImport(binding) = lifecycle else {
        panic!("second-file failure must retain only fresh inactive import origin");
    };
    let token: PortableSnapshotToken = residue
        .begin_portable_snapshot(&context, namespace.domain())
        .unwrap();
    assert_eq!(token.mutation_sequence(), 0);
    for collection in [
        DurableCollection::State,
        DurableCollection::Receipts,
        DurableCollection::ObjectHeads,
        DurableCollection::ObjectVersions,
    ] {
        let scan: DurableRecordScan =
            DurableRecordScan::new(collection, None, NonZeroUsize::new(128).unwrap()).unwrap();
        let page: DurableRecordPage = residue
            .scan_portable_keys_at(&context, namespace.domain(), &token, &scan)
            .unwrap();
        assert!(
            page.keys().is_empty(),
            "failed creation installed business rows"
        );
        assert!(page.continuation().is_none());
    }
    residue
        .check_portable_outbox_empty_at(&context, namespace.domain(), &token)
        .unwrap();
    (binding, token)
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
    let (identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        fixture.history();
    let before: SourceBusinessSnapshot = fixture.snapshot();
    let history: Directory = Directory::new("import-history-parent");
    let history_root: PathBuf = history.0.join("history");
    fixture.write_history(&history_root, &identity, &ordered);
    let pins: Vec<OsString> = pinned_arguments(&fixture, &identity, &history_root);
    let source_state: PathBuf = fixture.directory.0.join("state-0.sqlite");
    let source_blobs: PathBuf = fixture.directory.0.join("blobs.sqlite");
    let cut: Directory = Directory::new("import-saved-cut");
    let mut export: Command = cut_command(&pins, &cut.0, "export-sqlite");
    export.args([
        "--state-db",
        source_state.to_str().unwrap(),
        "--blob-db",
        source_blobs.to_str().unwrap(),
        "--validator-id",
        &hex(fixture.network.validators[0].validator_id.as_bytes()),
        "--page-size",
        "128",
        "--chunk-size",
        "1048576",
        "--max-new-work",
        "4096",
        "--timeout-seconds",
        "300",
    ]);
    assert!(
        success(export.output().unwrap()).contains("business_cut=complete"),
        "the actual compiled exporter must produce the saved cut",
    );
    let original_files: BTreeMap<String, Vec<u8>> = files(&cut.0);
    let saved_identity: BusinessCutIdentity =
        decode_business_cut_identity(&original_files["identity.bin"]).unwrap();
    let original_history_files: BTreeMap<PathBuf, Option<Vec<u8>>> = history_files(&history_root);
    let incoming: ValidatorId = ValidatorId::new([0xE7; 32]);
    assert!(
        fixture.policy.registered_validator(incoming).is_none(),
        "a namespace identifier is not eligibility proof"
    );
    // Keep the actual signed pins and directory, but close EVERY SQLite owner
    // before moving either attachment. No independent SQLite leaf is opened.
    let Fixture {
        network,
        directory: source_directory,
        stores,
        blobs,
        ..
    } = fixture;
    drop(stores);
    drop(blobs);
    let hidden_state: PathBuf = source_directory.0.join("offline-source-state.sqlite");
    let hidden_blobs: PathBuf = source_directory.0.join("offline-source-blobs.sqlite");
    std::fs::rename(&source_state, &hidden_state).unwrap();
    std::fs::rename(&source_blobs, &hidden_blobs).unwrap();
    let source_paths: [&Path; 2] = [source_state.as_path(), source_blobs.as_path()];
    assert!(
        success(offline_output(
            cut_command(&pins, &cut.0, "verify-saved"),
            source_paths,
        ))
        .contains("business_cut=independently-verified"),
    );
    assert_eq!(files(&cut.0), original_files);
    let destination: Directory = Directory::new("import-destination");
    let state_file: PathBuf = destination.0.join("state.sqlite");
    let blob_file: PathBuf = destination.0.join("blobs.sqlite");
    let invalid: Output = offline_output(
        command(
            &pins,
            &cut.0,
            &state_file,
            &blob_file,
            "create-sqlite",
            incoming,
            "0",
        ),
        source_paths,
    );
    assert!(!invalid.status.success());
    assert!(!destination.0.join("state.sqlite").exists());
    assert!(!destination.0.join("blobs.sqlite").exists());
    for input_root in [&cut.0, &history_root] {
        for mode in ["create-sqlite", "resume-sqlite"] {
            for (flag, filename) in [
                ("--state-db", "state.sqlite"),
                ("--blob-db", "blobs.sqlite"),
            ] {
                let original: Command =
                    command(&pins, &cut.0, &state_file, &blob_file, mode, incoming, "1");
                let mut arguments: Vec<OsString> =
                    original.get_args().map(OsString::from).collect();
                let position: usize = arguments.iter().position(|value| value == flag).unwrap();
                arguments[position + 1] = input_root.join(filename).into_os_string();
                let mut misplaced_command: Command =
                    Command::new(env!("CARGO_BIN_EXE_business_import"));
                misplaced_command.args(arguments);
                let misplaced: Output = offline_output(misplaced_command, source_paths);
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
    let corrupt: Output = offline_output(
        command(
            &pins,
            &corrupt_cut.0,
            &state_file,
            &blob_file,
            "create-sqlite",
            incoming,
            "1",
        ),
        source_paths,
    );
    assert!(
        !corrupt.status.success(),
        "an altered saved identity is not an import capability"
    );
    assert!(!destination.0.join("state.sqlite").exists());
    assert!(!destination.0.join("blobs.sqlite").exists());
    // Both targets start absent. The first factory creates its own active WAL,
    // so the second file reservation fails before acquiring a blob descriptor.
    let failure: Directory = Directory::new("import-second-file-failure");
    let failed_state: PathBuf = failure.0.join("state.sqlite");
    let colliding_body: PathBuf = failure.0.join("state.sqlite-wal");
    assert_unavailable([failed_state.as_path(), colliding_body.as_path()]);
    let failed_validator: ValidatorId = network.validators[0].validator_id;
    let failed: Output = offline_output(
        command(
            &pins,
            &cut.0,
            &failed_state,
            &colliding_body,
            "create-sqlite",
            failed_validator,
            "1",
        ),
        source_paths,
    );
    assert!(!failed.status.success());
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("SQLite blob file operation failed:"),
        "second-file reservation must actually fail after state creation: {}",
        String::from_utf8_lossy(&failed.stderr),
    );
    assert!(failed_state.is_file());
    let failed_namespace: SqliteNamespace =
        SqliteNamespace::new(network.chain_id.clone(), failed_validator, network.domain);
    let (binding_before, residue_before): (ImportBinding, PortableSnapshotToken) =
        inspect_fresh_residue(&failed_state, &failed_namespace);
    assert_eq!(
        binding_before.generation_floor,
        saved_identity.generation_floor
    );
    assert_ne!(
        residue_before.namespace(),
        before.token.namespace(),
        "even the same logical namespace receives a fresh destination source-instance identity",
    );
    assert!(matches!(
        SqliteDurableStore::open_existing(&failed_state, failed_namespace.clone()),
        Err(SqliteDurableStoreError::InactiveNamespace),
    ));
    // Never reopen the WAL collision as a blob: historical state inspection
    // can legitimately recreate that active sidecar. Use another absent path.
    let missing_body: PathBuf = failure.0.join("missing-body.sqlite");
    assert!(matches!(
        std::fs::symlink_metadata(&missing_body),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound,
    ));
    let missing: Output = offline_output(
        command(
            &pins,
            &cut.0,
            &failed_state,
            &missing_body,
            "resume-sqlite",
            failed_validator,
            "1",
        ),
        source_paths,
    );
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("SQLite blob file operation failed:"),
        "resume must actually refuse the missing body attachment: {}",
        String::from_utf8_lossy(&missing.stderr),
    );
    assert!(matches!(
        std::fs::symlink_metadata(&missing_body),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound,
    ));
    let (binding_after, residue_after): (ImportBinding, PortableSnapshotToken) =
        inspect_fresh_residue(&failed_state, &failed_namespace);
    assert_eq!(binding_after, binding_before);
    assert_eq!(residue_after, residue_before);
    assert_eq!(files(&cut.0), original_files);
    assert!(history_files(&history_root) == original_history_files);
    let first: String = success(offline_output(
        command(
            &pins,
            &cut.0,
            &state_file,
            &blob_file,
            "create-sqlite",
            incoming,
            "1",
        ),
        source_paths,
    ));
    eprintln!("compiled import first result: {first}");
    assert!(
        first.contains("business_import=partial")
            || first.contains("business_import=complete-inactive")
    );
    assert!(!first.contains("business_import=active"));
    let namespace: SqliteNamespace =
        SqliteNamespace::new(network.chain_id.clone(), incoming, network.domain);
    assert!(
        SqliteDurableStore::open_existing(destination.0.join("state.sqlite"), namespace.clone())
            .is_err()
    );
    let complete: String = success(offline_output(
        command(
            &pins,
            &cut.0,
            &state_file,
            &blob_file,
            "resume-sqlite",
            incoming,
            "4096",
        ),
        source_paths,
    ));
    assert!(complete.contains("business_import=complete-inactive"));
    assert_eq!(identity_fields(&first), identity_fields(&complete));
    let replay: String = success(offline_output(
        command(
            &pins,
            &cut.0,
            &state_file,
            &blob_file,
            "resume-sqlite",
            incoming,
            "1",
        ),
        source_paths,
    ));
    assert!(replay.contains("business_import=complete-inactive"));
    assert!(replay.contains("new_batches=0"));
    assert_eq!(identity_fields(&complete), identity_fields(&replay));
    {
        let installed: SqliteDurableStore =
            SqliteDurableStore::open_historical(&state_file, namespace.clone()).unwrap();
        let own_writer: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        assert_eq!(installed.writer_fence().unwrap(), own_writer);
        let context: DurableOperationContext = observation_context(own_writer);
        let lifecycle: NamespaceLifecycle = installed
            .get_namespace_lifecycle(&context, namespace.domain())
            .unwrap();
        let NamespaceLifecycle::CompleteInactive { binding, .. } = lifecycle else {
            panic!("compiled import and replay must retain the inactive installation origin");
        };
        assert_eq!(binding, binding_before);
    }
    assert!(matches!(
        SqliteDurableStore::open_existing(&state_file, namespace),
        Err(SqliteDurableStoreError::InactiveNamespace),
    ));
    assert_eq!(
        files(&cut.0),
        original_files,
        "import never rewrites the saved cut"
    );
    assert!(
        history_files(&history_root) == original_history_files,
        "successful import and resume preserve all original history files and directories"
    );
    assert_unavailable(source_paths);
    assert_eq!(
        std::fs::read(source_directory.0.join("genesis.bin")).unwrap(),
        network.manifest_bytes,
        "the independently retained signed genesis pin is never rewritten",
    );
    // The entire source-free sequence is over before either attachment returns.
    std::fs::rename(&hidden_state, &source_state).unwrap();
    std::fs::rename(&hidden_blobs, &source_blobs).unwrap();
    let source: ExistingSqliteSource = ExistingSqliteSource::open(
        &source_state,
        &source_blobs,
        network.chain_id.clone(),
        network.validators[0].validator_id,
        network.domain,
        300,
    )
    .unwrap();
    let after: SourceBusinessSnapshot = capture_source_business_snapshot(
        &source.durable,
        &source.blobs,
        &source.operation,
        network.domain,
        NonZeroUsize::new(128).unwrap(),
    )
    .unwrap();
    assert_eq!(after, before, "import never writes or fences its source");
}
