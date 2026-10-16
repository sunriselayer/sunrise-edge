//! Actual compiled import command over a genuinely frozen/drained SQLite source.
//! This is inactive installation evidence, not provider or activation acceptance.

#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[path = "support/encrypted_recovery_acceptance.rs"]
mod encrypted_recovery_acceptance;
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

fn floor_arguments(epoch: u64, height: u64, digest: &str) -> Vec<OsString> {
    vec![
        OsString::from("--history-floor-epoch"),
        OsString::from(epoch.to_string()),
        OsString::from("--history-floor-height"),
        OsString::from(height.to_string()),
        OsString::from("--history-floor-digest"),
        OsString::from(digest),
    ]
}

fn closure_pin_arguments(cut: &str, package: &str, plan: &str) -> Vec<OsString> {
    vec![
        OsString::from("--expected-cut-digest"),
        OsString::from(cut),
        OsString::from("--expected-package-digest"),
        OsString::from(package),
        OsString::from("--expected-plan-digest"),
        OsString::from(plan),
    ]
}

fn flipped_last_byte(digest: &str) -> String {
    let mut bytes: Vec<u8> = (0..digest.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&digest[index..index + 2], 16).unwrap())
        .collect();
    let last: usize = bytes.len() - 1;
    bytes[last] ^= 1;
    hex(&bytes)
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
    let expected_local_receipts: BTreeMap<
        runtime::portable::DurableRecordKey,
        protocol_types::Digest32,
    > = encrypted_recovery_acceptance::local_prepare_receipts(&before, &fixture.network.resolver);
    assert_eq!(expected_local_receipts.len(), 1);
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
    // Add encrypted relocation to THIS genuine frozen/drained producer, after
    // every existing inactive/refusal/replay oracle and before source returns.
    let recovery_directory: Directory = Directory::new("original-encrypted-relocation");
    encrypted_recovery_acceptance::relocate(encrypted_recovery_acceptance::Relocation {
        recovery: Path::new(env!("CARGO_BIN_EXE_business_recovery")),
        importer: Path::new(env!("CARGO_BIN_EXE_business_import")),
        pins: &pins,
        cut: &cut.0,
        predecessors: &[],
        genesis: &source_directory.0.join("genesis.bin"),
        unavailable_roots: std::slice::from_ref(&source_directory.0),
        work: &recovery_directory.0,
        binding: &binding_before,
        validator: ValidatorId::new([0xe8; 32]),
        expected_state: &BTreeMap::new(),
        expected_business: &before,
        expected_local_receipts: &expected_local_receipts,
    });
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

#[test]
fn compiled_import_history_floor_refuses_before_destination_and_accepts_authenticated_ancestor() {
    let mut fixture: Fixture = Fixture::new();
    fixture.freeze_and_complete();
    std::fs::write(
        fixture.directory.0.join("genesis.bin"),
        &fixture.network.manifest_bytes,
    )
    .unwrap();
    let (identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        fixture.history();
    assert!(
        identity.through_height >= 2,
        "fixture must distinguish an authenticated interior ancestor from the tip"
    );
    let history: Directory = Directory::new("floor-history-parent");
    let history_root: PathBuf = history.0.join("history");
    fixture.write_history(&history_root, &identity, &ordered);
    let pins: Vec<OsString> = pinned_arguments(&fixture, &identity, &history_root);
    let source_state: PathBuf = fixture.directory.0.join("state-0.sqlite");
    let source_blobs: PathBuf = fixture.directory.0.join("blobs.sqlite");
    let cut: Directory = Directory::new("floor-saved-cut");
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
    let original_history_files: BTreeMap<PathBuf, Option<Vec<u8>>> = history_files(&history_root);
    let incoming: ValidatorId = ValidatorId::new([0xF1; 32]);
    let source_paths: [&Path; 2] = [source_state.as_path(), source_blobs.as_path()];
    let destination: Directory = Directory::new("floor-import-destination");
    let state_file: PathBuf = destination.0.join("state.sqlite");
    let blob_file: PathBuf = destination.0.join("blobs.sqlite");
    let epoch: u64 = fixture.network.epoch.get();
    let tip_digest: String = hex(&identity.through_digest.bytes());
    let interior_digest: String = hex(&ordered[0].descriptor.block_digest.bytes());
    assert_eq!(ordered[0].descriptor.height, 1);
    assert_ne!(interior_digest, tip_digest);
    let zero_digest: String = hex(&[0u8; 32]);
    let mut flipped: [u8; 32] = identity.through_digest.bytes();
    flipped[31] ^= 1;
    let fork_digest: String = hex(&flipped);
    // Match the existing offline import control: close every source owner
    // before relocating the attachments. The signed pins remain available,
    // but none of the import calls can fall back to the live source paths.
    fixture.close_source_owners();
    std::fs::rename(
        &source_state,
        fixture
            .directory
            .0
            .join("offline-floor-source-state.sqlite"),
    )
    .unwrap();
    std::fs::rename(
        &source_blobs,
        fixture
            .directory
            .0
            .join("offline-floor-source-blobs.sqlite"),
    )
    .unwrap();
    assert_unavailable(source_paths);
    let negative_cases: [(u64, u64, &str, &str); 3] = [
        (
            epoch,
            identity.through_height.checked_add(1).unwrap(),
            zero_digest.as_str(),
            "below the independent history floor",
        ),
        (
            epoch,
            identity.through_height,
            fork_digest.as_str(),
            "does not extend the independent history floor block",
        ),
        (
            epoch.checked_add(1).unwrap(),
            1,
            interior_digest.as_str(),
            "history floor epoch differs from the verified current epoch",
        ),
    ];
    for (case_epoch, case_height, case_digest, expected_message) in negative_cases {
        let mut attempt: Command = command(
            &pins,
            &cut.0,
            &state_file,
            &blob_file,
            "create-sqlite",
            incoming,
            "4096",
        );
        attempt.args(floor_arguments(case_epoch, case_height, case_digest));
        let output: Output = offline_output(attempt, source_paths);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected_message),
            "unexpected stderr: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(!state_file.exists());
        assert!(!blob_file.exists());
        assert_eq!(files(&cut.0), original_files);
        assert!(history_files(&history_root) == original_history_files);
    }
    // A partial flag set refuses before any file access, same as a foreign epoch.
    let mut partial: Command = command(
        &pins,
        &cut.0,
        &state_file,
        &blob_file,
        "create-sqlite",
        incoming,
        "4096",
    );
    partial.args([
        OsString::from("--history-floor-epoch"),
        OsString::from(epoch.to_string()),
    ]);
    let partial_output: Output = offline_output(partial, source_paths);
    assert!(!partial_output.status.success());
    assert!(
        String::from_utf8_lossy(&partial_output.stderr)
            .contains("must be supplied together or not at all")
    );
    assert!(!state_file.exists());
    assert!(!blob_file.exists());
    // The exact authenticated tip is accepted.
    let mut accept_tip: Command = command(
        &pins,
        &cut.0,
        &state_file,
        &blob_file,
        "create-sqlite",
        incoming,
        "4096",
    );
    accept_tip.args(floor_arguments(epoch, identity.through_height, &tip_digest));
    let accepted: String = success(offline_output(accept_tip, source_paths));
    assert!(accepted.contains("business_import=complete-inactive"));
    // An interior authenticated ancestor is also accepted, on the completed destination.
    let mut accept_interior: Command = command(
        &pins,
        &cut.0,
        &state_file,
        &blob_file,
        "resume-sqlite",
        incoming,
        "4096",
    );
    accept_interior.args(floor_arguments(epoch, 1, &interior_digest));
    let resumed: String = success(offline_output(accept_interior, source_paths));
    assert!(resumed.contains("business_import=complete-inactive"));
    let state_before: Vec<u8> = std::fs::read(&state_file).unwrap();
    let blobs_before: Vec<u8> = std::fs::read(&blob_file).unwrap();
    // A mismatched floor on resume refuses and leaves the destination unchanged.
    let mut mismatched_resume: Command = command(
        &pins,
        &cut.0,
        &state_file,
        &blob_file,
        "resume-sqlite",
        incoming,
        "4096",
    );
    mismatched_resume.args(floor_arguments(
        epoch,
        identity.through_height,
        &zero_digest,
    ));
    let mismatched: Output = offline_output(mismatched_resume, source_paths);
    assert!(!mismatched.status.success());
    assert!(
        String::from_utf8_lossy(&mismatched.stderr)
            .contains("does not extend the independent history floor block")
    );
    assert_eq!(std::fs::read(&state_file).unwrap(), state_before);
    assert_eq!(std::fs::read(&blob_file).unwrap(), blobs_before);
    assert_eq!(files(&cut.0), original_files);
    assert!(history_files(&history_root) == original_history_files);
}

#[test]
fn compiled_import_closure_pins_refuse_before_destination_and_accept_exact_identity() {
    let mut fixture: Fixture = Fixture::new();
    fixture.freeze_and_complete();
    std::fs::write(
        fixture.directory.0.join("genesis.bin"),
        &fixture.network.manifest_bytes,
    )
    .unwrap();
    let (identity, ordered): (OrderedHistoryIdentity, Vec<OrderedHistoryHeightMaterial>) =
        fixture.history();
    let history: Directory = Directory::new("closure-pin-history-parent");
    let history_root: PathBuf = history.0.join("history");
    fixture.write_history(&history_root, &identity, &ordered);
    let pins: Vec<OsString> = pinned_arguments(&fixture, &identity, &history_root);
    let source_state: PathBuf = fixture.directory.0.join("state-0.sqlite");
    let source_blobs: PathBuf = fixture.directory.0.join("blobs.sqlite");
    let cut: Directory = Directory::new("closure-pin-saved-cut");
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
    let original_history_files: BTreeMap<PathBuf, Option<Vec<u8>>> = history_files(&history_root);
    // Close every source owner, same as the other offline import controls:
    // the independently retained pins below never come from these sources.
    fixture.close_source_owners();
    std::fs::rename(
        &source_state,
        fixture
            .directory
            .0
            .join("offline-closure-pin-source-state.sqlite"),
    )
    .unwrap();
    std::fs::rename(
        &source_blobs,
        fixture
            .directory
            .0
            .join("offline-closure-pin-source-blobs.sqlite"),
    )
    .unwrap();
    let source_paths: [&Path; 2] = [source_state.as_path(), source_blobs.as_path()];
    assert_unavailable(source_paths);

    // Establish the independently retained pins from a genuinely separate,
    // unpinned, earlier-completed run against another fresh destination.
    let unpinned_validator: ValidatorId = ValidatorId::new([0xF4; 32]);
    let unpinned_destination: Directory = Directory::new("closure-pin-unpinned-destination");
    let unpinned_state: PathBuf = unpinned_destination.0.join("state.sqlite");
    let unpinned_blobs: PathBuf = unpinned_destination.0.join("blobs.sqlite");
    let unpinned: String = success(offline_output(
        command(
            &pins,
            &cut.0,
            &unpinned_state,
            &unpinned_blobs,
            "create-sqlite",
            unpinned_validator,
            "4096",
        ),
        source_paths,
    ));
    assert!(unpinned.contains("business_import=complete-inactive"));
    let unpinned_fields: Vec<&str> = identity_fields(&unpinned);
    let cut_digest: String = unpinned_fields[0].strip_prefix("cut=").unwrap().to_string();
    let package_digest: String = unpinned_fields[1]
        .strip_prefix("package=")
        .unwrap()
        .to_string();
    let plan_digest: String = unpinned_fields[2]
        .strip_prefix("plan=")
        .unwrap()
        .to_string();

    let pinned_validator: ValidatorId = ValidatorId::new([0xF5; 32]);
    let failure_destination: Directory = Directory::new("closure-pin-failure-destination");
    let failure_state: PathBuf = failure_destination.0.join("state.sqlite");
    let failure_blobs: PathBuf = failure_destination.0.join("blobs.sqlite");

    // A strict subset of the three flags refuses before any destination file,
    // the same as a missing flag entirely.
    let subsets: Vec<Vec<OsString>> = vec![
        vec![
            OsString::from("--expected-cut-digest"),
            OsString::from(cut_digest.clone()),
        ],
        vec![
            OsString::from("--expected-package-digest"),
            OsString::from(package_digest.clone()),
        ],
        vec![
            OsString::from("--expected-cut-digest"),
            OsString::from(cut_digest.clone()),
            OsString::from("--expected-package-digest"),
            OsString::from(package_digest.clone()),
        ],
    ];
    for subset in subsets {
        let mut attempt: Command = command(
            &pins,
            &cut.0,
            &failure_state,
            &failure_blobs,
            "create-sqlite",
            pinned_validator,
            "4096",
        );
        attempt.args(subset);
        let output: Output = offline_output(attempt, source_paths);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("must be supplied together or not at all")
        );
        assert_unavailable([failure_state.as_path(), failure_blobs.as_path()]);
    }
    assert_eq!(files(&cut.0), original_files);
    assert!(history_files(&history_root) == original_history_files);

    // Exactly one flipped final byte in each of the three pins, in turn, must
    // reach the new comparison and refuse before any fresh destination file.
    let flipped_cut: String = flipped_last_byte(&cut_digest);
    let flipped_package: String = flipped_last_byte(&package_digest);
    let flipped_plan: String = flipped_last_byte(&plan_digest);
    let mismatches: [(&str, &str, &str); 3] = [
        (
            flipped_cut.as_str(),
            package_digest.as_str(),
            plan_digest.as_str(),
        ),
        (
            cut_digest.as_str(),
            flipped_package.as_str(),
            plan_digest.as_str(),
        ),
        (
            cut_digest.as_str(),
            package_digest.as_str(),
            flipped_plan.as_str(),
        ),
    ];
    for (bad_cut, bad_package, bad_plan) in mismatches {
        let mut attempt: Command = command(
            &pins,
            &cut.0,
            &failure_state,
            &failure_blobs,
            "create-sqlite",
            pinned_validator,
            "4096",
        );
        attempt.args(closure_pin_arguments(bad_cut, bad_package, bad_plan));
        let output: Output = offline_output(attempt, source_paths);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(
                "verified closure identity does not match the independently retained cut/package/plan digest pins"
            ),
            "unexpected stderr: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        assert_unavailable([failure_state.as_path(), failure_blobs.as_path()]);
    }
    assert_eq!(files(&cut.0), original_files);
    assert!(history_files(&history_root) == original_history_files);

    // Exact pins taken from the earlier independent run reach CompleteInactive
    // on a genuinely fresh destination, with the same reported identities.
    let destination: Directory = Directory::new("closure-pin-destination");
    let state_file: PathBuf = destination.0.join("state.sqlite");
    let blob_file: PathBuf = destination.0.join("blobs.sqlite");
    let mut accept: Command = command(
        &pins,
        &cut.0,
        &state_file,
        &blob_file,
        "create-sqlite",
        pinned_validator,
        "4096",
    );
    accept.args(closure_pin_arguments(
        &cut_digest,
        &package_digest,
        &plan_digest,
    ));
    let accepted: String = success(offline_output(accept, source_paths));
    assert!(accepted.contains("business_import=complete-inactive"));
    assert_eq!(identity_fields(&unpinned), identity_fields(&accepted));

    let namespace: SqliteNamespace = SqliteNamespace::new(
        fixture.network.chain_id.clone(),
        pinned_validator,
        fixture.network.domain,
    );
    let complete_residue = |state: &Path| -> (ImportBinding, PortableSnapshotToken) {
        let residue: SqliteDurableStore =
            SqliteDurableStore::open_historical(state, namespace.clone()).unwrap();
        let own_writer: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
        assert_eq!(residue.writer_fence().unwrap(), own_writer);
        let context: DurableOperationContext = observation_context(own_writer);
        let lifecycle: NamespaceLifecycle = residue
            .get_namespace_lifecycle(&context, namespace.domain())
            .unwrap();
        let NamespaceLifecycle::CompleteInactive { binding, .. } = lifecycle else {
            panic!("exact closure pins must retain the completed inactive import origin");
        };
        let token: PortableSnapshotToken = residue
            .begin_portable_snapshot(&context, namespace.domain())
            .unwrap();
        (binding, token)
    };
    let (binding_before, token_before): (ImportBinding, PortableSnapshotToken) =
        complete_residue(&state_file);

    // A wrong resume plan pin refuses and leaves the existing destination
    // contents, inner resume binding and portable token unchanged.
    let state_before: Vec<u8> = std::fs::read(&state_file).unwrap();
    let blobs_before: Vec<u8> = std::fs::read(&blob_file).unwrap();
    let mut wrong_resume: Command = command(
        &pins,
        &cut.0,
        &state_file,
        &blob_file,
        "resume-sqlite",
        pinned_validator,
        "4096",
    );
    wrong_resume.args(closure_pin_arguments(
        &cut_digest,
        &package_digest,
        &flipped_plan,
    ));
    let wrong: Output = offline_output(wrong_resume, source_paths);
    assert!(!wrong.status.success());
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains(
            "verified closure identity does not match the independently retained cut/package/plan digest pins"
        )
    );
    assert_eq!(std::fs::read(&state_file).unwrap(), state_before);
    assert_eq!(std::fs::read(&blob_file).unwrap(), blobs_before);
    let (binding_after, token_after): (ImportBinding, PortableSnapshotToken) =
        complete_residue(&state_file);
    assert_eq!(binding_after, binding_before);
    assert_eq!(token_after, token_before);

    // Resume with the exact pins succeeds, and the inner existing full-binding
    // resume check still enforces agreement; no new batches are installed.
    let mut exact_resume: Command = command(
        &pins,
        &cut.0,
        &state_file,
        &blob_file,
        "resume-sqlite",
        pinned_validator,
        "4096",
    );
    exact_resume.args(closure_pin_arguments(
        &cut_digest,
        &package_digest,
        &plan_digest,
    ));
    let resumed: String = success(offline_output(exact_resume, source_paths));
    assert!(resumed.contains("business_import=complete-inactive"));
    assert!(resumed.contains("new_batches=0"));
    assert_eq!(identity_fields(&accepted), identity_fields(&resumed));
    let (binding_final, token_final): (ImportBinding, PortableSnapshotToken) =
        complete_residue(&state_file);
    assert_eq!(binding_final, binding_before);
    assert_eq!(token_final, token_before);

    assert_eq!(
        files(&cut.0),
        original_files,
        "closure-pin controls never rewrite the saved cut"
    );
    assert!(
        history_files(&history_root) == original_history_files,
        "closure-pin controls preserve all original history files and directories"
    );
    assert_unavailable(source_paths);
}
