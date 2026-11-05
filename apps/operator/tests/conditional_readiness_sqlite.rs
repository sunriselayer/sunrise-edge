//! Compiled local readiness over a genuinely frozen/drained SQLite source.
//! Distinct cases retain the original committee and register E before a real
//! A/B/C/E handoff. No original fixture is relabelled as membership-change proof.
#[path = "support/acceptance_timing.rs"]
mod acceptance_timing;
#[path = "support/causal_genesis_fixture.rs"]
mod causal_genesis_fixture;
#[path = "support/command_output.rs"]
mod command_output;
#[path = "support/compiled_executable_snapshot.rs"]
mod compiled_executable_snapshot;
#[path = "support/compiled_source_host_process.rs"]
mod compiled_source_host_process;
#[path = "support/encrypted_recovery_acceptance.rs"]
mod encrypted_recovery_acceptance;
#[path = "business_cut/fixture.rs"]
mod fixture;
#[path = "support/genesis_fixture.rs"]
pub mod genesis_fixture;
#[path = "support/hex.rs"]
mod hex;
#[path = "support/ordered_seal_sqlite_acceptance.rs"]
mod ordered_seal_sqlite_acceptance;
#[path = "support/successor_host_acceptance.rs"]
mod successor_host_acceptance;

use command_output::success;
use compiled_executable_snapshot::CompiledExecutableSnapshot;
use consensus::readiness::{
    ReadinessCertificate, ReadinessCertifier, ReadinessVote, decode_readiness_certificate,
    decode_readiness_vote,
};
use fixture::{Directory, Fixture, copy_files, files};
use hex::hex;
use node_core::business_reconstruction::{
    SourceBusinessSnapshot,
    cut::{
        BUSINESS_CUT_STREAMS, BusinessCutChunk, BusinessCutPage, SavedBusinessCut,
        SavedBusinessCutComponent, VerifiedBusinessCut,
    },
    inactive_import::verify_saved_business_import,
};
use protocol_types::ValidatorId;
use runtime::portable::DurablePortableSnapshotRepository;
use runtime::{
    BlobStore, InactiveImportRepository, ReadinessRetentionRepository, ReadinessSlot,
    ReadinessSlotObservation,
};
use runtime_sqlite::{SqliteImportTarget, SqliteNamespace};
use std::{
    collections::BTreeMap,
    io::Read,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
use sunrise_edge_client::immutable_archive::ARCHIVE_STAGING_DIRECTORY;
use sunrise_edge_operator::{
    business_cut::{CutArchiveLimits, export_source_business_cut, verify_business_cut_archive},
    business_snapshot::capture_source_business_snapshot,
    immutable_archive::ImmutableArchive,
};
use validator_set::{ValidatorInfo, ValidatorSet, encode_validator_set};

/// Assemble public paginated transport from a genuinely verified archive;
/// private import verification must still reconstruct it independently.
fn public_transfer(
    cut: &VerifiedBusinessCut,
    resolver: &hashing::HashSuiteResolver,
) -> SavedBusinessCut {
    let mut saved: SavedBusinessCut = SavedBusinessCut {
        identity: cut.identity().clone(),
        package: cut.package_identity().clone(),
        components: Vec::new(),
    };
    for collection in BUSINESS_CUT_STREAMS {
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page: BusinessCutPage = cut
                .read_page(
                    resolver,
                    collection,
                    after.as_deref(),
                    NonZeroUsize::new(128).unwrap(),
                )
                .unwrap();
            for descriptor in page.descriptors {
                let mut bytes: Vec<u8> = Vec::new();
                let mut offset: u64 = 0;
                loop {
                    let chunk: BusinessCutChunk = cut
                        .read_chunk(&descriptor, offset, NonZeroUsize::new(1048576).unwrap())
                        .unwrap();
                    offset = offset
                        .checked_add(u64::try_from(chunk.bytes.len()).unwrap())
                        .unwrap();
                    bytes.extend_from_slice(&chunk.bytes);
                    if offset == descriptor.length {
                        break;
                    }
                }
                after = Some(descriptor.key.clone());
                saved
                    .components
                    .push(SavedBusinessCutComponent { descriptor, bytes });
            }
            if page.terminal {
                break;
            }
        }
    }
    saved
}
fn pins(command: &mut Command, fixture: &Fixture, history: &Path, cut: &Path) {
    command.args([
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
    ]);
}
#[allow(clippy::too_many_arguments)]
fn voting(
    executables: &CompiledExecutableSnapshot,
    fixture: &Fixture,
    history: &Path,
    cut: &Path,
    next: &Path,
    destination: &Path,
    output: &Path,
    validator: ValidatorId,
    key: &Path,
) -> Command {
    let mut command: Command = Command::new(&executables.conditional_readiness);
    command.arg("vote-sqlite");
    pins(&mut command, fixture, history, cut);
    command.args([
        "--next-set",
        next.to_str().unwrap(),
        "--out-dir",
        output.to_str().unwrap(),
        "--state-db",
        destination.join("state.db").to_str().unwrap(),
        "--blob-db",
        destination.join("body.db").to_str().unwrap(),
        "--validator-id",
        &hex(validator.as_bytes()),
        "--signer-key-file",
        key.to_str().unwrap(),
    ]);
    command
}

#[cfg(target_os = "linux")]
fn readiness_multiuid_enabled() -> bool {
    if std::env::var_os("SUNRISE_READINESS_MULTIUID_FIXTURE").is_none() {
        return false;
    }
    assert!(
        Path::new("/.dockerenv").exists(),
        "multi-UID fixture requires its bounded container"
    );
    let status: String = std::fs::read_to_string("/proc/self/status").unwrap();
    let effective: u32 = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")?
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()
        })
        .unwrap();
    assert_eq!(
        effective, 0,
        "multi-UID fixture requires root inside its container"
    );
    true
}

#[cfg(target_os = "linux")]
fn change_owner(path: &Path, uid: u32) {
    let output: Output = Command::new("chown")
        .arg(format!("{uid}:0"))
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture chown failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
fn write_private(path: &Path, uid: u32, contents: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    change_owner(path, uid);
}

#[cfg(target_os = "linux")]
fn wait_bounded(mut child: Child, limit: Duration) -> Output {
    let end: Instant = Instant::now().checked_add(limit).unwrap();
    while Instant::now() < end {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.kill().unwrap();
    let output: Output = child.wait_with_output().unwrap();
    panic!(
        "bounded readiness child exceeded {limit:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
struct OwnedWorker(Option<Child>);

#[cfg(target_os = "linux")]
impl OwnedWorker {
    fn child(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }

    fn take(&mut self) -> Child {
        self.0.take().unwrap()
    }
}

#[cfg(target_os = "linux")]
impl Drop for OwnedWorker {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn protected_vote(
    executables: &CompiledExecutableSnapshot,
    fixture: &Fixture,
    history: &Path,
    cut: &Path,
    next: &Path,
    destination: &Path,
    output: &Path,
    validator: ValidatorId,
    key: &Path,
    lost_first: bool,
) {
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};
    const WORKER_UID: u32 = 10_001;
    const FRONTEND_UID: u32 = 10_002;
    let mut public: Command = Command::new(&executables.conditional_readiness);
    pins(&mut public, fixture, history, cut);
    public.arg("--next-set").arg(next);
    let args: Vec<String> = public
        .get_args()
        .map(|arg| arg.to_str().unwrap().to_owned())
        .collect();
    let mut common: String = String::new();
    for pair in args.chunks_exact(2) {
        common.push_str(pair[0].trim_start_matches("--"));
        common.push('=');
        common.push_str(&pair[1]);
        common.push('\n');
    }
    let socket_dir: Directory = Directory::new("readiness-socket");
    std::fs::set_permissions(&socket_dir.0, std::fs::Permissions::from_mode(0o750)).unwrap();
    change_owner(&socket_dir.0, WORKER_UID);
    let socket: PathBuf = socket_dir.0.join("readiness.sock");
    let worker_dir: Directory = Directory::new("readiness-worker-config");
    std::fs::set_permissions(&worker_dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    change_owner(&worker_dir.0, WORKER_UID);
    let worker_config: PathBuf = worker_dir.0.join("config");
    let frontend_dir: Directory = Directory::new("readiness-frontend-config");
    std::fs::set_permissions(&frontend_dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    change_owner(&frontend_dir.0, FRONTEND_UID);
    let frontend_config: PathBuf = frontend_dir.0.join("config");
    for entry in std::fs::read_dir(destination).unwrap() {
        let path: PathBuf = entry.unwrap().path();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        change_owner(&path, WORKER_UID);
    }
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700)).unwrap();
    change_owner(destination, WORKER_UID);
    std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700)).unwrap();
    change_owner(output, FRONTEND_UID);
    // The preceding ordinary invalid-artifact refusal opened this archive as
    // root and left its empty staging role. Transfer that existing role too;
    // changing only the archive root would make frontend publication fail.
    for entry in std::fs::read_dir(output).unwrap() {
        let path: PathBuf = entry.unwrap().path();
        assert_eq!(path.file_name().unwrap(), ARCHIVE_STAGING_DIRECTORY);
        assert!(std::fs::symlink_metadata(&path).unwrap().is_dir());
        change_owner(&path, FRONTEND_UID);
    }
    let worker_contents: String = format!(
        "{common}socket={}\nfrontend-uid={FRONTEND_UID}\nmax-connections=3\nmax-requests=1\ntotal-deadline-seconds=300\ntimeout-seconds=270\nstate-db={}\nblob-db={}\nvalidator-id={}\nsigner-key-file={}\n",
        socket.display(),
        destination.join("state.db").display(),
        destination.join("body.db").display(),
        hex(validator.as_bytes()),
        key.display(),
    );
    let frontend_contents: String = format!(
        "{common}socket={}\nworker-uid={WORKER_UID}\ntotal-deadline-seconds=300\nvalidator-id={}\nout-dir={}\n",
        socket.display(),
        hex(validator.as_bytes()),
        output.display(),
    );
    write_private(&worker_config, WORKER_UID, &worker_contents);
    write_private(&frontend_config, FRONTEND_UID, &frontend_contents);
    let wrong_key: PathBuf = destination.join("wrong.key");
    std::fs::write(&wrong_key, [0xE5; 32]).unwrap();
    std::fs::set_permissions(&wrong_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    change_owner(&wrong_key, WORKER_UID);
    let wrong_config: PathBuf = worker_dir.0.join("wrong-config");
    let wrong_contents: String = worker_contents.replace(
        &format!("signer-key-file={}\n", key.display()),
        &format!("signer-key-file={}\n", wrong_key.display()),
    );
    assert_ne!(wrong_contents, worker_contents);
    write_private(&wrong_config, WORKER_UID, &wrong_contents);
    let restored_key: PathBuf = worker_dir.0.join("restored.key");
    let restored_config: PathBuf = worker_dir.0.join("restored-config");
    let restored_contents: String = worker_contents.replace(
        &format!("signer-key-file={}\n", key.display()),
        &format!("signer-key-file={}\n", restored_key.display()),
    );
    assert_ne!(restored_contents, worker_contents);
    assert_eq!(
        restored_contents.replace(
            &format!("signer-key-file={}\n", restored_key.display()),
            &format!("signer-key-file={}\n", key.display()),
        ),
        worker_contents,
        "restored worker config changed more than the key path"
    );
    write_private(&restored_config, WORKER_UID, &restored_contents);
    let round = |config: &Path, wrong_uid: bool, lost_response: bool| -> Output {
        assert!(
            matches!(
                std::fs::symlink_metadata(&socket),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ),
            "protected worker restart found a stale socket"
        );
        let mut worker_command: Command = Command::new(&executables.conditional_readiness);
        worker_command
            .arg("vote-worker")
            .arg("--config")
            .arg(config)
            .uid(WORKER_UID)
            .gid(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut worker: OwnedWorker = OwnedWorker(Some(worker_command.spawn().unwrap()));
        let ready_end: Instant = Instant::now().checked_add(Duration::from_secs(10)).unwrap();
        while !socket.exists() {
            if worker.child().try_wait().unwrap().is_some() {
                let failed: Output = worker.take().wait_with_output().unwrap();
                panic!(
                    "protected worker exited before socket bind: {}",
                    String::from_utf8_lossy(&failed.stderr)
                );
            }
            if Instant::now() >= ready_end {
                worker.child().kill().unwrap();
                let failed: Output = worker.take().wait_with_output().unwrap();
                panic!(
                    "protected worker did not bind a socket: {}",
                    String::from_utf8_lossy(&failed.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if wrong_uid {
            let mut unauthorized: std::os::unix::net::UnixStream =
                std::os::unix::net::UnixStream::connect(&socket).unwrap();
            unauthorized
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut response: [u8; 1] = [0];
            assert_eq!(unauthorized.read(&mut response).unwrap(), 0);
        }
        let mut frontend_command: Command = if lost_response {
            let mut probe: Command = Command::new(std::env::current_exe().unwrap());
            probe
                .arg("--ignored")
                .arg("--exact")
                .arg("compiled_conditional_readiness_real_retention_restart_and_distinct_certificate")
                .arg("--nocapture")
                .env("SUNRISE_READINESS_LOST_RESPONSE_SOCKET", &socket);
            probe
        } else {
            let mut frontend: Command = Command::new(&executables.conditional_readiness);
            frontend
                .arg("vote-frontend")
                .arg("--config")
                .arg(&frontend_config);
            frontend
        };
        frontend_command
            .uid(FRONTEND_UID)
            .gid(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let frontend: Output =
            wait_bounded(frontend_command.spawn().unwrap(), Duration::from_secs(310));
        let completed: Output = wait_bounded(worker.take(), Duration::from_secs(310));
        assert!(
            completed.status.success(),
            "protected worker failed: {}",
            String::from_utf8_lossy(&completed.stderr)
        );
        let retained: bool =
            String::from_utf8_lossy(&completed.stdout).contains("readiness_worker=retained-vote");
        assert_eq!(
            retained,
            config == worker_config.as_path() || config == restored_config.as_path(),
            "unexpected protected retention result"
        );
        frontend
    };
    if !lost_first {
        let refusal: Output = round(&wrong_config, false, false);
        assert!(
            !refusal.status.success(),
            "wrong-key protected worker released a vote"
        );
        assert!(!output.join("vote.bin").exists());
        assert!(
            success(round(&worker_config, true, false))
                .contains("conditional_readiness=retained-vote")
        );
    } else {
        let lost: Output = round(&worker_config, false, true);
        assert!(
            lost.status.success(),
            "lost-response probe failed: {}",
            String::from_utf8_lossy(&lost.stderr)
        );
        assert!(
            String::from_utf8_lossy(&lost.stdout).contains("readiness_lost_response_probe=sent"),
            "lost-response probe did not execute"
        );
        assert!(
            !output.join("vote.bin").exists(),
            "closed frontend published a vote"
        );
        assert!(
            success(round(&worker_config, false, false))
                .contains("conditional_readiness=retained-vote")
        );
    }
    let first: Vec<u8> = std::fs::read(output.join("vote.bin")).unwrap();
    assert!(
        success(round(&worker_config, false, false))
            .contains("conditional_readiness=retained-vote")
    );
    assert_eq!(
        std::fs::read(output.join("vote.bin")).unwrap(),
        first,
        "retained readiness vote changed after protected worker restart"
    );
    // round has waited for the previous worker and frontend. Recover the same
    // disposable key at another worker-owned private absolute path, then make
    // the original unavailable for both the refusal and recovered restart.
    assert!(restored_key.is_absolute());
    assert_eq!(std::fs::copy(key, &restored_key).unwrap(), 32);
    std::fs::set_permissions(&restored_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    change_owner(&restored_key, WORKER_UID);
    std::fs::remove_file(key).unwrap();
    assert!(!key.exists(), "original readiness key remained available");
    let refusal: Output = round(&wrong_config, false, false);
    assert!(
        !refusal.status.success(),
        "wrong-key worker released a retained readiness vote"
    );
    assert_eq!(
        std::fs::read(output.join("vote.bin")).unwrap(),
        first,
        "wrong-key refusal changed the retained readiness vote"
    );
    assert!(
        success(round(&restored_config, false, false))
            .contains("conditional_readiness=retained-vote")
    );
    assert!(
        !key.exists(),
        "restored worker recreated the original key path"
    );
    assert_eq!(
        std::fs::read(output.join("vote.bin")).unwrap(),
        first,
        "retained readiness vote changed after same-key path recovery"
    );
    // The unchanged ordinary CLI assertions below still use the original path.
    assert_eq!(std::fs::copy(&restored_key, key).unwrap(), 32);
    std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600)).unwrap();
    change_owner(key, 0);
    // Restore fixture ownership before the unchanged ordinary CLI assertions.
    for directory in [destination, output] {
        for entry in std::fs::read_dir(directory).unwrap() {
            change_owner(&entry.unwrap().path(), 0);
        }
        change_owner(directory, 0);
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "compiles and runs the real conditional_readiness CLI through a four-validator SQLite retain/restart/distinct-certificate cycle; owned by the dedicated readiness-sqlite required CI lane, not ordinary cargo test"]
async fn compiled_conditional_readiness_real_retention_restart_and_distinct_certificate() {
    #[cfg(target_os = "linux")]
    if let Some(socket) = std::env::var_os("SUNRISE_READINESS_LOST_RESPONSE_SOCKET") {
        let mut stream: tokio::net::UnixStream =
            tokio::net::UnixStream::connect(PathBuf::from(socket))
                .await
                .unwrap();
        native_http::local_custody_transport::write_frame(&mut stream, b"SRDVOTE1", || {
            std::io::Error::other("readiness lost-response probe refused")
        })
        .await
        .unwrap();
        drop(stream);
        println!("readiness_lost_response_probe=sent");
        return;
    }
    run_conditional_readiness(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "runs real changed-committee SQLite hosts through the configured seven-epoch withdrawal delay; owned by the unconditional recurring-sqlite required CI lane"]
async fn compiled_registered_replacement_and_recurring_successor_hosts() {
    run_conditional_readiness(true).await;
}

async fn run_conditional_readiness(recurring: bool) {
    let initial_readiness: acceptance_timing::AcceptanceSpan =
        acceptance_timing::AcceptanceSpan::start(acceptance_timing::Stage::InitialReadiness, None);
    let executables: CompiledExecutableSnapshot = CompiledExecutableSnapshot::capture();
    let mut fixture: Fixture = if recurring {
        Fixture::new_recurring()
    } else {
        Fixture::new()
    };
    let incoming: Vec<genesis_fixture::FastVoteValidator> = if recurring {
        fixture.register_incoming_e();
        fixture.replacement_members()
    } else {
        fixture.original_members()
    };
    fixture.freeze_and_complete_for(&incoming);
    std::fs::write(
        fixture.directory.0.join("genesis.bin"),
        &fixture.network.manifest_bytes,
    )
    .unwrap();
    let (identity, ordered) = fixture.history();
    let history: Directory = Directory::new("ready-history-parent");
    let history_root: PathBuf = history.0.join("history");
    fixture.write_history(&history_root, &identity, &ordered);
    let cut: Directory = Directory::new("ready-cut");
    let archive: ImmutableArchive = ImmutableArchive::open(&cut.0).unwrap();
    assert!(
        export_source_business_cut(
            fixture.plan(&identity, fixture.operation),
            &fixture.stores[0],
            &fixture.blobs,
            &ordered,
            &archive,
            CutArchiveLimits::new(128, 1048576, 4096).unwrap()
        )
        .unwrap()
        .complete
    );
    let verified_cut: VerifiedBusinessCut =
        verify_business_cut_archive(fixture.plan(&identity, fixture.operation), &archive).unwrap();
    let saved: SavedBusinessCut = public_transfer(&verified_cut, &fixture.network.resolver);
    let verified =
        verify_saved_business_import(fixture.plan(&identity, fixture.operation), &saved).unwrap();
    let original_cut: BTreeMap<String, Vec<u8>> = files(&cut.0);
    let before: SourceBusinessSnapshot = fixture.snapshot();
    let set: ValidatorSet = ValidatorSet::new(
        protocol_types::Epoch::new(fixture.network.epoch.get() + 1),
        incoming
            .iter()
            .map(|member| ValidatorInfo {
                id: member.validator_id,
                voting_power: 1,
                signature_scheme: protocol_types::SignatureSchemeId::Ed25519,
                public_key: member.validator_id.as_bytes().to_vec(),
            })
            .collect(),
    )
    .unwrap();
    let next: PathBuf = fixture.directory.0.join("next-set.bin");
    std::fs::write(&next, encode_validator_set(&set).unwrap()).unwrap();
    let expected_subject = node_core::conditional_readiness::readiness_subject_for_candidate(
        verified.binding(),
        &fixture.network.resolver,
        &set,
    )
    .unwrap();
    let owner: ReadinessCertifier<'_> =
        ReadinessCertifier::new(&fixture.network.resolver, &expected_subject, &set).unwrap();
    let mut votes: Vec<(Directory, Vec<u8>)> = Vec::new();
    let mut destinations: Vec<Directory> = Vec::new();
    for (index, validator) in incoming.iter().enumerate() {
        let destination: Directory = Directory::new(&format!("ready-import-{index}"));
        let mut importer: Command = Command::new(&executables.business_import);
        importer.arg("create-sqlite");
        pins(&mut importer, &fixture, &history_root, &cut.0);
        importer.args([
            "--state-db",
            destination.0.join("state.db").to_str().unwrap(),
            "--blob-db",
            destination.0.join("body.db").to_str().unwrap(),
            "--validator-id",
            &hex(validator.validator_id.as_bytes()),
            "--max-new-batches",
            "4096",
        ]);
        assert!(success(importer.output().unwrap()).contains("business_import=complete-inactive"));
        let key: PathBuf = destination.0.join("private.key");
        std::fs::write(&key, validator.signing_key.as_ref()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let output: Directory = Directory::new(&format!("ready-vote-{index}"));
        if index == 0 {
            #[cfg(unix)]
            {
                let alias: PathBuf = fixture.directory.0.join("linked-key-directory");
                std::os::unix::fs::symlink(&destination.0, &alias).unwrap();
                assert!(
                    !voting(
                        &executables,
                        &fixture,
                        &history_root,
                        &cut.0,
                        &next,
                        &destination.0,
                        &output.0,
                        validator.validator_id,
                        &alias.join("private.key")
                    )
                    .output()
                    .unwrap()
                    .status
                    .success()
                );
                assert!(!output.0.join("vote.bin").exists());
            }
            std::fs::write(output.0.join("vote.bin"), b"invalid retained artifact").unwrap();
            assert!(
                !voting(
                    &executables,
                    &fixture,
                    &history_root,
                    &cut.0,
                    &next,
                    &destination.0,
                    &output.0,
                    validator.validator_id,
                    &key
                )
                .output()
                .unwrap()
                .status
                .success()
            );
            let target: SqliteImportTarget = SqliteImportTarget::open_existing(
                destination.0.join("state.db"),
                SqliteNamespace::new(
                    fixture.network.chain_id.clone(),
                    validator.validator_id,
                    fixture.network.domain,
                ),
                verified.binding(),
            )
            .unwrap();
            let token = target
                .begin_portable_snapshot(&fixture.operation, fixture.network.domain)
                .unwrap();
            let progress = target
                .read_import_progress(&fixture.operation, fixture.network.domain)
                .unwrap()
                .unwrap();
            let slot: ReadinessSlot = ReadinessSlot {
                identity: expected_subject
                    .identity(&fixture.network.resolver)
                    .unwrap(),
                signer: validator.validator_id,
            };
            assert_eq!(
                target
                    .read_ready_slot_at(
                        &fixture.operation,
                        fixture.network.domain,
                        verified.binding(),
                        &progress,
                        &token,
                        &slot
                    )
                    .unwrap(),
                ReadinessSlotObservation::Absent
            );
            assert_eq!(
                std::fs::read(output.0.join("vote.bin")).unwrap(),
                b"invalid retained artifact"
            );
            std::fs::remove_file(output.0.join("vote.bin")).unwrap();
        }
        #[cfg(target_os = "linux")]
        if index < 2 && !recurring && readiness_multiuid_enabled() {
            protected_vote(
                &executables,
                &fixture,
                &history_root,
                &cut.0,
                &next,
                &destination.0,
                &output.0,
                validator.validator_id,
                &key,
                index == 1,
            );
        }
        assert!(
            success(
                voting(
                    &executables,
                    &fixture,
                    &history_root,
                    &cut.0,
                    &next,
                    &destination.0,
                    &output.0,
                    validator.validator_id,
                    &key
                )
                .output()
                .unwrap()
            )
            .contains("conditional_readiness=retained-vote")
        );
        let original: Vec<u8> = std::fs::read(output.0.join("vote.bin")).unwrap();
        let vote: ReadinessVote = decode_readiness_vote(&original).unwrap();
        owner.verify_vote(&vote).unwrap();
        assert_eq!(vote.signer, validator.validator_id);
        let mut retry: Command = voting(
            &executables,
            &fixture,
            &history_root,
            &cut.0,
            &next,
            &destination.0,
            &output.0,
            validator.validator_id,
            &key,
        );
        assert!(success(retry.output().unwrap()).contains("conditional_readiness=retained-vote"));
        assert_eq!(
            std::fs::read(output.0.join("vote.bin")).unwrap(),
            original,
            "separate restarted process returns the original artifact"
        );
        votes.push((output, original));
        destinations.push(destination);
    }
    let copied_vote: Directory = Directory::new("ready-public-vote-copy");
    copy_files(&votes[0].0.0, &copied_vote.0);
    assert_eq!(files(&votes[0].0.0), files(&copied_vote.0));
    let certificates: Directory = Directory::new("ready-certificates");
    let assembly = |count: usize, duplicate: bool, offset: usize, out_dir: &Path| -> Command {
        let mut command: Command = Command::new(&executables.conditional_readiness);
        command.arg("certificate");
        pins(&mut command, &fixture, &history_root, &cut.0);
        command.args([
            "--next-set",
            next.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
        ]);
        for index in 0..count {
            let selected: usize = if duplicate { 0 } else { offset + index };
            let directory: &Path = if selected == 0 {
                &copied_vote.0
            } else {
                &votes[selected].0.0
            };
            command.arg("--vote").arg(directory.join("vote.bin"));
        }
        command
    };
    assert!(
        !assembly(2, false, 0, &certificates.0)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        !assembly(3, true, 0, &certificates.0)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!certificates.0.join("certificate.bin").exists());
    assert!(
        success(assembly(3, false, 0, &certificates.0).output().unwrap())
            .contains("conditional_readiness=verified-certificate")
    );
    let bytes: Vec<u8> = std::fs::read(certificates.0.join("certificate.bin")).unwrap();
    let certificate: ReadinessCertificate = decode_readiness_certificate(&bytes).unwrap();
    owner.verify_certificate(&certificate).unwrap();
    success(assembly(3, false, 0, &certificates.0).output().unwrap());
    assert_eq!(
        std::fs::read(certificates.0.join("certificate.bin")).unwrap(),
        bytes
    );
    let roles: BTreeMap<ValidatorId, Vec<u8>> = votes
        .iter()
        .map(|(_, bytes)| {
            let vote: ReadinessVote = decode_readiness_vote(bytes).unwrap();
            (vote.signer, bytes.clone())
        })
        .collect();
    assert_eq!(roles.len(), 4);
    // Reuse the independently reconstructed cut and genuine successor quorum
    // above. Preparation is a separate compiled process, not a raw storage
    // completion, and adding this step does not duplicate the expensive setup.
    let seal_output: Directory = Directory::new("unsigned-seal-preparation");
    let prepare =
        |certificate_path: &Path, state: &Path, blobs: &Path, out_dir: &Path| -> Command {
            let mut command: Command = Command::new(&executables.ordered_seal);
            command.arg("prepare-sqlite");
            pins(&mut command, &fixture, &history_root, &cut.0);
            command.args([
                "--certificate",
                certificate_path.to_str().unwrap(),
                "--state-db",
                state.to_str().unwrap(),
                "--blob-db",
                blobs.to_str().unwrap(),
                "--validator-id",
                &hex(fixture.network.validators[0].validator_id.as_bytes()),
                "--out-dir",
                out_dir.to_str().unwrap(),
            ]);
            command
        };
    let certificate_path: PathBuf = certificates.0.join("certificate.bin");
    let source_state: PathBuf = fixture.directory.0.join("state-0.sqlite");
    let source_blobs: PathBuf = fixture.directory.0.join("blobs.sqlite");
    let certificate_digest = node_core::ordered_economics::seal_certificate_digest(
        &fixture.network.resolver,
        fixture.network.epoch,
        &bytes,
    )
    .unwrap();
    assert!(
        fixture
            .blobs
            .get_blob(&certificate_digest)
            .unwrap()
            .is_none()
    );
    assert!(
        !prepare(
            &certificate_path,
            &destinations[0].0.join("state.db"),
            &destinations[0].0.join("body.db"),
            &seal_output.0,
        )
        .output()
        .unwrap()
        .status
        .success(),
        "an inactive successor target is not an outgoing source"
    );
    assert!(!seal_output.0.join("candidate.bin").exists());
    assert!(
        success(
            prepare(
                &certificate_path,
                &source_state,
                &source_blobs,
                &seal_output.0
            )
            .output()
            .unwrap()
        )
        .contains("ordered_seal=prepared")
    );
    let candidate_bytes: Vec<u8> = std::fs::read(seal_output.0.join("candidate.bin")).unwrap();
    let candidate =
        node_core::ordered_economics::decode_ordered_candidate(&candidate_bytes).unwrap();
    assert_eq!(
        candidate.kind,
        node_core::ordered_economics::OrderedOperationKind::Seal
    );
    let seal = node_core::ordered_economics::decode_seal_intent(&candidate.intent).unwrap();
    assert_eq!(seal.readiness_subject, expected_subject);
    assert_eq!(
        candidate.created_checkpoint,
        saved.identity.ordered_history.through_height
    );
    assert_eq!(seal.certificate_digest, certificate_digest);
    assert_eq!(
        fixture.blobs.get_blob(&certificate_digest).unwrap(),
        Some(bytes.clone())
    );
    success(
        prepare(
            &certificate_path,
            &source_state,
            &source_blobs,
            &seal_output.0,
        )
        .output()
        .unwrap(),
    );
    assert_eq!(
        std::fs::read(seal_output.0.join("candidate.bin")).unwrap(),
        candidate_bytes
    );
    let bad_certificate: PathBuf = fixture.directory.0.join("invalid-seal-certificate.bin");
    let mut altered: ReadinessCertificate = certificate.clone();
    altered.votes[0].signature[0] ^= 1;
    std::fs::write(
        &bad_certificate,
        consensus::readiness::encode_readiness_certificate(&altered).unwrap(),
    )
    .unwrap();
    assert!(
        !prepare(
            &bad_certificate,
            &source_state,
            &source_blobs,
            &seal_output.0
        )
        .output()
        .unwrap()
        .status
        .success()
    );
    assert_eq!(
        std::fs::read(seal_output.0.join("candidate.bin")).unwrap(),
        candidate_bytes
    );
    assert_eq!(
        fixture.snapshot(),
        before,
        "preparation never changes source state or receipts"
    );
    assert_eq!(files(&cut.0), original_cut);
    assert_eq!(
        fixture.snapshot(),
        before,
        "local readiness cannot mutate the source"
    );
    // DR-0187: build a second, genuinely quorum-backed Seal candidate that
    // shares this exact semantic target but a distinct certificate variant
    // (a different 3-of-4 successor combination), never a raw-fabricated
    // protocol proof. The operator acceptance replays it after the first
    // candidate is accepted to show the Sealed barrier -- not stale
    // completion bookkeeping -- rejects it.
    let certificates_b: Directory = Directory::new("ready-certificates-competing");
    assert!(
        success(assembly(3, false, 1, &certificates_b.0).output().unwrap())
            .contains("conditional_readiness=verified-certificate")
    );
    let competing_certificate_bytes: Vec<u8> =
        std::fs::read(certificates_b.0.join("certificate.bin")).unwrap();
    assert_ne!(competing_certificate_bytes, bytes);
    let competing_certificate: ReadinessCertificate =
        decode_readiness_certificate(&competing_certificate_bytes).unwrap();
    owner.verify_certificate(&competing_certificate).unwrap();
    let seal_output_b: Directory = Directory::new("unsigned-seal-preparation-competing");
    let competing_certificate_path: PathBuf = certificates_b.0.join("certificate.bin");
    assert!(
        success(
            prepare(
                &competing_certificate_path,
                &source_state,
                &source_blobs,
                &seal_output_b.0
            )
            .output()
            .unwrap()
        )
        .contains("ordered_seal=prepared")
    );
    let competing_candidate_bytes: Vec<u8> =
        std::fs::read(seal_output_b.0.join("candidate.bin")).unwrap();
    let competing_candidate =
        node_core::ordered_economics::decode_ordered_candidate(&competing_candidate_bytes).unwrap();
    assert_eq!(
        competing_candidate.kind,
        node_core::ordered_economics::OrderedOperationKind::Seal
    );
    assert_ne!(competing_candidate.request_id, candidate.request_id);
    assert_eq!(
        competing_candidate.created_checkpoint,
        candidate.created_checkpoint
    );
    let competing_seal =
        node_core::ordered_economics::decode_seal_intent(&competing_candidate.intent).unwrap();
    assert_eq!(competing_seal.readiness_subject, seal.readiness_subject);
    assert_eq!(competing_seal.predecessor_tag, seal.predecessor_tag);
    assert_eq!(competing_seal.predecessor_digest, seal.predecessor_digest);
    assert_ne!(competing_seal.certificate_digest, seal.certificate_digest);
    let competing_certificate_digest = node_core::ordered_economics::seal_certificate_digest(
        &fixture.network.resolver,
        fixture.network.epoch,
        &competing_certificate_bytes,
    )
    .unwrap();
    assert_eq!(
        competing_seal.certificate_digest,
        competing_certificate_digest
    );
    let subject_identity = seal
        .readiness_subject
        .identity(&fixture.network.resolver)
        .unwrap();
    let competing_subject_identity = competing_seal
        .readiness_subject
        .identity(&fixture.network.resolver)
        .unwrap();
    let target = node_core::ordered_economics::seal_target_digest(
        &fixture.network.resolver,
        &fixture.network.context,
        subject_identity,
        seal.predecessor_tag,
        seal.predecessor_digest,
    )
    .unwrap();
    let competing_target = node_core::ordered_economics::seal_target_digest(
        &fixture.network.resolver,
        &fixture.network.context,
        competing_subject_identity,
        competing_seal.predecessor_tag,
        competing_seal.predecessor_digest,
    )
    .unwrap();
    assert_eq!(
        target, competing_target,
        "the competing branch shares the exact same semantic Seal target"
    );
    assert_eq!(
        fixture.snapshot(),
        before,
        "the competing variant's preparation never changes source state or receipts"
    );
    drop(initial_readiness);
    drop(archive); // No held original cut/staging directory survives cold recovery.
    ordered_seal_sqlite_acceptance::run_compiled_four_host_seal(
        &executables,
        &fixture,
        &seal_output.0.join("candidate.bin"),
        &candidate,
    );
    ordered_seal_sqlite_acceptance::run(
        &mut fixture,
        &seal_output.0.join("candidate.bin"),
        &candidate,
        &competing_candidate,
        &successor_host_acceptance::SuccessorProcessInputs {
            executables: executables.clone(),
            recur_changed_committee: recurring,
            plan_history: history_root.clone(),
            cut: cut.0.clone(),
            certificate: certificates.0.clone(),
            competing_certificate: certificates_b.0.clone(),
            targets: destinations
                .iter()
                .map(|destination: &Directory| destination.0.clone())
                .collect(),
            members: incoming
                .iter()
                .map(|member| successor_host_acceptance::SuccessorProcessMember {
                    validator_id: member.validator_id,
                    seed: member.seed,
                })
                .collect(),
            binding: verified.binding().clone(),
        },
    )
    .await;
}
