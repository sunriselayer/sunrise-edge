//! Optional real-UID transport in the original first-successor owner.
//! The seven-epoch flow and its selectors stay in the parent acceptance.
use super::*;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
};

const WORKER_UID: u32 = 10_001;
const FRONTEND_UID: u32 = 10_002;

pub(super) fn enabled() -> bool {
    if std::env::var_os("SUNRISE_SUCCESSOR_MULTIUID_FIXTURE").is_none() {
        return false;
    }
    assert!(
        Path::new("/.dockerenv").exists(),
        "multi-UID fixture requires its bounded container"
    );
    let status: String = fs::read_to_string("/proc/self/status").unwrap();
    let effective: u32 = status
        .lines()
        .find_map(|line: &str| {
            line.strip_prefix("Uid:")?
                .split_whitespace()
                .nth(1)?
                .parse::<u32>()
                .ok()
        })
        .unwrap();
    assert_eq!(
        effective, 0,
        "multi-UID fixture requires root inside its container"
    );
    true
}

fn chown(path: &Path, uid: u32) {
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

fn traverse_ancestors(path: &Path) {
    assert!(
        path.starts_with("/tmp/"),
        "fixture path must be in disposable tmpfs"
    );
    let mut parent: Option<&Path> = path.parent();
    while let Some(directory) = parent {
        if directory == Path::new("/tmp") {
            break;
        }
        let metadata: fs::Metadata = fs::symlink_metadata(directory).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        if metadata.permissions().mode() & 0o7777 != 0o710 {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o710)).unwrap();
        }
        parent = directory.parent();
    }
}

fn public_tree(path: &Path) {
    traverse_ancestors(path);
    let metadata: fs::Metadata = fs::symlink_metadata(path).unwrap();
    assert!(!metadata.file_type().is_symlink());
    if metadata.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            public_tree(&entry.unwrap().path());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o750)).unwrap();
    } else {
        assert!(metadata.is_file());
        fs::set_permissions(path, fs::Permissions::from_mode(0o640)).unwrap();
    }
}

fn worker_tree(path: &Path) {
    traverse_ancestors(path);
    let metadata: fs::Metadata = fs::symlink_metadata(path).unwrap();
    assert!(!metadata.file_type().is_symlink());
    if metadata.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            worker_tree(&entry.unwrap().path());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    } else {
        assert!(metadata.is_file());
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    chown(path, WORKER_UID);
}

fn target_fence(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    index: usize,
) -> WriterFenceGeneration {
    let store: SqliteDurableStore = SqliteDurableStore::open_historical(
        inputs.targets[index].join("state.db"),
        SqliteNamespace::new(
            fixture.network.chain_id.clone(),
            inputs.members[index].validator_id,
            fixture.network.domain,
        ),
    )
    .unwrap();
    store.writer_fence().unwrap()
}

fn target_rows(target: &Path) -> (recurring::SqlRows, recurring::SqlRows) {
    // The failed startup is permitted to claim a writer generation. Every
    // other durable row and blob must remain byte-for-byte unchanged, including
    // non-fence metadata columns in the same row as the writer fence.
    let state: recurring::SqlRows = recurring::capture_state_rows(
        &target.join("state.db"),
        "SELECT id, schema_identity, chain_id, validator_id, domain, mutation_sequence, \
         source_instance_id, namespace_origin, import_binding FROM durable_metadata ORDER BY id",
    );
    let blobs: recurring::SqlRows = recurring::capture_blob_rows(&target.join("body.db"));
    (state, blobs)
}

pub(super) fn start_host(
    fixture: &Fixture,
    inputs: &SuccessorProcessInputs,
    export: &Path,
    index: usize,
) -> HostProcess {
    assert_eq!(
        index, 3,
        "one exact protected successor role in the existing quorum"
    );
    for path in [
        fixture.directory.0.join("genesis.bin"),
        inputs.plan_history.clone(),
        inputs.cut.clone(),
        export.to_path_buf(),
        inputs.certificate.clone(),
    ] {
        public_tree(&path);
    }
    worker_tree(&inputs.targets[index]);
    let socket_dir: PathBuf = fixture.directory.0.join("successor-protected-socket-3");
    if !socket_dir.exists() {
        fs::create_dir(&socket_dir).unwrap();
    }
    traverse_ancestors(&socket_dir);
    fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o750)).unwrap();
    chown(&socket_dir, WORKER_UID);
    let socket: PathBuf = socket_dir.join("worker.sock");
    assert!(
        !socket.exists(),
        "orderly stop removes the prior owned socket"
    );

    let worker_command = |key: &Path| -> Command {
        let mut command: Command = Command::new(&inputs.executables.successor_host);
        command.arg("serve-protected-worker");
        pins(&mut command, fixture, inputs);
        target_flags_with_key(
            &mut command,
            inputs,
            export,
            &inputs.certificate,
            index,
            key,
        );
        command.args([
            "--created-checkpoint",
            &HOST_CHECKPOINT.to_string(),
            "--timeout-seconds",
            "600",
            "--confirm-offline-fence-advance",
            "--socket",
            socket.to_str().unwrap(),
            "--frontend-uid",
            &FRONTEND_UID.to_string(),
            "--max-connections",
            "4098",
            "--max-requests",
            "4096",
            "--total-deadline-seconds",
            "3600",
        ]);
        command.uid(WORKER_UID).gid(0);
        command
    };
    let wrong_key: PathBuf = inputs.targets[index].join("wrong-private.key");
    let wrong_seed: [u8; 32] = [0x97; 32];
    let wrong_signer: ed25519_zebra::SigningKey = wrong_seed.into();
    let wrong_public: [u8; 32] = ed25519_zebra::VerificationKey::from(&wrong_signer).into();
    assert_ne!(wrong_public, *inputs.members[index].validator_id.as_bytes());
    fs::write(&wrong_key, wrong_seed).unwrap();
    fs::set_permissions(&wrong_key, fs::Permissions::from_mode(0o600)).unwrap();
    chown(&wrong_key, WORKER_UID);
    let before_fence: WriterFenceGeneration = target_fence(fixture, inputs, index);
    let before_rows: (recurring::SqlRows, recurring::SqlRows) = target_rows(&inputs.targets[index]);
    let wrong: Output =
        process::spawn_bounded_output(worker_command(&wrong_key), Duration::from_secs(600));
    assert!(
        !wrong.status.success(),
        "wrong-key successor worker started"
    );
    assert!(
        String::from_utf8_lossy(&wrong.stderr)
            .contains("successor member key differs from the local signing key"),
        "wrong-key successor refusal lacked the actual-key check: {}",
        String::from_utf8_lossy(&wrong.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&wrong.stdout).contains("complete=true") && !socket.exists(),
        "wrong-key successor worker exposed a listening or signed route"
    );
    let after_fence: WriterFenceGeneration = target_fence(fixture, inputs, index);
    assert_eq!(
        before_fence.checked_next(),
        Some(after_fence),
        "failed startup claims exactly one writer generation"
    );
    assert_eq!(
        target_rows(&inputs.targets[index]),
        before_rows,
        "wrong-key startup changed retained business, receipt or blob rows"
    );
    println!("successor_protected_wrong_key_refused=passed");

    let key: PathBuf = inputs.targets[index].join("private.key");
    let mut worker: Command = worker_command(&key);
    worker.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let startup_cap: NonZeroUsize =
        process::compiled_host_startup_line_limit(fixture.network.chain_id.as_str());
    let (worker_guard, worker_line): (process::ChildGuard, String) =
        process::spawn_bounded_status_line(worker, Duration::from_secs(600), startup_cap);
    assert!(
        worker_line.contains("mode=successor-protected-worker"),
        "{worker_line}"
    );
    let generation: u64 = field(&worker_line, "writer_generation=").parse().unwrap();

    // The test owner is root only inside the bounded container. A request
    // from its UID must be closed before reaching the key-holding router.
    let mut unauthorized: std::os::unix::net::UnixStream =
        std::os::unix::net::UnixStream::connect(&socket).unwrap();
    unauthorized
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut byte: [u8; 1] = [0];
    use std::io::Read;
    assert_eq!(unauthorized.read(&mut byte).unwrap(), 0);

    let mut frontend: Command = Command::new(&inputs.executables.successor_host);
    frontend.arg("serve-protected-frontend");
    pins(&mut frontend, fixture, inputs);
    frontend.args([
        "--manifest-history-dir",
        export.to_str().unwrap(),
        "--certificate-dir",
        inputs.certificate.to_str().unwrap(),
        "--validator-id",
        &hex(inputs.members[index].validator_id.as_bytes()),
        "--socket",
        socket.to_str().unwrap(),
        "--worker-uid",
        &WORKER_UID.to_string(),
        "--listen",
        "127.0.0.1:0",
        "--timeout-seconds",
        "600",
        "--max-concurrent",
        "16",
        "--max-requests",
        "4096",
        "--total-deadline-seconds",
        "3600",
    ]);
    frontend
        .uid(FRONTEND_UID)
        .gid(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let (frontend_guard, frontend_line): (process::ChildGuard, String) =
        process::spawn_bounded_status_line(frontend, Duration::from_secs(600), startup_cap);
    assert!(
        frontend_line.contains("mode=successor-protected-frontend"),
        "{frontend_line}"
    );
    let address: SocketAddr = field(&frontend_line, "listen=").parse().unwrap();
    println!(
        "successor_protected=distinct-uid worker={WORKER_UID} frontend={FRONTEND_UID} generation={generation}"
    );
    HostProcess {
        child: frontend_guard.into_inner(),
        protected_worker: Some(worker_guard.into_inner()),
        address,
        generation,
        validator: inputs.members[index].validator_id,
    }
}
