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
        if metadata.permissions().mode() & 0o7777 != 0o750 {
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

    let mut worker: Command = Command::new(&inputs.executables.successor_host);
    worker.arg("serve-protected-worker");
    pins(&mut worker, fixture, inputs);
    target_flags(&mut worker, inputs, export, &inputs.certificate, index);
    worker.args([
        "--created-checkpoint",
        &HOST_CHECKPOINT.to_string(),
        "--timeout-seconds",
        "30",
        "--confirm-offline-fence-advance",
        "--socket",
        socket.to_str().unwrap(),
        "--frontend-uid",
        &FRONTEND_UID.to_string(),
        "--max-connections",
        "4096",
        "--max-requests",
        "4096",
        "--total-deadline-seconds",
        "3600",
    ]);
    worker
        .uid(WORKER_UID)
        .gid(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
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
        "30",
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
