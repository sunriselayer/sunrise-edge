//! Actual compiled local-v2 capture/restore between the existing all-four-owner
//! death and ordinary next-fence TLS business oracle. No new protocol fixtures.
use super::*;
use age::secrecy::ExposeSecret;
use compiled_source_host_process::spawn_strict_bounded_output;
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    time::Instant,
};

const RECOVERY_DEADLINE: Duration = Duration::from_secs(300);
const MAX_CIPHER_BYTES: u64 = 72 * 1024 * 1024;
const MAX_PLAIN_BYTES: u64 = 68 * 1024 * 1024;

/// Owns only the exclusively created sibling tree. Original files stay in its
/// forensic subdirectories and are never reopened by the restored host/CLI.
pub(super) struct RestoredCheckpoint {
    directory: PathBuf,
    original: Vec<(PathBuf, PathBuf)>,
    forensic: Vec<(PathBuf, PathBuf)>,
    restored: Vec<(PathBuf, PathBuf)>,
    original_images: Vec<sqlite_durable_image::Image>,
}
impl RestoredCheckpoint {
    pub(super) fn state(&self, index: usize) -> PathBuf {
        self.restored[index].0.clone()
    }
    pub(super) fn blobs(&self, index: usize) -> PathBuf {
        self.restored[index].1.clone()
    }
    pub(super) fn former_and_forensic_paths(&self, index: usize) -> Vec<PathBuf> {
        vec![
            self.original[index].0.clone(),
            self.original[index].1.clone(),
            self.forensic[index].0.clone(),
            self.forensic[index].1.clone(),
        ]
    }
    pub(super) fn assert_originals_unavailable(&self) {
        for ((state, blobs), (old_state, old_blobs)) in self.original.iter().zip(&self.forensic) {
            for main in [state, blobs] {
                for suffix in ["", "-wal", "-shm", "-journal"] {
                    assert_absent(&sidecar(main, suffix), "old source remains unavailable");
                }
            }
            assert!(old_state.is_file() && old_blobs.is_file());
        }
        let actual: Vec<sqlite_durable_image::Image> = self
            .forensic
            .iter()
            .map(|(state, blobs)| sqlite_durable_image::capture(state, blobs))
            .collect();
        assert_eq!(
            actual, self.original_images,
            "forensic original complete SQL/blob images remain unchanged"
        );
    }
}
impl Drop for RestoredCheckpoint {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}
fn sidecar(main: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = main.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}
fn private_directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
fn remaining(end: Instant) -> Duration {
    let left: Duration = end.saturating_duration_since(Instant::now());
    assert!(
        !left.is_zero(),
        "one original checkpoint invocation-group deadline"
    );
    left
}
fn run(mut command: Command, end: Instant) -> Output {
    let left: Duration = remaining(end);
    let seconds: u64 = left.as_secs().min(300);
    assert!(
        seconds > 0,
        "remaining downward recovery deadline must be positive"
    );
    command.args(["--timeout-seconds", &seconds.to_string()]);
    let output: Output = spawn_strict_bounded_output(command, left);
    assert!(
        Instant::now() < end,
        "complete child EOF/reap within original checkpoint group deadline"
    );
    output
}
fn common(network: &Network, index: usize, recipient: &str, mode: &str) -> Command {
    let anchors: &IndependentAnchors = network.independent_anchors.as_ref().unwrap();
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_business_recovery"));
    command
        .arg(mode)
        .args([
            "--chain-id",
            network.fixture.context.chain_id().as_str(),
            "--validator-id",
            &hex(&network.fixture.validators[index]),
            "--domain",
            &hex(network.domain.as_bytes()),
            "--recipient",
            recipient,
            "--max-files",
            "4",
            "--max-file-bytes",
            "33554432",
            "--max-plaintext-bytes",
            &MAX_PLAIN_BYTES.to_string(),
            "--max-ciphertext-bytes",
            &MAX_CIPHER_BYTES.to_string(),
            "--max-control-bytes",
            "4096",
            "--max-header-bytes",
            "65536",
        ])
        .arg("--independent-anchor-db")
        .arg(&anchors.paths[index]);
    command
}
fn pack_command(
    network: &Network,
    index: usize,
    recipient: &str,
    parent: &Path,
    capture: &str,
    cipher: &str,
) -> Command {
    let mut command: Command = common(network, index, recipient, "pack-checkpoint");
    command
        .arg("--state-db")
        .arg(network.state_db(index))
        .arg("--blob-db")
        .arg(network.blob_db(index))
        .arg("--capture-root")
        .arg(parent.join(capture))
        .arg("--ciphertext-out")
        .arg(parent.join(cipher));
    command
}
fn open_command(
    network: &Network,
    index: usize,
    recipient: &str,
    parent: &Path,
    output: &str,
) -> Command {
    let mut command: Command = common(network, index, recipient, "open-checkpoint");
    command
        .arg("--ciphertext-file")
        .arg(parent.join("checkpoint.age"))
        .arg("--identity-file")
        .arg(parent.join("recovery.identity"))
        .arg("--out-dir")
        .arg(parent.join(output));
    command
}
fn replace_value(command: &Command, flag: &str, value: OsString) -> Command {
    let mut args: Vec<OsString> = command.get_args().map(OsString::from).collect();
    let at: usize = args.iter().position(|arg| arg == flag).unwrap();
    assert_eq!(args.iter().filter(|arg| *arg == flag).count(), 1);
    args[at + 1] = value;
    let mut replaced: Command = Command::new(command.get_program());
    replaced.args(args);
    replaced
}

fn recovery_success(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "actual compiled recovery exit"
    );
    assert!(
        output.stderr.is_empty(),
        "successful recovery stderr must be empty"
    );
    let line: String = String::from_utf8(output.stdout).expect("recovery diagnostic is UTF-8");
    assert!(
        line.ends_with('\n') && line.lines().count() == 1 && !line.contains('\r'),
        "one complete recovery diagnostic line"
    );
    line
}

fn refusal(output: Output, message: &str) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "ordinary compiled recovery refusal"
    );
    assert!(
        output.stdout.is_empty(),
        "failed recovery never advertises completion"
    );
    assert_eq!(lossy(&output.stderr), format!("{message}\n"));
}
fn complete(root: &Path) {
    for name in [
        "state.sqlite",
        "blobs.sqlite",
        "checkpoint-manifest-v2.bin",
        "checkpoint-complete-v2.bin",
    ] {
        let metadata: fs::Metadata = fs::symlink_metadata(root.join(name)).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(
        fs::read_dir(root).unwrap().count(),
        4,
        "closed complete local-v2 inventory"
    );
    assert_eq!(
        fs::metadata(root).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
fn current_restored(
    network: &Network,
    index: usize,
    state: &Path,
    blobs: &Path,
    end: Instant,
) -> AnchorObservation {
    let mut args: Vec<OsString> = anchor_namespace_args(network, index);
    for (flag, path) in [("--state-db", state), ("--blob-db", blobs)] {
        let at: usize = args.iter().position(|value| value == flag).unwrap();
        args[at + 1] = path.as_os_str().to_owned();
    }
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_sqlite_source_host"));
    command
        .arg("anchor-checkpoint")
        .args(args)
        .arg("--independent-anchor-db")
        .arg(&network.independent_anchors.as_ref().unwrap().paths[index]);
    let output: Output = spawn_strict_bounded_output(command, remaining(end));
    assert!(Instant::now() < end);
    AnchorObservation::parse(
        &success(output),
        "independent-local-acknowledgement-not-quorum-state-root",
    )
}

pub(super) fn pack_and_restore(network: &Network) -> RestoredCheckpoint {
    assert!(network.independent_anchors.is_some());
    assert!(network.restored_checkpoint.is_none());
    assert_no_parent_sqlite_handles(network);
    let end: Instant = Instant::now().checked_add(RECOVERY_DEADLINE).unwrap();
    let source_name: &str = network
        .fixture
        .directory
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let directory: PathBuf = network
        .fixture
        .directory
        .with_file_name(format!("{source_name}-encrypted-checkpoints"));
    private_directory(&directory);
    let original: Vec<(PathBuf, PathBuf)> = (0..VALIDATORS)
        .map(|index| (network.state_db(index), network.blob_db(index)))
        .collect();
    let mut owner: RestoredCheckpoint = RestoredCheckpoint {
        directory,
        original,
        forensic: Vec::with_capacity(VALIDATORS),
        restored: Vec::with_capacity(VALIDATORS),
        original_images: sqlite_durable_images(network),
    };
    let anchors: &IndependentAnchors = network.independent_anchors.as_ref().unwrap();
    assert!(!owner.directory.starts_with(&network.fixture.directory));
    assert!(!network.fixture.directory.starts_with(&owner.directory));
    assert!(!owner.directory.starts_with(&anchors.directory));
    assert!(!anchors.directory.starts_with(&owner.directory));
    let before: Vec<AnchorObservation> = (0..VALIDATORS)
        .map(|index| anchors.checkpoint(network, index))
        .collect();
    let mut recipients: Vec<String> = Vec::with_capacity(VALIDATORS);
    for index in 0..VALIDATORS {
        let parent: PathBuf = owner.directory.join(format!("validator-{index}"));
        private_directory(&parent);
        private_directory(&parent.join("forensic"));
        let identity: age::x25519::Identity = age::x25519::Identity::generate();
        let recipient: String = identity.to_public().to_string();
        let encoded: age::secrecy::SecretString = identity.to_string();
        write_private_new(
            &parent.join("recovery.identity"),
            encoded.expose_secret().as_bytes(),
        );
        recipients.push(recipient);
        owner.forensic.push((
            parent.join("forensic/state.sqlite"),
            parent.join("forensic/blobs.sqlite"),
        ));
        owner.restored.push((
            parent.join("restored/state.sqlite"),
            parent.join("restored/blobs.sqlite"),
        ));
        if index == 0 {
            // Actual argv mode isolation, before any capture/publication.
            let mut wrong: Command = pack_command(
                network,
                index,
                &recipients[index],
                &parent,
                "wrong-mode-capture",
                "wrong-mode.age",
            );
            wrong
                .arg("--identity-file")
                .arg(parent.join("recovery.identity"));
            refusal(run(wrong, end), "recovery invalid input");
            assert_absent(
                &parent.join("wrong-mode-capture"),
                "mode-irrelevant flag refuses before output",
            );
            assert_absent(
                &parent.join("wrong-mode.age"),
                "mode-irrelevant flag has no publication",
            );
        }
        let line: String = recovery_success(run(
            pack_command(
                network,
                index,
                &recipients[index],
                &parent,
                "capture",
                "checkpoint.age",
            ),
            end,
        ));
        assert_eq!(
            line,
            "business_recovery=checkpoint-packed files=2 meaning=local-current-store-no-activation\n"
        );
        complete(&parent.join("capture"));
        let metadata: fs::Metadata = fs::metadata(parent.join("checkpoint.age")).unwrap();
        assert!(metadata.len() > 0 && metadata.len() <= MAX_CIPHER_BYTES);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_absent(
            &parent.join("checkpoint.age.incomplete"),
            "finished ciphertext publication has no pending leaf",
        );
    }
    assert_no_parent_sqlite_handles(network);
    assert_eq!(
        sqlite_durable_images(network),
        owner.original_images,
        "snapshot publication changes no source rows or bodies"
    );
    let published: Vec<AnchorObservation> = (0..VALIDATORS)
        .map(|index| anchors.checkpoint(network, index))
        .collect();
    for (old, new) in before.iter().zip(&published) {
        assert_eq!(
            old.state_root, new.state_root,
            "body-only snapshot publication preserves complete state root"
        );
        assert!(new.sequence >= old.sequence);
        if new.body_manifest_root != old.body_manifest_root {
            assert!(
                new.sequence > old.sequence,
                "new retained body inventory requires an advanced acknowledgement"
            );
        }
    }
    let authority_images: Vec<sqlite_durable_image::AnchorImage> = anchors.images();
    // All original state/body paths vanish BEFORE the first decrypt/verify.
    // Move closed files, never copy/open a live SQLite main/WAL/SHM inode.
    for ((state, blobs), (old_state, old_blobs)) in owner.original.iter().zip(&owner.forensic) {
        for (source, destination) in [(state, old_state), (blobs, old_blobs)] {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let source: PathBuf = sidecar(source, suffix);
                let destination: PathBuf = sidecar(destination, suffix);
                match fs::symlink_metadata(&source) {
                    Ok(metadata) => {
                        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
                        fs::rename(source, destination).unwrap();
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        assert!(!suffix.is_empty(), "original main file must exist")
                    }
                    Err(error) => panic!("inspect closed owned source: {error}"),
                }
            }
        }
    }
    owner.assert_originals_unavailable();
    for index in 0..VALIDATORS {
        let parent: PathBuf = owner.directory.join(format!("validator-{index}"));
        if index == 0 {
            let wrong: Command = replace_value(
                &open_command(
                    network,
                    index,
                    &recipients[index],
                    &parent,
                    "wrong-namespace",
                ),
                "--chain-id",
                OsString::from("foreign"),
            );
            refusal(run(wrong, end), "recovery proof refused");
            assert_absent(
                &parent.join("wrong-namespace/checkpoint-complete-v2.bin"),
                "wrong namespace remains unqualified",
            );
            let missing: PathBuf = parent.join("missing-authority.sqlite");
            let wrong: Command = replace_value(
                &open_command(
                    network,
                    index,
                    &recipients[index],
                    &parent,
                    "missing-authority-output",
                ),
                "--independent-anchor-db",
                missing.as_os_str().to_owned(),
            );
            refusal(run(wrong, end), "recovery proof refused");
            assert_absent(&missing, "recovery never enrolls missing authority");
            assert_absent(
                &sidecar(&missing, ".lease"),
                "recovery never creates missing authority lease",
            );
            assert_absent(
                &parent.join("missing-authority-output"),
                "missing authority refuses before receiving candidate files",
            );
        }
        let line: String = recovery_success(run(
            open_command(network, index, &recipients[index], &parent, "restored"),
            end,
        ));
        assert_eq!(
            line,
            "business_recovery=checkpoint-opened files=2 meaning=current-local-store-next-fence-and-serving-pins-still-required\n"
        );
        complete(&parent.join("restored"));
        assert_eq!(
            current_restored(
                network,
                index,
                &owner.restored[index].0,
                &owner.restored[index].1,
                end
            ),
            published[index],
            "actual compiled checkpoint reinspection matches independently held publication"
        );
        if index == 0 {
            refusal(
                run(
                    open_command(network, index, &recipients[index], &parent, "restored"),
                    end,
                ),
                "recovery publication refused",
            );
            complete(&parent.join("restored"));
        }
        owner.assert_originals_unavailable();
        assert_eq!(
            anchors.images(),
            authority_images,
            "decrypt/currentness verification never modifies independent acknowledged rows"
        );
    }
    let restored_images: Vec<sqlite_durable_image::Image> = owner
        .restored
        .iter()
        .map(|(state, blobs)| sqlite_durable_image::capture(state, blobs))
        .collect();
    assert_eq!(
        restored_images, owner.original_images,
        "compiled pack/open preserves every one of12+2 closed tables"
    );
    assert!(
        Instant::now() < end,
        "full four-validator source-free checkpoint group deadline"
    );
    owner
}
