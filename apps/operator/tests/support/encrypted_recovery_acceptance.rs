//! Additive compiled encrypted relocation over the caller's genuine producer.
//! Only ciphertext and a disposable typed identity cross into the cold root.
#![allow(dead_code)] // Compiled by both original and full recurring owners.

use super::compiled_source_host_process::spawn_strict_bounded_output;
use age::secrecy::ExposeSecret;
use node_core::business_reconstruction::SourceBusinessSnapshot;
use protocol_types::ValidatorId;
use runtime::portable::{DurableRecordKey, DurableRecordMetadata, PortableSnapshotToken};
use runtime::{
    DurableDomainStateStore, DurableOperationContext, ImportBinding, NamespaceLifecycle,
    StorageCorrelationId, StorageDeadline, WriterFenceGeneration,
};
use runtime_sqlite::{SqliteBlobStore, SqliteDurableStore, SqliteNamespace};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::Duration,
};

pub struct Relocation<'a> {
    pub recovery: &'a Path,
    pub importer: &'a Path,
    pub pins: &'a [OsString],
    pub cut: &'a Path,
    pub predecessors: &'a [[PathBuf; 4]],
    pub genesis: &'a Path,
    pub unavailable_roots: &'a [PathBuf],
    pub work: &'a Path,
    pub binding: &'a ImportBinding,
    pub validator: ValidatorId,
    pub expected_state: &'a BTreeMap<Vec<u8>, Vec<u8>>,
    pub expected_business: &'a SourceBusinessSnapshot,
}

fn execute(command: Command) -> Output {
    spawn_strict_bounded_output(command, Duration::from_secs(330))
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "compiled saved-closure stage failed: stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    String::from_utf8(output.stdout).expect("public ASCII recovery/import output")
}
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect()
}

pub fn public_pins(pins: &[OsString]) -> Vec<OsString> {
    assert_eq!(pins.len() % 2, 0);
    let mut result: Vec<OsString> = Vec::new();
    for pair in pins.chunks_exact(2) {
        match pair[0].to_str().unwrap() {
            "--genesis-manifest"
            | "--ordered-history-dir"
            | "--successor-plan-history-dir"
            | "--successor-cut-dir"
            | "--successor-manifest-history-dir"
            | "--successor-certificate-dir" => {}
            _ => result.extend_from_slice(pair),
        }
    }
    result
}
fn path_value(pins: &[OsString], name: &str) -> PathBuf {
    let pair: &[OsString] = pins
        .chunks_exact(2)
        .find(|pair: &&[OsString]| pair[0] == name)
        .expect("explicit history transport path");
    PathBuf::from(&pair[1])
}
fn role_paths(
    genesis: &Path,
    history: &Path,
    cut: &Path,
    predecessors: &[[PathBuf; 4]],
) -> Vec<(PathBuf, PathBuf)> {
    let mut roles: Vec<(PathBuf, PathBuf)> = vec![
        (genesis.to_path_buf(), PathBuf::from("genesis/genesis.bin")),
        (history.to_path_buf(), PathBuf::from("current/history")),
        (cut.to_path_buf(), PathBuf::from("current/cut")),
    ];
    for (index, paths) in predecessors.iter().enumerate() {
        for (name, source) in ["plan-history", "cut", "manifest-history", "certificate"]
            .into_iter()
            .zip(paths)
        {
            roles.push((
                source.clone(),
                PathBuf::from(format!("predecessors/link-{index:05}/{name}")),
            ));
        }
    }
    roles
}
fn inventory(path: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let metadata: std::fs::Metadata = std::fs::symlink_metadata(path).unwrap();
    if metadata.is_file() {
        return BTreeMap::from([(PathBuf::new(), Some(std::fs::read(path).unwrap()))]);
    }
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    let mut result: BTreeMap<PathBuf, Option<Vec<u8>>> = BTreeMap::new();
    let mut pending: Vec<PathBuf> = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry: std::fs::DirEntry = entry.unwrap();
            let relative: PathBuf = entry.path().strip_prefix(path).unwrap().to_path_buf();
            // The defining original archive owner explicitly excludes its
            // own unadopted publication staging role from proof inventory.
            if relative == Path::new(".cut-staging-v1") {
                continue;
            }
            let metadata: std::fs::Metadata = std::fs::symlink_metadata(entry.path()).unwrap();
            assert!(!metadata.file_type().is_symlink());
            let bytes: Option<Vec<u8>> = if metadata.is_dir() {
                pending.push(entry.path());
                None
            } else {
                assert!(metadata.is_file());
                Some(std::fs::read(entry.path()).unwrap())
            };
            assert!(result.insert(relative, bytes).is_none());
        }
    }
    result
}

struct HiddenRoots(Vec<(PathBuf, PathBuf)>);
impl HiddenRoots {
    fn hide(paths: Vec<PathBuf>) -> Self {
        let roots: BTreeSet<PathBuf> = paths.into_iter().collect();
        let selected: Vec<PathBuf> = roots
            .iter()
            .filter(|path: &&PathBuf| {
                !roots
                    .iter()
                    .any(|ancestor: &PathBuf| ancestor != *path && path.starts_with(ancestor))
            })
            .cloned()
            .collect();
        assert_no_source_fds(&selected);
        let mut hidden: Self = Self(Vec::new());
        for original in selected {
            let mut name = original.file_name().unwrap().to_os_string();
            name.push(".encrypted-recovery-unavailable");
            let destination: PathBuf = original.parent().unwrap().join(name);
            assert!(
                matches!(std::fs::symlink_metadata(&destination), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
            );
            std::fs::rename(&original, &destination).unwrap();
            hidden.0.push((original, destination));
        }
        hidden.assert_unavailable();
        hidden
    }
    fn assert_unavailable(&self) {
        for (path, _) in &self.0 {
            assert!(
                matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                "old source root became available"
            );
        }
    }
}
impl Drop for HiddenRoots {
    fn drop(&mut self) {
        for (original, hidden) in self.0.iter().rev() {
            std::fs::rename(hidden, original).expect("restore only this test's hidden input root");
        }
    }
}
#[cfg(target_os = "linux")]
pub fn assert_no_source_fds(roots: &[PathBuf]) {
    // Same-process, test-private attachment oracle. It never reads another
    // process, manager env, keyring, credential contents or protected profiles.
    for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
        let entry: std::fs::DirEntry = entry.unwrap();
        match std::fs::read_link(entry.path()) {
            Ok(target) => assert!(
                !roots.iter().any(|root: &PathBuf| target.starts_with(root)),
                "a source SQL/archive descriptor remains live before relocation"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {} // Own read_dir fd may have closed.
            Err(error) => panic!("self-FD attachment check failed: {error}"),
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub fn assert_no_source_fds(_: &[PathBuf]) {
    panic!("cold local recovery acceptance requires Linux");
}

pub fn relocate(input: Relocation<'_>) -> SourceBusinessSnapshot {
    let history: PathBuf = path_value(input.pins, "--ordered-history-dir");
    let roles: Vec<(PathBuf, PathBuf)> =
        role_paths(input.genesis, &history, input.cut, input.predecessors);
    assert_eq!(roles.len(), 3 + 4 * input.predecessors.len());
    let expected: Vec<BTreeMap<PathBuf, Option<Vec<u8>>>> =
        roles.iter().map(|(source, _)| inventory(source)).collect();
    let token: PortableSnapshotToken =
        sunrise_edge_client::business_cut_archive::decode_saved_source_token(
            &std::fs::read(input.cut.join("source-token.bin")).unwrap(),
        )
        .unwrap();
    let identity: age::x25519::Identity = age::x25519::Identity::generate();
    let recipient: String = identity.to_public().to_string();
    let key: PathBuf = input.work.join("disposable.identity");
    let secret = identity.to_string();
    std::fs::write(&key, secret.expose_secret().as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    drop(secret);
    drop(identity);
    let capture: PathBuf = input.work.join("capture");
    let encrypted: PathBuf = input.work.join("saved.age");
    let additions: Vec<OsString> = [
        "--expected-cut-digest",
        &hex(&input.binding.cut_digest.bytes()),
        "--expected-package-digest",
        &hex(&input.binding.package_digest.bytes()),
        "--recipient",
        &recipient,
        "--expected-links",
        &input.predecessors.len().to_string(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let pack = || -> Command {
        let mut command: Command = Command::new(input.recovery);
        command
            .arg("pack-saved")
            .args(input.pins)
            .args(&additions)
            .args([
                "--cut-dir",
                input.cut.to_str().unwrap(),
                "--capture-root",
                capture.to_str().unwrap(),
                "--ciphertext-out",
                encrypted.to_str().unwrap(),
            ]);
        command
    };
    assert!(success(execute(pack())).contains("business_recovery=packed"));
    for ((_, generated), expected) in roles.iter().zip(&expected) {
        assert_eq!(
            &inventory(&capture.join(generated)),
            expected,
            "every captured role keeps its original bytes and inventory"
        );
    }
    let diagnostic: Vec<u8> = std::fs::read(capture.join("recovery-complete-v1.bin")).unwrap();
    assert_eq!(diagnostic.len(), 49);
    let original_cipher: Vec<u8> = std::fs::read(&encrypted).unwrap();
    assert!(
        !execute(pack()).status.success(),
        "even identical existing pack outputs refuse, never resume/adopt"
    );
    assert_eq!(std::fs::read(&encrypted).unwrap(), original_cipher);
    let refusal = |cipher: &Path, key: &Path, output: &Path| -> Output {
        let mut command: Command = Command::new(input.recovery);
        command
            .arg("open-saved")
            .args(public_pins(input.pins))
            .args(&additions)
            .args([
                "--ciphertext-file",
                cipher.to_str().unwrap(),
                "--identity-file",
                key.to_str().unwrap(),
                "--out-dir",
                output.to_str().unwrap(),
            ]);
        execute(command)
    };
    let negative_root: PathBuf = input.work.join("negative-controls");
    std::fs::create_dir(&negative_root).unwrap();
    let malformed: PathBuf = negative_root.join("malformed.identity");
    let marker: &[u8] = b"AGE-SECRET-KEY-1-secret-like-disposable-invalid-line";
    std::fs::write(&malformed, marker).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&malformed, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let invalid_output: PathBuf = negative_root.join("invalid-identity-output");
    let invalid: Output = refusal(&encrypted, &malformed, &invalid_output);
    assert!(!invalid.status.success());
    assert!(
        !invalid_output.exists(),
        "identity validation precedes staging"
    );
    for bytes in [&invalid.stdout, &invalid.stderr] {
        assert!(
            !bytes
                .windows(marker.len())
                .any(|window: &[u8]| window == marker)
        );
    }
    // Real encrypted transport failures leave no completion marker. They are
    // not mock TLS/age failures or successful partial imports.
    for (name, bytes) in [
        (
            "truncated",
            original_cipher[..original_cipher.len() - 1].to_vec(),
        ),
        (
            "concatenated",
            original_cipher
                .iter()
                .chain(&original_cipher)
                .copied()
                .collect::<Vec<u8>>(),
        ),
        ("tampered", {
            let mut bytes: Vec<u8> = original_cipher.clone();
            let last: usize = bytes.len() - 1;
            bytes[last] ^= 1;
            bytes
        }),
    ] {
        let path: PathBuf = negative_root.join(format!("{name}.age"));
        std::fs::write(&path, bytes).unwrap();
        let output: PathBuf = negative_root.join(format!("{name}-output"));
        assert!(!refusal(&path, &key, &output).status.success());
        assert!(!output.join("recovery-complete-v1.bin").exists());
        if output.exists() {
            let before: BTreeMap<PathBuf, Option<Vec<u8>>> = inventory(&output);
            assert!(
                !refusal(&encrypted, &key, &output).status.success(),
                "incomplete stage is not adopted/repaired"
            );
            assert_eq!(inventory(&output), before);
        }
    }
    let cold: PathBuf = input.work.join("cold");
    std::fs::create_dir(&cold).unwrap();
    let cold_cipher: PathBuf = cold.join("saved.age");
    let cold_identity: PathBuf = cold.join("disposable.identity");
    std::fs::rename(&encrypted, &cold_cipher).unwrap();
    std::fs::rename(&key, &cold_identity).unwrap();
    let moved: BTreeSet<OsString> = std::fs::read_dir(&cold)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        moved,
        BTreeSet::from([
            OsString::from("saved.age"),
            OsString::from("disposable.identity")
        ])
    );
    let mut unavailable: Vec<PathBuf> = input.unavailable_roots.to_vec();
    unavailable.extend(roles.iter().map(|(source, _)| source.clone()));
    unavailable.push(capture.clone());
    unavailable.push(negative_root);
    let hidden: HiddenRoots = HiddenRoots::hide(unavailable);
    let opened: PathBuf = cold.join("opened");
    let mut open: Command = Command::new(input.recovery);
    open.arg("open-saved")
        .args(public_pins(input.pins))
        .args(&additions)
        .args([
            "--ciphertext-file",
            cold_cipher.to_str().unwrap(),
            "--identity-file",
            cold_identity.to_str().unwrap(),
            "--out-dir",
            opened.to_str().unwrap(),
        ]);
    assert!(success(execute(open)).contains("business_recovery=opened"));
    hidden.assert_unavailable();
    assert_eq!(
        std::fs::read(opened.join("recovery-complete-v1.bin")).unwrap(),
        diagnostic
    );
    assert!(
        !refusal(&cold_cipher, &cold_identity, &opened)
            .status
            .success(),
        "equal existing qualified output still refuses"
    );
    assert_eq!(
        std::fs::read(opened.join("recovery-complete-v1.bin")).unwrap(),
        diagnostic
    );
    for ((_, generated), expected) in roles.iter().zip(&expected) {
        assert_eq!(
            &inventory(&opened.join(generated)),
            expected,
            "every decrypted original raw role survives cold relocation"
        );
    }
    let mut restored_pins: Vec<OsString> = public_pins(input.pins);
    restored_pins.extend(
        [
            "--genesis-manifest",
            opened.join("genesis/genesis.bin").to_str().unwrap(),
            "--ordered-history-dir",
            opened.join("current/history").to_str().unwrap(),
        ]
        .into_iter()
        .map(OsString::from),
    );
    for index in 0..input.predecessors.len() {
        let link: PathBuf = opened.join(format!("predecessors/link-{index:05}"));
        for (flag, role) in [
            "--successor-plan-history-dir",
            "--successor-cut-dir",
            "--successor-manifest-history-dir",
            "--successor-certificate-dir",
        ]
        .into_iter()
        .zip(["plan-history", "cut", "manifest-history", "certificate"])
        {
            restored_pins.extend([OsString::from(flag), link.join(role).into_os_string()]);
        }
    }
    let target: PathBuf = cold.join("inactive");
    std::fs::create_dir(&target).unwrap();
    let state: PathBuf = target.join("state.db");
    let blobs: PathBuf = target.join("body.db");
    let import = |mode: &str, maximum: &str| -> Command {
        let mut command: Command = Command::new(input.importer);
        command.arg(mode).args(&restored_pins).args([
            "--cut-dir",
            opened.join("current/cut").to_str().unwrap(),
            "--state-db",
            state.to_str().unwrap(),
            "--blob-db",
            blobs.to_str().unwrap(),
            "--validator-id",
            &hex(input.validator.as_bytes()),
            "--max-new-batches",
            maximum,
        ]);
        command
    };
    let first: String = success(execute(import("create-sqlite", "1")));
    hidden.assert_unavailable();
    assert!(
        first.contains("business_import=partial")
            || first.contains("business_import=complete-inactive")
    );
    assert!(!first.contains("business_import=active"));
    assert!(
        success(execute(import("resume-sqlite", "4096")))
            .contains("business_import=complete-inactive")
    );
    hidden.assert_unavailable();
    let replay: String = success(execute(import("resume-sqlite", "1")));
    hidden.assert_unavailable();
    assert!(
        replay.contains("business_import=complete-inactive") && replay.contains("new_batches=0")
    );
    let namespace: SqliteNamespace = SqliteNamespace::new(
        input.binding.context.chain_id.clone(),
        input.validator,
        input.binding.domain,
    );
    assert!(
        SqliteDurableStore::open_existing(&state, namespace.clone()).is_err(),
        "cold recovery remains inactive, never ordinary-serving"
    );
    let store: SqliteDurableStore = SqliteDurableStore::open_historical(&state, namespace).unwrap();
    let own: WriterFenceGeneration = WriterFenceGeneration::new(1).unwrap();
    assert_eq!(store.writer_fence().unwrap(), own);
    let operation: DurableOperationContext = DurableOperationContext::new(
        own,
        StorageDeadline::new(u64::MAX / 2).unwrap(),
        StorageCorrelationId::new([0xed; 16]).unwrap(),
    );
    let NamespaceLifecycle::CompleteInactive { binding, .. } = store
        .get_namespace_lifecycle(&operation, input.binding.domain)
        .unwrap()
    else {
        panic!("new recovered destination remains CompleteInactive");
    };
    assert_eq!(&binding, input.binding);
    assert_eq!(binding.generation_floor, input.binding.generation_floor);
    let blobs: SqliteBlobStore = SqliteBlobStore::open_existing(&blobs).unwrap();
    let recovered: SourceBusinessSnapshot =
        sunrise_edge_operator::business_snapshot::capture_source_business_snapshot(
            &store,
            &blobs,
            &operation,
            input.binding.domain,
            std::num::NonZeroUsize::new(128).unwrap(),
        )
        .unwrap();
    assert_ne!(
        recovered.token.namespace(),
        token.namespace(),
        "physical instance/namespace is fresh, not copied source custody"
    );
    assert_eq!(recovered.token.writer_fence(), own);
    assert_eq!(
        logical_business(&recovered),
        logical_business(input.expected_business),
        "complete durable receipts and immutable object history keep logical bytes while replica-local revisions/checkpoints are fresh"
    );
    assert_eq!(
        recovered.referenced_blobs, input.expected_business.referenced_blobs,
        "full referenced blob bytes survive cold recovery"
    );
    for (key, bytes) in input.expected_state {
        let record = recovered.records.iter().find(|record| matches!(record.descriptor.key(), runtime::portable::DurableRecordKey::State(actual) if actual == key)).expect("full unlocked business state remains present");
        assert_eq!(record.value.as_deref(), Some(bytes.as_slice()));
    }
    drop(blobs);
    drop(store);
    hidden.assert_unavailable();
    drop(hidden); // Only after complete cold sequence.
    recovered
}

fn logical_business(
    snapshot: &SourceBusinessSnapshot,
) -> BTreeMap<DurableRecordKey, (DurableRecordMetadata, Option<Vec<u8>>)> {
    let mut result: BTreeMap<DurableRecordKey, (DurableRecordMetadata, Option<Vec<u8>>)> =
        BTreeMap::new();
    for record in &snapshot.records {
        if matches!(record.descriptor.key(), DurableRecordKey::State(_)) {
            continue;
        }
        let mut metadata: DurableRecordMetadata = record.descriptor.metadata().clone();
        match &mut metadata {
            DurableRecordMetadata::ObjectHead(
                runtime::DurableObjectHead::Current { head_revision, .. }
                | runtime::DurableObjectHead::Tombstoned { head_revision, .. },
            ) => *head_revision = runtime::ObjectHeadRevision::new(1).unwrap(),
            DurableRecordMetadata::ObjectVersion {
                created_checkpoint, ..
            } => *created_checkpoint = 0,
            _ => {}
        }
        assert!(
            result
                .insert(
                    record.descriptor.key().clone(),
                    (metadata, record.value.clone())
                )
                .is_none()
        );
    }
    result
}
