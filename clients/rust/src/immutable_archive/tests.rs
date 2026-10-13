//! Structural/local I/O controls, not cryptographic recovery qualification.
#![cfg(target_os = "linux")]

use super::*;
use std::{
    fs::{self, DirBuilder, OpenOptions},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new() -> Self {
        let nonce: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root: PathBuf = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "sunrise-bounded-archive-{}-{nonce}",
            std::process::id()
        ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        // Only this create-new synthetic test root; never source/operator residue.
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct OwnedChild(Child);

impl OwnedChild {
    fn wait(&mut self) -> ExitStatus {
        let expires: Instant = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= expires {
                self.0.kill().unwrap();
                let _ = self.0.wait().unwrap(); // Kill AND reap even on timeout.
                panic!("bounded synthetic attachment child timed out");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn budget() -> ArchiveReadBudget {
    ArchiveReadBudget::new(Default::default()).unwrap()
}

#[test]
fn ordinary_read_compatibility_and_public_send_sync() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<ImmutableArchiveReader>();
    send_sync::<ArchiveReadBudget>();
    send_sync::<AttachedRegularFile>();
    let root: OwnedDirectory = OwnedDirectory::new();
    fs::write(root.0.join("raw.bin"), b"original\0unchanged").unwrap();
    let ordinary: ImmutableArchiveReader = ImmutableArchiveReader::open(&root.0).unwrap();
    let bounded: ImmutableArchiveReader =
        ImmutableArchiveReader::open_bounded(&root.0, &budget()).unwrap();
    assert!(ordinary.read_budget().is_none());
    assert_eq!(
        ordinary.read("raw.bin", 64).unwrap(),
        bounded.read("raw.bin", 64).unwrap()
    );
    assert_eq!(ordinary.names().unwrap(), bounded.names().unwrap());
    // Ordinary genesis intentionally follows a leaf symlink; only the new profile refuses.
    symlink("raw.bin", root.0.join("genesis-link.bin")).unwrap();
    assert_eq!(
        crate::local_genesis::read_bounded(&root.0.join("genesis-link.bin"), 64).unwrap(),
        b"original\0unchanged"
    );
    assert!(bounded.read("genesis-link.bin", 64).is_err());
}

#[test]
fn constructor_charges_orphans_and_never_reads_or_changes_their_bytes() {
    let root: OwnedDirectory = OwnedDirectory::new();
    let staging: PathBuf = root.0.join(ARCHIVE_STAGING_DIRECTORY);
    fs::create_dir(&staging).unwrap();
    let empty: ArchiveReadBudget = budget();
    ImmutableArchiveReader::open_bounded(&root.0, &empty).unwrap();
    let empty_work: u64 = empty.used_observations();
    let orphan: PathBuf = staging.join(".cut-123-0.tmp");
    fs::write(&orphan, [0xff, 0, 0x80, 0x7f]).unwrap();
    let observed: ArchiveReadBudget = budget();
    let archive: ImmutableArchiveReader =
        ImmutableArchiveReader::open_bounded(&root.0, &observed).unwrap();
    assert_eq!(observed.used_observations(), empty_work + 1);
    assert!(archive.names().unwrap().is_empty());
    assert_eq!(fs::read(&orphan).unwrap(), [0xff, 0, 0x80, 0x7f]);
    let exhausted: ArchiveReadBudget = ArchiveReadBudget::new(ArchiveReadLimits {
        observations: empty_work,
        ..Default::default()
    })
    .unwrap();
    assert!(ImmutableArchiveReader::open_bounded(&root.0, &exhausted).is_err());
    assert!(exhausted.clone().check().is_err());
    assert_eq!(fs::read(&orphan).unwrap(), [0xff, 0, 0x80, 0x7f]);
}

#[test]
fn repeated_walks_and_sibling_roles_exhaust_one_budget_without_reset() {
    let root: OwnedDirectory = OwnedDirectory::new();
    fs::write(root.0.join("one.bin"), b"one").unwrap();
    let calibration: ArchiveReadBudget = budget();
    ImmutableArchiveReader::open_bounded(&root.0, &calibration).unwrap();
    let shared: ArchiveReadBudget = ArchiveReadBudget::new(ArchiveReadLimits {
        observations: calibration.used_observations() * 2 + 20,
        ..Default::default()
    })
    .unwrap();
    let first: ImmutableArchiveReader =
        ImmutableArchiveReader::open_bounded(&root.0, &shared).unwrap();
    let sibling: ImmutableArchiveReader =
        ImmutableArchiveReader::open_bounded(&root.0, &shared.clone()).unwrap();
    let mut refused: bool = false;
    for _ in 0..100 {
        if first.names().is_err() {
            refused = true;
            break;
        }
        if sibling.names().is_err() {
            refused = true;
            break;
        }
    }
    assert!(refused);
    assert!(shared.check().is_err());
    assert!(first.read("one.bin", 3).is_err());
    assert!(ImmutableArchiveReader::open_bounded(&root.0, &shared).is_err());
}

#[test]
fn nested_inventory_retains_directory_markers_and_refuses_symlink_descent() {
    let root: OwnedDirectory = OwnedDirectory::new();
    fs::create_dir_all(root.0.join("height-00000000000000000001/component-01")).unwrap();
    fs::write(
        root.0.join("height-00000000000000000001/descriptor.bin"),
        b"untrusted",
    )
    .unwrap();
    let archive: ImmutableArchiveReader =
        ImmutableArchiveReader::open_bounded(&root.0, &budget()).unwrap();
    let names: BTreeSet<String> = archive.names_recursive().unwrap();
    assert!(names.contains("height-00000000000000000001/"));
    assert!(names.contains("height-00000000000000000001/component-01/"));
    symlink(
        "height-00000000000000000001",
        root.0.join("foreign-directory"),
    )
    .unwrap();
    assert!(archive.names_recursive().is_err());
}

#[test]
fn zero_budget_refuses_before_missing_root_lookup_and_relative_paths_are_closed() {
    let zero: ArchiveReadBudget = ArchiveReadBudget::new(ArchiveReadLimits {
        observations: 0,
        ..Default::default()
    })
    .unwrap();
    let error: io::Error =
        ImmutableArchiveReader::open_bounded(Path::new("/missing-bounded-before-io"), &zero)
            .err()
            .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    for name in ["", "/x", "../x", "x/../y", "x//y", "x/./y", "x\\y", "x\0y"] {
        assert!(ImmutableArchiveReader::relative_filename(name).is_err());
    }
    assert!(ImmutableArchiveReader::relative_filename(&"x".repeat(252)).is_err());
}

#[test]
fn body_cap_refuses_before_materialization_and_root_replacement_stays_attached() {
    let root: OwnedDirectory = OwnedDirectory::new();
    let archive_path: PathBuf = root.0.join("role");
    fs::create_dir(&archive_path).unwrap();
    fs::write(archive_path.join("one.bin"), b"three").unwrap();
    let limited: ArchiveReadBudget = ArchiveReadBudget::new(ArchiveReadLimits {
        file_bytes: 2,
        ..Default::default()
    })
    .unwrap();
    let archive: ImmutableArchiveReader =
        ImmutableArchiveReader::open_bounded(&archive_path, &limited).unwrap();
    assert!(archive.read("one.bin", 64).is_err());
    assert!(limited.clone().check().is_err());
    let attached: ImmutableArchiveReader =
        ImmutableArchiveReader::open_bounded(&archive_path, &budget()).unwrap();
    fs::rename(&archive_path, root.0.join("original-role")).unwrap();
    fs::create_dir(&archive_path).unwrap();
    fs::write(archive_path.join("one.bin"), b"three").unwrap();
    assert!(attached.names().is_err());
    assert!(attached.read("one.bin", 64).is_err());
}

#[test]
fn private_policy_precedes_reads_and_exact_cap_has_real_physical_eof() {
    let root: OwnedDirectory = OwnedDirectory::new();
    let path: PathBuf = root.0.join("identity.bin");
    fs::write(&path, b"synthetic-not-a-real-key").unwrap();
    let uid: u32 = fs::metadata(&path).unwrap().uid();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        AttachedRegularFile::open(
            &path,
            64,
            &budget(),
            AttachedFilePolicy::private_identity(uid)
        )
        .is_err()
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        AttachedRegularFile::open(
            &path,
            64,
            &budget(),
            AttachedFilePolicy::private_identity(uid ^ 1)
        )
        .is_err()
    );
    fs::hard_link(&path, root.0.join("second-link")).unwrap();
    assert!(
        AttachedRegularFile::open(
            &path,
            64,
            &budget(),
            AttachedFilePolicy::private_identity(uid)
        )
        .is_err()
    );
    fs::remove_file(root.0.join("second-link")).unwrap();
    let length: u64 = fs::metadata(&path).unwrap().len();
    let mut input: AttachedRegularFile = AttachedRegularFile::open(
        &path,
        length,
        &budget(),
        AttachedFilePolicy::private_identity(uid),
    )
    .unwrap();
    let mut bytes: Vec<u8> = Vec::new();
    input.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"synthetic-not-a-real-key");
    let mut probe: [u8; 1] = [0];
    assert_eq!(input.read(&mut probe).unwrap(), 0);
    assert_eq!(input.observed_bytes(), length);
    input.ensure_attached().unwrap();
}

/// Runs only in an explicitly selected synthetic child, with closed environment.
#[test]
fn attachment_refusal_child() {
    let Ok(case) = std::env::var("SUNRISE_BOUNDED_ATTACHMENT_CASE") else {
        return;
    };
    let path: PathBuf = PathBuf::from(std::env::var_os("SUNRISE_BOUNDED_ATTACHMENT_PATH").unwrap());
    if case == "replace" || case == "replace-symlink" || case == "replace-fifo" {
        let mut input: AttachedRegularFile =
            AttachedRegularFile::open(&path, 64, &budget(), AttachedFilePolicy::public()).unwrap();
        fs::rename(&path, path.with_extension("old")).unwrap();
        if case == "replace-symlink" {
            symlink("target", &path).unwrap();
        } else if case == "replace-fifo" {
            fs::rename(path.with_extension("fifo"), &path).unwrap();
        } else {
            fs::write(&path, b"replacement").unwrap();
        }
        assert!(input.read(&mut [0; 1]).is_err());
        assert!(input.read(&mut [0; 1]).is_err());
    } else if case == "mutate" {
        let mut input: AttachedRegularFile =
            AttachedRegularFile::open(&path, 64, &budget(), AttachedFilePolicy::public()).unwrap();
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        assert!(input.read(&mut [0; 1]).is_err());
    } else {
        assert!(
            AttachedRegularFile::open(&path, 64, &budget(), AttachedFilePolicy::public()).is_err()
        );
    }
}

#[test]
fn regular_symlink_and_fifo_refusals_are_owned_bounded_children() {
    let root: OwnedDirectory = OwnedDirectory::new();
    let path: PathBuf = root.0.join("input.bin");
    for case in [
        "replace",
        "mutate",
        "symlink",
        "fifo",
        "replace-symlink",
        "replace-fifo",
    ] {
        if path.exists() || fs::symlink_metadata(&path).is_ok() {
            fs::remove_file(&path).unwrap();
        }
        if case == "symlink" {
            fs::write(root.0.join("target"), b"synthetic-public").unwrap();
            symlink("target", &path).unwrap();
        } else if case == "fifo" || case == "replace-fifo" {
            let fifo: PathBuf = if case == "fifo" {
                path.clone()
            } else {
                path.with_extension("fifo")
            };
            let mut child: OwnedChild = OwnedChild(
                Command::new("/usr/bin/mkfifo")
                    .arg(&fifo)
                    .env_clear()
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            assert!(child.wait().success());
            if case == "replace-fifo" {
                fs::write(&path, b"synthetic-original").unwrap();
            }
        } else {
            fs::write(&path, b"synthetic-original").unwrap();
        }
        let mut child: OwnedChild = OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "immutable_archive::tests::attachment_refusal_child",
                ])
                .env_clear()
                .env("SUNRISE_BOUNDED_ATTACHMENT_CASE", case)
                .env("SUNRISE_BOUNDED_ATTACHMENT_PATH", &path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        assert!(child.wait().success(), "{case}");
    }
}
