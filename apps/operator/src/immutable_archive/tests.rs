use super::*;

/// Test-only child-process stop; this code is absent from ordinary libraries
/// and the compiled operator executable. No environment flag changes authority.
pub(super) fn publication_checkpoint(point: &str, root: &Path) -> io::Result<()> {
    if std::env::var("SUNRISE_CUT_TEST_ROLE").as_deref() != Ok("cut-export-worker")
        || std::env::var("SUNRISE_CUT_TEST_CHECKPOINT").as_deref() != Ok(point)
    {
        return Ok(());
    }
    let expected: PathBuf = std::env::var_os("SUNRISE_CUT_TEST_ROOT")
        .ok_or_else(|| invalid("missing test root"))?
        .into();
    if root != expected {
        return Ok(());
    }
    let signal: PathBuf = std::env::var_os("SUNRISE_CUT_TEST_SIGNAL")
        .ok_or_else(|| invalid("missing test signal"))?
        .into();
    let temporary_signal: PathBuf = signal.with_extension("ready.tmp");
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_signal)?;
    file.write_all(point.as_bytes())?;
    file.sync_all()?;
    // Expose the test notification only once its complete bytes are durable.
    // It is outside both the final artifact and staging inventories.
    std::fs::hard_link(&temporary_signal, &signal)?;
    std::fs::remove_file(&temporary_signal)?;
    File::open(
        signal
            .parent()
            .ok_or_else(|| invalid("missing signal parent"))?,
    )?
    .sync_all()?;
    loop {
        std::thread::park();
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence: u64 = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-cut-archive-{}-{sequence}",
            std::process::id(),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored: io::Result<()> = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn output_placement_refuses_input_descendants_without_creating_files() {
    let directory: TestDirectory = TestDirectory::new();
    let source: PathBuf = directory.0.join("input");
    let nested: PathBuf = source.join("nested");
    let sibling: PathBuf = directory.0.join("input-other");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&nested).unwrap();
    std::fs::create_dir(&sibling).unwrap();
    let archive: ImmutableArchive = ImmutableArchive::open_read_only(&source).unwrap();
    for destination in [
        source.join("state.sqlite"),
        source.join("./blobs.sqlite"),
        nested.join("state.sqlite"),
        source.join("../input-other/state.sqlite"),
    ] {
        assert!(archive.require_output_outside(&destination).is_err());
        assert!(!destination.exists());
    }
    let outside: PathBuf = sibling.join("state.sqlite");
    archive.require_output_outside(&outside).unwrap();
    assert!(!outside.exists(), "placement validation is read-only");
    #[cfg(unix)]
    {
        let alias: PathBuf = directory.0.join("input-alias");
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(
            archive
                .require_output_outside(&alias.join("state.sqlite"))
                .is_err()
        );
        assert!(!source.join("state.sqlite").exists());
    }
}

#[test]
fn exact_publication_and_bounded_reads_preserve_original_bytes() {
    let directory: TestDirectory = TestDirectory::new();
    let archive: ImmutableArchive = ImmutableArchive::open(&directory.0).unwrap();
    assert!(!archive.contains("component.bin").unwrap());
    assert!(archive.publish("component.bin", b"exact\0bytes").unwrap());
    assert!(!archive.publish("component.bin", b"exact\0bytes").unwrap());
    assert!(archive.publish("component.bin", b"changed").is_err());
    assert_eq!(archive.read("component.bin", 11).unwrap(), b"exact\0bytes");
    assert!(archive.read("component.bin", 10).is_err());
    assert!(archive.publish("../outside.bin", b"no").is_err());
    assert!(archive.publish("nested/file.bin", b"no").is_err());
    assert!(archive.publish("/absolute.bin", b"no").is_err());
    assert!(archive.publish("empty.bin", b"").unwrap());
    assert!(archive.read("empty.bin", 0).unwrap().is_empty());
}

#[test]
fn unowned_temporary_collision_is_not_removed_or_accepted() {
    let directory: TestDirectory = TestDirectory::new();
    let archive: ImmutableArchive = ImmutableArchive::open(&directory.0).unwrap();
    let collision: PathBuf = archive
        .staging()
        .unwrap()
        .path()
        .join(format!(".cut-{}-123.tmp", std::process::id()));
    std::fs::write(&collision, b"not ours").unwrap();
    assert!(
        archive
            .publish_number("result.bin", b"complete", 123)
            .is_err()
    );
    assert_eq!(std::fs::read(&collision).unwrap(), b"not ours");
    assert!(!archive.contains("result.bin").unwrap());
    assert!(
        archive
            .publish_number("result.bin", b"complete", 124)
            .unwrap()
    );
}

#[cfg(unix)]
#[test]
fn file_and_directory_substitution_refuse_before_publication() {
    let directory: TestDirectory = TestDirectory::new();
    let archive: ImmutableArchive = ImmutableArchive::open(&directory.0).unwrap();
    let original: PathBuf = directory.0.join("original");
    let link: PathBuf = directory.0.join("link");
    std::fs::write(&original, b"original").unwrap();
    std::os::unix::fs::symlink(&original, &link).unwrap();
    assert!(archive.read("link", 8).is_err());
    assert!(archive.publish("link", b"original").is_err());
    assert_eq!(std::fs::read(&original).unwrap(), b"original");

    let moved: PathBuf = directory.0.with_extension("held");
    std::fs::rename(&directory.0, &moved).unwrap();
    std::fs::create_dir(&directory.0).unwrap();
    assert!(archive.publish("result.bin", b"complete").is_err());
    assert!(archive.contains("result.bin").is_err());
    assert!(!directory.0.join("result.bin").exists());
    drop(archive);
    std::fs::remove_dir_all(&moved).unwrap();
}

#[cfg(unix)]
#[test]
fn archive_root_and_ancestor_symlinks_refuse_before_artifact_reads() {
    let directory: TestDirectory = TestDirectory::new();
    let actual: PathBuf = directory.0.join("actual");
    std::fs::create_dir(&actual).unwrap();
    let nested: PathBuf = actual.join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join("component.bin"), b"unchanged").unwrap();
    let alias: PathBuf = directory.0.join("alias");
    std::os::unix::fs::symlink(&actual, &alias).unwrap();
    assert!(ImmutableArchive::open(&alias).is_err());
    assert!(ImmutableArchive::open(&alias.join("nested")).is_err());
    assert_eq!(
        std::fs::read(nested.join("component.bin")).unwrap(),
        b"unchanged"
    );
    let regular: ImmutableArchive = ImmutableArchive::open(&nested).unwrap();
    assert_eq!(regular.read("component.bin", 9).unwrap(), b"unchanged");
    std::fs::create_dir(nested.join("foreign-directory")).unwrap();
    assert!(regular.names().is_err());
}

#[test]
fn staging_orphans_are_not_final_inventory_and_never_adopted_or_deleted() {
    let directory: TestDirectory = TestDirectory::new();
    let archive: ImmutableArchive = ImmutableArchive::open(&directory.0).unwrap();
    let orphan: PathBuf = archive.staging().unwrap().path().join(".cut-123-0.tmp");
    std::fs::write(&orphan, b"not the reconstructed component").unwrap();
    drop(archive);
    let resumed: ImmutableArchive = ImmutableArchive::open(&directory.0).unwrap();
    assert!(resumed.names().unwrap().is_empty());
    assert!(
        resumed
            .publish("component.bin", b"reconstructed exact bytes")
            .unwrap()
    );
    assert_eq!(
        resumed.read("component.bin", 25).unwrap(),
        b"reconstructed exact bytes"
    );
    assert_eq!(
        std::fs::read(&orphan).unwrap(),
        b"not the reconstructed component"
    );
    let final_prefix: PathBuf = directory.0.join(".cut-123-0.tmp");
    std::fs::write(&final_prefix, b"foreign final artifact").unwrap();
    assert!(resumed.names().unwrap().contains(".cut-123-0.tmp"));
    let unknown: PathBuf = resumed.staging().unwrap().path().join("unknown.bin");
    std::fs::write(&unknown, b"not an owned temporary name").unwrap();
    assert!(resumed.names().is_err());
    assert!(ImmutableArchive::open(&directory.0).is_err());
    assert_eq!(
        std::fs::read(&unknown).unwrap(),
        b"not an owned temporary name"
    );
}

#[test]
fn read_only_archive_never_creates_staging_or_publishes() {
    let directory: TestDirectory = TestDirectory::new();
    std::fs::write(directory.0.join("component.bin"), b"exact").unwrap();
    let archive: ImmutableArchive = ImmutableArchive::open_read_only(&directory.0).unwrap();
    assert_eq!(archive.read("component.bin", 5).unwrap(), b"exact");
    assert!(!directory.0.join(STAGING_DIRECTORY).exists());
    assert!(archive.publish("new.bin", b"no").is_err());
    assert!(!directory.0.join("new.bin").exists());
    let writable: ImmutableArchive = ImmutableArchive::open(&directory.0).unwrap();
    drop(writable);
    let existing: ImmutableArchive = ImmutableArchive::open_read_only(&directory.0).unwrap();
    assert!(existing.publish("new.bin", b"no").is_err());
}

#[test]
fn sdk_reader_never_creates_the_operator_staging_role() {
    let directory: TestDirectory = TestDirectory::new();
    std::fs::write(directory.0.join("component.bin"), b"exact").unwrap();
    let reader: ImmutableArchiveReader = ImmutableArchiveReader::open(&directory.0).unwrap();
    assert_eq!(reader.read("component.bin", 5).unwrap(), b"exact");
    assert_eq!(reader.names().unwrap().len(), 1);
    assert!(reader.staging().is_none());
    assert!(!directory.0.join(STAGING_DIRECTORY).exists());

    let writer: ImmutableArchive = ImmutableArchive::open(&directory.0).unwrap();
    assert!(directory.0.join(STAGING_DIRECTORY).is_dir());
    assert!(writer.publish("published.bin", b"complete").unwrap());
    let saved: ImmutableArchiveReader = ImmutableArchiveReader::open(&directory.0).unwrap();
    assert_eq!(saved.read("published.bin", 8).unwrap(), b"complete");
}

#[cfg(unix)]
#[test]
fn staging_symlink_substitution_and_unknown_role_names_refuse() {
    let directory: TestDirectory = TestDirectory::new();
    let archive: ImmutableArchive = ImmutableArchive::open(&directory.0).unwrap();
    let outside: PathBuf = directory.0.join("outside.bin");
    std::fs::write(&outside, b"unchanged").unwrap();
    let stage: PathBuf = archive.staging().unwrap().path().to_path_buf();
    let link: PathBuf = stage.join(".cut-123-0.tmp");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert!(archive.names().is_err());
    assert!(ImmutableArchive::open_read_only(&directory.0).is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"unchanged");
    std::fs::remove_file(&link).unwrap();
    let held: PathBuf = directory.0.join("held-stage");
    std::fs::rename(&stage, &held).unwrap();
    std::fs::create_dir(&stage).unwrap();
    assert!(archive.publish("component.bin", b"no").is_err());
    assert!(!directory.0.join("component.bin").exists());
    assert!(archive.names().is_err());
}
