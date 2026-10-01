use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-cli-network-artifacts-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn bounded_read_preserves_exact_bytes_and_path_specific_error() {
    let directory: TestDirectory = TestDirectory::new();
    let path: PathBuf = directory.path("input");
    let path_text: &str = path.to_str().unwrap();
    let bytes: [u8; 4] = [0, 0xff, 0x80, 1];
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(read_bounded(path_text, bytes.len()).unwrap(), bytes);
    let error: CliError = read_bounded(path_text, bytes.len() - 1).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&format!("{path_text} exceeds the maximum accepted size"))
    );
    assert!(read_bounded(path_text, 0).is_err());
    std::fs::write(&path, []).unwrap();
    assert!(read_bounded(path_text, 0).unwrap().is_empty());
}

#[test]
fn reservation_rejects_aliases_before_creating_and_preserves_existing_bytes() {
    let directory: TestDirectory = TestDirectory::new();
    let path: PathBuf = directory.path("output");
    let path_text: &str = path.to_str().unwrap();
    let alias_error: CliError =
        match reserve_artifacts(&[(path_text, "intent"), (path_text, "certificate")], &[]) {
            Ok(_) => panic!("aliasing outputs must not be reserved"),
            Err(error) => error,
        };
    assert!(alias_error.to_string().contains("artifact paths alias"));
    assert!(!path.exists());

    let mut artifacts: Vec<ReservedArtifact> =
        reserve_artifacts(&[(path_text, "intent")], &[]).unwrap();
    assert_eq!(artifacts[0].path(), path);
    let bytes: [u8; 4] = [0, 0xff, 0x80, 1];
    artifacts[0].persist(&bytes).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let existing_error: CliError = match reserve_artifacts(&[(path_text, "intent")], &[]) {
        Ok(_) => panic!("existing outputs must not be overwritten"),
        Err(error) => error,
    };
    assert!(existing_error.to_string().contains(
        "an existing file is never overwritten; recover exact saved bytes rather than re-signing"
    ));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[cfg(unix)]
#[test]
fn input_symlinks_are_read_but_output_symlinks_and_directory_aliases_are_refused() {
    let directory: TestDirectory = TestDirectory::new();
    let original: PathBuf = directory.path("original");
    let link: PathBuf = directory.path("input-link");
    std::fs::write(&original, b"exact\0bytes").unwrap();
    std::os::unix::fs::symlink(&original, &link).unwrap();
    assert_eq!(
        read_bounded(link.to_str().unwrap(), 11).unwrap(),
        b"exact\0bytes"
    );
    assert!(read_bounded(link.to_str().unwrap(), 10).is_err());
    assert!(reserve_artifacts(&[(link.to_str().unwrap(), "intent")], &[]).is_err());
    assert_eq!(std::fs::read(&original).unwrap(), b"exact\0bytes");

    let parent_link: PathBuf = directory.path("parent-link");
    std::os::unix::fs::symlink(&directory.0, &parent_link).unwrap();
    let output: PathBuf = directory.path("output");
    let alias: PathBuf = parent_link.join("output");
    assert!(
        reserve_artifacts(
            &[
                (output.to_str().unwrap(), "intent"),
                (alias.to_str().unwrap(), "certificate")
            ],
            &[],
        )
        .is_err()
    );
    assert!(!output.exists());
}
