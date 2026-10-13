//! Shared Unix ownership/permission/TOCTOU checks for custody-owned paths.
//!
//! This implements exactly the first OS-permission model DR-0214 lists as
//! "dedicated encrypted local custody" (without the encryption): a fixed,
//! exact-mode, non-symlink regular file under a fixed, exact-mode parent
//! directory. It does not claim resistance to a compromised root or local
//! administrator; the kernel's own owner/mode enforcement is the only trust
//! boundary this module relies on, consistent with
//! `docs/architecture/decisions/0214-protected-custody-and-review-boundary.md`.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use super::error::CustodyError;

fn exact_mode(metadata: &fs::Metadata) -> u32 {
    metadata.permissions().mode() & 0o777
}

fn io_error(path: &Path, source: std::io::Error) -> CustodyError {
    CustodyError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Verifies `dir` is a non-symlink directory at exactly `expected_mode`.
pub(super) fn require_private_dir(dir: &Path, expected_mode: u32) -> Result<(), CustodyError> {
    let metadata = fs::symlink_metadata(dir).map_err(|source| io_error(dir, source))?;
    if metadata.file_type().is_symlink() {
        return Err(CustodyError::Symlink(dir.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(CustodyError::NotADirectory(dir.to_path_buf()));
    }
    let mode = exact_mode(&metadata);
    if mode != expected_mode {
        return Err(CustodyError::UnexpectedMode {
            path: dir.to_path_buf(),
            expected: expected_mode,
            actual: mode,
        });
    }
    Ok(())
}

fn parent_of(path: &Path) -> Result<&Path, CustodyError> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| CustodyError::NotADirectory(path.to_path_buf()))
}

/// Reads a bounded, TOCTOU-protected private regular file: `path`'s parent
/// directory must already be exactly `expected_dir_mode`, and `path` itself
/// must not be a symlink and must be exactly `expected_file_mode`,
/// consistently both before and after opening (closing the same
/// validate-then-open race `apps/cli/src/seed.rs` documents).
pub(super) fn read_private_file(
    path: &Path,
    expected_file_mode: u32,
    expected_dir_mode: u32,
    read_cap: usize,
) -> Result<Vec<u8>, CustodyError> {
    require_private_dir(parent_of(path)?, expected_dir_mode)?;

    let pre_open = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if pre_open.file_type().is_symlink() {
        return Err(CustodyError::Symlink(path.to_path_buf()));
    }
    if !pre_open.is_file() {
        return Err(CustodyError::NotARegularFile(path.to_path_buf()));
    }
    let pre_mode = exact_mode(&pre_open);
    if pre_mode != expected_file_mode {
        return Err(CustodyError::UnexpectedMode {
            path: path.to_path_buf(),
            expected: expected_file_mode,
            actual: pre_mode,
        });
    }
    let pre_identity = (pre_open.dev(), pre_open.ino());

    let mut file = fs::File::open(path).map_err(|source| io_error(path, source))?;
    let opened = file.metadata().map_err(|source| io_error(path, source))?;
    if !opened.is_file() {
        return Err(CustodyError::NotARegularFile(path.to_path_buf()));
    }
    let opened_mode = exact_mode(&opened);
    if opened_mode != expected_file_mode {
        return Err(CustodyError::UnexpectedMode {
            path: path.to_path_buf(),
            expected: expected_file_mode,
            actual: opened_mode,
        });
    }
    if (opened.dev(), opened.ino()) != pre_identity {
        return Err(CustodyError::PathReplacedDuringOpen(path.to_path_buf()));
    }

    let mut buffer: Vec<u8> = Vec::new();
    let cap = u64::try_from(read_cap).unwrap_or(u64::MAX);
    file.by_ref()
        .take(cap.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|source| io_error(path, source))?;
    if buffer.len() > read_cap {
        return Err(CustodyError::FileTooLarge {
            path: path.to_path_buf(),
            maximum: read_cap,
        });
    }
    Ok(buffer)
}

/// Writes `contents` to `path` as a private file at exactly `mode`, under a
/// parent directory that must already be exactly `expected_dir_mode`.
/// Refuses to follow an existing symlink. When `replace` is `false`, refuses
/// if `path` already exists (used for key generation); when `true`, creates
/// or atomically truncates an existing regular file (used for idempotent
/// approval records), but still refuses an existing symlink or non-regular
/// file at `path`.
pub(super) fn write_private_file(
    path: &Path,
    expected_dir_mode: u32,
    mode: u32,
    contents: &[u8],
    replace: bool,
) -> Result<(), CustodyError> {
    require_private_dir(parent_of(path)?, expected_dir_mode)?;
    if replace {
        if let Ok(existing) = fs::symlink_metadata(path) {
            if existing.file_type().is_symlink() {
                return Err(CustodyError::Symlink(path.to_path_buf()));
            }
            if !existing.is_file() {
                return Err(CustodyError::NotARegularFile(path.to_path_buf()));
            }
        }
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).mode(mode);
    if replace {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    use std::io::Write;
    file.write_all(contents)
        .map_err(|source| io_error(path, source))?;
    // `OpenOptionsExt::mode` only applies to a newly created file; an
    // existing file keeps its prior mode unless set explicitly here.
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|source| io_error(path, source))?;
    Ok(())
}

#[cfg(test)]
pub(super) mod test_support {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    /// A self-cleaning temporary directory, mode `0o700` by default, unique
    /// per test process and call.
    pub struct TempDir(pub PathBuf);

    impl TempDir {
        pub fn new(mode: u32) -> Self {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sunrise-edge-cli-custody-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            Self(path)
        }

        pub fn child(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    pub fn write_mode_file(path: &std::path::Path, mode: u32, contents: &[u8]) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{TempDir, write_mode_file};
    use super::*;

    #[test]
    fn reads_a_correctly_permissioned_private_file() {
        let dir = TempDir::new(0o700);
        let path = dir.child("config");
        write_mode_file(&path, 0o600, b"hello");
        assert_eq!(
            read_private_file(&path, 0o600, 0o700, 4096).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn rejects_a_file_with_group_readable_mode() {
        let dir = TempDir::new(0o700);
        let path = dir.child("config");
        write_mode_file(&path, 0o640, b"hello");
        assert!(matches!(
            read_private_file(&path, 0o600, 0o700, 4096),
            Err(CustodyError::UnexpectedMode {
                expected: 0o600,
                actual: 0o640,
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_parent_directory_with_the_wrong_mode() {
        let dir = TempDir::new(0o750);
        let path = dir.child("config");
        write_mode_file(&path, 0o600, b"hello");
        assert!(matches!(
            read_private_file(&path, 0o600, 0o700, 4096),
            Err(CustodyError::UnexpectedMode {
                expected: 0o700,
                actual: 0o750,
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_symlink() {
        let dir = TempDir::new(0o700);
        let target = dir.child("real");
        write_mode_file(&target, 0o600, b"hello");
        let link = dir.child("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            read_private_file(&link, 0o600, 0o700, 4096),
            Err(CustodyError::Symlink(_))
        ));
    }

    #[test]
    fn rejects_a_file_larger_than_the_bound() {
        let dir = TempDir::new(0o700);
        let path = dir.child("config");
        write_mode_file(&path, 0o600, b"0123456789");
        assert!(matches!(
            read_private_file(&path, 0o600, 0o700, 4),
            Err(CustodyError::FileTooLarge { maximum: 4, .. })
        ));
    }

    #[test]
    fn write_private_file_refuses_an_existing_path_when_not_replacing() {
        let dir = TempDir::new(0o700);
        let path = dir.child("key");
        write_private_file(&path, 0o700, 0o600, b"first", false).unwrap();
        assert!(write_private_file(&path, 0o700, 0o600, b"second", false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
    }

    #[test]
    fn write_private_file_replaces_idempotently_when_requested() {
        let dir = TempDir::new(0o700);
        let path = dir.child("approval");
        write_private_file(&path, 0o700, 0o600, b"first", true).unwrap();
        write_private_file(&path, 0o700, 0o600, b"second", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        let mode = fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn write_private_file_never_follows_a_symlink_at_the_target_path() {
        let dir = TempDir::new(0o700);
        let victim = dir.child("victim");
        write_mode_file(&victim, 0o600, b"untouched");
        let link = dir.child("approval");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(matches!(
            write_private_file(&link, 0o700, 0o600, b"attack", true),
            Err(CustodyError::Symlink(_))
        ));
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    }
}
