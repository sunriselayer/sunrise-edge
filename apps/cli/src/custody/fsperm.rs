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

/// Includes the setuid/setgid/sticky bits (`0o7000`) in addition to the
/// ordinary owner/group/other permission bits (`0o0777`): a setuid/setgid
/// file masked away by a narrower `0o777` comparison would silently pass an
/// "exactly mode 0600" check while still carrying a dangerous special bit.
fn exact_mode(metadata: &fs::Metadata) -> u32 {
    metadata.permissions().mode() & 0o7777
}

fn io_error(path: &Path, source: std::io::Error) -> CustodyError {
    CustodyError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Reads this process's own current effective UID from a safe, bounded
/// parse of `/proc/self/status`'s `Uid:` line (Linux-specific), rather than
/// an `unsafe` `libc::geteuid` call or a new dependency. Unlike
/// `super::selfuid::own_uid`, this needs no Tokio runtime: it is called from
/// plain synchronous config/key/approval loading paths that run before any
/// runtime exists, as well as from inside `serve`'s own async context, and
/// must not spin up a nested runtime in either case.
fn current_effective_uid() -> Result<u32, CustodyError> {
    /// Generous bound for one bounded read of `/proc/self/status`, which is
    /// a small fixed-shape pseudo-file; this bounds the read before any
    /// parsing is attempted rather than reading to an unbounded `String`.
    const MAX_STATUS_BYTES: usize = 8192;
    let status_path = Path::new("/proc/self/status");
    let mut file = fs::File::open(status_path).map_err(|source| io_error(status_path, source))?;
    let mut buffer = String::new();
    file.by_ref()
        .take(u64::try_from(MAX_STATUS_BYTES).unwrap_or(u64::MAX))
        .read_to_string(&mut buffer)
        .map_err(|source| io_error(status_path, source))?;
    for line in buffer.lines() {
        // The `Uid:` line is `Uid:\t<real>\t<effective>\t<saved>\t<fs>`; the
        // effective UID is the second whitespace-separated field.
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest
                .split_whitespace()
                .nth(1)
                .and_then(|field| field.parse::<u32>().ok())
                .ok_or(CustodyError::SelfUidUnavailable);
        }
    }
    Err(CustodyError::SelfUidUnavailable)
}

/// Verifies `dir` is a non-symlink directory at exactly `expected_mode`,
/// owned by this process's own current effective UID.
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
    let own_uid = current_effective_uid()?;
    if metadata.uid() != own_uid {
        return Err(CustodyError::UnexpectedOwner {
            path: dir.to_path_buf(),
            expected: own_uid,
            actual: metadata.uid(),
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
    let own_uid = current_effective_uid()?;
    if pre_open.uid() != own_uid {
        return Err(CustodyError::UnexpectedOwner {
            path: path.to_path_buf(),
            expected: own_uid,
            actual: pre_open.uid(),
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
    // Re-checked on the already-opened handle too, not only on the
    // pre-open path metadata: a handle's metadata cannot be changed by a
    // later filesystem replacement, so this closes the same TOCTOU race the
    // dev/ino identity check below closes for file identity.
    if opened.uid() != own_uid {
        return Err(CustodyError::UnexpectedOwner {
            path: path.to_path_buf(),
            expected: own_uid,
            actual: opened.uid(),
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
            // Refuse to truncate/take over a file this process does not
            // already own, even though its mode happens to match.
            let own_uid = current_effective_uid()?;
            if existing.uid() != own_uid {
                return Err(CustodyError::UnexpectedOwner {
                    path: path.to_path_buf(),
                    expected: own_uid,
                    actual: existing.uid(),
                });
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

    /// Cross-checks the two independent, differently-implemented current-UID
    /// derivations this crate relies on: `current_effective_uid`'s bounded
    /// synchronous `/proc/self/status` parse (used by every fsperm check,
    /// including from plain sync code with no Tokio runtime), and
    /// `selfuid::own_uid`'s async `UnixStream::pair`/`peer_cred` derivation
    /// (used by `serve`'s own startup operator-UID check). They must agree.
    #[tokio::test(flavor = "current_thread")]
    async fn current_effective_uid_matches_the_async_peer_cred_derived_uid() {
        let sync_uid = current_effective_uid().unwrap();
        let async_uid = super::super::selfuid::own_uid().await.unwrap();
        assert_eq!(sync_uid, async_uid);
    }

    /// Every fixture file/directory in this test module is created by this
    /// same test process, so it is always owned by this process's own
    /// current effective UID; this proves the added owner check does not
    /// spuriously reject that completely ordinary case. A genuine
    /// wrong-owner fixture needs a second real UID (root, or `chown`
    /// privileges) and is exercised by the separate distinct-UID Docker
    /// fixture, not here.
    #[test]
    fn read_private_file_accepts_a_file_owned_by_this_process() {
        let dir = TempDir::new(0o700);
        let path = dir.child("config");
        write_mode_file(&path, 0o600, b"hello");
        let own_uid = current_effective_uid().unwrap();
        assert_eq!(fs::symlink_metadata(&path).unwrap().uid(), own_uid);
        assert_eq!(fs::symlink_metadata(&dir.0).unwrap().uid(), own_uid);
        read_private_file(&path, 0o600, 0o700, 4096).unwrap();
    }

    /// A setuid/setgid/sticky bit is not masked away by the exact-mode
    /// check: `0o4600` must be rejected even though `0o4600 & 0o777 ==
    /// 0o600`, proving special bits are compared, not only the ordinary
    /// owner/group/other bits.
    #[test]
    fn rejects_a_file_with_an_unexpected_setuid_bit() {
        let dir = TempDir::new(0o700);
        let path = dir.child("config");
        write_mode_file(&path, 0o4600, b"hello");
        assert!(matches!(
            read_private_file(&path, 0o600, 0o700, 4096),
            Err(CustodyError::UnexpectedMode {
                expected: 0o600,
                actual: 0o4600,
                ..
            })
        ));
    }
}
