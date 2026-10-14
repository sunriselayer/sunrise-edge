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
use std::path::{Path, PathBuf};

use super::error::CustodyError;

/// Bounded number of distinct private sibling names one non-replacing write
/// tries. A name is only ever already taken by a concurrent write in this
/// same process, or by an orphan an earlier writer with the same process ID
/// left behind (for example, after a crash).
const MAX_PENDING_ATTEMPTS: usize = 16;

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
/// parent directory that must already be exactly `expected_dir_mode`, and
/// returns only after both the bytes and the directory entry are
/// synchronized. Refuses to follow an existing symlink. When `replace` is
/// `false`, refuses if `path` already exists (used for key generation and
/// review preimages) and never leaves incomplete bytes there; see
/// `publish_new_private_file`. When `true`, creates or truncates an existing
/// regular file (used for idempotent approval records), but still refuses an
/// existing symlink or non-regular file at `path`.
pub(super) fn write_private_file(
    path: &Path,
    expected_dir_mode: u32,
    mode: u32,
    contents: &[u8],
    replace: bool,
) -> Result<(), CustodyError> {
    let parent = parent_of(path)?;
    require_private_dir(parent, expected_dir_mode)?;
    if !replace {
        return publish_new_private_file(
            path,
            parent,
            mode,
            contents,
            OnSyncFailure::RemoveLink,
            fs::File::sync_all,
        );
    }
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
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    write_synced(&mut file, mode, contents).map_err(|source| io_error(path, source))?;
    sync_directory(parent)
}

/// Publishes `contents` exactly like a non-replacing `write_private_file`,
/// except that a link whose directory synchronization fails is kept rather
/// than removed again (`OnSyncFailure::RetainLink`); that failure is still
/// reported, never success. Used for revocation records, whose identical
/// retry is idempotent and whose presence only ever reduces authority.
/// `sync` synchronizes the held directory handle (`fs::File::sync_all`,
/// unless a test injects a failure).
pub(super) fn publish_retained_private_file(
    path: &Path,
    expected_dir_mode: u32,
    mode: u32,
    contents: &[u8],
    sync: impl FnMut(&fs::File) -> std::io::Result<()>,
) -> Result<(), CustodyError> {
    let parent = parent_of(path)?;
    require_private_dir(parent, expected_dir_mode)?;
    publish_new_private_file(
        path,
        parent,
        mode,
        contents,
        OnSyncFailure::RetainLink,
        sync,
    )
}

/// What a non-replacing publication does with its own link when the
/// directory synchronization after that link fails. Either way, the failure
/// is reported, never success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OnSyncFailure {
    /// Remove the link again, and synchronize that removal, so an identical
    /// retry that refuses an existing path (such as `keygen`) is not blocked.
    RemoveLink,
    /// Keep the link, for a record whose identical retry is idempotent and
    /// whose presence only ever reduces authority (a revocation): an
    /// overlapping identical retry may already have found the complete
    /// linked bytes, synchronized the directory itself and reported durable
    /// success, which removing the link here would silently undo.
    RetainLink,
}

/// Publishes `contents` as a new private file at `path` without ever
/// replacing an existing entry or exposing incomplete bytes there. The bytes
/// are first written, given exactly `mode`, and synchronized in a freshly
/// created sibling inside the same private directory, then linked into place
/// with `link(2)`, which atomically refuses every existing destination (never
/// following a symlink), and the directory is synchronized before success is
/// reported. A failed write therefore leaves nothing at `path` to block an
/// identical retry, and a crash can leave at most an orphaned sibling that no
/// reader treats as the published file. A link whose directory
/// synchronization fails may already be durable regardless, so under
/// `OnSyncFailure::RemoveLink` it is removed again and that removal is
/// synchronized too, through the same directory handle; otherwise a crash
/// after the reported failure could still leave the complete file in place.
/// `OnSyncFailure::RetainLink` keeps it and reports only the failure. Cleanup
/// only ever removes an entry that is still this call's own inode. `sync`
/// synchronizes that held directory handle (`fs::File::sync_all`, unless a
/// test injects a failure).
fn publish_new_private_file(
    path: &Path,
    parent: &Path,
    mode: u32,
    contents: &[u8],
    on_sync_failure: OnSyncFailure,
    mut sync: impl FnMut(&fs::File) -> std::io::Result<()>,
) -> Result<(), CustodyError> {
    // Held from before the link, so the link and any rollback of it are both
    // synchronized through this one handle, and a directory this call cannot
    // even open never receives an entry at all.
    let directory = fs::File::open(parent).map_err(|source| io_error(parent, source))?;
    let (pending_path, mut pending) = create_pending_sibling(path, parent, mode)?;
    let published = write_synced(&mut pending, mode, contents)
        .and_then(|()| fs::hard_link(&pending_path, path))
        .map_err(|source| io_error(path, source));
    // The sibling is never the published file: remove it on every outcome.
    // On success, the directory synchronization below makes that durable.
    remove_if_same_file(&pending_path, &pending);
    published?;
    if let Err(source) = sync(&directory) {
        // Never report an entry that may not be durable.
        if on_sync_failure == OnSyncFailure::RemoveLink {
            // Never leave it behind to block an identical retry either. A
            // failed synchronization does not prove the link never reached
            // the disk, so its removal is synchronized too; otherwise a crash
            // after this reported failure could still leave the complete file
            // in place. Both steps are best-effort cleanup that never masks
            // this failure.
            remove_if_same_file(path, &pending);
            let _ = sync(&directory);
        }
        return Err(io_error(parent, source));
    }
    Ok(())
}

/// The private sibling name a non-replacing write tries on `attempt`.
fn pending_sibling_name(attempt: usize) -> String {
    format!(".custody-pending-{}-{attempt}", std::process::id())
}

/// Exclusively creates (`O_EXCL`) a fresh sibling at `mode` inside `parent`,
/// trying a bounded number of distinct names. Creation errors name `path`,
/// the file the caller actually asked to write; running out of names is
/// reported against `parent`, which holds the conflicting entries.
fn create_pending_sibling(
    path: &Path,
    parent: &Path,
    mode: u32,
) -> Result<(PathBuf, fs::File), CustodyError> {
    for attempt in 0..MAX_PENDING_ATTEMPTS {
        let pending_path = parent.join(pending_sibling_name(attempt));
        // The caller may itself have chosen a sibling-shaped file name.
        if pending_path == path {
            continue;
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&pending_path)
        {
            Ok(file) => return Ok((pending_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error(path, source)),
        }
    }
    Err(io_error(
        parent,
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "every bounded private sibling name is already taken",
        ),
    ))
}

/// Writes all of `contents`, sets exactly `mode` (`OpenOptionsExt::mode`
/// only applies to a newly created file, narrowed by the umask; an existing
/// file keeps its prior mode unless set explicitly here), then synchronizes
/// the file's data and metadata.
fn write_synced(file: &mut fs::File, mode: u32, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    file.write_all(contents)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()
}

/// Synchronizes `dir` itself, so entries just created in or removed from it
/// are durable before success is reported.
pub(super) fn sync_directory(dir: &Path) -> Result<(), CustodyError> {
    fs::File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|source| io_error(dir, source))
}

/// Removes `path` only while it is still exactly `file`'s own inode, never a
/// symlink or a replacement left at that path. Best-effort: a failed cleanup
/// never masks the result being reported.
fn remove_if_same_file(path: &Path, file: &fs::File) {
    let (Ok(current), Ok(held)) = (fs::symlink_metadata(path), file.metadata()) else {
        return;
    };
    if (current.dev(), current.ino()) == (held.dev(), held.ino()) {
        let _ = fs::remove_file(path);
    }
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

    /// Every entry name in `dir`, sorted, so a test can prove exactly which
    /// entries a write left behind (in particular, no private sibling).
    fn entry_names(dir: &TempDir) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&dir.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn write_private_file_refuses_an_existing_path_when_not_replacing() {
        let dir = TempDir::new(0o700);
        let path = dir.child("key");
        write_private_file(&path, 0o700, 0o600, b"first", false).unwrap();
        assert!(write_private_file(&path, 0o700, 0o600, b"second", false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        // The refused write also removed its own private sibling.
        assert_eq!(entry_names(&dir), ["key"]);
    }

    /// A new (non-replacing) write publishes exactly the requested bytes at
    /// exactly the requested mode, and leaves no private sibling behind.
    #[test]
    fn write_private_file_publishes_a_new_file_without_leaving_a_sibling() {
        let dir = TempDir::new(0o700);
        let path = dir.child("key");
        write_private_file(&path, 0o700, 0o600, b"complete", false).unwrap();
        assert_eq!(
            read_private_file(&path, 0o600, 0o700, 4096).unwrap(),
            b"complete"
        );
        assert_eq!(entry_names(&dir), ["key"]);
    }

    /// `link(2)` refuses every existing destination, so a non-replacing
    /// write never follows or replaces a symlink at the target path, not
    /// even a dangling one, and still removes its own private sibling.
    #[test]
    fn write_private_file_never_replaces_a_symlink_when_not_replacing() {
        let dir = TempDir::new(0o700);
        let victim = dir.child("victim");
        let link = dir.child("key");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(write_private_file(&link, 0o700, 0o600, b"attack", false).is_err());
        let metadata = fs::symlink_metadata(&link).unwrap();
        assert!(metadata.file_type().is_symlink());
        assert!(fs::symlink_metadata(&victim).is_err());
        assert_eq!(entry_names(&dir), ["key"]);
    }

    /// A crashed earlier writer can leave at most an orphaned (possibly
    /// partial) private sibling, never a partial file at the target path.
    /// Such an orphan never blocks a later write, and that write never
    /// deletes it, since it is not that write's own file.
    #[test]
    fn an_orphaned_pending_sibling_never_blocks_a_new_write() {
        let dir = TempDir::new(0o700);
        let orphan_name = pending_sibling_name(0);
        let orphan = dir.child(&orphan_name);
        write_mode_file(&orphan, 0o600, b"partial");
        let path = dir.child("key");
        write_private_file(&path, 0o700, 0o600, b"complete", false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"complete");
        assert_eq!(fs::read(&orphan).unwrap(), b"partial");
        assert_eq!(entry_names(&dir), [orphan_name.as_str(), "key"]);
    }

    /// The sibling search is bounded: once every bounded name is taken, the
    /// write is refused without creating the target or touching an orphan.
    #[test]
    fn write_private_file_refuses_once_every_sibling_name_is_taken() {
        let dir = TempDir::new(0o700);
        for attempt in 0..MAX_PENDING_ATTEMPTS {
            let orphan = dir.child(&pending_sibling_name(attempt));
            write_mode_file(&orphan, 0o600, b"orphan");
        }
        let path = dir.child("key");
        assert!(write_private_file(&path, 0o700, 0o600, b"complete", false).is_err());
        assert!(fs::symlink_metadata(&path).is_err());
        assert_eq!(entry_names(&dir).len(), MAX_PENDING_ATTEMPTS);
    }

    /// A link whose directory synchronization fails is removed again, and
    /// that removal is itself synchronized through the same held directory
    /// handle: the link may already be durable regardless, so an
    /// unsynchronized removal could let a crash keep the complete file, which
    /// a non-replacing retry such as `keygen` would then refuse.
    #[test]
    fn a_failed_directory_sync_removes_the_link_and_synchronizes_the_removal() {
        const INJECTED: &str = "injected directory sync failure";
        let dir = TempDir::new(0o700);
        let path = dir.child("key");
        let parent = fs::metadata(&dir.0).unwrap();
        let mut synchronized: Vec<Vec<String>> = Vec::new();
        let fail_first = |directory: &fs::File| {
            let held = directory.metadata().unwrap();
            assert_eq!((held.dev(), held.ino()), (parent.dev(), parent.ino()));
            synchronized.push(entry_names(&dir));
            if synchronized.len() == 1 {
                return Err(std::io::Error::other(INJECTED));
            }
            directory.sync_all()
        };
        let result = publish_new_private_file(
            &path,
            &dir.0,
            0o600,
            b"complete",
            OnSyncFailure::RemoveLink,
            fail_first,
        );
        assert!(matches!(
            result,
            Err(CustodyError::Io { path: failed, source })
                if failed == dir.0 && source.to_string() == INJECTED
        ));
        // The first synchronization saw exactly the link; the second ran only
        // after the rollback had removed it again.
        assert_eq!(synchronized.len(), 2);
        assert_eq!(synchronized[0], ["key"]);
        assert!(synchronized[1].is_empty());
        // Nothing is left behind to block an identical retry.
        assert!(entry_names(&dir).is_empty());
        write_private_file(&path, 0o700, 0o600, b"complete", false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"complete");
    }

    /// A retained link whose directory synchronization fails keeps its
    /// complete bytes, and only the failure is reported, with no rollback or
    /// second synchronization: an overlapping identical retry, such as a
    /// second revocation, may already have reported that link durable.
    #[test]
    fn a_failed_directory_sync_keeps_a_retained_link_in_place() {
        const INJECTED: &str = "injected directory sync failure";
        let dir = TempDir::new(0o700);
        let path = dir.child("record");
        let mut synchronized: Vec<Vec<String>> = Vec::new();
        let result = publish_new_private_file(
            &path,
            &dir.0,
            0o600,
            b"complete",
            OnSyncFailure::RetainLink,
            |_directory| {
                synchronized.push(entry_names(&dir));
                Err(std::io::Error::other(INJECTED))
            },
        );
        assert!(matches!(
            result,
            Err(CustodyError::Io { path: failed, source })
                if failed == dir.0 && source.to_string() == INJECTED
        ));
        assert_eq!(synchronized.len(), 1);
        assert_eq!(synchronized[0], ["record"]);
        assert_eq!(
            read_private_file(&path, 0o600, 0o700, 4096).unwrap(),
            b"complete"
        );
        assert_eq!(entry_names(&dir), ["record"]);
    }

    /// Cleanup removes a path only while it is still the cleaner's own
    /// inode: its own file is removed, a replacement survives untouched.
    #[test]
    fn remove_if_same_file_removes_only_its_own_inode() {
        let dir = TempDir::new(0o700);
        let own = dir.child("own");
        write_mode_file(&own, 0o600, b"own");
        remove_if_same_file(&own, &fs::File::open(&own).unwrap());
        assert!(fs::symlink_metadata(&own).is_err());

        let replaced = dir.child("replaced");
        write_mode_file(&replaced, 0o600, b"original");
        // Held open, so the replacement can never reuse the original inode.
        let original = fs::File::open(&replaced).unwrap();
        fs::remove_file(&replaced).unwrap();
        write_mode_file(&replaced, 0o600, b"replacement");
        remove_if_same_file(&replaced, &original);
        assert_eq!(fs::read(&replaced).unwrap(), b"replacement");
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
