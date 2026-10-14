//! Durable, administrator-owned publication approval revocations (DR-0244).
//! A request ID stays revoked even if its old approval record is restored.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sunrise_edge_client::RequestId;

use crate::args::{ParsedArgs, parse_flags, scalar};
use crate::error::CliError;
use crate::hex::decode_hex_32;

use super::approvals::{APPROVAL_FILE_MODE, APPROVALS_DIR_MODE};
use super::error::CustodyError;
use super::fsperm::{read_private_file, require_private_dir, sync_directory, write_private_file};

const RECORD_VERSION: u8 = 1;
const RECORD_BYTES: usize = 1 + 32;

fn record_path(dir: &Path, request_id: &RequestId) -> PathBuf {
    dir.join(format!("{request_id}.revoked"))
}

/// Missing means unrevoked; malformed or inaccessible records are errors,
/// never permission to sign. No expiry or unrevocation route exists.
pub(super) fn is_revoked(dir: &Path, request_id: &RequestId) -> Result<bool, CustodyError> {
    require_private_dir(dir, APPROVALS_DIR_MODE)?;
    let path: PathBuf = record_path(dir, request_id);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(CustodyError::Io { path, source }),
    }
    let bytes: Vec<u8> =
        read_private_file(&path, APPROVAL_FILE_MODE, APPROVALS_DIR_MODE, RECORD_BYTES)?;
    if bytes.len() != RECORD_BYTES
        || bytes[0] != RECORD_VERSION
        || &bytes[1..] != request_id.as_bytes()
    {
        return Err(CustodyError::RevocationMalformed);
    }
    Ok(true)
}

/// Publish complete bytes without overwrite and synchronize the directory.
/// An identical existing record makes an explicit retry idempotent.
pub(super) fn revoke(dir: &Path, request_id: &RequestId) -> Result<(), CustodyError> {
    revoke_with_retry_sync(dir, request_id, sync_directory)
}

fn revoke_with_retry_sync(
    dir: &Path,
    request_id: &RequestId,
    sync: impl FnOnce(&Path) -> Result<(), CustodyError>,
) -> Result<(), CustodyError> {
    let mut bytes: [u8; RECORD_BYTES] = [0; RECORD_BYTES];
    bytes[0] = RECORD_VERSION;
    bytes[1..].copy_from_slice(request_id.as_bytes());
    let path: PathBuf = record_path(dir, request_id);
    match write_private_file(&path, APPROVALS_DIR_MODE, APPROVAL_FILE_MODE, &bytes, false) {
        Ok(()) => Ok(()),
        Err(error @ CustodyError::Io { .. })
            if matches!(&error, CustodyError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            if is_revoked(dir, request_id)? {
                // A concurrent/previous writer may have linked the complete
                // synced bytes but not yet synced the directory entry.
                sync(dir)
            } else {
                // Sibling-name exhaustion can also return AlreadyExists.
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

pub(super) fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let specs = [scalar("--approvals-dir"), scalar("--request-id")];
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let request_id: RequestId = RequestId::new(decode_hex_32(
        "--request-id",
        parsed.require("--request-id")?,
    )?)?;
    revoke(Path::new(parsed.require("--approvals-dir")?), &request_id)?;
    println!("revoked=true");
    println!("request_id={request_id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::fsperm::test_support::{TempDir, write_mode_file};

    #[test]
    fn durable_revocation_is_idempotent_and_scoped_to_one_request() {
        let dir = TempDir::new(APPROVALS_DIR_MODE);
        let id = RequestId::new([7; 32]).unwrap();
        let other = RequestId::new([8; 32]).unwrap();
        assert!(!is_revoked(&dir.0, &id).unwrap());
        revoke(&dir.0, &id).unwrap();
        let original = std::fs::read(record_path(&dir.0, &id)).unwrap();
        assert_eq!(original, [vec![RECORD_VERSION], vec![7; 32]].concat());
        revoke(&dir.0, &id).unwrap();
        assert_eq!(std::fs::read(record_path(&dir.0, &id)).unwrap(), original);
        assert!(is_revoked(&dir.0, &id).unwrap());
        assert!(!is_revoked(&dir.0, &other).unwrap());
    }

    #[test]
    fn malformed_wrong_id_and_unknown_version_never_unrevoke() {
        let dir = TempDir::new(APPROVALS_DIR_MODE);
        let id = RequestId::new([7; 32]).unwrap();
        let path = record_path(&dir.0, &id);
        for bytes in [
            vec![],
            vec![1],
            vec![2; RECORD_BYTES],
            vec![1; RECORD_BYTES],
        ] {
            write_mode_file(&path, APPROVAL_FILE_MODE, &bytes);
            assert!(is_revoked(&dir.0, &id).is_err());
            assert!(revoke(&dir.0, &id).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn retry_does_not_report_success_when_directory_sync_fails() {
        let dir = TempDir::new(APPROVALS_DIR_MODE);
        let id = RequestId::new([6; 32]).unwrap();
        revoke(&dir.0, &id).unwrap();
        let error = revoke_with_retry_sync(&dir.0, &id, |path| {
            assert_eq!(path, dir.0);
            Err(CustodyError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::other("injected retry directory-sync failure"),
            })
        })
        .unwrap_err();
        assert!(matches!(error, CustodyError::Io { .. }));
        assert!(is_revoked(&dir.0, &id).unwrap());
        revoke(&dir.0, &id).unwrap();
    }

    #[test]
    fn symlink_and_wrong_permissions_are_refused_without_replacement() {
        let dir = TempDir::new(APPROVALS_DIR_MODE);
        let id = RequestId::new([9; 32]).unwrap();
        let path = record_path(&dir.0, &id);
        let other = dir.child("other");
        write_mode_file(&other, APPROVAL_FILE_MODE, b"preserve");
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(is_revoked(&dir.0, &id).is_err());
        assert!(revoke(&dir.0, &id).is_err());
        assert_eq!(std::fs::read(&other).unwrap(), b"preserve");
        std::fs::remove_file(&path).unwrap();
        write_mode_file(&path, 0o640, &[1; RECORD_BYTES]);
        assert!(is_revoked(&dir.0, &id).is_err());
        assert!(revoke(&dir.0, &id).is_err());
    }
}
