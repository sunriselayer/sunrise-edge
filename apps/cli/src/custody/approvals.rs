//! Local, file-based approval records.
//!
//! `custody approve` is the only writer. `custody serve` only ever reads
//! this store; per DR-0214/the human-approve contract, it never writes an
//! approval from a live caller request. Each record is keyed by request id
//! and binds the *whole* exact signable frame (not merely its digest),
//! the publisher it was approved for, and an explicit expiry.

use std::path::{Path, PathBuf};

use sunrise_edge_client::{Address, RequestId};

use super::error::CustodyError;
use super::fsperm::{read_private_file, require_private_dir, write_private_file};
use super::wire::MAX_CUSTODY_REQUEST_FRAME_BYTES;

/// Required exact approvals-directory mode.
pub(super) const APPROVALS_DIR_MODE: u32 = 0o700;
/// Required exact approval-record file mode.
pub(super) const APPROVAL_FILE_MODE: u32 = 0o600;
const RECORD_VERSION: u8 = 1;
const RECORD_HEADER_BYTES: usize = 1 + 32 + 8 + 4;
/// A frame can never exceed the request frame bound (it is built from the
/// same bounded artifact); reuse that bound rather than inventing a second.
const MAX_RECORD_FILE_BYTES: usize = RECORD_HEADER_BYTES + MAX_CUSTODY_REQUEST_FRAME_BYTES;

/// One human-approved exact signable frame, bound to its expected publisher
/// and an explicit expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub publisher: Address,
    pub not_after_unix_seconds: u64,
    pub frame: Vec<u8>,
}

fn record_path(dir: &Path, request_id: &RequestId) -> PathBuf {
    // `RequestId`'s `Display` is exactly 64 lowercase hex characters: a safe,
    // collision-resistant-by-protocol-invariant filename component with no
    // path separators.
    dir.join(request_id.to_string())
}

/// Writes (creating or idempotently replacing) the approval record for
/// `request_id`. Only ever called by `custody approve`.
pub fn write_approval(
    dir: &Path,
    request_id: &RequestId,
    record: &ApprovalRecord,
) -> Result<(), CustodyError> {
    if super::revoke::is_revoked(dir, request_id)? {
        return Err(CustodyError::ApprovalRevoked);
    }
    let frame_len =
        u32::try_from(record.frame.len()).map_err(|_| CustodyError::ApprovalMalformed)?;
    let mut bytes = Vec::with_capacity(RECORD_HEADER_BYTES + record.frame.len());
    bytes.push(RECORD_VERSION);
    bytes.extend_from_slice(record.publisher.as_bytes());
    bytes.extend_from_slice(&record.not_after_unix_seconds.to_be_bytes());
    bytes.extend_from_slice(&frame_len.to_be_bytes());
    bytes.extend_from_slice(&record.frame);
    let path = record_path(dir, request_id);
    write_private_file(&path, APPROVALS_DIR_MODE, APPROVAL_FILE_MODE, &bytes, true)?;
    // A concurrent revocation wins even if this write already completed.
    if super::revoke::is_revoked(dir, request_id)? {
        return Err(CustodyError::ApprovalRevoked);
    }
    Ok(())
}

/// Reads the approval record for `request_id`, if any. Only ever called by
/// `custody serve`, and only ever to read.
pub fn read_approval(
    dir: &Path,
    request_id: &RequestId,
) -> Result<Option<ApprovalRecord>, CustodyError> {
    require_private_dir(dir, APPROVALS_DIR_MODE)?;
    let path = record_path(dir, request_id);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(CustodyError::Io { path, source });
        }
    }
    let bytes = read_private_file(
        &path,
        APPROVAL_FILE_MODE,
        APPROVALS_DIR_MODE,
        MAX_RECORD_FILE_BYTES,
    )?;
    if bytes.len() < RECORD_HEADER_BYTES {
        return Err(CustodyError::ApprovalMalformed);
    }
    if bytes[0] != RECORD_VERSION {
        return Err(CustodyError::ApprovalUnsupportedVersion(bytes[0]));
    }
    let mut publisher_bytes = [0_u8; 32];
    publisher_bytes.copy_from_slice(&bytes[1..33]);
    let not_after_unix_seconds = u64::from_be_bytes(
        bytes[33..41]
            .try_into()
            .map_err(|_| CustodyError::ApprovalMalformed)?,
    );
    let frame_len = u32::from_be_bytes(
        bytes[41..45]
            .try_into()
            .map_err(|_| CustodyError::ApprovalMalformed)?,
    ) as usize;
    let expected_total = RECORD_HEADER_BYTES
        .checked_add(frame_len)
        .ok_or(CustodyError::ApprovalMalformed)?;
    if bytes.len() != expected_total {
        return Err(CustodyError::ApprovalMalformed);
    }
    Ok(Some(ApprovalRecord {
        publisher: Address::new(publisher_bytes),
        not_after_unix_seconds,
        frame: bytes[RECORD_HEADER_BYTES..].to_vec(),
    }))
}

/// Whether `record` is expired at `now_unix_seconds` (exclusive: expiry
/// itself is already refused, never a boundary grace moment).
#[must_use]
pub const fn is_expired(record: &ApprovalRecord, now_unix_seconds: u64) -> bool {
    now_unix_seconds >= record.not_after_unix_seconds
}

#[cfg(test)]
mod tests {
    use super::super::fsperm::test_support::TempDir;
    use super::*;

    fn request_id(byte: u8) -> RequestId {
        RequestId::new([byte; 32]).unwrap()
    }

    #[test]
    fn missing_record_reads_as_none() {
        let dir = TempDir::new(APPROVALS_DIR_MODE);
        assert_eq!(read_approval(&dir.0, &request_id(1)).unwrap(), None);
    }

    #[test]
    fn write_then_read_round_trips_exactly() {
        let dir = TempDir::new(APPROVALS_DIR_MODE);
        let id = request_id(7);
        let record = ApprovalRecord {
            publisher: Address::new([0x44; 32]),
            not_after_unix_seconds: 1_000,
            frame: vec![1, 2, 3, 4, 5],
        };
        write_approval(&dir.0, &id, &record).unwrap();
        assert_eq!(read_approval(&dir.0, &id).unwrap(), Some(record));
    }

    #[test]
    fn writing_the_same_request_id_twice_is_idempotent_and_overwrites() {
        let dir = TempDir::new(APPROVALS_DIR_MODE);
        let id = request_id(9);
        let first = ApprovalRecord {
            publisher: Address::new([0x11; 32]),
            not_after_unix_seconds: 1,
            frame: vec![1],
        };
        let second = ApprovalRecord {
            publisher: Address::new([0x22; 32]),
            not_after_unix_seconds: 2,
            frame: vec![2, 2],
        };
        write_approval(&dir.0, &id, &first).unwrap();
        write_approval(&dir.0, &id, &second).unwrap();
        assert_eq!(read_approval(&dir.0, &id).unwrap(), Some(second));
    }

    #[test]
    fn expiry_is_exclusive_at_the_boundary() {
        let record = ApprovalRecord {
            publisher: Address::new([0; 32]),
            not_after_unix_seconds: 100,
            frame: vec![],
        };
        assert!(!is_expired(&record, 99));
        assert!(is_expired(&record, 100));
        assert!(is_expired(&record, 101));
    }

    #[test]
    fn rejects_an_approvals_directory_with_the_wrong_mode() {
        let dir = TempDir::new(0o750);
        assert!(matches!(
            read_approval(&dir.0, &request_id(1)),
            Err(CustodyError::UnexpectedMode { .. })
        ));
    }
}
