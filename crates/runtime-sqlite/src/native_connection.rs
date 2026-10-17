//! One native settings and physical attachment owner. No raw VFS/handle access.
use crate::native_files::{self, ImportFile};
use rusqlite::{Connection, OpenFlags};
use std::{io, path::Path, time::Duration};

pub(crate) const MAX_BUSY_TIMEOUT_MILLIS: u64 = 5_000;
pub(crate) const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_millis(MAX_BUSY_TIMEOUT_MILLIS);

#[derive(Debug)]
pub(crate) enum NativeError {
    File(io::Error),
    Database(rusqlite::Error),
    JournalMode(String),
    CommitIndeterminate,
}

impl From<rusqlite::Error> for NativeError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}
impl From<io::Error> for NativeError {
    fn from(error: io::Error) -> Self {
        Self::File(error)
    }
}

/// Sets and reads back connection-local settings; never changes file identity
/// or repairs an application's schema. Only a fresh/development caller selects WAL.
pub(crate) fn configure_writable(connection: &Connection) -> rusqlite::Result<()> {
    connection.busy_timeout(DEFAULT_BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;
    verify_writable(connection)
}

fn verify_writable(connection: &Connection) -> rusqlite::Result<()> {
    for (name, expected) in [
        ("foreign_keys", 1_i64),
        ("trusted_schema", 0_i64),
        ("synchronous", 2_i64),
        ("wal_autocheckpoint", 1_000_i64),
    ] {
        let actual: i64 = connection.pragma_query_value(None, name, |row| row.get(0))?;
        if actual != expected {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "SQLite setting {name}: expected {expected}, found {actual}"
            )));
        }
    }
    Ok(())
}

fn configure_read_only(connection: &Connection) -> rusqlite::Result<()> {
    connection.busy_timeout(DEFAULT_BUSY_TIMEOUT)?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    let trusted: i64 = connection.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
    if trusted != 0 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClosedSnapshotStamp {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

#[cfg(target_os = "linux")]
fn snapshot_stamp(path: &Path) -> Result<ClosedSnapshotStamp, NativeError> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    // The same bounded kernel effective-UID field used by the recovery owner;
    // no libc/unsafe or independent descriptor on a SQLite inode is required.
    let mut status: String = String::new();
    std::fs::File::open("/proc/self/status")?
        .take(16385)
        .read_to_string(&mut status)?;
    if status.len() > 16384 {
        return Err(rusqlite::Error::InvalidQuery.into());
    }
    let uid: u32 = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or(rusqlite::Error::InvalidQuery)?;
    let metadata: std::fs::Metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
    {
        return Err(rusqlite::Error::InvalidQuery.into());
    }
    Ok(ClosedSnapshotStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        length: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    })
}
#[cfg(not(target_os = "linux"))]
fn snapshot_stamp(_: &Path) -> Result<ClosedSnapshotStamp, NativeError> {
    Err(io::Error::from(io::ErrorKind::Unsupported).into())
}

#[derive(Debug)]
pub(crate) struct NativeConnection {
    pub(crate) sqlite: Connection,
    pub(crate) identity: ImportFile,
}

impl NativeConnection {
    pub(crate) fn open_existing(path: &Path, writable: bool) -> Result<Self, NativeError> {
        let identity: ImportFile = native_files::open_existing(path)?;
        Self::open_reserved(identity, writable, false)
    }

    pub(crate) fn open_development(path: &Path) -> Result<Self, NativeError> {
        if path == Path::new(":memory:") || path.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory-only development SQLite is not a guarded file profile",
            )
            .into());
        }
        // This explicit auto-bootstrap API can initialize an absent file, but
        // never treats a symlink or an unsupported existing file as fresh.
        let mut identity: ImportFile = match std::fs::symlink_metadata(path) {
            Ok(_) => native_files::open_existing(path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                native_files::create_new(path)?
            }
            Err(error) => return Err(error.into()),
        };
        identity.restrict_development();
        Self::open_reserved(identity, true, true)
    }

    pub(crate) fn open_reserved(
        mut identity: ImportFile,
        writable: bool,
        select_wal: bool,
    ) -> Result<Self, NativeError> {
        identity.check()?;
        let access: OpenFlags = if writable {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let sqlite: Connection =
            Connection::open_with_flags(identity.path(), access | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        identity.check()?;
        if writable {
            configure_writable(&sqlite)?;
        } else {
            configure_read_only(&sqlite)?;
        }
        if writable {
            let journal: String = sqlite.query_row(
                if select_wal {
                    "PRAGMA journal_mode = WAL"
                } else {
                    "PRAGMA journal_mode"
                },
                [],
                |row| row.get(0),
            )?;
            if !journal.eq_ignore_ascii_case("wal") {
                return Err(NativeError::JournalMode(journal));
            }
        }
        // Immutable source blob inspection retains its read-only contract;
        // writable FULL/WAL configuration is not imposed on that consumer.
        identity.check()?;
        Ok(Self { sqlite, identity })
    }

    pub(crate) fn closed_snapshot_stamp(path: &Path) -> Result<ClosedSnapshotStamp, NativeError> {
        snapshot_stamp(path)
    }

    /// Only a fully closed privately owned snapshot without sidecars may use
    /// immutable SQLite reads. This never inspects a live source through an
    /// immutable connection and never changes the archived WAL header bytes.
    pub(crate) fn open_closed_snapshot(path: &Path) -> Result<Self, NativeError> {
        native_files::require_no_sidecars(path)?;
        let before: ClosedSnapshotStamp = snapshot_stamp(path)?;
        let mut identity: ImportFile = native_files::open_existing(path)?;
        identity.check()?;
        #[cfg(unix)]
        let uri: String = {
            use std::os::unix::ffi::OsStrExt;
            let bytes: &[u8] = identity.path().as_os_str().as_bytes();
            if bytes.len() > 65536 {
                return Err(rusqlite::Error::InvalidQuery.into());
            }
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            let mut uri: String = String::with_capacity(bytes.len() * 3 + 32);
            uri.push_str("file:");
            for byte in bytes {
                match byte {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                        uri.push(char::from(*byte))
                    }
                    _ => {
                        uri.push('%');
                        uri.push(char::from(HEX[usize::from(*byte >> 4)]));
                        uri.push(char::from(HEX[usize::from(*byte & 15)]));
                    }
                }
            }
            uri.push_str("?mode=ro&immutable=1");
            uri
        };
        #[cfg(not(unix))]
        let uri: String = return Err(io::Error::from(io::ErrorKind::Unsupported).into());
        let sqlite: Connection = Connection::open_with_flags(
            &uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )?;
        configure_read_only(&sqlite)?;
        identity.check()?;
        native_files::require_no_sidecars(path)?;
        if snapshot_stamp(path)? != before {
            return Err(rusqlite::Error::InvalidQuery.into());
        }
        Ok(Self { sqlite, identity })
    }

    /// A fresh private snapshot chooses the source page size BEFORE WAL. No
    /// independent main-file descriptor remains open while SQLite owns it.
    pub(crate) fn snapshot_destination(path: &Path, page_size: i64) -> Result<Self, NativeError> {
        if !(512..=65536).contains(&page_size) || !(page_size as u64).is_power_of_two() {
            return Err(rusqlite::Error::InvalidQuery.into());
        }
        let mut identity: ImportFile = native_files::create_new_private(path)?;
        identity.check()?;
        let sqlite: Connection = Connection::open_with_flags(
            identity.path(),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        identity.check()?;
        sqlite.pragma_update(None, "page_size", page_size)?;
        configure_writable(&sqlite)?;
        let journal: String = sqlite.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if journal != "wal" {
            return Err(NativeError::JournalMode(journal));
        }
        identity.check()?;
        Ok(Self { sqlite, identity })
    }

    /// Scoped reads/maintenance stay inside the caller's mutex and check before
    /// releasing their output. This cannot eliminate hostile path-swap races.
    pub(crate) fn inspect<T, E: From<NativeError>>(
        &mut self,
        read: impl FnOnce(&Connection) -> Result<T, E>,
    ) -> Result<T, E> {
        self.identity.check().map_err(NativeError::from)?;
        let result: Result<T, E> = read(&self.sqlite);
        self.identity.check().map_err(NativeError::from)?;
        result
    }

    /// Complete SQLite-owned FULL checkpoint and cache flush; no leaf reopen.
    /// Check every checkpoint result field and sync the retained parent only.
    pub(crate) fn sync_created(&mut self) -> Result<(), NativeError> {
        self.identity.require_fresh()?;
        self.identity.check()?;
        if !self.sqlite.is_autocommit() || self.sqlite.is_busy() {
            return Err(rusqlite::Error::InvalidQuery.into());
        }
        let (busy, wal_frames, checkpointed): (i64, i64, i64) =
            self.sqlite
                .query_row("PRAGMA wal_checkpoint(FULL)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
        if busy != 0 || wal_frames < 0 || checkpointed < 0 || wal_frames != checkpointed {
            return Err(rusqlite::Error::InvalidQuery.into());
        }
        self.sqlite.cache_flush()?;
        self.identity
            .sync_parent()
            .map_err(|_| NativeError::CommitIndeterminate)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_test_connection(sqlite: Connection) -> Self {
        configure_writable(&sqlite).unwrap();
        let path: &str = sqlite.path().expect("test requires a real file");
        let identity: ImportFile = native_files::open_existing(Path::new(path)).unwrap();
        Self { sqlite, identity }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn writable_settings_are_verified_and_refuse_weakened_connections() {
        let connection: Connection = Connection::open_in_memory().unwrap();
        configure_writable(&connection).unwrap();
        for (name, bad) in [
            ("foreign_keys", 0_i64),
            ("trusted_schema", 1_i64),
            ("synchronous", 1_i64),
            ("wal_autocheckpoint", 0_i64),
        ] {
            connection.pragma_update(None, name, bad).unwrap();
            assert!(verify_writable(&connection).is_err(), "{name}");
            configure_writable(&connection).unwrap();
        }
    }
}
