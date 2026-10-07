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
            sqlite.busy_timeout(DEFAULT_BUSY_TIMEOUT)?;
            sqlite.pragma_update(None, "trusted_schema", "OFF")?;
            let trusted: i64 =
                sqlite.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
            if trusted != 0 {
                return Err(rusqlite::Error::InvalidQuery.into());
            }
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
