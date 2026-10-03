//! Local immutable artifact publication, not protocol or import authority.
//!
//! Complete bytes and the containing directory are synchronized before a
//! final filename is exposed. Existing bytes are compared, never overwritten.
//! Every read, attachment, filename and inventory rule is owned by the SDK
//! [ImmutableArchiveReader] this writer dereferences to; only staging
//! publication lives here.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    ops::Deref,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
#[cfg(test)]
use sunrise_edge_client::immutable_archive::ARCHIVE_STAGING_DIRECTORY as STAGING_DIRECTORY;
pub use sunrise_edge_client::immutable_archive::{ArchiveStagingDirectory, ImmutableArchiveReader};

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);
const MAX_STAGING_COLLISION_RETRIES: usize = 32;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// A caller-selected existing output directory. No saved marker is trusted.
pub struct ImmutableArchive {
    reader: ImmutableArchiveReader,
    writable: bool,
}

impl Deref for ImmutableArchive {
    type Target = ImmutableArchiveReader;

    fn deref(&self) -> &ImmutableArchiveReader {
        &self.reader
    }
}

impl ImmutableArchive {
    pub fn open(root: &Path) -> io::Result<Self> {
        Self::open_mode(root, true)
    }

    /// Opens saved material without creating a staging directory or artifact.
    /// This composition cannot publish, even if a valid staging role exists.
    pub fn open_read_only(root: &Path) -> io::Result<Self> {
        Self::open_mode(root, false)
    }

    fn open_mode(root: &Path, writable: bool) -> io::Result<Self> {
        let archive: Self = Self {
            reader: ImmutableArchiveReader::open_mode(root, writable)?,
            writable,
        };
        // Refuse unsupported directory synchronization before publication.
        if writable {
            archive.reader.directory().sync_all()?;
            archive.staging()?.directory().sync_all()?;
        }
        Ok(archive)
    }

    /// The held read-only handle, for shared SDK artifact consumers.
    #[must_use]
    pub fn into_reader(self) -> ImmutableArchiveReader {
        self.reader
    }

    fn staging(&self) -> io::Result<&ArchiveStagingDirectory> {
        if !self.writable {
            return Err(invalid("read-only archive cannot publish"));
        }
        self.reader
            .staging()
            .ok_or_else(|| invalid("archive has no held staging role"))
    }

    /// Returns true only when this invocation publishes a new complete file.
    /// A failed invocation can leave complete immutable files for reverification.
    pub fn publish(&self, name: &str, bytes: &[u8]) -> io::Result<bool> {
        self.staging()?;
        for _ in 0..MAX_STAGING_COLLISION_RETRIES {
            let sequence: u64 = NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed);
            match self.publish_number(name, bytes, sequence) {
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                outcome => return outcome,
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "archive staging collision retry bound reached; existing bytes were preserved",
        ))
    }

    fn publish_number(&self, name: &str, bytes: &[u8], sequence: u64) -> io::Result<bool> {
        let relative: &Path = ImmutableArchiveReader::filename(name)?;
        let staging: &ArchiveStagingDirectory = self.staging()?;
        if self.contains(name)? {
            if self.read(name, bytes.len())? != bytes {
                return Err(invalid(
                    "saved archive bytes differ from the fixed artifact",
                ));
            }
            return Ok(false);
        }
        let target: PathBuf = self.root().join(relative);
        let temporary: PathBuf = staging
            .path()
            .join(format!(".cut-{}-{sequence}.tmp", std::process::id()));
        // Ownership begins only after create_new succeeds. An unowned collision
        // must not be deleted by a cleanup path.
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let outcome: io::Result<()> = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            staging.directory().sync_all()?;
            self.ensure_attached()?;
            ImmutableArchiveReader::ensure_file_attached(&temporary, &file)?;
            #[cfg(test)]
            tests::publication_checkpoint("after-stage-sync", self.root())?;
            std::fs::hard_link(&temporary, &target)?;
            self.reader.directory().sync_all()?;
            self.ensure_attached()?;
            ImmutableArchiveReader::ensure_file_attached(&target, &file)?;
            #[cfg(test)]
            tests::publication_checkpoint("after-link", self.root())?;
            if self.read(name, bytes.len())? != bytes {
                return Err(invalid("published archive bytes changed"));
            }
            #[cfg(test)]
            tests::publication_checkpoint("before-cleanup", self.root())?;
            Ok(())
        })();
        // Do not delete a substituted pathname after ownership was lost.
        let cleanup: io::Result<()> = (|| {
            self.ensure_attached()?;
            ImmutableArchiveReader::ensure_file_attached(&temporary, &file)?;
            std::fs::remove_file(&temporary)?;
            staging.directory().sync_all()?;
            self.ensure_attached()
        })();
        outcome?;
        cleanup?;
        #[cfg(test)]
        tests::publication_checkpoint("after-cleanup", self.root())?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
