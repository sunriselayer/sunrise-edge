//! Local immutable artifact publication, not protocol or import authority.
//!
//! Complete bytes and the containing directory are synchronized before a
//! final filename is exposed. Existing bytes are compared, never overwritten.

use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);
const STAGING_DIRECTORY: &str = ".cut-staging-v1";
const MAX_STAGING_COLLISION_RETRIES: usize = 32;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// A caller-selected existing output directory. No saved marker is trusted.
pub struct ImmutableArchive {
    root: PathBuf,
    directory: File,
    staging: Option<StagingDirectory>,
    writable: bool,
}

struct StagingDirectory {
    path: PathBuf,
    directory: File,
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

    /// A destination must not add files to this exact input inventory.
    /// Check regular ancestors and their held identities, including Unix
    /// directory aliases; a string prefix alone is not a placement guard.
    pub(crate) fn require_output_outside(&self, path: &Path) -> io::Result<()> {
        self.ensure_attached()?;
        let absolute: PathBuf = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let parent: &Path = absolute
            .parent()
            .ok_or_else(|| invalid("destination database has no parent directory"))?;
        let parent: PathBuf = Self::directory_path(parent)?;
        if parent.starts_with(&self.root) {
            return Err(invalid(
                "destination database must be outside pinned input archive",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let source: std::fs::Metadata = self.directory.metadata()?;
            for ancestor in parent.ancestors() {
                let directory: File = File::open(ancestor)?;
                Self::ensure_directory_attached(ancestor, &directory)?;
                let held: std::fs::Metadata = directory.metadata()?;
                if (held.dev(), held.ino()) == (source.dev(), source.ino()) {
                    return Err(invalid(
                        "destination database must be outside pinned input archive",
                    ));
                }
            }
        }
        self.ensure_attached()
    }

    fn open_mode(root: &Path, writable: bool) -> io::Result<Self> {
        let root: PathBuf = Self::directory_path(root)?;
        let before: std::fs::Metadata = std::fs::symlink_metadata(&root)?;
        if before.file_type().is_symlink() || !before.is_dir() {
            return Err(invalid(
                "archive root must be an existing regular directory",
            ));
        }
        let directory: File = File::open(&root)?;
        let held: std::fs::Metadata = directory.metadata()?;
        if !held.is_dir() {
            return Err(invalid("opened archive root is not a directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (before.dev(), before.ino()) != (held.dev(), held.ino()) {
                return Err(invalid("archive root changed while opening"));
            }
        }
        Self::ensure_directory_attached(&root, &directory)?;
        let staging_path: PathBuf = root.join(STAGING_DIRECTORY);
        if writable {
            match std::fs::create_dir(&staging_path) {
                Ok(()) => directory.sync_all()?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        let staging: Option<StagingDirectory> = match std::fs::symlink_metadata(&staging_path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                let staging_file: File = File::open(&staging_path)?;
                Self::ensure_directory_attached(&staging_path, &staging_file)?;
                Some(StagingDirectory {
                    path: staging_path,
                    directory: staging_file,
                })
            }
            Ok(_) => return Err(invalid("archive staging role is not a regular directory")),
            Err(error) if !writable && error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let archive: Self = Self {
            root,
            directory,
            staging,
            writable,
        };
        archive.ensure_attached()?;
        archive.validate_staging()?;
        // Refuse unsupported directory synchronization before publication.
        if writable {
            archive.directory.sync_all()?;
            archive.staging()?.directory.sync_all()?;
        }
        Ok(archive)
    }

    fn directory_path(root: &Path) -> io::Result<PathBuf> {
        let absolute: PathBuf = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()?.join(root)
        };
        let mut checked: PathBuf = PathBuf::new();
        for component in absolute.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => checked.push(component),
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(invalid("archive root must not traverse parent components"));
                }
                Component::Normal(_) => {
                    checked.push(component);
                    let metadata: std::fs::Metadata = std::fs::symlink_metadata(&checked)?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(invalid("archive root ancestor is not a regular directory"));
                    }
                }
            }
        }
        Ok(checked)
    }

    fn ensure_attached(&self) -> io::Result<()> {
        Self::ensure_directory_attached(&self.root, &self.directory)?;
        if let Some(staging) = &self.staging {
            Self::ensure_directory_attached(&staging.path, &staging.directory)?;
        }
        Ok(())
    }

    fn ensure_directory_attached(path: &Path, directory: &File) -> io::Result<()> {
        Self::directory_path(path)?;
        let actual: std::fs::Metadata = std::fs::symlink_metadata(path)?;
        if actual.file_type().is_symlink() || !actual.is_dir() {
            return Err(invalid("archive root was replaced"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let held: std::fs::Metadata = directory.metadata()?;
            if (actual.dev(), actual.ino()) != (held.dev(), held.ino()) {
                return Err(invalid("archive root was replaced"));
            }
        }
        Ok(())
    }

    fn staging(&self) -> io::Result<&StagingDirectory> {
        if !self.writable {
            return Err(invalid("read-only archive cannot publish"));
        }
        self.staging
            .as_ref()
            .ok_or_else(|| invalid("archive has no held staging role"))
    }

    fn staging_filename(name: &str) -> bool {
        let Some(inner) = name
            .strip_prefix(".cut-")
            .and_then(|value| value.strip_suffix(".tmp"))
        else {
            return false;
        };
        let Some((pid, sequence)) = inner.split_once('-') else {
            return false;
        };
        let (Ok(pid), Ok(sequence)) = (pid.parse::<u32>(), sequence.parse::<u64>()) else {
            return false;
        };
        pid != 0 && name == format!(".cut-{pid}-{sequence}.tmp")
    }

    fn validate_staging(&self) -> io::Result<()> {
        let Some(staging) = &self.staging else {
            return Ok(());
        };
        Self::ensure_directory_attached(&staging.path, &staging.directory)?;
        for entry in std::fs::read_dir(&staging.path)? {
            let entry: std::fs::DirEntry = entry?;
            let name: String = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("staging filename is not UTF-8"))?;
            let metadata: std::fs::Metadata = std::fs::symlink_metadata(entry.path())?;
            if !Self::staging_filename(&name)
                || !metadata.is_file()
                || metadata.file_type().is_symlink()
            {
                return Err(invalid(
                    "archive staging role contains an unknown or non-regular entry",
                ));
            }
            // Orphan bytes are deliberately never read, adopted or deleted.
        }
        Self::ensure_directory_attached(&staging.path, &staging.directory)
    }

    fn filename(name: &str) -> io::Result<&Path> {
        let path: &Path = Path::new(name);
        let mut components = path.components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(invalid("archive filename must be one normal component"));
        }
        Ok(path)
    }

    pub fn read(&self, name: &str, maximum: usize) -> io::Result<Vec<u8>> {
        let relative: &Path = Self::filename(name)?;
        self.ensure_attached()?;
        let path: PathBuf = self.root.join(relative);
        let before: std::fs::Metadata = std::fs::symlink_metadata(&path)?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(invalid("archive artifact is not a regular file"));
        }
        let mut file: File = File::open(&path)?;
        let held: std::fs::Metadata = file.metadata()?;
        let maximum: u64 =
            u64::try_from(maximum).map_err(|_| invalid("archive read bound overflow"))?;
        if held.len() > maximum {
            return Err(invalid("archive artifact exceeds its bounded file size"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (before.dev(), before.ino()) != (held.dev(), held.ino()) {
                return Err(invalid("archive file changed while opening"));
            }
        }
        Self::ensure_file_attached(&path, &file)?;
        let mut bytes: Vec<u8> = Vec::new();
        Read::by_ref(&mut file)
            .take(
                maximum
                    .checked_add(1)
                    .ok_or_else(|| invalid("archive read bound overflow"))?,
            )
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum
            || bytes.len() as u64 != held.len()
            || file.metadata()?.len() != held.len()
        {
            return Err(invalid(
                "archive artifact changed length or exceeds its bound",
            ));
        }
        Self::ensure_file_attached(&path, &file)?;
        self.ensure_attached()?;
        Ok(bytes)
    }

    pub fn contains(&self, name: &str) -> io::Result<bool> {
        let relative: &Path = Self::filename(name)?;
        self.ensure_attached()?;
        let outcome: io::Result<bool> = match std::fs::symlink_metadata(self.root.join(relative)) {
            Ok(metadata) if metadata.is_file() => Ok(true),
            Ok(_) => Err(invalid("archive artifact is not a regular file")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        };
        self.ensure_attached()?;
        outcome
    }

    /// Enumerates regular saved artifacts without following symbolic links.
    /// The consumer checks this complete inventory, not a saved progress flag.
    pub fn names(&self) -> io::Result<BTreeSet<String>> {
        self.ensure_attached()?;
        let mut names: BTreeSet<String> = BTreeSet::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry: std::fs::DirEntry = entry?;
            let name: String = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("archive filename is not UTF-8"))?;
            Self::filename(&name)?;
            let metadata: std::fs::Metadata = std::fs::symlink_metadata(entry.path())?;
            if name == STAGING_DIRECTORY {
                if self.staging.is_none() || !metadata.is_dir() || metadata.file_type().is_symlink()
                {
                    return Err(invalid("archive staging role changed"));
                }
                self.validate_staging()?;
                continue;
            }
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(invalid("archive contains a non-regular artifact"));
            }
            names.insert(name);
        }
        self.ensure_attached()?;
        Ok(names)
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
        let relative: &Path = Self::filename(name)?;
        let staging: &StagingDirectory = self.staging()?;
        if self.contains(name)? {
            if self.read(name, bytes.len())? != bytes {
                return Err(invalid(
                    "saved archive bytes differ from the fixed artifact",
                ));
            }
            return Ok(false);
        }
        let target: PathBuf = self.root.join(relative);
        let temporary: PathBuf = staging
            .path
            .join(format!(".cut-{}-{sequence}.tmp", std::process::id(),));
        // Ownership begins only after create_new succeeds. An unowned collision
        // must not be deleted by a cleanup path.
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let outcome: io::Result<()> = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            staging.directory.sync_all()?;
            self.ensure_attached()?;
            Self::ensure_file_attached(&temporary, &file)?;
            #[cfg(test)]
            tests::publication_checkpoint("after-stage-sync", &self.root)?;
            std::fs::hard_link(&temporary, &target)?;
            self.directory.sync_all()?;
            self.ensure_attached()?;
            Self::ensure_file_attached(&target, &file)?;
            #[cfg(test)]
            tests::publication_checkpoint("after-link", &self.root)?;
            if self.read(name, bytes.len())? != bytes {
                return Err(invalid("published archive bytes changed"));
            }
            #[cfg(test)]
            tests::publication_checkpoint("before-cleanup", &self.root)?;
            Ok(())
        })();
        // Do not delete a substituted pathname after ownership was lost.
        let cleanup: io::Result<()> = (|| {
            self.ensure_attached()?;
            Self::ensure_file_attached(&temporary, &file)?;
            std::fs::remove_file(&temporary)?;
            staging.directory.sync_all()?;
            self.ensure_attached()
        })();
        outcome?;
        cleanup?;
        #[cfg(test)]
        tests::publication_checkpoint("after-cleanup", &self.root)?;
        Ok(true)
    }

    fn ensure_file_attached(path: &Path, file: &File) -> io::Result<()> {
        let actual: std::fs::Metadata = std::fs::symlink_metadata(path)?;
        let held: std::fs::Metadata = file.metadata()?;
        if !actual.is_file() || actual.file_type().is_symlink() || !held.is_file() {
            return Err(invalid("archive file was replaced"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (actual.dev(), actual.ino()) != (held.dev(), held.ino()) {
                return Err(invalid("archive file was replaced"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
