//! Held-handle immutable archive reads, the single owner of artifact
//! directory attachment, symlink, filename, inventory and bounded-read
//! policy shared by the operator and the CLI. Every byte read is untrusted
//! transport: the owning node-core verifier decides what it means. The
//! operator publication writer wraps this reader and adds only staging
//! publication; nothing here writes an artifact.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

/// Name of the publication staging role inside an archive root.
pub const ARCHIVE_STAGING_DIRECTORY: &str = ".cut-staging-v1";

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// One held, attached staging role directory.
pub struct ArchiveStagingDirectory {
    path: PathBuf,
    directory: File,
}

impl ArchiveStagingDirectory {
    /// Validated absolute staging path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// The held staging directory handle.
    #[must_use]
    pub fn directory(&self) -> &File {
        &self.directory
    }
}

/// A caller-selected existing directory held by handle. No saved marker is
/// trusted; every read rechecks attachment around the access.
pub struct ImmutableArchiveReader {
    root: PathBuf,
    directory: File,
    staging: Option<ArchiveStagingDirectory>,
}

impl ImmutableArchiveReader {
    /// Opens saved material without creating a staging role or artifact.
    pub fn open(root: &Path) -> io::Result<Self> {
        Self::open_mode(root, false)
    }

    /// Opens and attaches one root. Only the operator publication writer
    /// passes create_staging; it creates the empty staging role before the
    /// held inventory is validated and never publishes through this type.
    pub fn open_mode(root: &Path, create_staging: bool) -> io::Result<Self> {
        let root: PathBuf = Self::directory_path(root)?;
        let before: std::fs::Metadata = std::fs::symlink_metadata(&root)?;
        if before.file_type().is_symlink() || !before.is_dir() {
            return Err(invalid("archive root must be an existing regular directory"));
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
        let staging_path: PathBuf = root.join(ARCHIVE_STAGING_DIRECTORY);
        if create_staging {
            match std::fs::create_dir(&staging_path) {
                Ok(()) => directory.sync_all()?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        let staging: Option<ArchiveStagingDirectory> =
            match std::fs::symlink_metadata(&staging_path) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    let staging_file: File = File::open(&staging_path)?;
                    Self::ensure_directory_attached(&staging_path, &staging_file)?;
                    Some(ArchiveStagingDirectory {
                        path: staging_path,
                        directory: staging_file,
                    })
                }
                Ok(_) => return Err(invalid("archive staging role is not a regular directory")),
                Err(error) if !create_staging && error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
        let archive: Self = Self {
            root,
            directory,
            staging,
        };
        archive.ensure_attached()?;
        archive.validate_staging()?;
        Ok(archive)
    }

    /// A destination must not add files to this exact input inventory.
    /// Check regular ancestors and their held identities, including Unix
    /// directory aliases; a string prefix alone is not a placement guard.
    pub fn require_output_outside(&self, path: &Path) -> io::Result<()> {
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
            return Err(invalid("destination database must be outside pinned input archive"));
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

    /// Rechecks that the root (and any held staging role) is still the
    /// exact directory this reader attached to.
    pub fn ensure_attached(&self) -> io::Result<()> {
        Self::ensure_directory_attached(&self.root, &self.directory)?;
        if let Some(staging) = &self.staging {
            Self::ensure_directory_attached(&staging.path, &staging.directory)?;
        }
        Ok(())
    }

    /// The validated absolute root this archive attached to. A caller using
    /// this path for its own direct reads must still call
    /// [Self::ensure_attached] around that use.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The held root directory handle (publication synchronizes it).
    #[must_use]
    pub fn directory(&self) -> &File {
        &self.directory
    }

    /// The held staging role, if one existed or was created at open.
    #[must_use]
    pub fn staging(&self) -> Option<&ArchiveStagingDirectory> {
        self.staging.as_ref()
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
            if !Self::staging_filename(&name) || !metadata.is_file() || metadata.file_type().is_symlink()
            {
                return Err(invalid(
                    "archive staging role contains an unknown or non-regular entry",
                ));
            }
            // Orphan bytes are deliberately never read, adopted or deleted.
        }
        Self::ensure_directory_attached(&staging.path, &staging.directory)
    }

    /// Accepts exactly one normal path component.
    pub fn filename(name: &str) -> io::Result<&Path> {
        let path: &Path = Path::new(name);
        let mut components = path.components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(invalid("archive filename must be one normal component"));
        }
        Ok(path)
    }

    /// Reads one regular artifact of at most maximum bytes, rechecking file
    /// and directory identity before and after the bounded read.
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
            return Err(invalid("archive artifact changed length or exceeds its bound"));
        }
        Self::ensure_file_attached(&path, &file)?;
        self.ensure_attached()?;
        Ok(bytes)
    }

    /// Whether one regular artifact exists; any non-regular entry refuses.
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
            if name == ARCHIVE_STAGING_DIRECTORY {
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

    /// Requires the held file to still be the regular file at path.
    pub fn ensure_file_attached(path: &Path, file: &File) -> io::Result<()> {
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
