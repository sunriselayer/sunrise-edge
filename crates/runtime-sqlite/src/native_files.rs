//! Lock-safe native file attachment, never protocol/bootstrap authority.
use std::{
    fs::{File, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
};

#[derive(Debug)]
pub(crate) struct ImportFile {
    path: PathBuf,
    main: FileIdentity,
    sidecars: [Option<FileIdentity>; 3],
    ancestors: Vec<(PathBuf, File)>,
    fresh: bool,
}

/// Observations only: closing an independent main/SHM descriptor can release
/// SQLite's process-wide POSIX locks. Only directory descriptors are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

fn regular_identity(metadata: &std::fs::Metadata) -> io::Result<FileIdentity> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SQLite path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SQLite file has a hard-link alias",
            ));
        }
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native SQLite attachment requires POSIX file identity",
        ))
    }
}

fn observe(path: &Path) -> io::Result<FileIdentity> {
    regular_identity(&std::fs::symlink_metadata(path)?)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

pub(crate) const SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

fn require_absent(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "fresh SQLite destination or sidecar already exists",
        )),
    }
}

/// Checks prospective ownership without creating a main file or a sidecar.
/// Existing import factories retain their separately defined policy.
pub(crate) fn validate_fresh(path: &Path) -> io::Result<PathBuf> {
    let normalized: PathBuf = absolute(path)?;
    let ancestors: Vec<(PathBuf, File)> = pin_ancestors(&normalized)?;
    require_absent(&normalized)?;
    require_no_sidecars(&normalized)?;
    for (ancestor, file) in ancestors {
        directory_attached(&ancestor, &file)?;
    }
    Ok(normalized)
}

pub(crate) fn require_no_sidecars(path: &Path) -> io::Result<()> {
    for suffix in SIDECAR_SUFFIXES {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        require_absent(Path::new(&sidecar))?;
    }
    Ok(())
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    let path: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result: PathBuf = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "import target cannot traverse parent components",
                ));
            }
            Component::CurDir => {}
            _ => result.push(component),
        }
    }
    Ok(result)
}
fn directory_attached(path: &Path, file: &File) -> io::Result<()> {
    let actual = std::fs::symlink_metadata(path)?;
    let held = file.metadata()?;
    if !actual.is_dir() || actual.file_type().is_symlink() || !held.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "import target ancestor is not a regular directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (actual.dev(), actual.ino()) != (held.dev(), held.ino()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "import target ancestor changed",
            ));
        }
    }
    Ok(())
}
fn pin_ancestors(path: &Path) -> io::Result<Vec<(PathBuf, File)>> {
    let parent: &Path = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "import target has no parent directory",
        )
    })?;
    let mut checked: PathBuf = PathBuf::new();
    let mut held: Vec<(PathBuf, File)> = Vec::new();
    for component in parent.components() {
        checked.push(component);
        let metadata = std::fs::symlink_metadata(&checked)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "import target ancestor is not a regular directory",
            ));
        }
        let file: File = File::open(&checked)?;
        directory_attached(&checked, &file)?;
        held.push((checked.clone(), file));
    }
    Ok(held)
}

pub(crate) fn check_attached(path: &Path, held: &mut ImportFile) -> io::Result<()> {
    if absolute(path)? != held.path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "import target pathname changed",
        ));
    }
    for (ancestor, directory) in &held.ancestors {
        directory_attached(ancestor, directory)?;
    }
    if observe(&held.path)? != held.main {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SQLite main file identity changed",
        ));
    }
    let mut observed: [Option<FileIdentity>; 3] = [None; 3];
    for (index, suffix) in SIDECAR_SUFFIXES.iter().enumerate() {
        let actual: Option<FileIdentity> = match observe(&sidecar_path(&held.path, suffix)) {
            Ok(identity) => Some(identity),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if held.sidecars[index].is_some() && actual.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SQLite attached sidecar disappeared",
            ));
        }
        if let Some(identity) = actual {
            if identity == held.main || observed.contains(&Some(identity)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SQLite main/sidecar alias",
                ));
            }
            if held.sidecars[index].is_some_and(|previous| previous != identity) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SQLite sidecar identity changed",
                ));
            }
        }
        // FULL/TRUNCATE checkpoints may change bytes and length, not this
        // attachment. Last-close cleanup drops the owner; a later constructor
        // observes its own optional sidecars. Do not bless an unlinked live WAL.
        observed[index] = actual;
    }
    held.sidecars = observed;
    Ok(())
}

impl ImportFile {
    pub(crate) fn require_fresh(&self) -> io::Result<()> {
        if !self.fresh {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SQLite handle is not from the fresh-only factory",
            ));
        }
        Ok(())
    }

    pub(crate) fn restrict_development(&mut self) {
        self.fresh = false;
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn check(&mut self) -> io::Result<()> {
        let path: PathBuf = self.path.clone();
        check_attached(&path, self)
    }

    pub(crate) fn sync_parent(&mut self) -> io::Result<()> {
        self.require_fresh()?;
        self.check()?;
        let (_, directory) = self.ancestors.last().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "SQLite target lost parent identity",
            )
        })?;
        directory.sync_all()?;
        self.check()
    }
}

pub(crate) fn create_new(path: &Path) -> io::Result<ImportFile> {
    let pinned_path: PathBuf = absolute(path)?;
    let ancestors: Vec<(PathBuf, File)> = pin_ancestors(&pinned_path)?;
    let file: File = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&pinned_path)?;
    let main: FileIdentity = regular_identity(&file.metadata()?)?;
    file.sync_all()?;
    // Must close this exclusive reservation BEFORE SQLite opens the inode.
    drop(file);
    let mut held: ImportFile = ImportFile {
        path: pinned_path,
        main,
        sidecars: [None; 3],
        ancestors,
        fresh: true,
    };
    check_attached(path, &mut held)?;
    Ok(held)
}
pub(crate) fn open_existing(path: &Path) -> io::Result<ImportFile> {
    let pinned_path: PathBuf = absolute(path)?;
    let ancestors: Vec<(PathBuf, File)> = pin_ancestors(&pinned_path)?;
    let main: FileIdentity = observe(&pinned_path)?;
    let mut held: ImportFile = ImportFile {
        path: pinned_path,
        main,
        sidecars: [None; 3],
        ancestors,
        fresh: false,
    };
    check_attached(path, &mut held)?;
    Ok(held)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn inactive_import_file_owner_refuses_ancestor_symlinks_and_replacement() {
        let nonce: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-import-file-owner-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let parent: PathBuf = root.join("parent");
        let replaced: PathBuf = root.join("replaced");
        let alias: PathBuf = root.join("alias");
        std::fs::create_dir(&parent).unwrap();
        std::os::unix::fs::symlink(&parent, &alias).unwrap();
        assert!(create_new(&alias.join("target.db")).is_err());
        assert!(!parent.join("target.db").exists());
        let path: PathBuf = parent.join("target.db");
        let mut held: ImportFile = create_new(&path).unwrap();
        assert!(check_attached(&path, &mut held).is_ok());
        std::fs::rename(&parent, &replaced).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::hard_link(replaced.join("target.db"), &path).unwrap();
        assert!(
            check_attached(&path, &mut held).is_err(),
            "leaf identity is identical but the held ancestor changed"
        );
        drop(held);
        for file in [&path, &replaced.join("target.db"), &alias] {
            std::fs::remove_file(file).unwrap();
        }
        std::fs::remove_dir(&parent).unwrap();
        std::fs::remove_dir(&replaced).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}
