//! Native import file ownership, never protocol/bootstrap authority.
use std::{
    fs::{File, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
};

#[derive(Debug)]
pub(crate) struct ImportFile {
    path: PathBuf,
    file: File,
    ancestors: Vec<(PathBuf, File)>,
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

pub(crate) fn sync_owned(held: &ImportFile) -> io::Result<()> {
    sync_created(&held.path, held)
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

pub(crate) fn check_attached(path: &Path, held: &ImportFile) -> io::Result<()> {
    if absolute(path)? != held.path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "import target pathname changed",
        ));
    }
    for (ancestor, directory) in &held.ancestors {
        directory_attached(ancestor, directory)?;
    }
    let actual = std::fs::symlink_metadata(path)?;
    let opened = held.file.metadata()?;
    if !actual.is_file() || actual.file_type().is_symlink() || !opened.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "import target is not an attached regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (actual.dev(), actual.ino()) != (opened.dev(), opened.ino()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "import target file changed while opening",
            ));
        }
    }
    Ok(())
}
pub(crate) fn create_new(path: &Path) -> io::Result<ImportFile> {
    let pinned_path: PathBuf = absolute(path)?;
    let ancestors: Vec<(PathBuf, File)> = pin_ancestors(&pinned_path)?;
    let file: File = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    let held: ImportFile = ImportFile {
        path: pinned_path,
        file,
        ancestors,
    };
    check_attached(path, &held)?;
    Ok(held)
}
pub(crate) fn open_existing(path: &Path) -> io::Result<ImportFile> {
    let pinned_path: PathBuf = absolute(path)?;
    let ancestors: Vec<(PathBuf, File)> = pin_ancestors(&pinned_path)?;
    let before = std::fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "import target is not a regular file",
        ));
    }
    let file: File = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "import target file changed while opening",
            ));
        }
    }
    let held: ImportFile = ImportFile {
        path: pinned_path,
        file,
        ancestors,
    };
    check_attached(path, &held)?;
    Ok(held)
}
pub(crate) fn sync_created(path: &Path, file: &ImportFile) -> io::Result<()> {
    check_attached(path, file)?;
    file.file.sync_all()?;
    let (_, directory) = file.ancestors.last().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "import target lost parent identity",
        )
    })?;
    directory.sync_all()?;
    check_attached(path, file)
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
        let held: ImportFile = create_new(&path).unwrap();
        assert!(check_attached(&path, &held).is_ok());
        std::fs::rename(&parent, &replaced).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::hard_link(replaced.join("target.db"), &path).unwrap();
        assert!(
            check_attached(&path, &held).is_err(),
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
