//! Fresh single-file genesis output, with native ownership only. Archive
//! staging, import resumption and protocol authority do not belong here.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};
use sunrise_edge_client::immutable_archive::ImmutableArchiveReader;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

fn normalized(path: &Path) -> io::Result<PathBuf> {
    let absolute: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result: PathBuf = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                return Err(invalid(
                    "genesis input/output cannot traverse parent components",
                ));
            }
            Component::CurDir => {}
            _ => result.push(component),
        }
    }
    Ok(result)
}

fn attached_directory(path: &Path, directory: &File) -> io::Result<()> {
    let actual: std::fs::Metadata = std::fs::symlink_metadata(path)?;
    let held: std::fs::Metadata = directory.metadata()?;
    if !actual.is_dir() || actual.file_type().is_symlink() || !held.is_dir() {
        return Err(invalid("genesis ancestor is not a regular directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (actual.dev(), actual.ino()) != (held.dev(), held.ino()) {
            return Err(invalid("genesis ancestor changed"));
        }
    }
    Ok(())
}

fn ancestors(path: &Path) -> io::Result<Vec<(PathBuf, File)>> {
    let parent: &Path = path
        .parent()
        .ok_or_else(|| invalid("genesis path has no parent"))?;
    let mut current: PathBuf = PathBuf::new();
    let mut pinned: Vec<(PathBuf, File)> = Vec::new();
    for component in parent.components() {
        current.push(component);
        let metadata: std::fs::Metadata = std::fs::symlink_metadata(&current)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("genesis ancestor is not a regular directory"));
        }
        let file: File = File::open(&current)?;
        attached_directory(&current, &file)?;
        pinned.push((current.clone(), file));
    }
    Ok(pinned)
}

pub(crate) struct FreshGenesisOutput {
    path: PathBuf,
    parents: Vec<(PathBuf, File)>,
}

impl FreshGenesisOutput {
    pub(crate) fn plan(output: &Path, inputs: &[&Path]) -> io::Result<Self> {
        let path: PathBuf = normalized(output)?;
        let parents: Vec<(PathBuf, File)> = ancestors(&path)?;
        for input in inputs {
            let input: PathBuf = normalized(input)?;
            if input == path {
                return Err(invalid("genesis output aliases a configured input"));
            }
            let held: Vec<(PathBuf, File)> = ancestors(&input)?;
            let metadata: std::fs::Metadata = std::fs::symlink_metadata(&input)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(invalid("genesis input must be a regular non-symlink file"));
            }
            for (parent, directory) in held {
                attached_directory(&parent, &directory)?;
            }
        }
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "genesis output already exists",
                ));
            }
        }
        let planned: Self = Self { path, parents };
        planned.ensure_parents()?;
        Ok(planned)
    }

    fn ensure_parents(&self) -> io::Result<()> {
        for (path, directory) in &self.parents {
            attached_directory(path, directory)?;
        }
        Ok(())
    }

    pub(crate) fn publish(self, bytes: &[u8]) -> io::Result<PublishedGenesis> {
        self.ensure_parents()?;
        // A reservation failure owns nothing. Later failures retain partial
        // output for explicit inspection; no cleanup adopts/deletes paths.
        let mut file: File = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&self.path)?;
        self.ensure_parents()?;
        ImmutableArchiveReader::ensure_file_attached(&self.path, &file)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let (_, parent) = self
            .parents
            .last()
            .ok_or_else(|| invalid("genesis output lost parent"))?;
        parent.sync_all()?;
        self.ensure_parents()?;
        ImmutableArchiveReader::ensure_file_attached(&self.path, &file)?;
        file.seek(SeekFrom::Start(0))?;
        let read_limit: u64 = u64::try_from(bytes.len())
            .map_err(|_| invalid("manifest length overflow"))?
            .checked_add(1)
            .ok_or_else(|| invalid("manifest read limit overflow"))?;
        let mut persisted: Vec<u8> = Vec::with_capacity(bytes.len());
        Read::by_ref(&mut file)
            .take(read_limit)
            .read_to_end(&mut persisted)?;
        if persisted != bytes {
            return Err(invalid("published genesis bytes differ"));
        }
        let published: PublishedGenesis = PublishedGenesis {
            planned: self,
            file,
        };
        published.ensure_attached()?;
        Ok(published)
    }
}

pub(crate) struct PublishedGenesis {
    planned: FreshGenesisOutput,
    file: File,
}

impl PublishedGenesis {
    pub(crate) fn ensure_attached(&self) -> io::Result<()> {
        self.planned.ensure_parents()?;
        ImmutableArchiveReader::ensure_file_attached(&self.planned.path, &self.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Directory(PathBuf);
    impl Directory {
        fn new(label: &str) -> Self {
            let nonce: u128 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path: PathBuf = std::env::temp_dir().join(format!(
                "sunrise-genesis-output-{label}-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn output_reservation_refuses_an_intervening_file_without_overwrite() {
        let directory: Directory = Directory::new("reservation");
        let path: PathBuf = directory.0.join("manifest.bin");
        let planned: FreshGenesisOutput = FreshGenesisOutput::plan(&path, &[]).unwrap();
        std::fs::write(&path, b"intervening owner").unwrap();
        assert!(planned.publish(b"author output").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"intervening owner");
    }

    #[cfg(unix)]
    #[test]
    fn output_claim_retains_leaf_and_ancestor_identity_through_success_line() {
        let directory: Directory = Directory::new("identity");
        for parent_swap in [false, true] {
            let parent: PathBuf = directory.0.join(format!("parent-{parent_swap}"));
            std::fs::create_dir(&parent).unwrap();
            let path: PathBuf = parent.join("manifest.bin");
            let published: PublishedGenesis = FreshGenesisOutput::plan(&path, &[])
                .unwrap()
                .publish(b"manifest")
                .unwrap();
            published.ensure_attached().unwrap();
            if parent_swap {
                let detached: PathBuf = parent.with_extension("detached");
                std::fs::rename(&parent, &detached).unwrap();
                std::fs::create_dir(&parent).unwrap();
                std::fs::hard_link(detached.join("manifest.bin"), &path).unwrap();
            } else {
                std::fs::rename(&path, parent.join("original.bin")).unwrap();
                std::fs::write(&path, b"replacement").unwrap();
            }
            assert!(published.ensure_attached().is_err());
        }
    }
}
