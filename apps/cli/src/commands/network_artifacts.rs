//! Local exact-artifact I/O shared by the online network command workflows.
//!
//! This module owns only bounded reads, fresh output reservations, original
//! file/directory handles and synchronization. It establishes no genesis,
//! validator, replay, transport or offline operator authority.

use std::{
    collections::BTreeSet,
    error::Error,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use crate::error::CliError;

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: impl Into<String>) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

pub(super) fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes: Vec<u8> = Vec::new();
    File::open(path)
        .map_err(failure)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() > maximum {
        return Err(invalid(format!("{path} exceeds the maximum accepted size")));
    }
    Ok(bytes)
}

/// A newly reserved output whose original file and parent-directory handles
/// remain held until the workflow ends. Persistence never reopens its path.
pub(super) struct ReservedArtifact {
    pub(super) path: PathBuf,
    pub(super) file: File,
    pub(super) parent: File,
    pub(super) kind: &'static str,
}

pub(super) fn artifact_path(path: &str) -> Result<PathBuf, CliError> {
    let supplied: &Path = Path::new(path);
    let filename = supplied
        .file_name()
        .ok_or_else(|| invalid("artifact path needs a filename"))?;
    let parent: &Path = supplied
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent.canonicalize().map_err(failure)?.join(filename))
}

/// Resolve all destinations before reserving any. Canonical parents catch
/// relative and symlink-directory aliases; existing destinations (including
/// symlinks and hard links to inputs) are always rejected by create_new.
pub(super) fn reserve_artifacts(
    outputs: &[(&str, &'static str)],
    inputs: &[&str],
) -> Result<Vec<ReservedArtifact>, CliError> {
    let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
    for input in inputs {
        paths.insert(Path::new(input).canonicalize().map_err(failure)?);
    }
    let mut destinations: Vec<(PathBuf, &'static str)> = Vec::new();
    for (path, kind) in outputs {
        let destination: PathBuf = artifact_path(path)?;
        if !paths.insert(destination.clone()) {
            return Err(invalid(format!(
                "artifact paths alias at {destination:?}; recover exact saved bytes, never a fresh nonce"
            )));
        }
        destinations.push((destination, *kind));
    }
    let mut artifacts: Vec<ReservedArtifact> = Vec::new();
    for (path, kind) in destinations {
        let parent_path: &Path = path
            .parent()
            .ok_or_else(|| invalid("artifact parent missing"))?;
        let parent: File = File::open(parent_path).map_err(failure)?;
        // Refuse unsupported directory synchronization before any POST.
        parent.sync_all().map_err(failure)?;
        let file: File = OpenOptions::new().write(true).create_new(true).open(&path)
            .map_err(|source| invalid(format!(
                "failed to reserve {kind} artifact at {path:?} (an existing file is never overwritten; recover exact saved bytes rather than re-signing): {source}"
            )))?;
        parent.sync_all().map_err(failure)?;
        artifacts.push(ReservedArtifact {
            path,
            file,
            parent,
            kind,
        });
    }
    Ok(artifacts)
}

impl ReservedArtifact {
    pub(super) fn ensure_exact_input(&mut self, expected: &[u8]) -> Result<(), CliError> {
        self.ensure_attached()?;
        let limit: u64 = u64::try_from(expected.len())
            .map_err(failure)?
            .checked_add(1)
            .ok_or_else(|| invalid("input recheck bound overflow"))?;
        self.file.seek(SeekFrom::Start(0)).map_err(failure)?;
        let mut actual: Vec<u8> = Vec::new();
        Read::by_ref(&mut self.file)
            .take(limit)
            .read_to_end(&mut actual)
            .map_err(failure)?;
        if actual != expected {
            return Err(invalid(format!(
                "retained {} input changed at {:?}",
                self.kind, self.path
            )));
        }
        self.file.sync_all().map_err(failure)?;
        self.parent.sync_all().map_err(failure)?;
        Ok(())
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn ensure_attached(&self) -> Result<(), CliError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let actual: std::fs::Metadata =
                std::fs::symlink_metadata(&self.path).map_err(failure)?;
            let held: std::fs::Metadata = self.file.metadata().map_err(failure)?;
            let parent_path = self
                .path
                .parent()
                .ok_or_else(|| invalid("artifact parent missing"))?;
            let actual_parent: std::fs::Metadata =
                std::fs::metadata(parent_path).map_err(failure)?;
            let held_parent: std::fs::Metadata = self.parent.metadata().map_err(failure)?;
            if (actual.dev(), actual.ino()) != (held.dev(), held.ino())
                || (actual_parent.dev(), actual_parent.ino())
                    != (held_parent.dev(), held_parent.ino())
            {
                return Err(invalid(format!(
                    "reserved {} artifact path was replaced at {:?}; recover exact saved bytes from the original file, never a fresh nonce",
                    self.kind, self.path
                )));
            }
        }
        Ok(())
    }

    pub(super) fn persist(&mut self, bytes: &[u8]) -> Result<(), CliError> {
        self.ensure_attached()?;
        let recovery = |source: &dyn Error| {
            invalid(format!(
                "failed to persist {} artifact at {:?}: {source}; retained recovery bytes may be partial; replay identical saved signed bytes with the same request ID and nonce, never a fresh nonce",
                self.kind, self.path
            ))
        };
        persist_handles(&mut self.file, &self.parent, bytes).map_err(|source| recovery(&source))?;
        self.ensure_attached()?;
        Ok(())
    }
}

pub(super) fn persist_handles(file: &mut File, parent: &File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()?;
    parent.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
