//! Selected local Unix attachment policy; not a replacement for ordinary SDK reads.

use super::{ArchiveReadBudget, ImmutableArchiveReader, invalid};
use std::{
    fs::{File, Metadata, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
};

/// Exact immutable regular-file stamps. Equality includes ownership and timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachedFileStamp {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub nlink: u64,
    pub length: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

impl AttachedFileStamp {
    fn from_metadata(metadata: &Metadata) -> io::Result<Self> {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("attached input is not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                dev: metadata.dev(),
                ino: metadata.ino(),
                mode: metadata.mode(),
                uid: metadata.uid(),
                nlink: metadata.nlink(),
                length: metadata.len(),
                mtime: metadata.mtime(),
                mtime_nsec: metadata.mtime_nsec(),
                ctime: metadata.ctime(),
                ctime_nsec: metadata.ctime_nsec(),
            })
        }
        #[cfg(not(unix))]
        {
            Err(invalid("bounded local archive profile requires Unix"))
        }
    }
}

/// Narrow caller policy applied BEFORE any input byte is read.
#[derive(Clone, Copy)]
pub struct AttachedFilePolicy {
    private_uid: Option<u32>,
}

impl AttachedFilePolicy {
    /// Public artifact/ciphertext: still requires an attached stable regular file.
    #[must_use]
    pub const fn public() -> Self {
        Self { private_uid: None }
    }

    /// Separate recovery identity/private input: exact uid, mode0400/0600, one link.
    /// The caller must obtain the effective uid from its own safe platform owner.
    #[must_use]
    pub const fn private_identity(expected_uid: u32) -> Self {
        Self {
            private_uid: Some(expected_uid),
        }
    }

    fn check(self, stamp: &AttachedFileStamp) -> io::Result<()> {
        if let Some(uid) = self.private_uid {
            let mode: u32 = stamp.mode & 0o7777;
            if stamp.uid != uid || !matches!(mode, 0o400 | 0o600) || stamp.nlink != 1 {
                return Err(invalid("private attached input policy differs"));
            }
        }
        Ok(())
    }
}

/// One unbuffered held cursor with immutable stamps and a caller-specific byte cap.
/// No seek, raw-file exposure, reopen or clone API is provided. This standalone cap
/// is separate from the32MiB archive-body budget (ciphertext has a different owner).
pub struct AttachedRegularFile {
    path: PathBuf,
    parent_path: PathBuf,
    parent: File,
    file: File,
    stamp: AttachedFileStamp,
    budget: ArchiveReadBudget,
    maximum: u64,
    observed: u64,
    refused: bool,
}

impl AttachedRegularFile {
    /// Opens only a selected Unix regular leaf, with no-follow/nonblocking flags.
    /// Pre/open/post full stamps and the consumer policy run before its first byte.
    pub fn open(
        path: &Path,
        maximum: u64,
        budget: &ArchiveReadBudget,
        policy: AttachedFilePolicy,
    ) -> io::Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (path, maximum, budget, policy);
            return Err(invalid("bounded local archive profile requires Unix"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            budget.charge_observations(1)?;
            let name = path
                .file_name()
                .ok_or_else(|| invalid("attached input has no leaf"))?;
            if name.len() > 251 {
                return Err(budget.refuse());
            }
            let parent_path: PathBuf = ImmutableArchiveReader::directory_path_with_budget(
                path.parent()
                    .filter(|parent: &&Path| !parent.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new(".")),
                Some(budget),
            )?;
            let parent: File = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY)
                .open(&parent_path)?;
            ImmutableArchiveReader::ensure_directory_with_budget(
                &parent_path,
                &parent,
                Some(budget),
            )?;
            let path: PathBuf = parent_path.join(name);
            let before: AttachedFileStamp =
                AttachedFileStamp::from_metadata(&std::fs::symlink_metadata(&path)?)?;
            policy.check(&before)?;
            if before.length > maximum {
                return Err(budget.refuse());
            }
            let file: File = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)?;
            let stamp: AttachedFileStamp = AttachedFileStamp::from_metadata(&file.metadata()?)?;
            policy.check(&stamp)?;
            if stamp != before || stamp.length > maximum {
                return Err(invalid("attached file changed while opening"));
            }
            let input: Self = Self {
                path,
                parent_path,
                parent,
                file,
                stamp,
                budget: budget.clone(),
                maximum,
                observed: 0,
                refused: false,
            };
            input.ensure_attached()?;
            Ok(input)
        }
    }

    /// Original checked metadata; it is not an authority claim.
    #[must_use]
    pub fn stamp(&self) -> &AttachedFileStamp {
        &self.stamp
    }

    /// Cumulative actual bytes observed, including an excess-byte refusal probe.
    #[must_use]
    pub const fn observed_bytes(&self) -> u64 {
        self.observed
    }

    /// Checks the same held cursor's complete metadata and original path attachment.
    pub fn ensure_attached(&self) -> io::Result<()> {
        if self.refused {
            return Err(invalid("attached input was refused"));
        }
        self.budget.charge_observations(1)?;
        ImmutableArchiveReader::ensure_directory_with_budget(
            &self.parent_path,
            &self.parent,
            Some(&self.budget),
        )?;
        let actual: AttachedFileStamp =
            AttachedFileStamp::from_metadata(&std::fs::symlink_metadata(&self.path)?)?;
        let held: AttachedFileStamp = AttachedFileStamp::from_metadata(&self.file.metadata()?)?;
        if actual != self.stamp || held != self.stamp {
            return Err(invalid("attached file stamps changed"));
        }
        self.budget.check()
    }
}

impl Read for AttachedRegularFile {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.ensure_attached()
            .inspect_err(|_| self.refused = true)?;
        if output.is_empty() {
            return Ok(0); // Empty-buffer zero is not EOF evidence.
        }
        let remaining: u64 = self
            .maximum
            .checked_sub(self.observed)
            .ok_or_else(|| self.budget.refuse())?;
        if remaining == 0 {
            // A real SAME-cursor read, NEVER a synthetic quota EOF.
            let mut probe: [u8; 1] = [0];
            let count: usize = self
                .file
                .read(&mut probe)
                .inspect_err(|_| self.refused = true)?;
            self.observed = self
                .observed
                .checked_add(count as u64)
                .ok_or_else(|| self.budget.refuse())?;
            if count != 0 {
                self.refused = true;
                return Err(self.budget.refuse());
            }
            self.ensure_attached()
                .inspect_err(|_| self.refused = true)?;
            return Ok(0);
        }
        let count_limit: usize = output
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let count: usize = self
            .file
            .read(&mut output[..count_limit])
            .inspect_err(|_| self.refused = true)?;
        self.observed = self
            .observed
            .checked_add(u64::try_from(count).map_err(|_| self.budget.refuse())?)
            .ok_or_else(|| self.budget.refuse())?;
        self.ensure_attached()
            .inspect_err(|_| self.refused = true)?;
        Ok(count)
    }
}
