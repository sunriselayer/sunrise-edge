//! Linux-local custody admission shared by role-specific workers.
//! This module owns no route, key, storage, or signing decision.

use std::{
    fs::{self, File, Metadata},
    io::{self, Read},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixListener as StdUnixListener,
    },
    path::{Component, Path, PathBuf},
};
use tokio::net::UnixListener;

pub(crate) type Refuse = fn() -> io::Error;

pub(crate) fn own_uid(refuse: Refuse) -> io::Result<u32> {
    let file: File = File::open("/proc/self/status")?;
    let mut bytes: String = String::new();
    file.take(8192).read_to_string(&mut bytes)?;
    bytes
        .lines()
        .find_map(|line: &str| {
            line.strip_prefix("Uid:")?
                .split_whitespace()
                .nth(1)?
                .parse::<u32>()
                .ok()
        })
        .ok_or_else(refuse)
}

pub(crate) fn absolute(path: &Path, refuse: Refuse) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part: Component<'_>| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(refuse());
    }
    Ok(())
}

pub(crate) fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

pub(crate) fn owned(
    path: &Path,
    mode: u32,
    directory: bool,
    refuse: Refuse,
) -> io::Result<Metadata> {
    absolute(path, refuse)?;
    let metadata: Metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != own_uid(refuse)?
        || metadata.permissions().mode() & 0o7777 != mode
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(refuse());
    }
    Ok(metadata)
}

pub(crate) fn private_file(path: &Path, refuse: Refuse) -> io::Result<Metadata> {
    owned(path.parent().ok_or_else(refuse)?, 0o700, true, refuse)?;
    owned(path, 0o600, false, refuse)
}

pub(crate) fn config_file(path: &Path, maximum: u64, refuse: Refuse) -> io::Result<String> {
    let before: Metadata = private_file(path, refuse)?;
    if before.len() > maximum {
        return Err(refuse());
    }
    let file: File = File::open(path)?;
    let opened: Metadata = file.metadata()?;
    if identity(&before) != identity(&opened)
        || opened.uid() != own_uid(refuse)?
        || opened.permissions().mode() & 0o7777 != 0o600
        || !opened.is_file()
    {
        return Err(refuse());
    }
    let mut bytes: String = String::new();
    file.take(maximum + 1).read_to_string(&mut bytes)?;
    if bytes.len() as u64 > maximum || identity(&fs::symlink_metadata(path)?) != identity(&before) {
        return Err(refuse());
    }
    Ok(bytes)
}

pub(crate) struct SocketOwner {
    path: PathBuf,
    inode: (u64, u64),
    refuse: Refuse,
}

impl SocketOwner {
    pub(crate) fn bind(path: &Path, refuse: Refuse) -> io::Result<(Self, UnixListener)> {
        owned(path.parent().ok_or_else(refuse)?, 0o750, true, refuse)?;
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(refuse()),
        }
        let listener: StdUnixListener = StdUnixListener::bind(path)?;
        let metadata: Metadata = fs::symlink_metadata(path)?;
        let owner: Self = Self {
            path: path.into(),
            inode: identity(&metadata),
            refuse,
        };
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
        let after: Metadata = fs::symlink_metadata(path)?;
        if !after.file_type().is_socket()
            || after.uid() != own_uid(refuse)?
            || identity(&after) != owner.inode
        {
            return Err(refuse());
        }
        listener.set_nonblocking(true)?;
        Ok((owner, UnixListener::from_std(listener)?))
    }

    fn remove(&self) -> io::Result<()> {
        let after: Metadata = fs::symlink_metadata(&self.path)?;
        if identity(&after) != self.inode || !after.file_type().is_socket() {
            return Err((self.refuse)());
        }
        fs::remove_file(&self.path)
    }

    pub(crate) fn close(self) -> io::Result<()> {
        self.remove()
    }
}

impl Drop for SocketOwner {
    fn drop(&mut self) {
        let _removed: io::Result<()> = self.remove();
    }
}
