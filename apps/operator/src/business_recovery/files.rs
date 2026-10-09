//! Private capture, attached snapshots and no-clobber publication only.
#![forbid(unsafe_code)]

use super::{
    RecoveryError, RecoveryLimits,
    envelope::{COMPLETE, Entry, Manifest, Role},
    transport::effective_uid,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use sunrise_edge_client::immutable_archive::{
    ArchiveReadBudget, AttachedFilePolicy, AttachedFileStamp, AttachedRegularFile,
    ImmutableArchiveReader,
};

pub(super) const TRANSFER: usize = 64 * 1024;

/// The existing parent is held before any output creation. Both successful and
/// failed invocations refuse any preexisting leaf, including identical bytes.
pub(super) struct AbsentOutput {
    path: PathBuf,
    parent: ImmutableArchiveReader,
}
impl AbsentOutput {
    pub(super) fn new(path: &Path, budget: &ArchiveReadBudget) -> Result<Self, RecoveryError> {
        if path
            .components()
            .any(|part: Component<'_>| matches!(part, Component::ParentDir))
        {
            return Err(RecoveryError::InvalidInput);
        }
        let name = path.file_name().ok_or(RecoveryError::InvalidInput)?;
        if name.len() > 251 || name.is_empty() {
            return Err(RecoveryError::InvalidInput);
        }
        let parent: ImmutableArchiveReader = ImmutableArchiveReader::open_bounded(
            path.parent()
                .filter(|value: &&Path| !value.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
            budget,
        )
        .map_err(|_| RecoveryError::Attachment)?;
        let output: Self = Self {
            path: parent.root().join(name),
            parent,
        };
        output.check()?;
        Ok(output)
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn check(&self) -> Result<(), RecoveryError> {
        self.parent
            .ensure_attached()
            .map_err(|_| RecoveryError::Attachment)?;
        match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(RecoveryError::Publication),
        }
    }
    pub(super) fn headroom(&self, budget: &ArchiveReadBudget) -> Result<(), RecoveryError> {
        self.check()?;
        budget.check().map_err(|_| RecoveryError::Quota)?;
        #[cfg(unix)]
        let available: u64 = {
            let stat: rustix::fs::StatVfs = rustix::fs::fstatvfs(self.parent.directory())
                .map_err(|_| RecoveryError::Publication)?;
            if stat.f_frsize == 0 {
                return Err(RecoveryError::Quota);
            }
            stat.f_bavail
                .checked_mul(stat.f_frsize)
                .ok_or(RecoveryError::Quota)?
        };
        #[cfg(not(unix))]
        let available: u64 = return Err(RecoveryError::Unsupported);
        if available < 1024 * 1024 * 1024 {
            return Err(RecoveryError::Quota);
        }
        self.check()?;
        budget.check().map_err(|_| RecoveryError::Quota)
    }
}

pub(super) fn distinct(first: &AbsentOutput, second: &AbsentOutput) -> Result<(), RecoveryError> {
    first.check()?;
    second.check()?;
    if first.path.starts_with(&second.path) || second.path.starts_with(&first.path) {
        return Err(RecoveryError::InvalidInput);
    }
    Ok(())
}

pub(super) struct SourceRole {
    role: Role,
    root: ImmutableArchiveReader,
    genesis: Option<PathBuf>,
}
impl SourceRole {
    pub(super) fn archive(
        role: Role,
        path: &Path,
        budget: &ArchiveReadBudget,
    ) -> Result<Self, RecoveryError> {
        Ok(Self {
            role,
            root: ImmutableArchiveReader::open_bounded(path, budget)
                .map_err(|_| RecoveryError::Attachment)?,
            genesis: None,
        })
    }
    pub(super) fn genesis(path: &Path, budget: &ArchiveReadBudget) -> Result<Self, RecoveryError> {
        let parent: &Path = path
            .parent()
            .filter(|value: &&Path| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let root: ImmutableArchiveReader = ImmutableArchiveReader::open_bounded(parent, budget)
            .map_err(|_| RecoveryError::Attachment)?;
        let name = path.file_name().ok_or(RecoveryError::InvalidInput)?;
        let genesis: PathBuf = root.root().join(name);
        Ok(Self {
            role: Role {
                tag: 1,
                link: u16::MAX,
            },
            root,
            genesis: Some(genesis),
        })
    }
    pub(super) fn outside(&self, output: &AbsentOutput) -> Result<(), RecoveryError> {
        output.check()?;
        // A public genesis file is one leaf, not authority over its whole
        // parent. An absent destination cannot already alias that leaf.
        if let Some(genesis) = &self.genesis {
            if genesis.starts_with(output.path()) || output.path() == genesis {
                return Err(RecoveryError::InvalidInput);
            }
            self.root
                .ensure_attached()
                .map_err(|_| RecoveryError::Attachment)
        } else {
            self.root
                .require_output_outside(output.path())
                .map_err(|_| RecoveryError::InvalidInput)
        }
    }
    pub(super) fn names(&self) -> Result<BTreeSet<String>, RecoveryError> {
        let budget: &ArchiveReadBudget = self.root.read_budget().ok_or(RecoveryError::Quota)?;
        if self.genesis.is_some() {
            budget
                .charge_observations(1)
                .map_err(|_| RecoveryError::Quota)?;
            return Ok(BTreeSet::from(["genesis.bin".to_owned()]));
        }
        // Preserve the FULL source inventory across capture. Canonical empty
        // directories are not harmless: rebuilding only files must not silently
        // remove material that the defining history owner would reject.
        let names: BTreeSet<String> = self
            .root
            .names_recursive()
            .map_err(|_| RecoveryError::Inventory)?;
        let mut required_directories: BTreeSet<String> = BTreeSet::new();
        let mut has_file: bool = false;
        for name in &names {
            budget.check().map_err(|_| RecoveryError::Quota)?;
            if name.ends_with('/') {
                if !matches!(self.role.tag, 2 | 4 | 6)
                    || !sunrise_edge_client::ordered_history_archive::generated_directory(name)
                {
                    return Err(RecoveryError::Inventory);
                }
            } else {
                self.role.file_limit(name)?;
                has_file = true;
                for (end, _) in name.match_indices('/') {
                    budget
                        .charge_observations(1)
                        .map_err(|_| RecoveryError::Quota)?;
                    required_directories.insert(name[..=end].to_owned());
                }
            }
        }
        for name in &names {
            budget.check().map_err(|_| RecoveryError::Quota)?;
            if name.ends_with('/') && !required_directories.contains(name) {
                return Err(RecoveryError::Inventory);
            }
        }
        if !has_file
            || required_directories
                .iter()
                .any(|name: &String| !names.contains(name))
        {
            return Err(RecoveryError::Inventory);
        }
        Ok(names)
    }
    fn open(
        &self,
        name: &str,
        budget: &ArchiveReadBudget,
        limits: &RecoveryLimits,
    ) -> Result<AttachedRegularFile, RecoveryError> {
        let native: u64 =
            u64::try_from(self.role.file_limit(name)?).map_err(|_| RecoveryError::Quota)?;
        let maximum: u64 = native.min(limits.file_bytes);
        self.root
            .ensure_attached()
            .map_err(|_| RecoveryError::Attachment)?;
        match &self.genesis {
            Some(path) => {
                AttachedRegularFile::open(path, maximum, budget, AttachedFilePolicy::public())
                    .map_err(|_| RecoveryError::Attachment)
            }
            None => self
                .root
                .open_file(name, maximum)
                .map_err(|_| RecoveryError::Attachment),
        }
    }
}

/// One private exclusive stage. It is never adopted, repaired or deleted on
/// failure. Directory stamps exclude self-generated timestamp changes only;
/// exact regular-file snapshots include every timestamp.
pub(super) struct PrivateStage {
    root: ImmutableArchiveReader,
    budget: ArchiveReadBudget,
    uid: u32,
    directories: BTreeSet<PathBuf>,
    directory_stamps: BTreeMap<PathBuf, DirectoryStamp>,
    snapshots: BTreeMap<PathBuf, AttachedFileStamp>,
}
impl PrivateStage {
    pub(super) fn create(
        output: &AbsentOutput,
        budget: &ArchiveReadBudget,
    ) -> Result<Self, RecoveryError> {
        output.check()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(output.path())
                .map_err(|_| RecoveryError::Publication)?;
        }
        #[cfg(not(unix))]
        {
            return Err(RecoveryError::Unsupported);
        }
        let root: ImmutableArchiveReader =
            ImmutableArchiveReader::open_bounded(output.path(), budget)
                .map_err(|_| RecoveryError::Attachment)?;
        let stamp: DirectoryStamp = DirectoryStamp::read(root.directory())?;
        let stage: Self = Self {
            root,
            budget: budget.clone(),
            uid: effective_uid()?,
            directories: BTreeSet::from([PathBuf::new()]),
            directory_stamps: BTreeMap::from([(PathBuf::new(), stamp)]),
            snapshots: BTreeMap::new(),
        };
        stage.check_directory(Path::new(""))?;
        stage.sync(Path::new(""))?;
        output
            .parent
            .directory()
            .sync_all()
            .map_err(|_| RecoveryError::Publication)?;
        Ok(stage)
    }
    pub(super) fn root(&self) -> &Path {
        self.root.root()
    }
    fn check_directory(&self, relative: &Path) -> Result<ImmutableArchiveReader, RecoveryError> {
        self.root
            .ensure_attached()
            .map_err(|_| RecoveryError::Attachment)?;
        let directory: ImmutableArchiveReader =
            ImmutableArchiveReader::open_bounded(&self.root.root().join(relative), &self.budget)
                .map_err(|_| RecoveryError::Attachment)?;
        let metadata: std::fs::Metadata = directory
            .directory()
            .metadata()
            .map_err(|_| RecoveryError::Attachment)?;
        if self.directory_stamps.get(relative)
            != Some(&DirectoryStamp::read(directory.directory())?)
        {
            return Err(RecoveryError::Attachment);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != self.uid || metadata.mode() & 0o7777 != 0o700 {
                return Err(RecoveryError::Attachment);
            }
        }
        Ok(directory)
    }
    fn sync(&self, relative: &Path) -> Result<(), RecoveryError> {
        let directory: ImmutableArchiveReader = self.check_directory(relative)?;
        directory
            .directory()
            .sync_all()
            .map_err(|_| RecoveryError::Publication)?;
        directory
            .ensure_attached()
            .map_err(|_| RecoveryError::Attachment)
    }
    fn prepare_parent(&mut self, relative: &Path) -> Result<(), RecoveryError> {
        let parent: &Path = relative.parent().ok_or(RecoveryError::Inventory)?;
        let mut path: PathBuf = PathBuf::new();
        for part in parent.components() {
            if !matches!(part, Component::Normal(_)) {
                return Err(RecoveryError::Inventory);
            }
            let previous: PathBuf = path.clone();
            path.push(part);
            if self.directories.contains(&path) {
                self.check_directory(&path)?;
                continue;
            }
            self.check_directory(&previous)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(self.root.root().join(&path))
                    .map_err(|_| RecoveryError::Publication)?;
            }
            self.directories.insert(path.clone());
            let created: ImmutableArchiveReader =
                ImmutableArchiveReader::open_bounded(&self.root.root().join(&path), &self.budget)
                    .map_err(|_| RecoveryError::Attachment)?;
            self.directory_stamps
                .insert(path.clone(), DirectoryStamp::read(created.directory())?);
            self.check_directory(&path)?;
            self.sync(&previous)?;
        }
        Ok(())
    }
    pub(super) fn relative(&self, entry: &Entry) -> Result<PathBuf, RecoveryError> {
        entry.role.file_limit(&entry.name)?;
        let root: PathBuf = entry.role.root(Path::new(""))?;
        Ok(root.join(&entry.name))
    }
    fn new_file(&mut self, relative: &Path) -> Result<File, RecoveryError> {
        self.prepare_parent(relative)?;
        let file: File = create_private_file(&self.root.root().join(relative))?;
        self.check_directory(relative.parent().ok_or(RecoveryError::Inventory)?)?;
        Ok(file)
    }
    fn finish_file(
        &mut self,
        relative: PathBuf,
        file: File,
        expected: u64,
    ) -> Result<(), RecoveryError> {
        file.sync_all().map_err(|_| RecoveryError::Publication)?;
        let metadata: std::fs::Metadata = file.metadata().map_err(|_| RecoveryError::Attachment)?;
        if metadata.len() != expected {
            return Err(RecoveryError::Attachment);
        }
        check_private(&metadata, self.uid, 1)?;
        let leaf: AttachedRegularFile = AttachedRegularFile::open(
            &self.root.root().join(&relative),
            expected,
            &self.budget,
            AttachedFilePolicy::private_identity(self.uid),
        )
        .map_err(|_| RecoveryError::Attachment)?;
        check_same(&metadata, leaf.stamp())?;
        self.snapshots
            .insert(relative.clone(), leaf.stamp().clone());
        self.sync(relative.parent().ok_or(RecoveryError::Inventory)?)
    }
    pub(super) fn capture(
        &mut self,
        sources: &[SourceRole],
        links: u16,
        limits: &RecoveryLimits,
    ) -> Result<Manifest, RecoveryError> {
        let mut entries: Vec<Entry> = Vec::new();
        let mut aggregate: u64 = 0;
        let mut control: u64 = 68u64
            .checked_add(16)
            .and_then(|value| value.checked_add(7u64.checked_mul(u64::from(3 + 4 * links))?))
            .ok_or(RecoveryError::Quota)?;
        for source in sources {
            let before: BTreeSet<String> = source.names()?;
            for name in &before {
                // Directory markers participate in the before/after closure;
                // only their descendant files are carried in the envelope.
                if name.ends_with('/') {
                    continue;
                }
                if entries.len() >= limits.files {
                    return Err(RecoveryError::Quota);
                }
                let mut input: AttachedRegularFile = source.open(name, &self.budget, limits)?;
                let length: u64 = input.stamp().length;
                if length == 0 {
                    return Err(RecoveryError::Inventory);
                }
                aggregate = aggregate.checked_add(length).ok_or(RecoveryError::Quota)?;
                if aggregate > limits.plaintext_bytes {
                    return Err(RecoveryError::Quota);
                }
                let mut entry: Entry = Entry {
                    role: source.role,
                    name: name.clone(),
                    length,
                    hash: [0; 32],
                };
                // Corresponding framing/control admission happens before any
                // body write, not after a potentially oversized capture.
                control = control
                    .checked_add(62)
                    .and_then(|value| value.checked_add(u64::try_from(name.len()).ok()?))
                    .ok_or(RecoveryError::Quota)?;
                if control > limits.control_bytes
                    || control
                        .checked_add(aggregate)
                        .is_none_or(|value| value > limits.plaintext_bytes)
                {
                    return Err(RecoveryError::Quota);
                }
                let relative: PathBuf = self.relative(&entry)?;
                let mut output: File = self.new_file(&relative)?;
                entry.hash = copy_body(&mut input, &mut output, length, &self.budget)?;
                input
                    .ensure_attached()
                    .map_err(|_| RecoveryError::Attachment)?;
                self.finish_file(relative, output, length)?;
                entries.push(entry);
            }
            if before != source.names()? {
                return Err(RecoveryError::Inventory);
            }
        }
        Manifest::encode(links, entries, limits)
    }
    pub(super) fn receive<R: Read>(
        &mut self,
        reader: &mut R,
        entry: &Entry,
    ) -> Result<(), RecoveryError> {
        let relative: PathBuf = self.relative(entry)?;
        let mut output: File = self.new_file(&relative)?;
        let hash: [u8; 32] = copy_exact_body(reader, &mut output, entry.length, &self.budget)?;
        if hash != entry.hash {
            return Err(RecoveryError::Inventory);
        }
        self.finish_file(relative, output, entry.length)
    }
    pub(super) fn write_body<W: Write>(
        &self,
        output: &mut W,
        entry: &Entry,
    ) -> Result<(), RecoveryError> {
        let relative: PathBuf = self.relative(entry)?;
        let mut file: AttachedRegularFile = self.open_snapshot(&relative, entry.length)?;
        if copy_body(&mut file, output, entry.length, &self.budget)? != entry.hash {
            return Err(RecoveryError::Inventory);
        }
        file.ensure_attached()
            .map_err(|_| RecoveryError::Attachment)
    }
    fn open_snapshot(
        &self,
        relative: &Path,
        maximum: u64,
    ) -> Result<AttachedRegularFile, RecoveryError> {
        self.check_directory(relative.parent().ok_or(RecoveryError::Inventory)?)?;
        let file: AttachedRegularFile = AttachedRegularFile::open(
            &self.root.root().join(relative),
            maximum,
            &self.budget,
            AttachedFilePolicy::private_identity(self.uid),
        )
        .map_err(|_| RecoveryError::Attachment)?;
        if self.snapshots.get(relative) != Some(file.stamp()) {
            return Err(RecoveryError::Attachment);
        }
        Ok(file)
    }
    pub(super) fn check(&self, manifest: &Manifest) -> Result<(), RecoveryError> {
        self.budget.check().map_err(|_| RecoveryError::Quota)?;
        // Compare every direct entry at every KNOWN generated parent. Unknown
        // empty directories cannot be lost by a recursive file-only listing.
        self.check_inventory()?;
        if self.snapshots.len() != manifest.entries.len() {
            return Err(RecoveryError::Inventory);
        }
        for entry in &manifest.entries {
            self.write_body(&mut std::io::sink(), entry)?;
        }
        self.budget.check().map_err(|_| RecoveryError::Quota)
    }
    fn check_inventory(&self) -> Result<(), RecoveryError> {
        for directory in &self.directories {
            self.check_directory(directory)?;
            for entry in std::fs::read_dir(self.root.root().join(directory))
                .map_err(|_| RecoveryError::Inventory)?
            {
                self.budget
                    .charge_observations(1)
                    .map_err(|_| RecoveryError::Quota)?;
                let entry: std::fs::DirEntry = entry.map_err(|_| RecoveryError::Inventory)?;
                let relative: PathBuf = directory.join(entry.file_name());
                if !self.directories.contains(&relative) && !self.snapshots.contains_key(&relative)
                {
                    return Err(RecoveryError::Inventory);
                }
            }
        }
        Ok(())
    }
    pub(super) fn complete(
        &mut self,
        manifest: &Manifest,
        footer: &[u8; 49],
    ) -> Result<(), RecoveryError> {
        let relative: PathBuf = PathBuf::from(COMPLETE);
        let mut file: File = self.new_file(&relative)?;
        file.write_all(footer)
            .map_err(|_| RecoveryError::Publication)?;
        self.finish_file(relative.clone(), file, 49)?;
        self.sync(Path::new(""))?;
        self.check_inventory()?;
        if self.snapshots.len()
            != manifest
                .entries
                .len()
                .checked_add(1)
                .ok_or(RecoveryError::Quota)?
        {
            return Err(RecoveryError::Inventory);
        }
        for entry in &manifest.entries {
            self.write_body(&mut std::io::sink(), entry)?;
        }
        let mut diagnostic: AttachedRegularFile = self.open_snapshot(&relative, 49)?;
        let mut actual: [u8; 49] = [0; 49];
        diagnostic
            .read_exact(&mut actual)
            .map_err(|_| RecoveryError::Attachment)?;
        let mut probe: [u8; 1] = [0];
        if actual != *footer
            || diagnostic
                .read(&mut probe)
                .map_err(|_| RecoveryError::Attachment)?
                != 0
        {
            return Err(RecoveryError::Attachment);
        }
        diagnostic
            .ensure_attached()
            .map_err(|_| RecoveryError::Attachment)?;
        self.budget.check().map_err(|_| RecoveryError::Quota)
    }
}

#[derive(PartialEq, Eq)]
struct DirectoryStamp {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
}
impl DirectoryStamp {
    fn read(file: &File) -> Result<Self, RecoveryError> {
        let metadata: std::fs::Metadata = file.metadata().map_err(|_| RecoveryError::Attachment)?;
        Self::from_metadata(&metadata)
    }
    fn from_metadata(metadata: &std::fs::Metadata) -> Result<Self, RecoveryError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !metadata.is_dir() {
                return Err(RecoveryError::Attachment);
            }
            Ok(Self {
                dev: metadata.dev(),
                ino: metadata.ino(),
                mode: metadata.mode(),
                uid: metadata.uid(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(RecoveryError::Unsupported)
        }
    }
}

fn copy_exact_body<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    length: u64,
    budget: &ArchiveReadBudget,
) -> Result<[u8; 32], RecoveryError> {
    let mut left: u64 = length;
    let mut hash: Sha256 = Sha256::new();
    let mut buffer: [u8; TRANSFER] = [0; TRANSFER];
    while left != 0 {
        budget.check().map_err(|_| RecoveryError::Quota)?;
        let count: usize = buffer
            .len()
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        let read: usize = input
            .read(&mut buffer[..count])
            .map_err(|_| RecoveryError::Transport)?;
        if read == 0 || read > count {
            return Err(RecoveryError::Transport);
        }
        output
            .write_all(&buffer[..read])
            .map_err(|_| RecoveryError::Transport)?;
        hash.update(&buffer[..read]);
        left = left
            .checked_sub(u64::try_from(read).map_err(|_| RecoveryError::Quota)?)
            .ok_or(RecoveryError::Quota)?;
    }
    budget.check().map_err(|_| RecoveryError::Quota)?;
    Ok(hash.finalize().into())
}
fn copy_body<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    length: u64,
    budget: &ArchiveReadBudget,
) -> Result<[u8; 32], RecoveryError> {
    let hash: [u8; 32] = copy_exact_body(input, output, length, budget)?;
    let mut probe: [u8; 1] = [0];
    if input
        .read(&mut probe)
        .map_err(|_| RecoveryError::Transport)?
        != 0
    {
        return Err(RecoveryError::Attachment);
    }
    budget.check().map_err(|_| RecoveryError::Quota)?;
    Ok(hash)
}

fn create_private_file(path: &Path) -> Result<File, RecoveryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| RecoveryError::Publication)?;
        check_private(
            &file.metadata().map_err(|_| RecoveryError::Attachment)?,
            effective_uid()?,
            1,
        )?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(RecoveryError::Unsupported)
    }
}
fn check_private(metadata: &std::fs::Metadata, uid: u32, links: u64) -> Result<(), RecoveryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != links
        {
            return Err(RecoveryError::Attachment);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, uid, links);
        Err(RecoveryError::Unsupported)
    }
}
fn check_same(
    metadata: &std::fs::Metadata,
    stamp: &AttachedFileStamp,
) -> Result<(), RecoveryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.uid(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ) != (
            stamp.dev,
            stamp.ino,
            stamp.mode,
            stamp.uid,
            stamp.nlink,
            stamp.length,
            stamp.mtime,
            stamp.mtime_nsec,
            stamp.ctime,
            stamp.ctime_nsec,
        ) {
            return Err(RecoveryError::Attachment);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, stamp);
        Err(RecoveryError::Unsupported)
    }
}

pub(super) struct CipherPublication {
    final_output: AbsentOutput,
    pending: PathBuf,
    file: File,
    budget: ArchiveReadBudget,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PublicationFailureAt {
    PendingCreate,
    CreateParentSync,
    PendingFileSync,
    FinalHardLink,
    LinkedParentSync,
    PendingUnlink,
    FinalParentSync,
}

fn publication_step(
    selected: Option<PublicationFailureAt>,
    step: PublicationFailureAt,
) -> Result<(), RecoveryError> {
    if selected == Some(step) {
        Err(RecoveryError::Publication)
    } else {
        Ok(())
    }
}

impl CipherPublication {
    pub(super) fn pending_path(path: &Path) -> Result<PathBuf, RecoveryError> {
        let mut name = path
            .file_name()
            .ok_or(RecoveryError::InvalidInput)?
            .to_os_string();
        name.push(".incomplete");
        if name.len() > 251 {
            return Err(RecoveryError::InvalidInput);
        }
        Ok(path.parent().ok_or(RecoveryError::InvalidInput)?.join(name))
    }
    pub(super) fn create(
        output: AbsentOutput,
        budget: &ArchiveReadBudget,
    ) -> Result<Self, RecoveryError> {
        Self::create_inner(output, budget, None)
    }
    fn create_inner(
        output: AbsentOutput,
        budget: &ArchiveReadBudget,
        fail_at: Option<PublicationFailureAt>,
    ) -> Result<Self, RecoveryError> {
        output.check()?;
        let pending: PathBuf = Self::pending_path(output.path())?;
        publication_step(fail_at, PublicationFailureAt::PendingCreate)?;
        let file: File = create_private_file(&pending)?;
        publication_step(fail_at, PublicationFailureAt::CreateParentSync)?;
        output
            .parent
            .directory()
            .sync_all()
            .map_err(|_| RecoveryError::Publication)?;
        Ok(Self {
            final_output: output,
            pending,
            file,
            budget: budget.clone(),
        })
    }
    #[cfg(all(test, target_os = "linux"))]
    fn create_with_failure_at(
        output: AbsentOutput,
        budget: &ArchiveReadBudget,
        fail_at: PublicationFailureAt,
    ) -> Result<Self, RecoveryError> {
        Self::create_inner(output, budget, Some(fail_at))
    }
    pub(super) fn writer(&mut self) -> &mut File {
        &mut self.file
    }
    pub(super) fn publish(
        self,
        length: u64,
        hash: [u8; 32],
        maximum: u64,
    ) -> Result<(), RecoveryError> {
        self.publish_inner(length, hash, maximum, None)
    }
    fn publish_inner(
        self,
        length: u64,
        hash: [u8; 32],
        maximum: u64,
        fail_at: Option<PublicationFailureAt>,
    ) -> Result<(), RecoveryError> {
        publication_step(fail_at, PublicationFailureAt::PendingFileSync)?;
        self.file
            .sync_all()
            .map_err(|_| RecoveryError::Publication)?;
        let stamp: std::fs::Metadata = self
            .file
            .metadata()
            .map_err(|_| RecoveryError::Attachment)?;
        check_private(&stamp, effective_uid()?, 1)?;
        if stamp.len() != length {
            return Err(RecoveryError::Attachment);
        }
        let mut held: AttachedRegularFile = AttachedRegularFile::open(
            &self.pending,
            maximum,
            &self.budget,
            AttachedFilePolicy::private_identity(effective_uid()?),
        )
        .map_err(|_| RecoveryError::Attachment)?;
        check_same(&stamp, held.stamp())?;
        if copy_body(&mut held, &mut std::io::sink(), length, &self.budget)? != hash {
            return Err(RecoveryError::Attachment);
        }
        held.ensure_attached()
            .map_err(|_| RecoveryError::Attachment)?;
        self.final_output.check()?;
        publication_step(fail_at, PublicationFailureAt::FinalHardLink)?;
        std::fs::hard_link(&self.pending, self.final_output.path())
            .map_err(|_| RecoveryError::Publication)?;
        // Only this successful owned publication may change nlink/ctime.
        // No arbitrary preexisting alias is accepted or removed.
        let actual: std::fs::Metadata = std::fs::symlink_metadata(self.final_output.path())
            .map_err(|_| RecoveryError::Attachment)?;
        let pending: std::fs::Metadata =
            std::fs::symlink_metadata(&self.pending).map_err(|_| RecoveryError::Attachment)?;
        check_link(&stamp, &actual, 2)?;
        check_link(&stamp, &pending, 2)?;
        publication_step(fail_at, PublicationFailureAt::LinkedParentSync)?;
        self.final_output
            .parent
            .directory()
            .sync_all()
            .map_err(|_| RecoveryError::Publication)?;
        self.final_output
            .parent
            .ensure_attached()
            .map_err(|_| RecoveryError::Attachment)?;
        let mut linked: AttachedRegularFile = AttachedRegularFile::open(
            &self.pending,
            maximum,
            &self.budget,
            AttachedFilePolicy::public(),
        )
        .map_err(|_| RecoveryError::Attachment)?;
        if copy_body(&mut linked, &mut std::io::sink(), length, &self.budget)? != hash {
            return Err(RecoveryError::Attachment);
        }
        linked
            .ensure_attached()
            .map_err(|_| RecoveryError::Attachment)?;
        check_link(
            &stamp,
            &self
                .file
                .metadata()
                .map_err(|_| RecoveryError::Attachment)?,
            2,
        )?;
        publication_step(fail_at, PublicationFailureAt::PendingUnlink)?;
        std::fs::remove_file(&self.pending).map_err(|_| RecoveryError::Publication)?;
        let actual: std::fs::Metadata = std::fs::symlink_metadata(self.final_output.path())
            .map_err(|_| RecoveryError::Attachment)?;
        check_link(&stamp, &actual, 1)?;
        publication_step(fail_at, PublicationFailureAt::FinalParentSync)?;
        self.final_output
            .parent
            .directory()
            .sync_all()
            .map_err(|_| RecoveryError::Publication)?;
        let mut final_file: AttachedRegularFile = AttachedRegularFile::open(
            self.final_output.path(),
            maximum,
            &self.budget,
            AttachedFilePolicy::private_identity(effective_uid()?),
        )
        .map_err(|_| RecoveryError::Attachment)?;
        if copy_body(&mut final_file, &mut std::io::sink(), length, &self.budget)? != hash {
            return Err(RecoveryError::Attachment);
        }
        final_file
            .ensure_attached()
            .map_err(|_| RecoveryError::Attachment)
    }
    #[cfg(all(test, target_os = "linux"))]
    fn publish_with_failure_at(
        self,
        length: u64,
        hash: [u8; 32],
        maximum: u64,
        fail_at: PublicationFailureAt,
    ) -> Result<(), RecoveryError> {
        self.publish_inner(length, hash, maximum, Some(fail_at))
    }
}
fn check_link(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
    links: u64,
) -> Result<(), RecoveryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (
            before.dev(),
            before.ino(),
            before.mode(),
            before.uid(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mode(),
            after.uid(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
        ) || after.nlink() != links
            || !after.is_file()
        {
            return Err(RecoveryError::Attachment);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (before, after, links);
        Err(RecoveryError::Unsupported)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod publication_controls {
    use super::*;
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    struct PublicationTestDirectory {
        path: PathBuf,
        root: ImmutableArchiveReader,
        original: DirectoryStamp,
    }

    impl PublicationTestDirectory {
        fn new(budget: &ArchiveReadBudget) -> Self {
            budget.check().expect("admit fixture before creating it");
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
            let path: PathBuf = std::env::temp_dir().join(format!(
                "recovery-publication-{}-{sequence}",
                std::process::id()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .expect("create this test's private fixture root");
            let root: ImmutableArchiveReader =
                ImmutableArchiveReader::open_bounded(&path, budget)
                    .expect("hold this test's private fixture root");
            let original: DirectoryStamp =
                DirectoryStamp::read(root.directory()).expect("stamp fixture root");
            assert_eq!(root.root(), path.as_path());
            assert_eq!(original.uid, effective_uid().unwrap());
            assert_eq!(original.mode & 0o7777, 0o700);
            Self {
                path,
                root,
                original,
            }
        }
    }

    impl Drop for PublicationTestDirectory {
        fn drop(&mut self) {
            self.root
                .ensure_attached()
                .expect("held fixture root remains attached before cleanup");
            let attached: DirectoryStamp =
                DirectoryStamp::read(self.root.directory()).expect("read held fixture root");
            let named: std::fs::Metadata = std::fs::symlink_metadata(&self.path)
                .expect("fixture path remains present before cleanup");
            let named_stamp: DirectoryStamp = DirectoryStamp::from_metadata(&named)
                .expect("fixture path still names a directory");
            assert!(attached == self.original, "held fixture identity changed");
            assert!(named_stamp == self.original, "named fixture identity changed");
            assert_eq!(self.root.root(), self.path.as_path());
            std::fs::remove_dir_all(&self.path)
                .expect("remove only the still-attached private fixture root");
        }
    }

    fn absent(path: &Path) {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => panic!("expected absent publication leaf"),
        }
    }

    fn file_stamp(
        metadata: &std::fs::Metadata,
    ) -> (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64) {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.uid(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    }

    fn assert_retained_file(
        path: &Path,
        expected: &[u8],
        original: &std::fs::Metadata,
        links: u64,
        allow_ctime_change: bool,
    ) {
        let metadata: std::fs::Metadata =
            std::fs::symlink_metadata(path).expect("expected retained publication leaf");
        assert!(metadata.is_file());
        assert_eq!(metadata.dev(), original.dev());
        assert_eq!(metadata.ino(), original.ino());
        assert_eq!(metadata.uid(), original.uid());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.mode(), original.mode());
        assert_eq!(metadata.nlink(), links);
        assert_eq!(metadata.len(), original.len());
        assert_eq!(metadata.len(), expected.len() as u64);
        assert_eq!(metadata.mtime(), original.mtime());
        assert_eq!(metadata.mtime_nsec(), original.mtime_nsec());
        if !allow_ctime_change {
            assert_eq!(metadata.ctime(), original.ctime());
            assert_eq!(metadata.ctime_nsec(), original.ctime_nsec());
        }
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }

    fn ready_publication(
        directory: &Path,
        name: &str,
        bytes: &[u8],
        budget: &ArchiveReadBudget,
    ) -> (CipherPublication, PathBuf, PathBuf, std::fs::Metadata) {
        let output: PathBuf = directory.join(name);
        let pending: PathBuf = CipherPublication::pending_path(&output).unwrap();
        let absent_output: AbsentOutput = AbsentOutput::new(&output, budget).unwrap();
        let mut publication: CipherPublication =
            CipherPublication::create(absent_output, budget).unwrap();
        publication.writer().write_all(bytes).unwrap();
        let original: std::fs::Metadata =
            publication.file.metadata().expect("capture held pending metadata");
        (publication, output, pending, original)
    }

    fn create_sentinel(directory: &Path, name: &str) -> (PathBuf, Vec<u8>, std::fs::Metadata) {
        let path: PathBuf = directory.join(name);
        let bytes: Vec<u8> = format!("unrelated sentinel for {name}").into_bytes();
        std::fs::write(&path, &bytes).expect("create unrelated sentinel");
        let metadata: std::fs::Metadata =
            std::fs::symlink_metadata(&path).expect("stamp unrelated sentinel");
        (path, bytes, metadata)
    }

    fn assert_sentinel(path: &Path, bytes: &[u8], original: &std::fs::Metadata) {
        let current: std::fs::Metadata =
            std::fs::symlink_metadata(path).expect("unrelated sentinel remains present");
        assert_eq!(file_stamp(&current), file_stamp(original));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    fn content_hash(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    #[test]
    fn pending_create_refusal_and_real_collision_preserve_existing_leaf() {
        let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
        let directory: PublicationTestDirectory = PublicationTestDirectory::new(&budget);
        let (sentinel_path, sentinel_bytes, sentinel_before):
            (PathBuf, Vec<u8>, std::fs::Metadata) =
            create_sentinel(&directory.path, "pending-create-sentinel");
        let output: PathBuf = directory.path.join("new-output");
        let pending: PathBuf = CipherPublication::pending_path(&output).unwrap();
        let refused: Result<CipherPublication, RecoveryError> =
            CipherPublication::create_with_failure_at(
                AbsentOutput::new(&output, &budget).unwrap(),
                &budget,
                PublicationFailureAt::PendingCreate,
            );
        assert!(matches!(refused, Err(RecoveryError::Publication)));
        absent(&output);
        absent(&pending);
        assert_sentinel(&sentinel_path, &sentinel_bytes, &sentinel_before);

        let (collision_sentinel_path, collision_sentinel_bytes, collision_sentinel_before):
            (PathBuf, Vec<u8>, std::fs::Metadata) =
            create_sentinel(&directory.path, "collision-sentinel");
        let collision_output: PathBuf = directory.path.join("collision-output");
        let collision_pending: PathBuf =
            CipherPublication::pending_path(&collision_output).unwrap();
        let sentinel: &[u8] = b"preexisting pending sentinel";
        std::fs::write(&collision_pending, sentinel).unwrap();
        let before: std::fs::Metadata = std::fs::symlink_metadata(&collision_pending).unwrap();
        let refused: Result<CipherPublication, RecoveryError> = CipherPublication::create(
            AbsentOutput::new(&collision_output, &budget).unwrap(),
            &budget,
        );
        assert!(matches!(refused, Err(RecoveryError::Publication)));
        let after: std::fs::Metadata = std::fs::symlink_metadata(&collision_pending).unwrap();
        assert_eq!(file_stamp(&after), file_stamp(&before));
        assert_eq!(std::fs::read(&collision_pending).unwrap(), sentinel);
        absent(&collision_output);
        assert_sentinel(
            &collision_sentinel_path,
            &collision_sentinel_bytes,
            &collision_sentinel_before,
        );
    }

    #[test]
    fn create_parent_sync_refusal_retains_only_empty_owned_pending_file() {
        let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
        let directory: PublicationTestDirectory = PublicationTestDirectory::new(&budget);
        let (sentinel_path, sentinel_bytes, sentinel_before):
            (PathBuf, Vec<u8>, std::fs::Metadata) =
            create_sentinel(&directory.path, "create-sync-sentinel");
        let output: PathBuf = directory.path.join("create-sync-output");
        let pending: PathBuf = CipherPublication::pending_path(&output).unwrap();
        let refused: Result<CipherPublication, RecoveryError> =
            CipherPublication::create_with_failure_at(
                AbsentOutput::new(&output, &budget).unwrap(),
                &budget,
                PublicationFailureAt::CreateParentSync,
            );
        assert!(matches!(refused, Err(RecoveryError::Publication)));
        let metadata: std::fs::Metadata =
            std::fs::symlink_metadata(&pending).expect("empty pending file remains");
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), effective_uid().unwrap());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.len(), 0);
        assert_eq!(std::fs::read(&pending).unwrap(), b"");
        absent(&output);
        assert_sentinel(&sentinel_path, &sentinel_bytes, &sentinel_before);
    }

    #[test]
    fn prelink_sync_and_link_refusals_retain_complete_pending_only() {
        let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
        let directory: PublicationTestDirectory = PublicationTestDirectory::new(&budget);
        let bytes: &[u8] = b"deterministic publication body before linking";
        let cases: [(&str, PublicationFailureAt); 2] = [
            ("file-sync", PublicationFailureAt::PendingFileSync),
            ("hard-link", PublicationFailureAt::FinalHardLink),
        ];
        for (name, fail_at) in cases {
            let (sentinel_path, sentinel_bytes, sentinel_before):
                (PathBuf, Vec<u8>, std::fs::Metadata) =
                create_sentinel(&directory.path, &format!("{name}-sentinel"));
            let (publication, output, pending, original):
                (CipherPublication, PathBuf, PathBuf, std::fs::Metadata) =
                ready_publication(&directory.path, name, bytes, &budget);
            let refused: Result<(), RecoveryError> = publication.publish_with_failure_at(
                bytes.len() as u64,
                content_hash(bytes),
                bytes.len() as u64,
                fail_at,
            );
            assert!(matches!(refused, Err(RecoveryError::Publication)));
            assert_retained_file(&pending, bytes, &original, 1, false);
            absent(&output);
            assert_sentinel(&sentinel_path, &sentinel_bytes, &sentinel_before);
        }
    }

    #[test]
    fn postlink_sync_and_unlink_refusals_retain_both_owned_hardlinks() {
        let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
        let directory: PublicationTestDirectory = PublicationTestDirectory::new(&budget);
        let bytes: &[u8] = b"deterministic body retained at link count two";
        let cases: [(&str, PublicationFailureAt); 2] = [
            ("linked-sync", PublicationFailureAt::LinkedParentSync),
            ("pending-unlink", PublicationFailureAt::PendingUnlink),
        ];
        for (name, fail_at) in cases {
            let (sentinel_path, sentinel_bytes, sentinel_before):
                (PathBuf, Vec<u8>, std::fs::Metadata) =
                create_sentinel(&directory.path, &format!("{name}-sentinel"));
            let (publication, output, pending, original):
                (CipherPublication, PathBuf, PathBuf, std::fs::Metadata) =
                ready_publication(&directory.path, name, bytes, &budget);
            let refused: Result<(), RecoveryError> = publication.publish_with_failure_at(
                bytes.len() as u64,
                content_hash(bytes),
                bytes.len() as u64,
                fail_at,
            );
            assert!(matches!(refused, Err(RecoveryError::Publication)));
            assert_retained_file(&pending, bytes, &original, 2, true);
            assert_retained_file(&output, bytes, &original, 2, true);
            let pending_after: std::fs::Metadata = std::fs::symlink_metadata(&pending).unwrap();
            let output_after: std::fs::Metadata = std::fs::symlink_metadata(&output).unwrap();
            assert_eq!(pending_after.dev(), output_after.dev());
            assert_eq!(pending_after.ino(), output_after.ino());
            assert_eq!(pending_after.ctime(), output_after.ctime());
            assert_eq!(pending_after.ctime_nsec(), output_after.ctime_nsec());
            assert_sentinel(&sentinel_path, &sentinel_bytes, &sentinel_before);
        }
    }

    #[test]
    fn final_parent_sync_refusal_retains_final_only_and_success_preserves_sentinels() {
        let budget: ArchiveReadBudget = RecoveryLimits::default().budget().unwrap();
        let directory: PublicationTestDirectory = PublicationTestDirectory::new(&budget);
        let (failure_sentinel_path, failure_sentinel_bytes, failure_sentinel_before):
            (PathBuf, Vec<u8>, std::fs::Metadata) =
            create_sentinel(&directory.path, "final-sync-sentinel");
        let bytes: &[u8] = b"deterministic final-only body";
        let (publication, output, pending, original):
            (CipherPublication, PathBuf, PathBuf, std::fs::Metadata) =
            ready_publication(&directory.path, "final-sync", bytes, &budget);
        let refused: Result<(), RecoveryError> = publication.publish_with_failure_at(
            bytes.len() as u64,
            content_hash(bytes),
            bytes.len() as u64,
            PublicationFailureAt::FinalParentSync,
        );
        assert!(matches!(refused, Err(RecoveryError::Publication)));
        assert_retained_file(&output, bytes, &original, 1, true);
        absent(&pending);
        assert_sentinel(
            &failure_sentinel_path,
            &failure_sentinel_bytes,
            &failure_sentinel_before,
        );

        let sentinel_output: PathBuf = directory.path.join("sentinel-output");
        let sentinel: &[u8] = b"do not replace an existing final leaf";
        std::fs::write(&sentinel_output, sentinel).unwrap();
        let sentinel_before: std::fs::Metadata =
            std::fs::symlink_metadata(&sentinel_output).unwrap();
        assert!(AbsentOutput::new(&sentinel_output, &budget).is_err());
        let sentinel_after: std::fs::Metadata =
            std::fs::symlink_metadata(&sentinel_output).unwrap();
        assert_eq!(file_stamp(&sentinel_after), file_stamp(&sentinel_before));
        assert_eq!(std::fs::read(&sentinel_output).unwrap(), sentinel);

        let (success_sentinel_path, success_sentinel_bytes, success_sentinel_before):
            (PathBuf, Vec<u8>, std::fs::Metadata) =
            create_sentinel(&directory.path, "success-sentinel");
        let (publication, success_output, success_pending, success_original):
            (CipherPublication, PathBuf, PathBuf, std::fs::Metadata) =
            ready_publication(&directory.path, "success", bytes, &budget);
        publication
            .publish(bytes.len() as u64, content_hash(bytes), bytes.len() as u64)
            .unwrap();
        assert_retained_file(&success_output, bytes, &success_original, 1, true);
        absent(&success_pending);
        assert_sentinel(
            &success_sentinel_path,
            &success_sentinel_bytes,
            &success_sentinel_before,
        );
    }
}
