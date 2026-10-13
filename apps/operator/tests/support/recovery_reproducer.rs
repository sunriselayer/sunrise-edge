//! Failure-only, private reproducer DATA. Never runs the retained argv.
#![forbid(unsafe_code)]

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, mkdirat, openat, statat};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{DirBuilder, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        process::ExitStatusExt,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Inventory = BTreeMap<PathBuf, Option<Vec<u8>>>;
const ARG_BYTES: usize = 64 * 1024;
const HEADROOM: u64 = 1024 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
static SERIAL: AtomicU64 = AtomicU64::new(0);

pub(super) struct Request<'a> {
    pub program: &'a Path,
    pub arguments: &'a [OsString],
    pub roles: &'a [(PathBuf, PathBuf)],
    pub inventories: &'a [Inventory],
    pub identity: &'a Path,
    pub work: &'a Path,
    pub excluded_roots: &'a [PathBuf],
    pub output: &'a Output,
    pub elapsed: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    Input,
    Limit,
    Identity,
    Headroom,
    Deadline,
    Io,
    Verification,
}

pub(super) struct Failure {
    pub reason: Refusal,
    pub root: Option<PathBuf>,
}

pub(super) fn public_arguments(command: &Command) -> Result<Vec<OsString>, Refusal> {
    let mut bytes: usize = command
        .get_program()
        .len()
        .checked_add(1)
        .ok_or(Refusal::Limit)?;
    if bytes > ARG_BYTES {
        return Err(Refusal::Limit);
    }
    let mut arguments: Vec<OsString> = Vec::new();
    for argument in command.get_args() {
        bytes = bytes
            .checked_add(argument.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(Refusal::Limit)?;
        if bytes > ARG_BYTES
            || arguments
                .len()
                .checked_add(1)
                .filter(|count| *count <= ARG_BYTES)
                .is_none()
        {
            return Err(Refusal::Limit);
        }
        arguments.push(argument.to_os_string());
    }
    Ok(arguments)
}

#[derive(Clone, Copy)]
struct Limits {
    files: usize,
    directories: usize,
    body: usize,
    total: u64,
    control: usize,
}
const LIMITS: Limits = Limits {
    files: 32_768,
    directories: 32_768,
    body: 32 * 1024 * 1024,
    total: 256 * 1024 * 1024,
    control: 4 * 1024 * 1024,
};

fn deadline(end: Instant) -> Result<(), Refusal> {
    if Instant::now() >= end {
        Err(Refusal::Deadline)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn effective_uid(end: Instant) -> Result<(u32, usize), Refusal> {
    deadline(end)?;
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/proc/self/status")
        .map_err(|_| Refusal::Io)?;
    if !file.metadata().map_err(|_| Refusal::Io)?.is_file() {
        return Err(Refusal::Identity);
    }
    let mut bytes: Vec<u8> = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| Refusal::Io)?;
    if bytes.len() > 16_384 {
        return Err(Refusal::Limit);
    }
    let status: &str = std::str::from_utf8(&bytes).map_err(|_| Refusal::Identity)?;
    let value: &str = status
        .lines()
        .find_map(|line: &str| line.strip_prefix("Uid:"))
        .ok_or(Refusal::Identity)?;
    let mut values = value.split_ascii_whitespace();
    let _: u32 = values
        .next()
        .ok_or(Refusal::Identity)?
        .parse()
        .map_err(|_| Refusal::Identity)?;
    let uid: u32 = values
        .next()
        .ok_or(Refusal::Identity)?
        .parse()
        .map_err(|_| Refusal::Identity)?;
    deadline(end)?;
    Ok((uid, bytes.len()))
}
#[cfg(not(target_os = "linux"))]
fn effective_uid(_end: Instant) -> Result<(u32, usize), Refusal> {
    Err(Refusal::Identity)
}

fn normal(path: &Path) -> Result<(), Refusal> {
    if path.as_os_str().is_empty() || path.as_os_str().len() > 4096 {
        return Err(Refusal::Input);
    }
    let raw: &str = path.to_str().ok_or(Refusal::Input)?;
    if raw.split('/').any(|part| matches!(part, "" | "." | "..")) {
        return Err(Refusal::Input);
    }
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(Refusal::Input);
        };
        let text: &str = name.to_str().ok_or(Refusal::Input)?;
        if text.is_empty() || text.len() > 255 || text.as_bytes().contains(&0) {
            return Err(Refusal::Input);
        }
        if text.ends_with("-wal")
            || text.ends_with("-shm")
            || text.ends_with("-journal")
            || matches!(
                Path::new(text).extension().and_then(|part| part.to_str()),
                Some("db" | "sqlite" | "sqlite3")
            )
        {
            return Err(Refusal::Input);
        }
    }
    Ok(())
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
}
fn read_flags() -> OFlags {
    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryStamp {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
}
impl DirectoryStamp {
    fn metadata(metadata: &Metadata) -> Result<Self, Refusal> {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Refusal::Identity);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
        })
    }
    fn named(parent: &File, name: &std::ffi::OsStr) -> Result<Self, Refusal> {
        let stat: rustix::fs::Stat =
            statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| Refusal::Io)?;
        if !FileType::from_raw_mode(stat.st_mode).is_dir() {
            return Err(Refusal::Identity);
        }
        Ok(Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            uid: stat.st_uid,
        })
    }
}

struct Guard {
    path: PathBuf,
    directory: File,
    device: u64,
    inode: u64,
    uid: u32,
    private: bool,
    end: Instant,
    ancestors: BTreeMap<PathBuf, DirectoryStamp>,
    prefixes: BTreeMap<PathBuf, DirectoryStamp>,
}
impl Guard {
    fn new(path: &Path, private: bool, uid: u32, end: Instant) -> Result<Self, Refusal> {
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(Refusal::Input);
        }
        let mut directory: File = rustix::fs::open("/", directory_flags(), Mode::empty())
            .map(File::from)
            .map_err(|_| Refusal::Io)?;
        let mut current: PathBuf = PathBuf::from("/");
        let mut ancestors: BTreeMap<PathBuf, DirectoryStamp> = BTreeMap::new();
        ancestors.insert(
            current.clone(),
            DirectoryStamp::metadata(&directory.metadata().map_err(|_| Refusal::Io)?)?,
        );
        for component in path.components().skip(1) {
            deadline(end)?;
            let Component::Normal(name) = component else {
                return Err(Refusal::Input);
            };
            if ancestors
                .len()
                .checked_add(1)
                .filter(|count| *count <= LIMITS.directories)
                .is_none()
            {
                return Err(Refusal::Limit);
            }
            let expected: DirectoryStamp = DirectoryStamp::named(&directory, name)?;
            let next: File = openat(&directory, name, directory_flags(), Mode::empty())
                .map(File::from)
                .map_err(|_| Refusal::Io)?;
            if DirectoryStamp::metadata(&next.metadata().map_err(|_| Refusal::Io)?)? != expected
                || DirectoryStamp::named(&directory, name)? != expected
            {
                return Err(Refusal::Identity);
            }
            current.push(name);
            ancestors.insert(current.clone(), expected);
            directory = next;
        }
        let root: DirectoryStamp =
            DirectoryStamp::metadata(&directory.metadata().map_err(|_| Refusal::Io)?)?;
        let guard: Self = Self {
            path: path.to_path_buf(),
            directory,
            device: root.device,
            inode: root.inode,
            uid,
            private,
            end,
            ancestors,
            prefixes: BTreeMap::from([(PathBuf::new(), root)]),
        };
        guard.check(0)?;
        Ok(guard)
    }
    fn check(&self, reservation: u64) -> Result<(), Refusal> {
        deadline(self.end)?;
        for (path, expected) in &self.ancestors {
            deadline(self.end)?;
            let named: Metadata = std::fs::symlink_metadata(path).map_err(|_| Refusal::Io)?;
            if DirectoryStamp::metadata(&named)? != *expected {
                return Err(Refusal::Identity);
            }
        }
        let named: Metadata = std::fs::symlink_metadata(&self.path).map_err(|_| Refusal::Io)?;
        let held: Metadata = self.directory.metadata().map_err(|_| Refusal::Io)?;
        for metadata in [&named, &held] {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
                || (self.private
                    && (metadata.mode() & 0o7777 != 0o700 || metadata.uid() != self.uid))
            {
                return Err(Refusal::Identity);
            }
        }
        let stat: rustix::fs::StatVfs =
            rustix::fs::fstatvfs(&self.directory).map_err(|_| Refusal::Io)?;
        let available: u64 = stat
            .f_bavail
            .checked_mul(stat.f_frsize)
            .ok_or(Refusal::Limit)?;
        if stat.f_frsize == 0
            || available < HEADROOM.checked_add(reservation).ok_or(Refusal::Limit)?
        {
            return Err(Refusal::Headroom);
        }
        deadline(self.end)
    }
    fn named_prefixes(&self, relative: &Path) -> Result<(), Refusal> {
        self.check(0)?;
        let mut prefix: PathBuf = PathBuf::new();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(Refusal::Input);
            };
            prefix.push(name);
            let named: Metadata =
                std::fs::symlink_metadata(self.path.join(&prefix)).map_err(|_| Refusal::Io)?;
            let actual: DirectoryStamp = DirectoryStamp::metadata(&named)?;
            if self.prefixes.get(&prefix) != Some(&actual)
                || actual.device != self.device
                || actual.uid != self.uid
                || actual.mode & 0o7777 != 0o700
            {
                return Err(Refusal::Identity);
            }
            deadline(self.end)?;
        }
        self.check(0)
    }
    fn recheck(&self, relative: &Path, held: &File) -> Result<(), Refusal> {
        self.named_prefixes(relative)?;
        let actual: DirectoryStamp =
            DirectoryStamp::metadata(&held.metadata().map_err(|_| Refusal::Io)?)?;
        if self.prefixes.get(relative) != Some(&actual) {
            return Err(Refusal::Identity);
        }
        self.check(0)
    }
    fn stream_check(&self, relative: &Path, stream: &Dir) -> Result<(), Refusal> {
        self.named_prefixes(relative)?;
        let stat: rustix::fs::Stat =
            rustix::fs::fstat(stream.fd().map_err(|_| Refusal::Io)?).map_err(|_| Refusal::Io)?;
        if !FileType::from_raw_mode(stat.st_mode).is_dir() {
            return Err(Refusal::Identity);
        }
        let actual: DirectoryStamp = DirectoryStamp {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            uid: stat.st_uid,
        };
        if self.prefixes.get(relative) != Some(&actual) {
            return Err(Refusal::Identity);
        }
        self.named_prefixes(relative)
    }
    fn descend(&self, relative: &Path) -> Result<File, Refusal> {
        if !relative.as_os_str().is_empty() {
            normal(relative)?;
        }
        self.recheck(Path::new(""), &self.directory)?;
        let mut prefix: PathBuf = PathBuf::new();
        let mut held: Option<File> = None;
        // Root + current descendant are retained; one next descendant is
        // transient during replacement. No prefix descriptor cache exists.
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(Refusal::Input);
            };
            let parent: &File = held.as_ref().unwrap_or(&self.directory);
            self.recheck(&prefix, parent)?;
            let next: File = openat(parent, name, directory_flags(), Mode::empty())
                .map(File::from)
                .map_err(|error: rustix::io::Errno| {
                    if error == rustix::io::Errno::NOTDIR || error == rustix::io::Errno::LOOP {
                        Refusal::Identity
                    } else {
                        Refusal::Io
                    }
                })?;
            prefix.push(name);
            let actual: DirectoryStamp =
                DirectoryStamp::metadata(&next.metadata().map_err(|_| Refusal::Io)?)?;
            if self.prefixes.get(&prefix) != Some(&actual)
                || DirectoryStamp::named(parent, name)? != actual
            {
                return Err(Refusal::Identity);
            }
            self.recheck(&prefix, &next)?;
            held = Some(next);
        }
        match held {
            Some(file) => Ok(file),
            None => self.directory.try_clone().map_err(|_| Refusal::Io),
        }
    }
    fn create_directory(&mut self, relative: &Path, limit: usize) -> Result<(), Refusal> {
        normal(relative)?;
        if self.prefixes.contains_key(relative) {
            return Err(Refusal::Input);
        }
        if self
            .prefixes
            .len()
            .checked_add(1)
            .filter(|count| *count <= limit)
            .is_none()
        {
            return Err(Refusal::Limit);
        }
        let parent_path: &Path = relative.parent().ok_or(Refusal::Input)?;
        let name: &std::ffi::OsStr = relative.file_name().ok_or(Refusal::Input)?;
        let parent: File = self.descend(parent_path)?;
        self.recheck(parent_path, &parent)?;
        self.check(4096)?;
        mkdirat(&parent, name, Mode::from_bits_truncate(0o700)).map_err(|_| Refusal::Io)?;
        let expected: DirectoryStamp = DirectoryStamp::named(&parent, name)?;
        let created: File = openat(&parent, name, directory_flags(), Mode::empty())
            .map(File::from)
            .map_err(|_| Refusal::Io)?;
        let actual: DirectoryStamp =
            DirectoryStamp::metadata(&created.metadata().map_err(|_| Refusal::Io)?)?;
        if actual != expected
            || actual.device != self.device
            || actual.uid != self.uid
            || actual.mode & 0o7777 != 0o700
            || DirectoryStamp::named(&parent, name)? != actual
        {
            return Err(Refusal::Identity);
        }
        self.recheck(parent_path, &parent)?;
        self.prefixes.insert(relative.to_path_buf(), actual);
        self.recheck(relative, &created)?;
        self.check(0)
    }
}

#[derive(PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    links: u64,
    bytes: u64,
    mode: u32,
    uid: u32,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn stamp(metadata: &Metadata) -> FileStamp {
    FileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        bytes: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        mtime: metadata.mtime(),
        mtime_ns: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_ns: metadata.ctime_nsec(),
    }
}

fn named_file_stamp(parent: &File, name: &std::ffi::OsStr) -> Result<FileStamp, Refusal> {
    let named: File = openat(parent, name, read_flags(), Mode::empty())
        .map(File::from)
        .map_err(|_| Refusal::Io)?;
    let metadata: Metadata = named.metadata().map_err(|_| Refusal::Io)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(Refusal::Identity);
    }
    Ok(stamp(&metadata))
}

fn attached_file(
    root: &Guard,
    parent_path: &Path,
    parent: &File,
    name: &std::ffi::OsStr,
    file: &File,
) -> Result<Metadata, Refusal> {
    root.recheck(parent_path, parent)?;
    let metadata: Metadata = file.metadata().map_err(|_| Refusal::Io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.dev() != root.device
        || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != root.uid
        || stamp(&metadata) != named_file_stamp(parent, name)?
    {
        return Err(Refusal::Identity);
    }
    root.recheck(parent_path, parent)?;
    Ok(metadata)
}

fn identity_bytes(request: &Request<'_>, guard: &Guard) -> Result<Vec<u8>, Refusal> {
    guard.check(0)?;
    if request.identity != request.work.join("disposable.identity") {
        return Err(Refusal::Input);
    }
    let work: Guard = Guard::new(request.work, false, guard.uid, guard.end)?;
    work.recheck(Path::new(""), &work.directory)?;
    let name: &std::ffi::OsStr = std::ffi::OsStr::new("disposable.identity");
    let mut file: File = openat(&work.directory, name, read_flags(), Mode::empty())
        .map(File::from)
        .map_err(|_| Refusal::Io)?;
    let before: Metadata = attached_file(&work, Path::new(""), &work.directory, name, &file)?;
    if before.len() == 0 || before.len() > 256 {
        return Err(Refusal::Identity);
    }
    let mut bytes: Vec<u8> = Vec::new();
    Read::by_ref(&mut file)
        .take(257)
        .read_to_end(&mut bytes)
        .map_err(|_| Refusal::Io)?;
    let after: Metadata = attached_file(&work, Path::new(""), &work.directory, name, &file)?;
    if stamp(&before) != stamp(&after)
        || bytes.len() > 256
        || u64::try_from(bytes.len()).map_err(|_| Refusal::Limit)? != before.len()
    {
        return Err(Refusal::Identity);
    }
    guard.check(0)?;
    Ok(bytes)
}

fn field(output: &mut Vec<u8>, value: &[u8], maximum: usize) -> Result<(), Refusal> {
    if value.contains(&0)
        || output
            .len()
            .checked_add(value.len())
            .and_then(|n| n.checked_add(1))
            .filter(|n| *n <= maximum)
            .is_none()
    {
        return Err(Refusal::Limit);
    }
    output.extend_from_slice(value);
    output.push(0);
    Ok(())
}

fn pack_argv(request: &Request<'_>, root: &Path) -> Result<Vec<u8>, Refusal> {
    let mut original_bytes: usize = request
        .program
        .as_os_str()
        .len()
        .checked_add(1)
        .ok_or(Refusal::Limit)?;
    if request.arguments.len() > ARG_BYTES || original_bytes > ARG_BYTES {
        return Err(Refusal::Limit);
    }
    for argument in request.arguments {
        original_bytes = original_bytes
            .checked_add(argument.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(Refusal::Limit)?;
        if original_bytes > ARG_BYTES {
            return Err(Refusal::Limit);
        }
    }
    if request.arguments.first().and_then(|value| value.to_str()) != Some("pack-saved")
        || !(request.arguments.len() - 1).is_multiple_of(2)
    {
        return Err(Refusal::Input);
    }
    let links: usize = (request.roles.len() - 3) / 4;
    let mut seen: [usize; 9] = [0; 9];
    let mut argv: Vec<u8> = Vec::new();
    field(
        &mut argv,
        request.program.to_str().ok_or(Refusal::Input)?.as_bytes(),
        ARG_BYTES,
    )?;
    field(&mut argv, b"pack-saved", ARG_BYTES)?;
    for pair in request.arguments[1..].chunks_exact(2) {
        let flag: &str = pair[0].to_str().ok_or(Refusal::Input)?;
        let selected: Option<(usize, usize)> = match flag {
            "--genesis-manifest" => Some((0, 0)),
            "--ordered-history-dir" => Some((1, 1)),
            "--cut-dir" => Some((2, 2)),
            "--successor-plan-history-dir" => Some((3, 3)),
            "--successor-cut-dir" => Some((4, 4)),
            "--successor-manifest-history-dir" => Some((5, 5)),
            "--successor-certificate-dir" => Some((6, 6)),
            _ => None,
        };
        let value: OsString = if let Some((slot, first_role)) = selected {
            let role: usize = if slot < 3 {
                if seen[slot] != 0 {
                    return Err(Refusal::Input);
                }
                first_role
            } else {
                if seen[slot] >= links {
                    return Err(Refusal::Input);
                }
                first_role
                    .checked_add(seen[slot].checked_mul(4).ok_or(Refusal::Limit)?)
                    .ok_or(Refusal::Limit)?
            };
            if Path::new(&pair[1]) != request.roles[role].0 {
                return Err(Refusal::Input);
            }
            seen[slot] = seen[slot].checked_add(1).ok_or(Refusal::Limit)?;
            root.join(&request.roles[role].1).into_os_string()
        } else if matches!(flag, "--capture-root" | "--ciphertext-out") {
            let (slot, original, generated): (usize, PathBuf, &str) = if flag == "--capture-root" {
                (7, request.work.join("capture"), "capture")
            } else {
                (8, request.work.join("saved.age"), "saved.age")
            };
            if seen[slot] != 0 || Path::new(&pair[1]) != original {
                return Err(Refusal::Input);
            }
            seen[slot] = 1;
            root.join(generated).into_os_string()
        } else {
            if !matches!(
                flag,
                "--chain-id"
                    | "--protocol-version"
                    | "--epoch"
                    | "--domain"
                    | "--suite"
                    | "--expected-genesis-digest"
                    | "--expected-cut-digest"
                    | "--expected-package-digest"
                    | "--recipient"
                    | "--expected-links"
                    | "--successor-max-links"
                    | "--max-files"
                    | "--max-observations"
                    | "--max-heights"
                    | "--max-components"
                    | "--max-file-bytes"
                    | "--max-control-bytes"
                    | "--max-plaintext-bytes"
                    | "--max-ciphertext-bytes"
                    | "--max-header-bytes"
                    | "--timeout-seconds"
            ) {
                return Err(Refusal::Input);
            }
            pair[1].clone()
        };
        field(&mut argv, flag.as_bytes(), ARG_BYTES)?;
        field(
            &mut argv,
            value.to_str().ok_or(Refusal::Input)?.as_bytes(),
            ARG_BYTES,
        )?;
    }
    if seen[..3] != [1, 1, 1]
        || seen[3..7].iter().any(|count| *count != links)
        || seen[7..] != [1, 1]
    {
        return Err(Refusal::Input);
    }
    Ok(argv)
}

struct Plan<'a> {
    files: BTreeMap<PathBuf, &'a [u8]>,
    directories: BTreeSet<PathBuf>,
    argv: Vec<u8>,
    inventory: Vec<u8>,
    result: Vec<u8>,
    total: u64,
}

fn directory_insert(
    directories: &mut BTreeSet<PathBuf>,
    path: &Path,
    limit: usize,
) -> Result<bool, Refusal> {
    if directories.contains(path) {
        return Ok(false);
    }
    // The owned root is a directory node too, before any allocation grows.
    if directories
        .len()
        .checked_add(2)
        .filter(|count| *count <= limit)
        .is_none()
    {
        return Err(Refusal::Limit);
    }
    Ok(directories.insert(path.to_path_buf()))
}
fn parent_directories(
    directories: &mut BTreeSet<PathBuf>,
    path: &Path,
    limit: usize,
) -> Result<(), Refusal> {
    for parent in path
        .ancestors()
        .skip(1)
        .filter(|path| !path.as_os_str().is_empty())
    {
        directory_insert(directories, parent, limit)?;
    }
    Ok(())
}

fn plan<'a>(
    request: &'a Request<'_>,
    root: &Path,
    identity: &[u8],
    process_metadata_bytes: usize,
    limits: Limits,
    end: Instant,
) -> Result<Plan<'a>, Refusal> {
    deadline(end)?;
    if request.roles.len() > 67 {
        return Err(Refusal::Limit);
    }
    if request.output.status.success()
        || request.roles.len() < 3
        || !(request.roles.len() - 3).is_multiple_of(4)
        || request.roles.len() != request.inventories.len()
        || identity.is_empty()
        || identity.len() > 256
    {
        return Err(Refusal::Input);
    }
    if request.roles.len() > limits.directories {
        return Err(Refusal::Limit);
    }
    if root.starts_with(request.work)
        || request
            .excluded_roots
            .iter()
            .any(|excluded| root.starts_with(excluded))
        || root.starts_with(request.roles[0].0.parent().ok_or(Refusal::Input)?)
    {
        return Err(Refusal::Input);
    }
    let links: usize = (request.roles.len() - 3) / 4;
    let mut roles: Vec<PathBuf> = Vec::new();
    for role in ["genesis/genesis.bin", "current/history", "current/cut"] {
        if roles
            .len()
            .checked_add(1)
            .filter(|count| *count <= request.roles.len())
            .is_none()
        {
            return Err(Refusal::Limit);
        }
        roles.push(PathBuf::from(role));
    }
    for link in 0..links {
        for role in ["plan-history", "cut", "manifest-history", "certificate"] {
            if roles
                .len()
                .checked_add(1)
                .filter(|count| *count <= request.roles.len())
                .is_none()
            {
                return Err(Refusal::Limit);
            }
            roles.push(PathBuf::from(format!("predecessors/link-{link:05}/{role}")));
        }
    }
    let mut files: BTreeMap<PathBuf, &'a [u8]> = BTreeMap::new();
    let mut directories: BTreeSet<PathBuf> = BTreeSet::new();
    let mut inventory: Vec<u8> = Vec::new();
    let mut total: u64 = u64::try_from(identity.len()).map_err(|_| Refusal::Limit)?;
    for (index, ((source, generated), entries)) in
        request.roles.iter().zip(request.inventories).enumerate()
    {
        deadline(end)?;
        if generated != &roles[index] || root.starts_with(source) || root.starts_with(request.work)
        {
            return Err(Refusal::Input);
        }
        normal(generated)?;
        if index != 0 {
            directory_insert(&mut directories, generated, limits.directories)?;
            parent_directories(&mut directories, generated, limits.directories)?;
        }
        if index == 0
            && (entries.len() != 1 || !entries.get(Path::new("")).is_some_and(Option::is_some))
        {
            return Err(Refusal::Input);
        }
        for (relative, body) in entries {
            deadline(end)?;
            if !relative.as_os_str().is_empty() {
                normal(relative)?;
            } else if index != 0 {
                return Err(Refusal::Input);
            }
            for parent in relative
                .ancestors()
                .skip(1)
                .filter(|path| !path.as_os_str().is_empty())
            {
                if !matches!(entries.get(parent), Some(None)) {
                    return Err(Refusal::Input);
                }
            }
            let path: PathBuf = if relative.as_os_str().is_empty() {
                generated.clone()
            } else {
                generated.join(relative)
            };
            normal(&path)?;
            field(
                &mut inventory,
                if body.is_some() { b"FILE" } else { b"DIR" },
                limits.control,
            )?;
            field(
                &mut inventory,
                path.to_str().ok_or(Refusal::Input)?.as_bytes(),
                limits.control,
            )?;
            if let Some(bytes) = body {
                if bytes.len() > limits.body
                    || files
                        .len()
                        .checked_add(5)
                        .filter(|count| *count <= limits.files)
                        .is_none()
                {
                    return Err(Refusal::Limit);
                }
                if files.contains_key(&path) {
                    return Err(Refusal::Input);
                }
                total = total
                    .checked_add(u64::try_from(bytes.len()).map_err(|_| Refusal::Limit)?)
                    .ok_or(Refusal::Limit)?;
                if total > limits.total {
                    return Err(Refusal::Limit);
                }
                parent_directories(&mut directories, &path, limits.directories)?;
                files.insert(path.clone(), bytes.as_slice());
                field(
                    &mut inventory,
                    bytes.len().to_string().as_bytes(),
                    limits.control,
                )?;
                let digest_bytes: sha2::digest::Output<Sha256> = Sha256::digest(bytes);
                let digest: String = digest_bytes
                    .iter()
                    .map(|byte: &u8| format!("{byte:02x}"))
                    .collect();
                field(&mut inventory, digest.as_bytes(), limits.control)?;
            } else {
                if !directory_insert(&mut directories, &path, limits.directories)? {
                    return Err(Refusal::Input);
                }
                parent_directories(&mut directories, &path, limits.directories)?;
            }
        }
    }
    if files.keys().any(|path| directories.contains(path)) {
        return Err(Refusal::Input);
    }
    let argv: Vec<u8> = pack_argv(request, root)?;
    // No raw arbitrary child text, provider response or key line is retained.
    let result: Vec<u8> = format!(
        "reproducer=DATA_ONLY_UNQUALIFIED_NOT_AUTOMATICALLY_EXECUTABLE\nstage=pack-saved\nexit_code={:?}\nsignal={:?}\nelapsed_ms={}\nstdout_bytes={}\nstderr_bytes={}\nprocess_metadata_bytes={}\nchild_text=not-retained\nno-proof-import-custody-authority\n",
        request.output.status.code(), request.output.status.signal(), request.elapsed.as_millis(),
        request.output.stdout.len(), request.output.stderr.len(), process_metadata_bytes,
    ).into_bytes();
    let control: usize = argv
        .len()
        .checked_add(inventory.len())
        .and_then(|n| n.checked_add(result.len()))
        .and_then(|n| n.checked_add(process_metadata_bytes))
        .ok_or(Refusal::Limit)?;
    total = total
        .checked_add(u64::try_from(control).map_err(|_| Refusal::Limit)?)
        .ok_or(Refusal::Limit)?;
    if files
        .len()
        .checked_add(4)
        .filter(|n| *n <= limits.files)
        .is_none()
        || directories
            .len()
            .checked_add(1)
            .filter(|n| *n <= limits.directories)
            .is_none()
        || control > limits.control
        || total > limits.total
    {
        return Err(Refusal::Limit);
    }
    deadline(end)?;
    Ok(Plan {
        files,
        directories,
        argv,
        inventory,
        result,
        total,
    })
}

fn write_file(root: &Guard, relative: &Path, bytes: &[u8]) -> Result<(), Refusal> {
    normal(relative)?;
    root.check(u64::try_from(bytes.len().min(CHUNK)).map_err(|_| Refusal::Limit)?)?;
    let parent_path: &Path = relative.parent().ok_or(Refusal::Input)?;
    let name: &std::ffi::OsStr = relative.file_name().ok_or(Refusal::Input)?;
    let parent: File = root.descend(parent_path)?;
    root.recheck(parent_path, &parent)?;
    let mut file: File = openat(
        &parent,
        name,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map(File::from)
    .map_err(|_| Refusal::Io)?;
    attached_file(root, parent_path, &parent, name, &file)?;
    let mut offset: usize = 0;
    while offset < bytes.len() {
        let end: usize = offset
            .checked_add(CHUNK)
            .ok_or(Refusal::Limit)?
            .min(bytes.len());
        root.check(u64::try_from(end - offset).map_err(|_| Refusal::Limit)?)?;
        attached_file(root, parent_path, &parent, name, &file)?;
        let written: usize = file.write(&bytes[offset..end]).map_err(|_| Refusal::Io)?;
        if written == 0 || written > end - offset {
            return Err(Refusal::Io);
        }
        offset = offset.checked_add(written).ok_or(Refusal::Limit)?;
        attached_file(root, parent_path, &parent, name, &file)?;
    }
    attached_file(root, parent_path, &parent, name, &file)?;
    drop(file);
    root.recheck(parent_path, &parent)?;
    drop(parent);
    verify_file(root, relative, bytes)
}

fn verify_file(root: &Guard, relative: &Path, expected: &[u8]) -> Result<(), Refusal> {
    normal(relative)?;
    let parent_path: &Path = relative.parent().ok_or(Refusal::Input)?;
    let name: &std::ffi::OsStr = relative.file_name().ok_or(Refusal::Input)?;
    let parent: File = root.descend(parent_path)?;
    root.recheck(parent_path, &parent)?;
    let mut file: File = openat(&parent, name, read_flags(), Mode::empty())
        .map(File::from)
        .map_err(|_| Refusal::Io)?;
    let before: Metadata = attached_file(root, parent_path, &parent, name, &file)?;
    if before.len() != u64::try_from(expected.len()).map_err(|_| Refusal::Limit)? {
        return Err(Refusal::Identity);
    }
    let mut offset: usize = 0;
    let mut buffer: [u8; CHUNK] = [0; CHUNK];
    while offset < expected.len() {
        attached_file(root, parent_path, &parent, name, &file)?;
        let limit: usize = (expected.len() - offset).min(CHUNK);
        let read: usize = file.read(&mut buffer[..limit]).map_err(|_| Refusal::Io)?;
        let next: usize = offset.checked_add(read).ok_or(Refusal::Limit)?;
        if read == 0 || next > expected.len() || buffer[..read] != expected[offset..next] {
            return Err(Refusal::Verification);
        }
        offset = next;
        attached_file(root, parent_path, &parent, name, &file)?;
    }
    attached_file(root, parent_path, &parent, name, &file)?;
    if file.read(&mut buffer[..1]).map_err(|_| Refusal::Io)? != 0 {
        return Err(Refusal::Verification);
    }
    let after: Metadata = attached_file(root, parent_path, &parent, name, &file)?;
    if stamp(&before) != stamp(&after) {
        return Err(Refusal::Identity);
    }
    root.recheck(parent_path, &parent)
}

fn expected_body<'a>(
    plan: &'a Plan<'_>,
    identity: &'a [u8],
    path: &Path,
) -> Result<&'a [u8], Refusal> {
    if let Some(bytes) = plan.files.get(path) {
        return Ok(bytes);
    }
    match path.to_str().ok_or(Refusal::Input)? {
        "disposable.identity" => Ok(identity),
        "pack-argv.nul" => Ok(&plan.argv),
        "inventory.nul" => Ok(&plan.inventory),
        "result.txt" => Ok(&plan.result),
        _ => Err(Refusal::Verification),
    }
}

fn verify_tree(root: &Guard, plan: &Plan<'_>, identity: &[u8]) -> Result<(), Refusal> {
    let mut files: BTreeSet<PathBuf> = BTreeSet::new();
    let mut directories: BTreeSet<PathBuf> = BTreeSet::new();
    let mut pending: Vec<PathBuf> = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let held: File = root.descend(&relative)?;
        root.recheck(&relative, &held)?;
        let mut stream: Dir = Dir::new(held).map_err(|_| Refusal::Io)?;
        let mut observed: Vec<PathBuf> = Vec::new();
        while let Some(entry) = stream.read() {
            root.stream_check(&relative, &stream)?;
            let entry: rustix::fs::DirEntry = entry.map_err(|_| Refusal::Io)?;
            let name: &str = entry.file_name().to_str().map_err(|_| Refusal::Input)?;
            if matches!(name, "." | "..") {
                continue;
            }
            let path: PathBuf = relative.join(name);
            normal(&path)?;
            let stat: rustix::fs::Stat = statat(
                stream.fd().map_err(|_| Refusal::Io)?,
                name,
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|_| Refusal::Io)?;
            let kind: FileType = FileType::from_raw_mode(stat.st_mode);
            root.stream_check(&relative, &stream)?;
            if kind.is_dir() {
                if !plan.directories.contains(&path) || directories.contains(&path) {
                    return Err(Refusal::Verification);
                }
                if directories
                    .len()
                    .checked_add(2)
                    .filter(|count| *count <= LIMITS.directories)
                    .is_none()
                    || pending
                        .len()
                        .checked_add(1)
                        .filter(|count| *count <= LIMITS.directories)
                        .is_none()
                {
                    return Err(Refusal::Limit);
                }
                if stat.st_dev != root.device
                    || stat.st_uid != root.uid
                    || stat.st_mode & 0o7777 != 0o700
                {
                    return Err(Refusal::Identity);
                }
                directories.insert(path.clone());
                pending.push(path);
            } else if kind.is_file() {
                expected_body(plan, identity, &path)?;
                if files.contains(&path) {
                    return Err(Refusal::Verification);
                }
                if files
                    .len()
                    .checked_add(1)
                    .filter(|count| *count <= LIMITS.files)
                    .is_none()
                    || observed
                        .len()
                        .checked_add(1)
                        .filter(|count| *count <= LIMITS.files)
                        .is_none()
                {
                    return Err(Refusal::Limit);
                }
                files.insert(path.clone());
                observed.push(path);
            } else {
                return Err(Refusal::Identity);
            }
        }
        root.stream_check(&relative, &stream)?;
        drop(stream);
        let held: File = root.descend(&relative)?;
        root.recheck(&relative, &held)?;
        drop(held);
        for path in observed {
            verify_file(root, &path, expected_body(plan, identity, &path)?)?;
        }
    }
    if files.len() != plan.files.len().checked_add(4).ok_or(Refusal::Limit)?
        || plan.files.keys().any(|path| !files.contains(path))
        || directories != plan.directories
    {
        return Err(Refusal::Verification);
    }
    for name in ["capture", "saved.age"] {
        root.recheck(Path::new(""), &root.directory)?;
        match statat(&root.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(error) if error == rustix::io::Errno::NOENT => {}
            _ => return Err(Refusal::Verification),
        }
    }
    root.check(0)
}

pub(super) fn retain(request: Request<'_>) -> Result<PathBuf, Failure> {
    let end: Instant = Instant::now()
        .checked_add(Duration::from_secs(300))
        .ok_or(Failure {
            reason: Refusal::Deadline,
            root: None,
        })?;
    let mut retained: Option<PathBuf> = None;
    let result: Result<PathBuf, Refusal> = (|| {
        let temporary: PathBuf = std::env::temp_dir();
        let (uid, process_metadata_bytes): (u32, usize) = effective_uid(end)?;
        let parent: Guard = Guard::new(&temporary, false, uid, end)?;
        let identity: Vec<u8> = identity_bytes(&request, &parent)?;
        let now: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Refusal::Io)?
            .as_nanos();
        let serial: u64 = SERIAL
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Refusal::Limit)?;
        let root: PathBuf = temporary.join(format!(
            "sunrise-edge-recovery-reproducer-{}-{now}-{serial}",
            std::process::id()
        ));
        let plan: Plan<'_> = plan(
            &request,
            &root,
            &identity,
            process_metadata_bytes,
            LIMITS,
            end,
        )?;
        parent.check(plan.total)?;
        let name: &std::ffi::OsStr = root.file_name().ok_or(Refusal::Input)?;
        parent.recheck(Path::new(""), &parent.directory)?;
        mkdirat(&parent.directory, name, Mode::from_bits_truncate(0o700))
            .map_err(|_| Refusal::Io)?;
        retained = Some(root.clone());
        let expected: DirectoryStamp = DirectoryStamp::named(&parent.directory, name)?;
        let directory: File = openat(&parent.directory, name, directory_flags(), Mode::empty())
            .map(File::from)
            .map_err(|_| Refusal::Io)?;
        let actual: DirectoryStamp =
            DirectoryStamp::metadata(&directory.metadata().map_err(|_| Refusal::Io)?)?;
        if actual != expected
            || actual.device != parent.device
            || actual.uid != uid
            || actual.mode & 0o7777 != 0o700
            || DirectoryStamp::named(&parent.directory, name)? != actual
        {
            return Err(Refusal::Identity);
        }
        parent.recheck(Path::new(""), &parent.directory)?;
        if parent
            .ancestors
            .len()
            .checked_add(1)
            .filter(|count| *count <= LIMITS.directories)
            .is_none()
        {
            return Err(Refusal::Limit);
        }
        let mut ancestors: BTreeMap<PathBuf, DirectoryStamp> = parent.ancestors.clone();
        ancestors.insert(root.clone(), actual);
        let mut guard: Guard = Guard {
            path: root.clone(),
            directory,
            device: actual.device,
            inode: actual.inode,
            uid,
            private: true,
            end,
            ancestors,
            prefixes: BTreeMap::from([(PathBuf::new(), actual)]),
        };
        guard.check(0)?;
        let mut directories: Vec<&PathBuf> = Vec::new();
        for path in &plan.directories {
            if directories
                .len()
                .checked_add(2)
                .filter(|count| *count <= LIMITS.directories)
                .is_none()
            {
                return Err(Refusal::Limit);
            }
            directories.push(path);
        }
        directories.sort_by(|first, second| {
            first
                .components()
                .count()
                .cmp(&second.components().count())
                .then_with(|| first.cmp(second))
        });
        for path in directories {
            guard.create_directory(path, LIMITS.directories)?;
        }
        for (path, bytes) in &plan.files {
            write_file(&guard, path, bytes)?;
        }
        write_file(&guard, Path::new("disposable.identity"), &identity)?;
        write_file(&guard, Path::new("pack-argv.nul"), &plan.argv)?;
        write_file(&guard, Path::new("inventory.nul"), &plan.inventory)?;
        write_file(&guard, Path::new("result.txt"), &plan.result)?;
        verify_tree(&guard, &plan, &identity)?;
        Ok(root)
    })();
    result.map_err(|reason| Failure {
        reason,
        root: retained,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use std::os::unix::{
        fs::{PermissionsExt, symlink},
        process::ExitStatusExt,
    };

    #[test]
    #[cfg(target_os = "linux")]
    fn failed_pack_reproducer_copies_only_closed_roles_and_refuses_unsafe_or_oversized_plan() {
        let now: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let fixture: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-edge-reproducer-control-{}-{now}",
            std::process::id()
        ));
        DirBuilder::new().mode(0o700).create(&fixture).unwrap();
        let fixture_stamp: DirectoryStamp =
            DirectoryStamp::metadata(&std::fs::symlink_metadata(&fixture).unwrap()).unwrap();
        let key: PathBuf = fixture.join("disposable.identity");
        let identity: age::x25519::Identity = age::x25519::Identity::generate();
        let secret = identity.to_string();
        let bytes: Vec<u8> = secret.expose_secret().as_bytes().to_vec();
        let mut key_file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key)
            .unwrap();
        key_file.write_all(&bytes).unwrap();
        drop(key_file);
        drop(secret);
        drop(identity);
        let generated: [&str; 7] = [
            "genesis/genesis.bin",
            "current/history",
            "current/cut",
            "predecessors/link-00000/plan-history",
            "predecessors/link-00000/cut",
            "predecessors/link-00000/manifest-history",
            "predecessors/link-00000/certificate",
        ];
        let roles: Vec<(PathBuf, PathBuf)> = generated
            .iter()
            .enumerate()
            .map(|(index, generated)| {
                (
                    PathBuf::from(format!("/original/role-{index}")),
                    PathBuf::from(generated),
                )
            })
            .collect();
        let mut inventories: Vec<Inventory> = vec![BTreeMap::from([(
            PathBuf::new(),
            Some(b"genesis".to_vec()),
        )])];
        for index in 1_u8..7 {
            inventories.push(BTreeMap::from([
                (PathBuf::from("empty"), None),
                (PathBuf::from("body.bin"), Some(vec![index; 3])),
            ]));
        }
        let mut arguments: Vec<OsString> = vec![
            "pack-saved".into(),
            "--chain-id".into(),
            "reproducer-test".into(),
        ];
        for (flag, index) in [
            ("--genesis-manifest", 0),
            ("--ordered-history-dir", 1),
            ("--cut-dir", 2),
            ("--successor-plan-history-dir", 3),
            ("--successor-cut-dir", 4),
            ("--successor-manifest-history-dir", 5),
            ("--successor-certificate-dir", 6),
        ] {
            arguments.extend([
                OsString::from(flag),
                roles[index].0.clone().into_os_string(),
            ]);
        }
        arguments.extend([
            "--expected-links".into(),
            "1".into(),
            "--capture-root".into(),
            fixture.join("capture").into_os_string(),
            "--ciphertext-out".into(),
            fixture.join("saved.age").into_os_string(),
        ]);
        let output: Output = Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"not-retained-private-provider-text".to_vec(),
        };
        let request = || Request {
            program: Path::new("/test/business_recovery"),
            arguments: &arguments,
            roles: &roles,
            inventories: &inventories,
            identity: &key,
            work: &fixture,
            excluded_roots: std::slice::from_ref(&fixture),
            output: &output,
            elapsed: Duration::from_millis(17),
        };
        let root: PathBuf = retain(request())
            .unwrap_or_else(|failure| panic!("static refusal: {:?}", failure.reason));
        let retained_stamp: DirectoryStamp =
            DirectoryStamp::metadata(&std::fs::symlink_metadata(&root).unwrap()).unwrap();
        assert!(!root.starts_with(&fixture));
        assert_eq!(
            std::fs::symlink_metadata(&root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::symlink_metadata(root.join("disposable.identity"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(
            std::fs::read(root.join("disposable.identity")).unwrap() == bytes,
            "exact disposable identity bytes, never printed"
        );
        for (index, role) in generated.iter().enumerate() {
            if index == 0 {
                assert_eq!(std::fs::read(root.join(role)).unwrap(), b"genesis");
            } else {
                assert_eq!(
                    std::fs::read(root.join(role).join("body.bin")).unwrap(),
                    vec![u8::try_from(index).unwrap(); 3]
                );
                assert!(root.join(role).join("empty").is_dir());
            }
        }
        let mut expected: Vec<OsString> = vec![
            "/test/business_recovery".into(),
            "pack-saved".into(),
            "--chain-id".into(),
            "reproducer-test".into(),
        ];
        for (flag, role) in [
            ("--genesis-manifest", generated[0]),
            ("--ordered-history-dir", generated[1]),
            ("--cut-dir", generated[2]),
            ("--successor-plan-history-dir", generated[3]),
            ("--successor-cut-dir", generated[4]),
            ("--successor-manifest-history-dir", generated[5]),
            ("--successor-certificate-dir", generated[6]),
        ] {
            expected.extend([OsString::from(flag), root.join(role).into_os_string()]);
        }
        expected.extend([
            "--expected-links".into(),
            "1".into(),
            "--capture-root".into(),
            root.join("capture").into_os_string(),
            "--ciphertext-out".into(),
            root.join("saved.age").into_os_string(),
        ]);
        let expected_bytes: Vec<u8> = expected
            .iter()
            .flat_map(|argument| {
                argument
                    .to_str()
                    .unwrap()
                    .as_bytes()
                    .iter()
                    .copied()
                    .chain([0])
            })
            .collect();
        assert_eq!(
            std::fs::read(root.join("pack-argv.nul")).unwrap(),
            expected_bytes
        );
        let result: Vec<u8> = std::fs::read(root.join("result.txt")).unwrap();
        assert!(
            result
                .windows(b"elapsed_ms=17".len())
                .any(|window| window == b"elapsed_ms=17")
        );
        assert!(
            !result
                .windows(output.stderr.len())
                .any(|window| window == output.stderr)
        );
        assert!(!root.join("capture").exists() && !root.join("saved.age").exists());
        let end: Instant = Instant::now() + Duration::from_secs(300);
        let absent: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-edge-reproducer-refusal-{}-{now}",
            std::process::id()
        ));
        assert!(!absent.exists());
        assert!(
            plan(&request(), &absent, &bytes, 0, LIMITS, end).is_ok(),
            "valid baseline reaches the later refusal conditions"
        );
        let valid_request: Request<'_> = request();
        let baseline: Plan<'_> = plan(&valid_request, &absent, &bytes, 0, LIMITS, end)
            .unwrap_or_else(|reason| panic!("static refusal: {reason:?}"));
        let exact: Limits = Limits {
            files: baseline.files.len().checked_add(4).unwrap(),
            directories: baseline.directories.len().checked_add(1).unwrap(),
            body: baseline
                .files
                .values()
                .map(|body| body.len())
                .max()
                .unwrap(),
            total: baseline.total,
            control: baseline
                .argv
                .len()
                .checked_add(baseline.inventory.len())
                .and_then(|value| value.checked_add(baseline.result.len()))
                .unwrap(),
        };
        assert!(
            plan(&request(), &absent, &bytes, 0, exact, end).is_ok(),
            "exact file/directory/body/aggregate/control capacities admit"
        );
        for limits in [
            Limits {
                files: exact.files.checked_sub(1).unwrap(),
                ..exact
            },
            Limits {
                directories: exact.directories.checked_sub(1).unwrap(),
                ..exact
            },
            Limits {
                body: exact.body.checked_sub(1).unwrap(),
                ..exact
            },
            Limits {
                total: exact.total.checked_sub(1).unwrap(),
                ..exact
            },
            Limits {
                control: exact.control.checked_sub(1).unwrap(),
                ..exact
            },
        ] {
            assert!(
                plan(&request(), &absent, &bytes, 0, limits, end).err() == Some(Refusal::Limit)
            );
            assert!(
                !absent.exists(),
                "one item/byte beyond capacity refuses before writes"
            );
        }
        let mut edge_roles: Vec<(PathBuf, PathBuf)> = roles[..3].to_vec();
        let mut edge_inventories: Vec<Inventory> = inventories[..3].to_vec();
        let mut edge_arguments: Vec<OsString> = arguments[..3].to_vec();
        for (flag, index) in [
            ("--genesis-manifest", 0),
            ("--ordered-history-dir", 1),
            ("--cut-dir", 2),
        ] {
            edge_arguments.extend([
                OsString::from(flag),
                edge_roles[index].0.clone().into_os_string(),
            ]);
        }
        for link in 0_usize..16 {
            for (flag, role) in [
                ("--successor-plan-history-dir", "plan-history"),
                ("--successor-cut-dir", "cut"),
                ("--successor-manifest-history-dir", "manifest-history"),
                ("--successor-certificate-dir", "certificate"),
            ] {
                assert!(edge_roles.len() < 67 && edge_inventories.len() < 67);
                let source: PathBuf = PathBuf::from(format!("/original/link-{link:05}-{role}"));
                edge_roles.push((
                    source.clone(),
                    PathBuf::from(format!("predecessors/link-{link:05}/{role}")),
                ));
                edge_inventories.push(inventories[1].clone());
                edge_arguments.extend([OsString::from(flag), source.into_os_string()]);
            }
        }
        edge_arguments.extend([
            "--expected-links".into(),
            "16".into(),
            "--capture-root".into(),
            fixture.join("capture").into_os_string(),
            "--ciphertext-out".into(),
            fixture.join("saved.age").into_os_string(),
        ]);
        let edge: Request<'_> = Request {
            roles: &edge_roles,
            inventories: &edge_inventories,
            arguments: &edge_arguments,
            ..request()
        };
        assert_eq!(edge_roles.len(), 67);
        assert!(plan(&edge, &absent, &bytes, 0, LIMITS, end).is_ok());
        edge_roles.push((
            PathBuf::from("/original/one-too-many"),
            PathBuf::from("one-too-many"),
        ));
        edge_inventories.push(inventories[1].clone());
        let overflow: Request<'_> = Request {
            roles: &edge_roles,
            inventories: &edge_inventories,
            arguments: &edge_arguments,
            ..request()
        };
        assert!(plan(&overflow, &absent, &bytes, 0, LIMITS, end).err() == Some(Refusal::Limit));
        assert!(!absent.exists());
        for relative in [
            "../escape",
            "/absolute",
            "./not-normal",
            "sub/./bad",
            "state.db",
        ] {
            let mut bad: Vec<Inventory> = inventories.clone();
            bad[1].insert(PathBuf::from(relative), Some(vec![1]));
            let bad_request: Request<'_> = Request {
                inventories: &bad,
                ..request()
            };
            assert!(plan(&bad_request, &absent, &bytes, 0, LIMITS, end).is_err());
            assert!(!absent.exists());
        }
        for limits in [
            Limits { body: 2, ..LIMITS },
            Limits {
                control: 4,
                ..LIMITS
            },
            Limits { total: 1, ..LIMITS },
            Limits { files: 1, ..LIMITS },
            Limits {
                directories: 1,
                ..LIMITS
            },
        ] {
            assert!(plan(&request(), &absent, &bytes, 0, limits, end).is_err());
            assert!(!absent.exists());
        }
        for value in [
            OsString::from("bad\0public-value"),
            OsString::from("x".repeat(ARG_BYTES + 1)),
        ] {
            let mut bad_arguments: Vec<OsString> = arguments.clone();
            bad_arguments[2] = value;
            let bad_request: Request<'_> = Request {
                arguments: &bad_arguments,
                ..request()
            };
            assert!(plan(&bad_request, &absent, &bytes, 0, LIMITS, end).is_err());
            assert!(!absent.exists());
        }
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused: Failure =
            retain(request()).expect_err("nonprivate identity refuses before output writes");
        assert!(refused.root.is_none());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let original_key: PathBuf = fixture.join("original-disposable.identity");
        std::fs::rename(&key, &original_key).unwrap();
        let (uid, _metadata_bytes): (u32, usize) = effective_uid(end).unwrap();
        let work: Guard = Guard::new(&fixture, false, uid, end)
            .unwrap_or_else(|reason| panic!("static refusal: {reason:?}"));
        rustix::fs::mkfifoat(
            &work.directory,
            "disposable.identity",
            Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        let fifo_stamp: FileStamp = stamp(&std::fs::symlink_metadata(&key).unwrap());
        let refused: Failure = retain(request()).expect_err(
            "NONBLOCK identity open rejects FIFO before any payload read or output write",
        );
        assert!(refused.reason == Refusal::Identity && refused.root.is_none());
        assert!(stamp(&std::fs::symlink_metadata(&key).unwrap()) == fifo_stamp);
        std::fs::remove_file(&key).unwrap();
        std::fs::rename(&original_key, &key).unwrap();
        drop(work);
        assert!(
            DirectoryStamp::metadata(&std::fs::symlink_metadata(&root).unwrap()).unwrap()
                == retained_stamp
        );
        assert!(
            DirectoryStamp::metadata(&std::fs::symlink_metadata(&fixture).unwrap()).unwrap()
                == fixture_stamp
        );
        std::fs::remove_dir_all(&root).unwrap(); // Exact fresh roots created by this control only.
        std::fs::remove_dir_all(&fixture).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn failed_pack_reproducer_refuses_replaced_prefix_special_mode_and_fifo_without_outside_writes()
    {
        let end: Instant = Instant::now() + Duration::from_secs(300);
        let (uid, _metadata_bytes): (u32, usize) = effective_uid(end).unwrap();
        let now: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let fixture: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-edge-reproducer-prefix-{}-{now}",
            std::process::id()
        ));
        let outside: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-edge-reproducer-sentinel-{}-{now}",
            std::process::id()
        ));
        DirBuilder::new().mode(0o700).create(&fixture).unwrap();
        DirBuilder::new().mode(0o700).create(&outside).unwrap();
        let outside_stamp: DirectoryStamp =
            DirectoryStamp::metadata(&std::fs::symlink_metadata(&outside).unwrap()).unwrap();
        let sentinel: PathBuf = outside.join("sentinel.bin");
        let mut sentinel_file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&sentinel)
            .unwrap();
        sentinel_file.write_all(b"outside-unchanged").unwrap();
        drop(sentinel_file);
        let sentinel_stamp: FileStamp = stamp(&std::fs::symlink_metadata(&sentinel).unwrap());
        let mut root: Guard = Guard::new(&fixture, true, uid, end)
            .unwrap_or_else(|reason| panic!("static refusal: {reason:?}"));
        let fixture_stamp: DirectoryStamp =
            DirectoryStamp::metadata(&root.directory.metadata().unwrap()).unwrap();
        root.create_directory(Path::new("prefix"), 2).unwrap();
        assert!(root.create_directory(Path::new("one-too-many"), 2).err() == Some(Refusal::Limit));
        assert!(!fixture.join("one-too-many").exists());
        let original: PathBuf = fixture.join("prefix");
        let displaced: PathBuf = fixture.join("original-prefix");
        let untouched = || {
            assert!(std::fs::read(&sentinel).unwrap() == b"outside-unchanged");
            assert!(stamp(&std::fs::symlink_metadata(&sentinel).unwrap()) == sentinel_stamp);
            assert!(!outside.join("new.bin").exists());
        };

        std::fs::rename(&original, &displaced).unwrap();
        symlink(&outside, &original).unwrap();
        let link_stamp: FileStamp = stamp(&std::fs::symlink_metadata(&original).unwrap());
        assert!(
            write_file(&root, Path::new("prefix/new.bin"), b"must-not-escape").err()
                == Some(Refusal::Identity)
        );
        assert!(
            verify_file(
                &root,
                Path::new("prefix/sentinel.bin"),
                b"outside-unchanged"
            )
            .err()
                == Some(Refusal::Identity)
        );
        untouched();
        assert!(stamp(&std::fs::symlink_metadata(&original).unwrap()) == link_stamp);
        std::fs::remove_file(&original).unwrap();
        std::fs::rename(&displaced, &original).unwrap();

        std::fs::rename(&original, &displaced).unwrap();
        let mut replacement: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&original)
            .unwrap();
        replacement.write_all(b"not-a-directory").unwrap();
        drop(replacement);
        let replacement_stamp: FileStamp = stamp(&std::fs::symlink_metadata(&original).unwrap());
        assert!(
            write_file(&root, Path::new("prefix/new.bin"), b"must-not-escape").err()
                == Some(Refusal::Identity)
        );
        untouched();
        assert!(stamp(&std::fs::symlink_metadata(&original).unwrap()) == replacement_stamp);
        std::fs::remove_file(&original).unwrap();
        std::fs::rename(&displaced, &original).unwrap();

        std::fs::rename(&original, &displaced).unwrap();
        DirBuilder::new().mode(0o700).create(&original).unwrap();
        let replacement_stamp: DirectoryStamp =
            DirectoryStamp::metadata(&std::fs::symlink_metadata(&original).unwrap()).unwrap();
        assert!(
            write_file(&root, Path::new("prefix/new.bin"), b"must-refuse-new-inode").err()
                == Some(Refusal::Identity)
        );
        untouched();
        assert!(
            DirectoryStamp::metadata(&std::fs::symlink_metadata(&original).unwrap()).unwrap()
                == replacement_stamp
        );
        std::fs::remove_dir(&original).unwrap(); // Exact fresh replacement, empty; no recursive deletion.
        std::fs::rename(&displaced, &original).unwrap();

        for mode in [0o755_u32, 0o1700_u32] {
            std::fs::set_permissions(&original, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                write_file(&root, Path::new("prefix/new.bin"), b"must-refuse-mode").err()
                    == Some(Refusal::Identity)
            );
            untouched();
            std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let prefix: File = root
            .descend(Path::new("prefix"))
            .unwrap_or_else(|reason| panic!("static refusal: {reason:?}"));
        rustix::fs::mkfifoat(&prefix, "fifo.bin", Mode::from_bits_truncate(0o600)).unwrap();
        let fifo_stamp: FileStamp =
            stamp(&std::fs::symlink_metadata(original.join("fifo.bin")).unwrap());
        assert!(
            verify_file(&root, Path::new("prefix/fifo.bin"), b"never-read-fifo").err()
                == Some(Refusal::Identity)
        );
        assert!(
            write_file(&root, Path::new("prefix/fifo.bin"), b"never-overwrite-fifo").err()
                == Some(Refusal::Io)
        );
        untouched();
        assert!(
            stamp(&std::fs::symlink_metadata(original.join("fifo.bin")).unwrap()) == fifo_stamp
        );
        std::fs::remove_file(original.join("fifo.bin")).unwrap();
        drop(prefix);
        write_file(&root, Path::new("prefix/normal.bin"), b"held-parent-copy").unwrap();
        std::fs::set_permissions(
            original.join("normal.bin"),
            std::fs::Permissions::from_mode(0o1600),
        )
        .unwrap();
        assert!(
            verify_file(&root, Path::new("prefix/normal.bin"), b"held-parent-copy").err()
                == Some(Refusal::Identity)
        );
        std::fs::set_permissions(
            original.join("normal.bin"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        verify_file(&root, Path::new("prefix/normal.bin"), b"held-parent-copy").unwrap();
        untouched();
        assert!(
            DirectoryStamp::metadata(&std::fs::symlink_metadata(&fixture).unwrap()).unwrap()
                == fixture_stamp
        );
        assert!(
            DirectoryStamp::metadata(&std::fs::symlink_metadata(&outside).unwrap()).unwrap()
                == outside_stamp
        );
        drop(root);
        std::fs::remove_dir_all(&fixture).unwrap(); // Original checked fresh test identity only.
        std::fs::remove_file(&sentinel).unwrap();
        std::fs::remove_dir(&outside).unwrap(); // Never recursively remove the outside sentinel directory.
    }
}
