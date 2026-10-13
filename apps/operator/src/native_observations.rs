//! Bounded foreground collection of fixed local Native HTTP snapshots.
use std::ffi::OsString;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeObservationsError {
    Arguments,
    UnsupportedPlatform,
    Directory,
    Socket,
    Collection,
    Record,
    Output,
}

impl NativeObservationsError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Arguments => "invalid collector arguments",
            Self::UnsupportedPlatform => "native observations require Linux",
            Self::Directory => "collector directory refused",
            Self::Socket => "collector socket refused",
            Self::Collection => "observation collection incomplete",
            Self::Record => "invalid live observation record",
            Self::Output => "observation output failed",
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::NativeObservationsError as Error;
    use native_http::{NativeHttpSnapshot, decode_live_summary};
    use rustix::{
        fd::OwnedFd,
        fs::{AtFlags, FileType, Mode, OFlags, open, openat, statat},
        io::Errno,
    };
    use std::{
        ffi::OsString,
        fs::File,
        io::{self, Read, Write},
        os::fd::{AsRawFd, RawFd},
        os::unix::net::UnixDatagram,
        path::PathBuf,
        time::{Duration, Instant},
    };

    const MAX_PATH_BYTES: usize = 100;
    const MAX_RECORD_BYTES: usize = 2_048;
    const MAX_SAMPLES: usize = 1_024;
    const MAX_TIMEOUT_MILLIS: u64 = 300_000;
    const MAX_NUMERIC_ARGUMENT_BYTES: usize = 20;
    const MAX_ATTEMPTS: usize = 4_096;
    const MAX_PROC_STATUS_BYTES: usize = 64 * 1024;
    const DIRECTORY_MODE: u32 = 0o700;

    fn check_deadline_at(deadline: Instant, now: Instant) -> Result<(), Error> {
        if now >= deadline {
            Err(Error::Collection)
        } else {
            Ok(())
        }
    }

    fn check_deadline(deadline: Instant) -> Result<(), Error> {
        check_deadline_at(deadline, Instant::now())
    }

    fn deadline_step<T, F>(deadline: Instant, operation: F) -> Result<T, Error>
    where
        F: FnOnce() -> Result<T, Error>,
    {
        deadline_step_with_clock(deadline, Instant::now, operation)
    }

    fn deadline_step_with_clock<T, F, N>(
        deadline: Instant,
        mut now: N,
        operation: F,
    ) -> Result<T, Error>
    where
        F: FnOnce() -> Result<T, Error>,
        N: FnMut() -> Instant,
    {
        check_deadline_at(deadline, now())?;
        let result: Result<T, Error> = operation();
        check_deadline_at(deadline, now())?;
        result
    }

    fn receive_attempt<T, F>(attempts: &mut usize, receive: F) -> Result<Option<T>, Error>
    where
        F: FnOnce() -> io::Result<T>,
    {
        if !charge_attempt(attempts) {
            return Err(Error::Collection);
        }
        match receive() {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(_error) => Err(Error::Collection),
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CollectorArgs {
        socket: String,
        samples: usize,
        timeout: Duration,
    }

    fn parse_decimal(value: &str) -> Option<u64> {
        if value.is_empty()
            || value.len() > MAX_NUMERIC_ARGUMENT_BYTES
            || (value.len() > 1 && value.as_bytes().first() == Some(&b'0'))
            || !value.as_bytes().iter().all(u8::is_ascii_digit)
        {
            return None;
        }
        let mut parsed: u64 = 0;
        for digit in value.bytes() {
            parsed = parsed
                .checked_mul(10)?
                .checked_add(u64::from(digit - b'0'))?;
        }
        Some(parsed)
    }

    fn validate_socket_path(value: &str) -> Result<(Vec<String>, String), Error> {
        let bytes: &[u8] = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_PATH_BYTES
            || bytes.contains(&0)
            || !value.starts_with('/')
        {
            return Err(Error::Arguments);
        }
        let mut parts: Vec<&str> = value.split('/').collect();
        if parts.first() != Some(&"") || parts.len() < 2 {
            return Err(Error::Arguments);
        }
        parts.remove(0);
        if parts
            .iter()
            .any(|part: &&str| part.is_empty() || *part == "." || *part == "..")
        {
            return Err(Error::Arguments);
        }
        let leaf: String = match parts.pop() {
            Some(value) => value.to_owned(),
            None => return Err(Error::Arguments),
        };
        if leaf.is_empty() {
            return Err(Error::Arguments);
        }
        let parent_components: Vec<String> =
            parts.iter().map(|part: &&str| (*part).to_owned()).collect();
        Ok((parent_components, leaf))
    }

    fn parse_args<I>(arguments: I) -> Result<CollectorArgs, Error>
    where
        I: Iterator<Item = OsString>,
    {
        let mut socket: Option<String> = None;
        let mut samples: Option<usize> = None;
        let mut timeout_ms: Option<u64> = None;
        let mut pending: Option<String> = None;
        let mut argument_count: usize = 0;
        for argument in arguments {
            argument_count = argument_count.checked_add(1).ok_or(Error::Arguments)?;
            if argument_count > 6 {
                return Err(Error::Arguments);
            }
            let text: &str = argument.to_str().ok_or(Error::Arguments)?;
            if let Some(flag) = pending.take() {
                match flag.as_str() {
                    "--socket" => {
                        validate_socket_path(text)?;
                        if socket.replace(text.to_owned()).is_some() {
                            return Err(Error::Arguments);
                        }
                    }
                    "--max-samples" => {
                        let parsed: usize =
                            usize::try_from(parse_decimal(text).ok_or(Error::Arguments)?)
                                .map_err(|_error| Error::Arguments)?;
                        if !(1..=MAX_SAMPLES).contains(&parsed) || samples.replace(parsed).is_some()
                        {
                            return Err(Error::Arguments);
                        }
                    }
                    "--timeout-ms" => {
                        let parsed: u64 = parse_decimal(text).ok_or(Error::Arguments)?;
                        if !(1..=MAX_TIMEOUT_MILLIS).contains(&parsed)
                            || timeout_ms.replace(parsed).is_some()
                        {
                            return Err(Error::Arguments);
                        }
                    }
                    _ => return Err(Error::Arguments),
                }
            } else if matches!(text, "--socket" | "--max-samples" | "--timeout-ms") {
                pending = Some(text.to_owned());
            } else {
                return Err(Error::Arguments);
            }
        }
        if pending.is_some() {
            return Err(Error::Arguments);
        }
        let socket: String = socket.ok_or(Error::Arguments)?;
        let samples: usize = samples.ok_or(Error::Arguments)?;
        let timeout_ms: u64 = timeout_ms.ok_or(Error::Arguments)?;
        Ok(CollectorArgs {
            socket,
            samples,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct DirectoryIdentity {
        dev: u64,
        ino: u64,
        uid: u32,
        mode: u32,
    }

    struct HeldDirectory {
        name: String,
        fd: OwnedFd,
        identity: DirectoryIdentity,
    }

    struct DirectoryChain {
        root: OwnedFd,
        root_identity: DirectoryIdentity,
        directories: Vec<HeldDirectory>,
        leaf: String,
        euid: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LeafIdentity {
        dev: u64,
        ino: u64,
        uid: u32,
        mode: u32,
    }

    impl DirectoryChain {
        fn open(path: &str, deadline: Instant) -> Result<Self, Error> {
            check_deadline(deadline)?;
            let (components, leaf): (Vec<String>, String) = validate_socket_path(path)?;
            let euid: u32 = effective_uid(deadline)?;
            let flags: OFlags =
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let root: OwnedFd = deadline_step(deadline, || {
                open("/", flags, Mode::empty()).map_err(|_error| Error::Directory)
            })?;
            let root_stat: rustix::fs::Stat = deadline_step(deadline, || {
                rustix::fs::fstat(&root).map_err(|_error| Error::Directory)
            })?;
            let root_identity: DirectoryIdentity = identity(root_stat);
            if !FileType::from_raw_mode(root_stat.st_mode).is_dir() {
                return Err(Error::Directory);
            }
            let mut directories: Vec<HeldDirectory> = Vec::with_capacity(components.len());
            for component in components {
                let parent: &OwnedFd = directories
                    .last()
                    .map_or(&root, |directory: &HeldDirectory| &directory.fd);
                let child: OwnedFd = deadline_step(deadline, || {
                    openat(parent, component.as_str(), flags, Mode::empty())
                        .map_err(|_error| Error::Directory)
                })?;
                let child_stat: rustix::fs::Stat = deadline_step(deadline, || {
                    rustix::fs::fstat(&child).map_err(|_error| Error::Directory)
                })?;
                if !FileType::from_raw_mode(child_stat.st_mode).is_dir() {
                    return Err(Error::Directory);
                }
                let child_identity: DirectoryIdentity = identity(child_stat);
                let named: rustix::fs::Stat = deadline_step(deadline, || {
                    statat(parent, component.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(|_error| Error::Directory)
                })?;
                if identity(named) != child_identity {
                    return Err(Error::Directory);
                }
                directories.push(HeldDirectory {
                    name: component,
                    fd: child,
                    identity: child_identity,
                });
            }
            let chain: Self = Self {
                root,
                root_identity,
                directories,
                leaf,
                euid,
            };
            chain.check_directory_policy(deadline)?;
            chain.check_leaf_absent(deadline)?;
            check_deadline(deadline)?;
            Ok(chain)
        }

        fn final_fd(&self) -> &OwnedFd {
            self.directories
                .last()
                .map_or(&self.root, |directory: &HeldDirectory| &directory.fd)
        }

        fn check_directory_policy(&self, deadline: Instant) -> Result<(), Error> {
            let stat: rustix::fs::Stat = deadline_step(deadline, || {
                rustix::fs::fstat(self.final_fd()).map_err(|_error| Error::Directory)
            })?;
            if stat.st_uid != self.euid || stat.st_mode & 0o7777 != DIRECTORY_MODE {
                return Err(Error::Directory);
            }
            let root_stat: rustix::fs::Stat = deadline_step(deadline, || {
                rustix::fs::fstat(&self.root).map_err(|_error| Error::Directory)
            })?;
            if identity(root_stat) != self.root_identity {
                return Err(Error::Directory);
            }
            let mut parent: &OwnedFd = &self.root;
            for directory in &self.directories {
                let held: rustix::fs::Stat = deadline_step(deadline, || {
                    rustix::fs::fstat(&directory.fd).map_err(|_error| Error::Directory)
                })?;
                let named: rustix::fs::Stat = deadline_step(deadline, || {
                    statat(parent, directory.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(|_error| Error::Directory)
                })?;
                if identity(held) != directory.identity || identity(named) != directory.identity {
                    return Err(Error::Directory);
                }
                parent = &directory.fd;
            }
            Ok(())
        }

        fn check_leaf_absent(&self, deadline: Instant) -> Result<(), Error> {
            deadline_step(deadline, || {
                match statat(
                    self.final_fd(),
                    self.leaf.as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                ) {
                    Err(Errno::NOENT) => Ok(()),
                    _ => Err(Error::Socket),
                }
            })
        }

        fn bind_address(&self, deadline: Instant) -> Result<PathBuf, Error> {
            deadline_step(deadline, || {
                bind_address_for_fd(self.final_fd().as_raw_fd(), &self.leaf)
            })
        }

        fn verify_bound_leaf(&self, deadline: Instant) -> Result<LeafIdentity, Error> {
            self.check_directory_policy(deadline)?;
            let leaf: rustix::fs::Stat = deadline_step(deadline, || {
                statat(
                    self.final_fd(),
                    self.leaf.as_str(),
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(|_error| Error::Socket)
            })?;
            if !FileType::from_raw_mode(leaf.st_mode).is_socket() || leaf.st_uid != self.euid {
                return Err(Error::Socket);
            }
            let identity: LeafIdentity = LeafIdentity {
                dev: leaf.st_dev,
                ino: leaf.st_ino,
                uid: leaf.st_uid,
                mode: leaf.st_mode,
            };
            check_deadline(deadline)?;
            Ok(identity)
        }
    }

    fn bind_address_for_fd(fd: RawFd, leaf: &str) -> Result<PathBuf, Error> {
        let address: String = format!("/proc/self/fd/{fd}/{leaf}");
        if address.len() > MAX_PATH_BYTES {
            return Err(Error::Socket);
        }
        Ok(PathBuf::from(address))
    }

    fn identity(stat: rustix::fs::Stat) -> DirectoryIdentity {
        DirectoryIdentity {
            dev: stat.st_dev,
            ino: stat.st_ino,
            uid: stat.st_uid,
            mode: stat.st_mode,
        }
    }

    fn parse_effective_uid(bytes: &[u8]) -> Result<u32, Error> {
        if bytes.len() > MAX_PROC_STATUS_BYTES {
            return Err(Error::Directory);
        }
        for line in bytes.split(|byte: &u8| *byte == b'\n') {
            if let Some(values) = line.strip_prefix(b"Uid:") {
                let fields: Vec<&[u8]> = values
                    .split(u8::is_ascii_whitespace)
                    .filter(|field: &&[u8]| !field.is_empty())
                    .collect();
                if fields.len() != 4 {
                    return Err(Error::Directory);
                }
                for field in fields.iter() {
                    let value: &str =
                        std::str::from_utf8(field).map_err(|_error| Error::Directory)?;
                    if u32::try_from(parse_decimal(value).ok_or(Error::Directory)?).is_err() {
                        return Err(Error::Directory);
                    }
                }
                let effective: &str =
                    std::str::from_utf8(fields[1]).map_err(|_error| Error::Directory)?;
                let uid: u32 = u32::try_from(parse_decimal(effective).ok_or(Error::Directory)?)
                    .map_err(|_error| Error::Directory)?;
                return Ok(uid);
            }
        }
        Err(Error::Directory)
    }

    fn effective_uid(deadline: Instant) -> Result<u32, Error> {
        let file: File = deadline_step(deadline, || {
            File::open("/proc/self/status").map_err(|_error| Error::Directory)
        })?;
        let mut bytes: Vec<u8> = Vec::with_capacity(MAX_PROC_STATUS_BYTES + 1);
        deadline_step(deadline, || {
            file.take((MAX_PROC_STATUS_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_error| Error::Directory)
                .map(|_read| ())
        })?;
        deadline_step(deadline, || parse_effective_uid(&bytes))
    }

    struct PreparedCollector {
        socket: UnixDatagram,
        directories: DirectoryChain,
        leaf_identity: LeafIdentity,
    }

    impl PreparedCollector {
        fn bind(path: &str, deadline: Instant) -> Result<Self, Error> {
            check_deadline(deadline)?;
            let directories: DirectoryChain = DirectoryChain::open(path, deadline)?;
            let address: PathBuf = directories.bind_address(deadline)?;
            let socket: UnixDatagram = deadline_step(deadline, || {
                UnixDatagram::bind(&address).map_err(|_error| Error::Socket)
            })?;
            let leaf_identity: LeafIdentity = directories.verify_bound_leaf(deadline)?;
            check_deadline(deadline)?;
            Ok(Self {
                socket,
                directories,
                leaf_identity,
            })
        }

        fn collect(
            self,
            count: usize,
            deadline: Instant,
        ) -> Result<Vec<NativeHttpSnapshot>, Error> {
            let snapshots: Vec<NativeHttpSnapshot> = receive_samples_with_clock(
                count,
                deadline,
                Instant::now,
                |remaining: Duration| {
                    self.socket
                        .set_read_timeout(Some(remaining))
                        .map_err(|_error| Error::Collection)
                },
                |buffer: &mut [u8; MAX_RECORD_BYTES]| self.socket.recv(buffer),
            )?;
            let final_leaf: LeafIdentity = self.directories.verify_bound_leaf(deadline)?;
            if final_leaf != self.leaf_identity {
                return Err(Error::Socket);
            }
            if Instant::now() >= deadline {
                return Err(Error::Collection);
            }
            drop(self.socket);
            drop(self.directories);
            Ok(snapshots)
        }
    }

    fn charge_attempt(attempts: &mut usize) -> bool {
        if *attempts >= MAX_ATTEMPTS {
            return false;
        }
        *attempts += 1;
        true
    }

    fn receive_samples_with_clock<N, S, R>(
        count: usize,
        deadline: Instant,
        mut now: N,
        mut set_timeout: S,
        mut receive: R,
    ) -> Result<Vec<NativeHttpSnapshot>, Error>
    where
        N: FnMut() -> Instant,
        S: FnMut(Duration) -> Result<(), Error>,
        R: FnMut(&mut [u8; MAX_RECORD_BYTES]) -> io::Result<usize>,
    {
        if !(1..=MAX_SAMPLES).contains(&count) {
            return Err(Error::Collection);
        }
        check_deadline_at(deadline, now())?;
        let mut snapshots: Vec<NativeHttpSnapshot> = Vec::with_capacity(count);
        let mut receive_buffer: [u8; MAX_RECORD_BYTES] = [0; MAX_RECORD_BYTES];
        let mut attempts: usize = 0;
        while snapshots.len() < count {
            let remaining: Duration = deadline
                .checked_duration_since(now())
                .ok_or(Error::Collection)?;
            if remaining.is_zero() {
                return Err(Error::Collection);
            }
            deadline_step_with_clock(deadline, &mut now, || set_timeout(remaining))?;
            check_deadline_at(deadline, now())?;
            let received: Option<usize> =
                receive_attempt(&mut attempts, || receive(&mut receive_buffer))?;
            check_deadline_at(deadline, now())?;
            let length: usize = match received {
                Some(length) => length,
                None => continue,
            };
            let snapshot: NativeHttpSnapshot = decode_received_record(&receive_buffer, length)?;
            check_deadline_at(deadline, now())?;
            snapshots.push(snapshot);
        }
        if snapshots.len() != count {
            return Err(Error::Collection);
        }
        check_deadline_at(deadline, now())?;
        Ok(snapshots)
    }

    fn decode_received_record(
        buffer: &[u8; MAX_RECORD_BYTES],
        length: usize,
    ) -> Result<NativeHttpSnapshot, Error> {
        if length >= MAX_RECORD_BYTES {
            return Err(Error::Record);
        }
        decode_live_summary(&buffer[..length]).map_err(|_error| Error::Record)
    }

    fn write_records<W: Write>(snapshots: &[NativeHttpSnapshot], writer: &mut W) -> io::Result<()> {
        for snapshot in snapshots {
            let record: String = snapshot.live_summary();
            writer.write_all(record.as_bytes())?;
        }
        Ok(())
    }

    fn write_complete_collection<W: Write>(
        collection: Result<Vec<NativeHttpSnapshot>, Error>,
        writer: &mut W,
    ) -> Result<(), Error> {
        let snapshots: Vec<NativeHttpSnapshot> = collection?;
        write_records(&snapshots, writer).map_err(|_error| Error::Output)?;
        writer.flush().map_err(|_error| Error::Output)
    }

    fn collect(args: CollectorArgs) -> Result<Vec<NativeHttpSnapshot>, Error> {
        let deadline: Instant = Instant::now()
            .checked_add(args.timeout)
            .ok_or(Error::Collection)?;
        let collector: PreparedCollector = PreparedCollector::bind(&args.socket, deadline)?;
        collector.collect(args.samples, deadline)
    }

    pub(super) fn run<I>(arguments: I) -> Result<(), Error>
    where
        I: Iterator<Item = OsString>,
    {
        let args: CollectorArgs = parse_args(arguments)?;
        let snapshots: Vec<NativeHttpSnapshot> = collect(args)?;
        let stdout: io::Stdout = io::stdout();
        let mut output: io::StdoutLock<'_> = stdout.lock();
        write_complete_collection(Ok(snapshots), &mut output)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs::{self, DirBuilder},
            os::unix::{
                fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
                net::UnixDatagram,
            },
            sync::atomic::{AtomicU64, Ordering},
        };

        static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

        struct Fixture {
            root: PathBuf,
        }

        impl Fixture {
            fn new() -> Self {
                let index: u64 = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let root: PathBuf = std::env::temp_dir().join(format!(
                    "sunrise-native-observations-{}-{index}",
                    std::process::id()
                ));
                let mut builder: DirBuilder = DirBuilder::new();
                builder.mode(DIRECTORY_MODE);
                builder.create(&root).expect("unique fixture directory");
                fs::set_permissions(&root, fs::Permissions::from_mode(DIRECTORY_MODE))
                    .expect("set owned fixture directory mode");
                Self { root }
            }

            fn socket_path(&self, leaf: &str) -> String {
                self.root.join(leaf).to_string_lossy().into_owned()
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _removed: io::Result<()> = fs::remove_dir_all(&self.root);
            }
        }

        fn live_record(sequence: u64) -> Vec<u8> {
            NativeHttpSnapshot {
                connections_admitted: sequence,
                connections_refused: 2,
                accept_failures: 3,
                upgrade_failures: 4,
                upgrade_timeouts: 5,
                requests_dispatched: 6,
                requests_refused: 7,
                input_timeouts: 8,
                output_timeouts: 9,
                connection_failures: 10,
                connection_task_failures: 11,
                blocking_admitted: 12,
                blocking_overloaded: 13,
                blocking_closed: 14,
                blocking_panics: 15,
            }
            .live_summary()
            .into_bytes()
        }

        fn argument_vector(socket: &str, samples: &str, timeout: &str) -> Vec<OsString> {
            vec![
                OsString::from("--socket"),
                OsString::from(socket),
                OsString::from("--max-samples"),
                OsString::from(samples),
                OsString::from("--timeout-ms"),
                OsString::from(timeout),
            ]
        }

        fn deadline_after(duration: Duration) -> Instant {
            Instant::now()
                .checked_add(duration)
                .expect("test deadline representable")
        }

        #[test]
        fn deadline_step_rejects_preexpired_and_late_success_without_sleeping() {
            let now: Instant = Instant::now();
            let deadline: Instant = now.checked_add(Duration::from_secs(1)).unwrap();
            let mut calls: std::array::IntoIter<Instant, 2> = [now, deadline].into_iter();
            let mut invoked: bool = false;
            let late: Result<u8, Error> = deadline_step_with_clock(
                deadline,
                || calls.next().unwrap_or(deadline),
                || {
                    invoked = true;
                    Ok(7)
                },
            );
            assert_eq!(late, Err(Error::Collection));
            assert!(invoked);

            let mut preexpired_invoked: bool = false;
            let preexpired: Result<(), Error> = deadline_step_with_clock(
                now,
                || now,
                || {
                    preexpired_invoked = true;
                    Ok(())
                },
            );
            assert_eq!(preexpired, Err(Error::Collection));
            assert!(!preexpired_invoked);
        }

        #[test]
        fn expired_deadline_refuses_setup_before_creating_a_socket_leaf() {
            let fixture: Fixture = Fixture::new();
            let path: String = fixture.socket_path("expired.sock");
            let deadline: Instant = Instant::now();
            let result: Result<PreparedCollector, Error> = PreparedCollector::bind(&path, deadline);
            assert_eq!(result.err(), Some(Error::Collection));
            assert!(fs::symlink_metadata(path).is_err());
        }

        #[test]
        fn interrupted_receive_attempts_are_charged_before_retry() {
            let mut attempts: usize = 0;
            let interrupted: Result<Option<usize>, Error> = receive_attempt(&mut attempts, || {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            });
            assert_eq!(interrupted, Ok(None));
            assert_eq!(attempts, 1);

            let received: Result<Option<usize>, Error> = receive_attempt(&mut attempts, || Ok(23));
            assert_eq!(received, Ok(Some(23)));
            assert_eq!(attempts, 2);

            attempts = MAX_ATTEMPTS;
            let mut invoked: bool = false;
            let refused: Result<Option<usize>, Error> = receive_attempt(&mut attempts, || {
                invoked = true;
                Ok(24)
            });
            assert_eq!(refused, Err(Error::Collection));
            assert_eq!(attempts, MAX_ATTEMPTS);
            assert!(!invoked);
        }

        #[test]
        fn receive_loop_accepts_exact_count_completed_before_deadline() {
            let start: Instant = Instant::now();
            let deadline: Instant = start.checked_add(Duration::from_secs(1)).unwrap();
            let clock: std::cell::Cell<Instant> = std::cell::Cell::new(start);
            let mut sequence: u64 = 0;
            let snapshots: Vec<NativeHttpSnapshot> = receive_samples_with_clock(
                2,
                deadline,
                || clock.get(),
                |_remaining: Duration| Ok(()),
                |buffer: &mut [u8; MAX_RECORD_BYTES]| {
                    sequence += 1;
                    let record: Vec<u8> = live_record(sequence);
                    let length: usize = record.len();
                    buffer[..length].copy_from_slice(&record);
                    Ok(length)
                },
            )
            .unwrap();
            assert_eq!(snapshots.len(), 2);
            assert_eq!(snapshots[0].connections_admitted, 1);
            assert_eq!(snapshots[1].connections_admitted, 2);
        }

        #[test]
        fn receive_loop_rejects_late_success_without_prefix_output() {
            let start: Instant = Instant::now();
            let deadline: Instant = start.checked_add(Duration::from_secs(1)).unwrap();
            let clock: std::cell::Cell<Instant> = std::cell::Cell::new(start);
            let record: Vec<u8> = live_record(1);
            let mut sequence: usize = 0;
            let result: Result<Vec<NativeHttpSnapshot>, Error> = receive_samples_with_clock(
                2,
                deadline,
                || clock.get(),
                |_remaining: Duration| Ok(()),
                |buffer: &mut [u8; MAX_RECORD_BYTES]| {
                    sequence += 1;
                    let length: usize = record.len();
                    buffer[..length].copy_from_slice(&record);
                    if sequence == 2 {
                        clock.set(deadline);
                    }
                    Ok(length)
                },
            );
            let mut output: Vec<u8> = Vec::new();
            assert_eq!(
                write_complete_collection(result, &mut output),
                Err(Error::Collection)
            );
            assert!(output.is_empty());
        }

        #[test]
        fn receive_loop_rejects_malformed_after_valid_prefix_without_output() {
            let start: Instant = Instant::now();
            let deadline: Instant = start.checked_add(Duration::from_secs(1)).unwrap();
            let record: Vec<u8> = live_record(1);
            let mut sequence: usize = 0;
            let result: Result<Vec<NativeHttpSnapshot>, Error> = receive_samples_with_clock(
                2,
                deadline,
                || start,
                |_remaining: Duration| Ok(()),
                |buffer: &mut [u8; MAX_RECORD_BYTES]| {
                    sequence += 1;
                    let bytes: &[u8] = if sequence == 1 {
                        &record
                    } else {
                        b"malformed\n"
                    };
                    let length: usize = bytes.len();
                    buffer[..length].copy_from_slice(bytes);
                    Ok(length)
                },
            );
            let mut output: Vec<u8> = Vec::new();
            assert_eq!(
                write_complete_collection(result, &mut output),
                Err(Error::Record)
            );
            assert!(output.is_empty());
        }

        #[test]
        fn receive_loop_charges_repeated_interruptions_to_attempt_limit() {
            let start: Instant = Instant::now();
            let deadline: Instant = start.checked_add(Duration::from_secs(1)).unwrap();
            let mut attempts: usize = 0;
            let result: Result<Vec<NativeHttpSnapshot>, Error> = receive_samples_with_clock(
                1,
                deadline,
                || start,
                |_remaining: Duration| Ok(()),
                |_buffer: &mut [u8; MAX_RECORD_BYTES]| {
                    attempts += 1;
                    Err(io::Error::from(io::ErrorKind::Interrupted))
                },
            );
            assert_eq!(result, Err(Error::Collection));
            assert_eq!(attempts, MAX_ATTEMPTS);
        }

        #[test]
        fn collector_arguments_are_exact_and_bounded_before_io() {
            let valid: Vec<OsString> = argument_vector("/tmp/observations.sock", "1024", "300000");
            assert!(parse_args(valid.into_iter()).is_ok());
            assert!(validate_socket_path(&format!("/{}", "a".repeat(99))).is_ok());
            assert!(validate_socket_path(&format!("/{}", "a".repeat(100))).is_err());
            for invalid in [
                argument_vector("relative.sock", "1", "1"),
                argument_vector("/tmp/../sock", "1", "1"),
                argument_vector("/tmp//sock", "1", "1"),
                argument_vector("/tmp/sock/", "1", "1"),
                argument_vector("/tmp/a\0b", "1", "1"),
                argument_vector(&format!("/{}", "a".repeat(100)), "1", "1"),
                argument_vector("/tmp/sock", "+1", "1"),
                argument_vector("/tmp/sock", "1025", "1"),
                argument_vector("/tmp/sock", "1", "0"),
                argument_vector("/tmp/sock", "1", "300001"),
                vec![
                    "--socket".into(),
                    "/tmp/one.sock".into(),
                    "--socket".into(),
                    "/tmp/two.sock".into(),
                    "--max-samples".into(),
                    "1".into(),
                ],
                vec![
                    "--socket".into(),
                    "/tmp/sock".into(),
                    "--max-samples".into(),
                    "1".into(),
                    "--max-samples".into(),
                    "2".into(),
                ],
                vec![
                    "--socket".into(),
                    "/tmp/sock".into(),
                    "--timeout-ms".into(),
                    "1".into(),
                    "--timeout-ms".into(),
                    "2".into(),
                ],
            ] {
                assert_eq!(parse_args(invalid.into_iter()), Err(Error::Arguments));
            }
        }

        #[test]
        fn collector_receives_real_local_datagrams_and_retains_own_leaf() {
            struct CompleteWriter {
                written: Vec<u8>,
                flush_calls: usize,
                refuse_flush: bool,
            }
            impl Write for CompleteWriter {
                fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                    self.written.extend_from_slice(bytes);
                    Ok(bytes.len())
                }

                fn flush(&mut self) -> io::Result<()> {
                    self.flush_calls += 1;
                    if self.refuse_flush {
                        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture flush"));
                    }
                    Ok(())
                }
            }
            let expected_snapshots: Vec<NativeHttpSnapshot> = vec![
                NativeHttpSnapshot {
                    connections_admitted: 71,
                    connections_refused: 2,
                    accept_failures: 3,
                    upgrade_failures: 4,
                    upgrade_timeouts: 5,
                    requests_dispatched: 6,
                    requests_refused: 7,
                    input_timeouts: 8,
                    output_timeouts: 9,
                    connection_failures: 10,
                    connection_task_failures: 11,
                    blocking_admitted: 12,
                    blocking_overloaded: 13,
                    blocking_closed: 14,
                    blocking_panics: 15,
                },
                NativeHttpSnapshot {
                    connections_admitted: 72,
                    connections_refused: 17,
                    accept_failures: 18,
                    upgrade_failures: 19,
                    upgrade_timeouts: 20,
                    requests_dispatched: 21,
                    requests_refused: 22,
                    input_timeouts: 23,
                    output_timeouts: 24,
                    connection_failures: 25,
                    connection_task_failures: 26,
                    blocking_admitted: 27,
                    blocking_overloaded: 28,
                    blocking_closed: 29,
                    blocking_panics: 30,
                },
            ];
            const EXPECTED_BYTES: &[u8] = concat!(
                "native_operations schema=1 kind=live connections_admitted=71 ",
                "connections_refused=2 accept_failures=3 upgrade_failures=4 ",
                "upgrade_timeouts=5 requests_dispatched=6 requests_refused=7 ",
                "input_timeouts=8 output_timeouts=9 connection_failures=10 ",
                "connection_task_failures=11 blocking_admitted=12 blocking_overloaded=13 ",
                "blocking_closed=14 blocking_panics=15\n",
                "native_operations schema=1 kind=live connections_admitted=72 ",
                "connections_refused=17 accept_failures=18 upgrade_failures=19 ",
                "upgrade_timeouts=20 requests_dispatched=21 requests_refused=22 ",
                "input_timeouts=23 output_timeouts=24 connection_failures=25 ",
                "connection_task_failures=26 blocking_admitted=27 blocking_overloaded=28 ",
                "blocking_closed=29 blocking_panics=30\n",
            )
            .as_bytes();
            let fixture: Fixture = Fixture::new();
            let path: String = fixture.socket_path("collector.sock");
            let deadline: Instant = deadline_after(Duration::from_secs(1));
            let collector: PreparedCollector = PreparedCollector::bind(&path, deadline).unwrap();
            let metadata_before: std::fs::Metadata = fs::symlink_metadata(&path).unwrap();
            let sender: UnixDatagram = UnixDatagram::unbound().unwrap();
            sender.connect(&path).unwrap();
            for snapshot in &expected_snapshots {
                let record: Vec<u8> = snapshot.live_summary().into_bytes();
                let sent: usize = sender.send(&record).unwrap();
                assert_eq!(sent, record.len());
            }
            let snapshots: Vec<NativeHttpSnapshot> = collector.collect(2, deadline).unwrap();
            assert_eq!(snapshots, expected_snapshots);
            let mut successful_writer: CompleteWriter = CompleteWriter {
                written: Vec::new(),
                flush_calls: 0,
                refuse_flush: false,
            };
            assert_eq!(
                write_complete_collection(Ok(snapshots.clone()), &mut successful_writer),
                Ok(())
            );
            assert_eq!(successful_writer.written, EXPECTED_BYTES);
            assert_eq!(successful_writer.flush_calls, 1);
            let mut failing_writer: CompleteWriter = CompleteWriter {
                written: Vec::new(),
                flush_calls: 0,
                refuse_flush: true,
            };
            assert_eq!(
                write_complete_collection(Ok(snapshots), &mut failing_writer),
                Err(Error::Output)
            );
            assert_eq!(failing_writer.written, EXPECTED_BYTES);
            assert_eq!(failing_writer.flush_calls, 1);
            let metadata_after: std::fs::Metadata = fs::symlink_metadata(&path).unwrap();
            assert!(metadata_after.file_type().is_socket());
            assert_eq!(metadata_before.dev(), metadata_after.dev());
            assert_eq!(metadata_before.ino(), metadata_after.ino());
        }

        #[test]
        fn collector_refuses_existing_regular_symlink_and_socket_leaves() {
            let fixture: Fixture = Fixture::new();
            let regular: String = fixture.socket_path("regular");
            fs::write(&regular, b"sentinel").unwrap();
            let deadline: Instant = deadline_after(Duration::from_secs(1));
            assert!(matches!(
                PreparedCollector::bind(&regular, deadline),
                Err(Error::Socket)
            ));
            assert_eq!(fs::read(&regular).unwrap(), b"sentinel");

            let target: String = fixture.socket_path("target");
            fs::write(&target, b"symlink target").unwrap();
            let symbolic: String = fixture.socket_path("symbolic");
            std::os::unix::fs::symlink(&target, &symbolic).unwrap();
            let deadline: Instant = deadline_after(Duration::from_secs(1));
            assert!(matches!(
                PreparedCollector::bind(&symbolic, deadline),
                Err(Error::Socket)
            ));
            assert!(
                fs::symlink_metadata(&symbolic)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );

            let occupied: String = fixture.socket_path("occupied.sock");
            let owner: UnixDatagram = UnixDatagram::bind(&occupied).unwrap();
            let inode: u64 = fs::symlink_metadata(&occupied).unwrap().ino();
            let deadline: Instant = deadline_after(Duration::from_secs(1));
            assert!(matches!(
                PreparedCollector::bind(&occupied, deadline),
                Err(Error::Socket)
            ));
            assert_eq!(fs::symlink_metadata(&occupied).unwrap().ino(), inode);
            drop(owner);
        }

        #[test]
        fn collector_rejects_symlinked_parent_and_invalid_datagram_without_unlinking() {
            let fixture: Fixture = Fixture::new();
            let target_directory: PathBuf = fixture.root.join("real-parent");
            fs::create_dir(&target_directory).unwrap();
            fs::set_permissions(
                &target_directory,
                fs::Permissions::from_mode(DIRECTORY_MODE),
            )
            .unwrap();
            let parent_link: PathBuf = fixture.root.join("parent-link");
            std::os::unix::fs::symlink(&target_directory, &parent_link).unwrap();
            let through_link: String = parent_link
                .join("collector.sock")
                .to_string_lossy()
                .into_owned();
            let deadline: Instant = deadline_after(Duration::from_secs(1));
            assert!(matches!(
                PreparedCollector::bind(&through_link, deadline),
                Err(Error::Directory)
            ));
            assert!(
                fs::symlink_metadata(&parent_link)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );

            let path: String = fixture.socket_path("invalid.sock");
            let deadline: Instant = deadline_after(Duration::from_secs(1));
            let collector: PreparedCollector = PreparedCollector::bind(&path, deadline).unwrap();
            let sender: UnixDatagram = UnixDatagram::unbound().unwrap();
            sender.connect(&path).unwrap();
            sender.send(b"not a live snapshot\n").unwrap();
            assert!(matches!(collector.collect(1, deadline), Err(Error::Record)));
            assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        }

        #[test]
        fn collector_timeout_fails_before_output_and_retains_own_leaf() {
            let fixture: Fixture = Fixture::new();
            let path: String = fixture.socket_path("timeout.sock");
            let deadline: Instant = deadline_after(Duration::from_secs(1));
            let collector: PreparedCollector = PreparedCollector::bind(&path, deadline).unwrap();
            let result: Result<Vec<NativeHttpSnapshot>, Error> = collector.collect(1, deadline);
            assert_eq!(result, Err(Error::Collection));
            assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        }

        #[test]
        fn output_failure_reports_error_after_collection_without_claiming_completion() {
            struct FailingWriter {
                remaining: usize,
                written: Vec<u8>,
            }
            impl Write for FailingWriter {
                fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                    if self.remaining == 0 {
                        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture"));
                    }
                    let accepted: usize = self.remaining.min(bytes.len());
                    self.written.extend_from_slice(&bytes[..accepted]);
                    self.remaining -= accepted;
                    Ok(accepted)
                }
                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            let record: String = NativeHttpSnapshot::default().live_summary();
            let mut writer: FailingWriter = FailingWriter {
                remaining: 7,
                written: Vec::new(),
            };
            assert_eq!(
                write_complete_collection(Ok(vec![NativeHttpSnapshot::default()]), &mut writer),
                Err(Error::Output)
            );
            assert_eq!(writer.written, record.as_bytes()[..7]);
        }

        #[test]
        fn receive_buffer_capacity_is_not_accepted_as_a_complete_record() {
            let mut bytes: [u8; MAX_RECORD_BYTES] = [b'x'; MAX_RECORD_BYTES];
            bytes[0] = b'n';
            assert_eq!(bytes.len(), MAX_RECORD_BYTES);
            assert_eq!(
                decode_received_record(&bytes, bytes.len()),
                Err(Error::Record)
            );
            assert_eq!(
                decode_received_record(&bytes, bytes.len() + 1),
                Err(Error::Record)
            );
        }

        #[test]
        fn procfd_bind_path_has_its_own_independent_byte_limit() {
            let accepted: PathBuf = bind_address_for_fd(7, &"a".repeat(80)).unwrap();
            assert!(accepted.to_string_lossy().len() <= MAX_PATH_BYTES);
            assert!(matches!(
                bind_address_for_fd(7, &"a".repeat(90)),
                Err(Error::Socket)
            ));
        }

        #[test]
        fn attempt_counter_is_finite_and_charges_each_receive() {
            let mut attempts: usize = 0;
            for _attempt in 0..MAX_ATTEMPTS {
                assert!(charge_attempt(&mut attempts));
            }
            assert_eq!(attempts, MAX_ATTEMPTS);
            assert!(!charge_attempt(&mut attempts));
            assert_eq!(attempts, MAX_ATTEMPTS);
        }

        #[test]
        fn collector_refuses_parent_attachment_replacement_without_unlinking_leaf() {
            let mut fixture: Fixture = Fixture::new();
            let path: String = fixture.socket_path("attached.sock");
            let deadline: Instant = deadline_after(Duration::from_secs(1));
            let collector: PreparedCollector = PreparedCollector::bind(&path, deadline).unwrap();
            let renamed: PathBuf = fixture.root.with_extension("moved");
            fs::rename(&fixture.root, &renamed).unwrap();
            fixture.root = renamed;
            assert!(matches!(
                collector.directories.verify_bound_leaf(deadline),
                Err(Error::Directory)
            ));
            assert!(fs::symlink_metadata(&path).is_err());
            let moved_leaf: PathBuf = fixture.root.join("attached.sock");
            assert!(
                fs::symlink_metadata(moved_leaf)
                    .unwrap()
                    .file_type()
                    .is_socket()
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub fn run<I>(arguments: I) -> Result<(), NativeObservationsError>
where
    I: Iterator<Item = OsString>,
{
    linux::run(arguments)
}

#[cfg(not(target_os = "linux"))]
pub fn run<I>(_arguments: I) -> Result<(), NativeObservationsError>
where
    I: Iterator<Item = OsString>,
{
    Err(NativeObservationsError::UnsupportedPlatform)
}
