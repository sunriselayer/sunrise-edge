//! Shared test-only lifecycle helpers for spawning and bounding real
//! sqlite_source_host (or any other real serving/refusing) child
//! processes. This owns only process lifetime and I/O timing; it is not
//! a production dispatcher or fault engine.
#![allow(dead_code)]
use std::{
    io::{BufRead, BufReader, Read},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

/// Owns a spawned child from the instant it is constructed, before any
/// fallible parse or read; a panic anywhere after construction still
/// kills and reaps the real process on unwind instead of leaking it.
pub struct ChildGuard(Option<Child>);
impl ChildGuard {
    pub fn new(child: Child) -> Self {
        Self(Some(child))
    }
    pub fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("guard still owns its child")
    }
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child_mut().try_wait()
    }

    /// One live observation request, not a stop or a transfer of ownership.
    #[cfg(target_os = "linux")]
    pub fn request_usr1(&mut self, end: Instant) {
        assert!(Instant::now() < end, "observation request deadline elapsed");
        assert!(
            self.try_wait()
                .expect("poll owned host before USR1")
                .is_none(),
            "owned host exited before USR1"
        );
        let pid: u32 = self.child_mut().id();
        assert!(pid > 0 && pid <= i32::MAX as u32, "positive owned host PID");
        let signal_end: Instant = end.min(
            Instant::now()
                .checked_add(Duration::from_secs(5))
                .expect("USR1 helper deadline"),
        );
        let mut command: Command = Command::new("kill");
        command.args(["-s", "USR1", "--"]).arg(pid.to_string());
        let mut signal: PendingStrictOutput = PendingStrictOutput::spawn(command, signal_end);
        let output: Output = signal.finish();
        assert_eq!(
            output.status.code(), Some(0),
            "owned-host USR1 helper failed"
        );
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert!(
            self.try_wait()
                .expect("poll still-owned host after USR1")
                .is_none(),
            "USR1 must not stop the owned host"
        );
    }

    pub fn into_inner(mut self) -> Child {
        self.0.take().expect("guard still owns its child")
    }

    /// Quiet local acceptance only: signal this still-owned, unreaped positive
    /// PID, then require an ordinary successful exit. Kill/reap remains solely
    /// failure cleanup, never evidence of an orderly stop.
    pub fn stop_orderly(self, deadline: Duration) {
        let _stderr: Option<Vec<u8>> = self.stop_with_signal(deadline, "INT", false);
    }

    /// The same owned-child lifecycle, exercising Unix SIGTERM explicitly.
    /// The direct Native fixture pipes stderr to assert its one fixed summary.
    pub fn stop_orderly_terminate(self, deadline: Duration) -> Vec<u8> {
        self.stop_with_signal(deadline, "TERM", true)
            .expect("TERM fixture must pipe owned child stderr")
    }

    pub fn stop_orderly_interrupt_observed(self, deadline: Duration) -> Vec<u8> {
        self.stop_with_signal(deadline, "INT", true)
            .expect("observed INT fixture must pipe owned child stderr")
    }

    fn stop_with_signal(
        mut self,
        deadline: Duration,
        signal_name: &'static str,
        capture: bool,
    ) -> Option<Vec<u8>> {
        let end: Instant = Instant::now()
            .checked_add(deadline)
            .expect("child stop deadline");
        if let Some(status) = self.try_wait().expect("poll owned child before signal") {
            let mut reaped: Child = self.0.take().expect("owned reaped child");
            let confirmed: ExitStatus = reaped.wait().expect("confirm already reaped child");
            assert_eq!(confirmed, status, "cached observed early exit status");
            panic!("owned child exited before orderly stop: {status}");
        }
        let pid: u32 = self.child_mut().id();
        let stderr = if capture {
            self.child_mut().stderr.take()
        } else {
            None
        }
        .map(|stderr| {
            let (sender, receiver) = mpsc::channel::<Vec<u8>>();
            std::thread::spawn(move || {
                let mut bytes: Vec<u8> = Vec::new();
                stderr
                    .take(2 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .expect("read child termination summary");
                let _sent = sender.send(bytes);
            });
            receiver
        });
        assert!(
            pid > 0 && pid <= i32::MAX as u32,
            "positive owned child PID"
        );
        let mut signal: Command = Command::new("kill");
        signal.args(["-s", signal_name, "--"]).arg(pid.to_string());
        let remaining: Duration = end.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "signal helper deadline elapsed");
        let output: Output = spawn_bounded_output(signal, remaining);
        assert!(
            output.status.success(),
            "owned-child {signal_name} helper failed: {:?}",
            output.stderr
        );
        let status: ExitStatus = loop {
            if let Some(status) = self.try_wait().expect("poll signaled child exit") {
                break status;
            }
            assert!(
                Instant::now() < end,
                "owned child did not stop orderly within {deadline:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut reaped: Child = self.0.take().expect("owned child successfully reaped");
        let confirmed: ExitStatus = reaped.wait().expect("confirm successful child reap");
        assert_eq!(confirmed, status, "cached observed orderly exit status");
        assert_eq!(
            status.code(),
            Some(0),
            "{signal_name} must produce an ordinary successful child exit"
        );
        assert!(status.success());
        stderr.map(|receiver| {
            receiver
                .recv_timeout(end.saturating_duration_since(Instant::now()))
                .expect("owned child termination stderr deadline")
        })
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ignored = child.kill();
            let _ignored = child.wait();
        }
    }
}

/// Spawns `command`, owning the child before its piped stdout is even
/// taken, and waits up to `deadline` for its first status line. Returns
/// the guard (still owning the live process) and the line; a timeout,
/// early exit, or malformed line panics while the guard still owns the
/// child, so unwind kills and reaps it rather than leaking it.
pub fn spawn_bounded_status_line(mut command: Command, deadline: Duration) -> (ChildGuard, String) {
    let child: Child = command
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn compiled host process");
    let mut guard: ChildGuard = ChildGuard::new(child);
    let stdout = guard.child_mut().stdout.take().expect("piped stdout");
    let (sender, receiver) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut line: String = String::new();
        let _ignored = BufReader::new(stdout).read_line(&mut line);
        let _ignored = sender.send(line);
    });
    let line: String = receiver.recv_timeout(deadline).unwrap_or_else(|_| {
        panic!(
            "compiled host process did not print a status line within {deadline:?}: {:?}",
            guard.try_wait()
        )
    });
    (guard, line)
}

/// Spawns `command` with piped stdout/stderr, owning the child before
/// either is taken, and waits up to `deadline` for it to exit, returning
/// its full captured `Output`. Unlike `Command::output`, a timeout still
/// kills and reaps the real process instead of hanging indefinitely.
pub fn spawn_bounded_output(mut command: Command, deadline: Duration) -> Output {
    let child: Child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn compiled host process");
    let mut guard: ChildGuard = ChildGuard::new(child);
    let stdout = guard.child_mut().stdout.take().expect("piped stdout");
    let stderr = guard.child_mut().stderr.take().expect("piped stderr");
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>();
    let (err_tx, err_rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buffer: Vec<u8> = Vec::new();
        let _ignored = BufReader::new(stdout).read_to_end(&mut buffer);
        let _ignored = out_tx.send(buffer);
    });
    std::thread::spawn(move || {
        let mut buffer: Vec<u8> = Vec::new();
        let _ignored = BufReader::new(stderr).read_to_end(&mut buffer);
        let _ignored = err_tx.send(buffer);
    });
    let start: Instant = Instant::now();
    let status: ExitStatus = loop {
        if let Some(status) = guard
            .try_wait()
            .expect("failed to poll compiled host process")
        {
            break status;
        }
        assert!(
            start.elapsed() <= deadline,
            "compiled host process did not exit within {deadline:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: out_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default(),
        stderr: err_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default(),
    }
}

/// Recovery's finite complete-capture control. A pipe read error, output-cap
/// breach or missing EOF is FAILURE, never an empty/default successful log.
/// The real compiled recovery/import children do not spawn subprocesses.
pub fn spawn_strict_bounded_output(mut command: Command, deadline: Duration) -> Output {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    const MAXIMUM: usize = 4 * 1024 * 1024;
    let child: Child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn compiled recovery child");
    let mut guard: ChildGuard = ChildGuard::new(child);
    let stdout = guard
        .child_mut()
        .stdout
        .take()
        .expect("piped recovery stdout");
    let stderr = guard
        .child_mut()
        .stderr
        .take()
        .expect("piped recovery stderr");
    let total: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let capture = |mut input: Box<dyn Read + Send>, total: Arc<AtomicUsize>| {
        let (send, receive) = mpsc::channel::<Result<Vec<u8>, &'static str>>();
        let thread = std::thread::spawn(move || {
            let result: Result<Vec<u8>, &'static str> = (|| {
                let mut bytes: Vec<u8> = Vec::new();
                let mut buffer: [u8; 64 * 1024] = [0; 64 * 1024];
                loop {
                    let count: usize = input
                        .read(&mut buffer)
                        .map_err(|_| "recovery child pipe read failed")?;
                    if count == 0 {
                        return Ok(bytes);
                    } // Actual pipe EOF.
                    total
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value: usize| {
                            value
                                .checked_add(count)
                                .filter(|sum: &usize| *sum <= MAXIMUM)
                        })
                        .map_err(|_| "recovery child complete capture exceeded cap")?;
                    bytes.extend_from_slice(&buffer[..count]);
                }
            })();
            send.send(result)
                .expect("strict capture owner still present");
        });
        (receive, thread)
    };
    let (out_receive, out_thread) = capture(Box::new(stdout), Arc::clone(&total));
    let (err_receive, err_thread) = capture(Box::new(stderr), Arc::clone(&total));
    let end: Instant = Instant::now()
        .checked_add(deadline)
        .expect("recovery child deadline");
    let mut out: Option<Vec<u8>> = None;
    let mut err: Option<Vec<u8>> = None;
    let status: ExitStatus = loop {
        for (receiver, slot) in [(&out_receive, &mut out), (&err_receive, &mut err)] {
            if slot.is_none() {
                match receiver.try_recv() {
                    Ok(Ok(bytes)) => *slot = Some(bytes),
                    Ok(Err(reason)) => panic!("{reason}"),
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => {
                        panic!("recovery capture disconnected before EOF")
                    }
                }
            }
        }
        if let Some(status) = guard.try_wait().expect("poll compiled recovery child") {
            break status;
        }
        assert!(
            Instant::now() < end,
            "compiled recovery child exceeded finite deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut reaped: Child = guard.into_inner();
    assert_eq!(
        reaped.wait().expect("confirm compiled recovery child reap"),
        status
    );
    let close_end: Instant = Instant::now()
        .checked_add(Duration::from_secs(5))
        .expect("pipe-close deadline");
    let finish = |receiver: mpsc::Receiver<Result<Vec<u8>, &'static str>>,
                  slot: Option<Vec<u8>>|
     -> Vec<u8> {
        match slot {
            Some(bytes) => bytes,
            None => receiver
                .recv_timeout(close_end.saturating_duration_since(Instant::now()))
                .expect("complete recovery pipe EOF within five seconds")
                .expect("strict recovery pipe capture"),
        }
    };
    let stdout: Vec<u8> = finish(out_receive, out);
    let stderr: Vec<u8> = finish(err_receive, err);
    out_thread.join().expect("stdout capture thread completed");
    err_thread.join().expect("stderr capture thread completed");
    Output {
        status,
        stdout,
        stderr,
    }
}

#[cfg(target_os = "linux")]
pub use pending_capture::PendingStrictOutput;

/// Separate asynchronous capture for the small foreground observation child.
/// Existing status-line and business-output helpers keep their original behavior.
#[cfg(target_os = "linux")]
mod pending_capture {
    use super::{Child, Command, Duration, ExitStatus, Instant, Output, Read, Stdio};
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    use std::{
        io::ErrorKind,
        os::fd::AsFd,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread::JoinHandle,
    };

    const PIPE_CAP: usize = 2_048;
    const READ_ATTEMPTS: usize = 1_000_000;
    const POLL_INTERVAL: Duration = Duration::from_millis(5);
    type PipeResult = Result<Vec<u8>, &'static str>;

    struct PendingPipe {
        thread: Option<JoinHandle<PipeResult>>,
        result: Option<PipeResult>,
    }

    impl PendingPipe {
        fn start<R>(mut input: R, end: Instant, stop: Arc<AtomicBool>) -> Self
        where
            R: Read + AsFd + Send + 'static,
        {
            let flags: OFlags = fcntl_getfl(&input).expect("read owned collector pipe flags");
            fcntl_setfl(&input, flags | OFlags::NONBLOCK)
                .expect("make owned collector pipe nonblocking");
            let thread: JoinHandle<PipeResult> = std::thread::spawn(move || {
                let mut bytes: Vec<u8> = Vec::new();
                let mut buffer: [u8; 256] = [0; 256];
                for _attempt in 0..READ_ATTEMPTS {
                    if stop.load(Ordering::SeqCst) {
                        return Err("collector pipe capture canceled before EOF");
                    }
                    if Instant::now() >= end {
                        return Err("collector pipe capture deadline elapsed before EOF");
                    }
                    let read: std::io::Result<usize> = input.read(&mut buffer);
                    if Instant::now() >= end {
                        return Err("collector pipe capture returned after its deadline");
                    }
                    match read {
                        Ok(0) => return Ok(bytes), // Only an actual read EOF is success.
                        Ok(count) => {
                            let length: usize = bytes
                                .len()
                                .checked_add(count)
                                .filter(|length: &usize| *length <= PIPE_CAP)
                                .ok_or("collector pipe capture exceeded 2048 bytes")?;
                            bytes.extend_from_slice(&buffer[..count]);
                            debug_assert_eq!(bytes.len(), length);
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(POLL_INTERVAL);
                        }
                        Err(_error) => return Err("collector pipe read failed"),
                    }
                }
                Err("collector pipe read-attempt limit exhausted")
            });
            Self {
                thread: Some(thread),
                result: None,
            }
        }

        fn poll(&mut self) {
            if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
                self.join();
            }
        }

        fn join(&mut self) {
            if let Some(thread) = self.thread.take() {
                self.result = Some(match thread.join() {
                    Ok(result) => result,
                    Err(_panic) => Err("collector pipe reader panicked"),
                });
            }
        }

        fn error(&self) -> Option<&'static str> {
            match self.result.as_ref() {
                Some(Err(reason)) => Some(*reason),
                Some(Ok(_bytes)) | None => None,
            }
        }

        fn take_complete(&mut self) -> PipeResult {
            self.result
                .take()
                .expect("joined collector pipe has a result")
        }
    }

    pub struct PendingStrictOutput {
        child: Option<Child>,
        stdout: Option<PendingPipe>,
        stderr: Option<PendingPipe>,
        stop: Arc<AtomicBool>,
        end: Instant,
        reaped: bool,
        cleanup_started: bool,
        cleanup_errors: Vec<&'static str>,
    }

    impl PendingStrictOutput {
        pub fn spawn(mut command: Command, end: Instant) -> Self {
            assert!(Instant::now() < end, "collector spawn deadline elapsed");
            let child: Child = command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn bounded foreground collector child");
            // Own the child before taking/configuring either pipe or spawning a reader.
            let mut pending: Self = Self {
                child: Some(child),
                stdout: None,
                stderr: None,
                stop: Arc::new(AtomicBool::new(false)),
                end,
                reaped: false,
                cleanup_started: false,
                cleanup_errors: Vec::new(),
            };
            let stdout: std::process::ChildStdout = pending
                .child
                .as_mut()
                .unwrap()
                .stdout
                .take()
                .expect("collector stdout");
            pending.stdout = Some(PendingPipe::start(stdout, end, Arc::clone(&pending.stop)));
            let stderr: std::process::ChildStderr = pending
                .child
                .as_mut()
                .unwrap()
                .stderr
                .take()
                .expect("collector stderr");
            pending.stderr = Some(PendingPipe::start(stderr, end, Arc::clone(&pending.stop)));
            pending
        }

        fn poll_pipes(&mut self) {
            for pipe in [&mut self.stdout, &mut self.stderr].into_iter().flatten() {
                pipe.poll();
            }
        }

        fn check_capture(&mut self) {
            self.poll_pipes();
            for pipe in [&self.stdout, &self.stderr].into_iter().flatten() {
                if let Some(reason) = pipe.error() {
                    panic!("{reason}");
                }
            }
        }

        pub fn assert_running(&mut self) {
            assert!(Instant::now() < self.end, "collector deadline elapsed");
            self.check_capture();
            assert!(
                self.child
                    .as_mut()
                    .expect("still-owned collector")
                    .try_wait()
                    .expect("poll still-owned collector")
                    .is_none(),
                "collector exited before its requested sample"
            );
            assert!(Instant::now() < self.end, "late collector liveness observation");
        }

        fn close_pipes(&mut self, end: Instant) -> Result<(), &'static str> {
            let mut expired: bool = false;
            loop {
                self.poll_pipes();
                if Instant::now() >= end {
                    expired = true;
                    self.stop.store(true, Ordering::SeqCst);
                    break;
                }
                let closed: bool = [&self.stdout, &self.stderr]
                    .into_iter()
                    .flatten()
                    .all(|pipe: &PendingPipe| pipe.thread.is_none());
                if closed {
                    break;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            // Cancellation ends the nonblocking reader loops. Retain and join
            // BOTH handles on failure too; no successful or failed detached reader.
            // As with the existing strict capture, this is not a guarantee against
            // globally blocked kernel syscalls or an unscheduled thread.
            for pipe in [&mut self.stdout, &mut self.stderr].into_iter().flatten() {
                pipe.join();
            }
            if expired || Instant::now() >= end {
                Err("collector pipes did not close within their deadline")
            } else {
                Ok(())
            }
        }

        pub fn finish(&mut self) -> Output {
            let status: ExitStatus = loop {
                assert!(Instant::now() < self.end, "collector completion deadline elapsed");
                self.check_capture();
                if let Some(status) = self.child
                    .as_mut()
                    .expect("owned collector")
                    .try_wait()
                    .expect("poll foreground collector exit")
                {
                    break status;
                }
                assert!(
                    Instant::now() < self.end,
                    "collector did not exit within its deadline"
                );
                std::thread::sleep(POLL_INTERVAL);
            };
            let confirmed: ExitStatus = self.child
                .as_mut()
                .unwrap()
                .wait()
                .expect("confirm actual foreground collector reap");
            assert_eq!(confirmed, status, "cached collector exit status");
            self.reaped = true;
            self.child = None;
            assert!(Instant::now() < self.end, "collector reap exceeded original deadline");
            let close_end: Instant = self.end.min(
                Instant::now()
                    .checked_add(Duration::from_secs(5))
                    .expect("collector pipe-close deadline"),
            );
            self.close_pipes(close_end)
                .expect("both complete collector pipe closures");
            let stdout: PipeResult = self.stdout.as_mut().unwrap().take_complete();
            let stderr: PipeResult = self.stderr.as_mut().unwrap().take_complete();
            assert!(Instant::now() < self.end, "collector capture exceeded original deadline");
            match (stdout, stderr) {
                (Ok(stdout), Ok(stderr)) => Output {
                    status,
                    stdout,
                    stderr,
                },
                (out, err) => panic!(
                    "collector capture failed: stdout={:?} stderr={:?}",
                    out.err(),
                    err.err()
                ),
            }
        }

        /// Failure-only kill/reap plus joined reader release. False means
        /// unresolved release: the caller must retain its filesystem residue.
        pub fn cleanup(&mut self) -> bool {
            if !self.cleanup_started {
                self.cleanup_started = true;
                if let Some(child) = self.child.as_mut() {
                    let needs_kill: bool = match child.try_wait() {
                        Ok(Some(_status)) => false,
                        Ok(None) => true,
                        Err(_error) => {
                            self.cleanup_errors.push("collector failure cleanup poll failed");
                            true
                        }
                    };
                    if needs_kill && child.kill().is_err() {
                        self.cleanup_errors.push("collector failure cleanup kill failed");
                    }
                    match child.wait() {
                        Ok(_status) => {
                            self.reaped = true;
                            self.child = None;
                        }
                        Err(_error) => {
                            self.cleanup_errors.push("collector failure cleanup reap failed");
                        }
                    }
                }
                self.stop.store(true, Ordering::SeqCst);
                let close_end: Instant = Instant::now()
                    .checked_add(Duration::from_secs(5))
                    .expect("collector failure pipe-close deadline");
                if let Err(reason) = self.close_pipes(close_end) {
                    self.cleanup_errors.push(reason);
                }
                for pipe in [&self.stdout, &self.stderr].into_iter().flatten() {
                    if let Some(reason) = pipe.error() {
                        self.cleanup_errors.push(reason);
                    }
                }
            }
            self.reaped
                && self.child.is_none()
                && [&self.stdout, &self.stderr]
                    .into_iter()
                    .flatten()
                    .all(|pipe: &PendingPipe| pipe.thread.is_none())
        }
    }

    impl Drop for PendingStrictOutput {
        fn drop(&mut self) {
            let released: bool = self.cleanup();
            for reason in &self.cleanup_errors {
                eprintln!("{reason}");
            }
            if !released {
                eprintln!("foreground collector release remains unconfirmed");
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod local_observation_collector {
    use super::PendingStrictOutput;
    use rustix::{
        fd::OwnedFd,
        fs::{
            AtFlags, CWD, FileType, Mode, OFlags, Stat, fstat, mkdirat, open, openat, statat,
            unlinkat,
        },
        io::Errno,
    };
    use std::{
        io::ErrorKind,
        os::unix::net::UnixDatagram,
        path::{Path, PathBuf},
        process::{Command, Output},
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    pub(crate) const TIMEOUT_MILLIS: u64 = 300_000;
    const LEAF: &str = "live.sock";
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct DirectoryIdentity {
        dev: u64,
        ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
    }

    impl DirectoryIdentity {
        fn from_stat(stat: &Stat) -> Self {
            Self {
                dev: stat.st_dev,
                ino: stat.st_ino,
                mode: stat.st_mode,
                uid: stat.st_uid,
                gid: stat.st_gid,
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SocketStamp {
        identity: DirectoryIdentity,
        nlink: i128,
        size: i128,
        mtime: (i128, i128),
        ctime: (i128, i128),
    }

    impl SocketStamp {
        fn from_stat(stat: &Stat) -> Self {
            Self {
                identity: DirectoryIdentity::from_stat(stat),
                nlink: i128::from(stat.st_nlink),
                size: i128::from(stat.st_size),
                mtime: (i128::from(stat.st_mtime), i128::from(stat.st_mtime_nsec)),
                ctime: (i128::from(stat.st_ctime), i128::from(stat.st_ctime_nsec)),
            }
        }
    }

    pub(crate) struct Collector {
        parent: OwnedFd,
        parent_identity: DirectoryIdentity,
        directory: OwnedFd,
        directory_identity: DirectoryIdentity,
        name: String,
        path: PathBuf,
        socket: PathBuf,
        socket_stamp: Option<SocketStamp>,
        capture: Option<PendingStrictOutput>,
        end: Instant,
        removed: bool,
    }

    impl Collector {
        pub(crate) fn start(end: Instant, owner_directory: &Path) -> Self {
            assert!(Instant::now() < end, "collector setup deadline elapsed");
            let flags: OFlags =
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let parent: OwnedFd =
                open("/tmp", flags, Mode::empty()).expect("hold caller socket parent");
            let parent_stat: Stat = fstat(&parent).expect("held caller socket parent identity");
            let parent_identity: DirectoryIdentity = DirectoryIdentity::from_stat(&parent_stat);
            assert!(FileType::from_raw_mode(parent_stat.st_mode).is_dir());
            let owner: Stat = statat(CWD, owner_directory, AtFlags::SYMLINK_NOFOLLOW)
                .expect("owning fixture directory identity");
            assert!(FileType::from_raw_mode(owner.st_mode).is_dir());
            let index: u64 = NEXT_DIRECTORY
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value: u64| {
                    value.checked_add(1)
                })
                .expect("caller socket directory sequence");
            let name: String = format!("sne-live-{}-{index}", std::process::id());
            let path: PathBuf = Path::new("/tmp").join(&name);
            let socket: PathBuf = path.join(LEAF);
            assert!(socket.is_absolute());
            assert!(socket.to_str().expect("ASCII socket path").len() <= 100);
            // Atomic exclusive creation; an existing directory is never adopted.
            mkdirat(&parent, name.as_str(), Mode::from_raw_mode(0o700))
                .expect("fresh private caller socket directory");
            let directory: OwnedFd = openat(&parent, name.as_str(), flags, Mode::empty())
                .expect("hold fresh caller socket directory");
            let directory_stat: Stat =
                fstat(&directory).expect("fresh held caller directory identity");
            assert!(FileType::from_raw_mode(directory_stat.st_mode).is_dir());
            assert_eq!(directory_stat.st_mode & 0o7777, 0o700);
            assert_eq!(directory_stat.st_uid, owner.st_uid);
            assert_eq!(directory_stat.st_gid, owner.st_gid);
            let mut collector: Self = Self {
                parent,
                parent_identity,
                directory,
                directory_identity: DirectoryIdentity::from_stat(&directory_stat),
                name,
                path,
                socket,
                socket_stamp: None,
                capture: None,
                end,
                removed: false,
            };
            collector
                .check_directories()
                .expect("initial caller directory attachment");
            assert!(
                matches!(
                    statat(&collector.directory, LEAF, AtFlags::SYMLINK_NOFOLLOW),
                    Err(Errno::NOENT)
                ),
                "new collector leaf must be absent"
            );
            assert!(
                Instant::now() < end,
                "collector setup exceeded original deadline"
            );
            let mut command: Command = Command::new(env!("CARGO_BIN_EXE_native_observations"));
            command
                .arg("--socket")
                .arg(&collector.socket)
                .args(["--max-samples", "1", "--timeout-ms"])
                .arg(TIMEOUT_MILLIS.to_string());
            collector.capture = Some(PendingStrictOutput::spawn(command, end));
            collector.wait_ready();
            collector
        }

        pub(crate) fn socket_path(&self) -> &Path {
            &self.socket
        }

        pub(crate) fn deadline(&self) -> Instant {
            self.end
        }

        fn check_directories(&self) -> Result<(), &'static str> {
            for stat in [
                fstat(&self.parent).map_err(|_error| "held socket parent unavailable")?,
                statat(CWD, "/tmp", AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_error| "named socket parent unavailable")?,
            ] {
                if DirectoryIdentity::from_stat(&stat) != self.parent_identity {
                    return Err("caller socket parent attachment changed");
                }
            }
            for stat in [
                fstat(&self.directory).map_err(|_error| "held caller directory unavailable")?,
                statat(&self.parent, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_error| "relative caller directory unavailable")?,
                statat(CWD, &self.path, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_error| "named caller directory unavailable")?,
            ] {
                // Directory mtime/size/nlink may change when its one socket is created.
                if DirectoryIdentity::from_stat(&stat) != self.directory_identity {
                    return Err("private caller directory attachment changed");
                }
            }
            Ok(())
        }

        fn observe_socket(&self) -> Result<SocketStamp, &'static str> {
            self.check_directories()?;
            let held: Stat = statat(&self.directory, LEAF, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_error| "held-directory socket leaf unavailable")?;
            let named: Stat = statat(CWD, &self.socket, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_error| "named socket leaf unavailable")?;
            let stamp: SocketStamp = SocketStamp::from_stat(&held);
            if !FileType::from_raw_mode(held.st_mode).is_socket()
                || held.st_uid != self.directory_identity.uid
                || held.st_gid != self.directory_identity.gid
                || stamp.nlink != 1
                || stamp != SocketStamp::from_stat(&named)
            {
                return Err("collector socket type or attachment refused");
            }
            Ok(stamp)
        }

        fn wait_ready(&mut self) {
            for _attempt in 0..4_096 {
                self.capture.as_mut().unwrap().assert_running();
                self.check_directories()
                    .expect("caller attachment before readiness probe");
                let probe: UnixDatagram =
                    UnixDatagram::unbound().expect("unbound collector readiness probe");
                probe
                    .set_nonblocking(true)
                    .expect("nonblocking collector readiness probe");
                match probe.connect(&self.socket) {
                    Ok(()) => {
                        self.capture.as_mut().unwrap().assert_running();
                        let stamp: SocketStamp = self
                            .observe_socket()
                            .expect("ready collector socket identity");
                        assert!(Instant::now() < self.end, "late collector readiness");
                        self.socket_stamp = Some(stamp);
                        return; // No datagram is ever sent by the readiness probe.
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::NotFound | ErrorKind::ConnectionRefused
                        ) => {}
                    Err(_error) => panic!("collector readiness connect refused"),
                }
                assert!(
                    Instant::now() < self.end,
                    "collector readiness deadline elapsed"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("collector readiness attempts exhausted");
        }

        pub(crate) fn finish(&mut self) {
            let output: Output = self.capture.as_mut().unwrap().finish();
            assert_eq!(
                output.status.code(), Some(0),
                "collector must exit ordinarily"
            );
            assert!(output.status.success());
            assert!(
                output.stderr.is_empty(),
                "collector success stderr must be empty"
            );
            assert!(!output.stdout.is_empty() && output.stdout.len() < 2_048);
            let snapshot: native_http::NativeHttpSnapshot =
                native_http::decode_live_summary(&output.stdout)
                    .expect("entire collector stdout is exactly one canonical live record");
            assert!(snapshot.connections_admitted > 0);
            assert!(snapshot.requests_dispatched > 0);
            assert_eq!(
                self.observe_socket().expect("retained socket after collector exit"),
                self.socket_stamp.expect("readiness-bound socket identity"),
                "collector exit must not remove or replace its caller-owned socket"
            );
            assert!(
                Instant::now() < self.end,
                "collector completion exceeded original deadline"
            );
        }

        fn remove_owned(&mut self) -> Result<(), &'static str> {
            self.check_directories()?;
            match self.socket_stamp {
                Some(expected) => {
                    if self.observe_socket()? != expected {
                        return Err("caller refuses to unlink a changed collector socket");
                    }
                    unlinkat(&self.directory, LEAF, AtFlags::empty())
                        .map_err(|_error| "caller socket cleanup failed")?;
                    self.socket_stamp = None;
                }
                None => {
                    if !matches!(
                        statat(&self.directory, LEAF, AtFlags::SYMLINK_NOFOLLOW),
                        Err(Errno::NOENT)
                    ) {
                        return Err("unqualified collector leaf retained without adoption");
                    }
                }
            }
            self.check_directories()?;
            unlinkat(&self.parent, self.name.as_str(), AtFlags::REMOVEDIR)
                .map_err(|_error| "caller directory cleanup failed; possible extra leaf retained")?;
            self.removed = true;
            Ok(())
        }
    }

    impl Drop for Collector {
        fn drop(&mut self) {
            let released: bool = self.capture.as_mut().is_none_or(PendingStrictOutput::cleanup);
            match (released, self.removed) {
                (true, false) => match self.remove_owned() {
                    Ok(()) => {}
                    Err(reason) if std::thread::panicking() => eprintln!("{reason}"),
                    Err(reason) => panic!("{reason}"),
                },
                (false, _) => {
                    eprintln!("caller socket residue retained: collector release unconfirmed");
                }
                (true, true) => {}
            }
        }
    }
}
