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
