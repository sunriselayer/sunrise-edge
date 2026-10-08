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
