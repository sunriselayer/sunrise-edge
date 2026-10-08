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
        self.stop_with_signal(deadline, "TERM", true).expect("TERM fixture must pipe owned child stderr")
    }

    pub fn stop_orderly_interrupt_observed(self, deadline: Duration) -> Vec<u8> {
        self.stop_with_signal(deadline, "INT", true).expect("observed INT fixture must pipe owned child stderr")
    }

    fn stop_with_signal(mut self, deadline: Duration, signal_name: &'static str, capture: bool) -> Option<Vec<u8>> {
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
        let stderr = if capture { self.child_mut().stderr.take() } else { None }.map(|stderr| {
            let (sender, receiver) = mpsc::channel::<Vec<u8>>();
            std::thread::spawn(move || {
                let mut bytes: Vec<u8> = Vec::new();
                stderr.take(2 * 1024 + 1).read_to_end(&mut bytes).expect("read child termination summary");
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
        stderr.map(|receiver| receiver.recv_timeout(end.saturating_duration_since(Instant::now()))
            .expect("owned child termination stderr deadline"))
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
