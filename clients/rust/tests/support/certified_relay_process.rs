//! Shared test-private owner for a pinned-Node relay fixture process.
//!
//! Both SDK integration tests spawn a Node fixture, feed it a disposable TLS
//! identity on stdin, and drain its bounded stdout for an exact outcome
//! sequence before an owned shutdown. This module is the one place that
//! bounded process/stdio lifecycle lives; it is not a general process
//! framework, so its entry point accepts only a closed fixture script path
//! plus an optional numeric native loopback port, never a generic callback.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

/// A per-line cap on the fixture's stdout. Every outcome/`READY`/`DONE`
/// record this crate's fixtures emit is far shorter than this; a longer line
/// is treated as a protocol violation, not patiently buffered.
const MAX_STDOUT_LINE_BYTES: usize = 4096;

/// A fixed whole-stream cap, bounding even an accidentally noisy child.
const MAX_STDOUT_TOTAL_BYTES: u64 = 8192;

/// Environment variables removed before spawning, so an operator's own
/// debugger or proxy configuration can never change a fixture's behavior.
const SCRUBBED_ENV_VARS: [&str; 9] = [
    "NODE_OPTIONS",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

/// One owned pinned-Node fixture child process plus its bounded stdout feed.
pub struct OwnedServer {
    child: Child,
    output: Receiver<String>,
}

impl Drop for OwnedServer {
    fn drop(&mut self) {
        // Runs on ordinary completion and on a test panic's unwind alike:
        // the fixture never outlives its owning test.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl OwnedServer {
    fn line(&self) -> String {
        self.output
            .recv_timeout(Duration::from_secs(15))
            .expect("bounded local fixture output")
    }

    /// Stops the fixture, asserting its exact recorded outcome lines (in the
    /// caller's given order) followed by `DONE`, then waits for the owned
    /// child to exit successfully within a bounded window. The expected
    /// lines are the caller's own closed contract with its fixture; this
    /// function never infers or relaxes them.
    pub fn stop(&mut self, expected_outcomes: &[&str]) {
        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"STOP\n")
            .unwrap();
        for expected in expected_outcomes {
            assert_eq!(self.line(), *expected);
        }
        assert_eq!(self.line(), "DONE");
        let end: Instant = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "actual pinned Node fixture must succeed");
                break;
            }
            assert!(Instant::now() < end, "owned Node process must terminate");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Spawns `script` under the pinned Node runtime, delivers the disposable
/// TLS `cert_pem`/`key_pem` (and, when given, the numeric native loopback
/// port) on stdin as JSON, and returns the owned child plus its ready
/// loopback address. The PEM travels only on stdin, never a log or argv.
pub fn start(
    script: &Path,
    cert_pem: &str,
    key_pem: &str,
    native_port: Option<u16>,
) -> (OwnedServer, SocketAddr) {
    let mut command: Command = Command::new("node");
    command
        .arg("--experimental-strip-types")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for var in SCRUBBED_ENV_VARS {
        command.env_remove(var);
    }
    let child: Child = command
        .spawn()
        .expect("Node 22.20.0 is a mandatory owning-test prerequisite, never skipped");
    let (sender, output): (mpsc::SyncSender<String>, Receiver<String>) = mpsc::sync_channel(8);
    let mut server: OwnedServer = OwnedServer { child, output };
    let stdout: std::process::ChildStdout = server.child.stdout.take().unwrap();
    thread::spawn(move || {
        let mut reader: BufReader<std::io::Take<std::process::ChildStdout>> =
            BufReader::new(stdout.take(MAX_STDOUT_TOTAL_BYTES));
        loop {
            let mut line: String = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) if line.len() > MAX_STDOUT_LINE_BYTES => break,
                Ok(_) => {
                    if sender.send(line.trim_end().to_owned()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let pem_escape = |value: &str| -> String { value.replace('\\', "\\\\").replace('\n', "\\n") };
    let configuration: String = match native_port {
        Some(port) => format!(
            "{{\"cert\":\"{}\",\"key\":\"{}\",\"nativePort\":{port}}}\n",
            pem_escape(cert_pem),
            pem_escape(key_pem),
        ),
        None => format!(
            "{{\"cert\":\"{}\",\"key\":\"{}\"}}\n",
            pem_escape(cert_pem),
            pem_escape(key_pem),
        ),
    };
    server
        .child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(configuration.as_bytes())
        .unwrap();
    let ready: String = server.line();
    let port: u16 = ready
        .strip_prefix("READY ")
        .expect("closed fixture startup record")
        .parse()
        .unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    (server, addr)
}
