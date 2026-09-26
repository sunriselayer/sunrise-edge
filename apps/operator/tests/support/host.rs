//! Real PostgreSQL HTTP host subprocess fixture shared by network E2Es.
#![allow(dead_code)]
use super::cli::{CHECKPOINT, DSN_ENV};
use super::genesis_fixture::{FastVoteGenesisFixture, SUITE_FLAG};
use std::{
    fs,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub struct TempDir(pub PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A `fastvote_host_pg` subprocess this test owns: killed on drop so a
/// failing assertion never leaks a background PostgreSQL-connected process.
pub struct HostProcess {
    pub child: Child,
    pub addr: SocketAddr,
}
impl Drop for HostProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn write_new(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
}

/// Writes a fresh file with `0600` permissions, exactly the shape
/// `fastvote_pg`'s signing-key-file loader requires (it rejects any
/// group/other bit set).
pub fn write_new_secure_mode(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;

    let mut options: fs::OpenOptions = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file: fs::File = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
}

pub fn temp_file(dir: &std::path::Path, name: &str) -> PathBuf {
    dir.join(name)
}

/// Spawns one real `fastvote_host_pg` subprocess against `dsn`, waits for its
/// `complete=true ... listen=<addr>` status line, and returns the process
/// (kept alive) plus the real bound loopback address.
#[allow(clippy::too_many_arguments)]
pub fn spawn_host(
    ca_path: &std::path::Path,
    dsn: &str,
    chain_id: &str,
    validator_hex: &str,
    domain_hex: &str,
    manifest_path: &std::path::Path,
    digest_hex: &str,
    signing_key_path: &std::path::Path,
    listen_addr: &str,
) -> HostProcess {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fastvote_host_pg"));
    command
        .env(DSN_ENV, dsn)
        .args([
            "--tls-root-der",
            ca_path.to_str().unwrap(),
            "--chain-id",
            chain_id,
            "--validator-id",
            validator_hex,
            "--domain",
            domain_hex,
            "--protocol-version",
            "3",
            "--epoch",
            "0",
            "--suite",
            SUITE_FLAG,
            "--genesis-manifest",
            manifest_path.to_str().unwrap(),
            "--expected-genesis-digest",
            digest_hex,
            "--signing-key-file",
            signing_key_path.to_str().unwrap(),
            "--listen",
            listen_addr,
            "--created-checkpoint",
            CHECKPOINT,
            "--timeout-seconds",
            "20",
            "--max-connections",
            "4",
            "--max-concurrent",
            "4",
            "--confirm-offline-fence-advance",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap_or_else(|error| {
        panic!("failed to spawn fastvote_host_pg: {error}");
    });
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        line.clear();
        let read = reader.read_line(&mut line).unwrap_or(0);
        if read == 0 {
            let stderr = {
                let mut buffer = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    use std::io::Read;
                    let _ = stderr.read_to_string(&mut buffer);
                }
                buffer
            };
            let status = child.try_wait().ok().flatten();
            panic!(
                "fastvote_host_pg exited before printing its status line (status={status:?}): {stderr}"
            );
        }
        if line.starts_with("complete=true") {
            break;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for fastvote_host_pg to report its listen address");
        }
    }
    let addr: SocketAddr = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("listen="))
        .unwrap_or_else(|| panic!("fastvote_host_pg status line lacked listen=: {line}"))
        .parse()
        .unwrap_or_else(|error| panic!("invalid listen address in {line:?}: {error}"));
    // Detach the piped stdout reader thread implicitly: further output is
    // simply never read, which is fine for a bounded test process.
    std::mem::forget(reader);
    HostProcess { child, addr }
}

pub fn write_network_config(
    path: &std::path::Path,
    fixture: &FastVoteGenesisFixture,
    hosts: &[HostProcess],
) {
    let mut text = String::new();
    for (validator, host) in fixture.validators.iter().zip(hosts) {
        text.push_str(&format!("{} {} - -\n", validator.validator_id, host.addr));
    }
    fs::write(path, text).unwrap();
}
