//! Compiled first-successor host and CLI process boundaries.
//!
//! These drive the real successor_host executable and the shipped Rust CLI
//! entry. They prove refusal ordering at the process boundary: loopback
//! and fence confirmation decide before any file, store or socket I/O;
//! missing artifact transport refuses before a target store is opened; and
//! successor CLI controls refuse explicitly with no ordinary-genesis
//! fallback. The full four-host ABCE e+1 acceptance reuses the genuine
//! Seal world of conditional_readiness_sqlite and is tracked separately.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-successor-host-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

fn host(root: &Path, listen: &str, confirm: bool) -> Output {
    let missing: PathBuf = root.join("missing");
    let mut command: Command = Command::new(env!("CARGO_BIN_EXE_successor_host"));
    command.arg("serve");
    let domain: String = "11".repeat(32);
    let digest: String = "22".repeat(32);
    let validator: String = "33".repeat(32);
    let state: PathBuf = root.join("state.db");
    let blobs: PathBuf = root.join("body.db");
    let pairs: [(&str, &str); 17] = [
        ("--chain-id", "successor-host-process"),
        ("--protocol-version", "1"),
        ("--epoch", "0"),
        ("--domain", &domain),
        ("--suite", "0:1:1:1:1:1:1:1"),
        ("--genesis-manifest", missing.to_str().unwrap()),
        ("--expected-genesis-digest", &digest),
        ("--ordered-history-dir", missing.to_str().unwrap()),
        ("--cut-dir", missing.to_str().unwrap()),
        ("--manifest-history-dir", missing.to_str().unwrap()),
        ("--certificate-dir", missing.to_str().unwrap()),
        ("--target-state-db", state.to_str().unwrap()),
        ("--target-blob-db", blobs.to_str().unwrap()),
        ("--validator-id", &validator),
        ("--signer-key-file", missing.to_str().unwrap()),
        ("--listen", listen),
        ("--created-checkpoint", "1"),
    ];
    for (flag, value) in pairs {
        command.arg(flag).arg(value);
    }
    if confirm {
        command.arg("--confirm-offline-fence-advance");
    }
    command.output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn no_target_written(root: &Path) {
    assert!(!root.join("state.db").exists());
    assert!(!root.join("body.db").exists());
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
}

#[test]
fn compiled_host_refuses_every_nonloopback_listen_before_any_io() {
    for listen in ["0.0.0.0:0", "127.0.0.2:0", "[::]:0", "[::ffff:127.0.0.1]:0", "localhost:0"] {
        let root: TempDir = TempDir::new("nonloopback");
        let output: Output = host(&root.0, listen, true);
        assert!(!output.status.success(), "{listen}");
        let message: String = stderr(&output);
        assert!(
            message.contains("successor host listens only on 127.0.0.1 or ::1")
                || message.contains("numeric ip:port"),
            "{listen}: {message}"
        );
        assert!(output.stdout.is_empty(), "nothing is served or printed");
        no_target_written(&root.0);
    }
}

#[test]
fn compiled_host_requires_fence_confirmation_before_any_io() {
    let root: TempDir = TempDir::new("confirm");
    let output: Output = host(&root.0, "127.0.0.1:0", false);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--confirm-offline-fence-advance"));
    no_target_written(&root.0);
}

#[test]
fn compiled_host_refuses_missing_artifact_transport_before_opening_a_target() {
    for listen in ["127.0.0.1:0", "[::1]:0"] {
        let root: TempDir = TempDir::new("artifacts");
        let output: Output = host(&root.0, listen, true);
        assert!(!output.status.success(), "{listen}");
        assert!(output.stdout.is_empty(), "no listener line is ever printed");
        no_target_written(&root.0);
    }
}

#[test]
fn compiled_host_help_and_unknown_modes_never_serve() {
    let help: Output = Command::new(env!("CARGO_BIN_EXE_successor_host"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("First-successor loopback host only"));
    for mode in ["activate", "import", "seal"] {
        let output: Output = Command::new(env!("CARGO_BIN_EXE_successor_host"))
            .arg(mode)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{mode}");
    }
}

#[test]
fn shipped_cli_successor_actions_refuse_without_ordinary_fallback() {
    let root: TempDir = TempDir::new("cli");
    let out: PathBuf = root.0.join("candidate.bin");
    let run = |values: &[&str]| -> String {
        let arguments: Vec<OsString> = values.iter().map(OsString::from).collect();
        sunrise_edge_cli::run(arguments).unwrap_err().to_string()
    };
    let freeze: String = run(&[
        "economics",
        "ordered-freeze-build",
        "--successor-genesis-epoch",
        "0",
    ]);
    assert!(freeze.contains("successor-control-unsupported"), "{freeze}");
    let claim: String = run(&["economics", "fee-claim-prepare", "--out", out.to_str().unwrap()]);
    assert!(claim.contains("--successor-*"), "{claim}");
    // A partial successor flag set never falls back to the ordinary genesis
    // policy and never writes the output candidate.
    let partial: String = run(&[
        "economics",
        "fee-claim-prepare",
        "--successor-cut-dir",
        root.0.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(!partial.is_empty());
    assert!(!out.exists());
}
