//! Exercise the actual offline CLI binary: successful admission never publishes.

use std::fs::{self, File};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use sunrise_edge_client::MAX_CONTRACT_WASM_BYTES;

// Stable core-WASM binary: defined bounded memory and an empty () -> () run.
// No counter/application sample and no runtime dependency on a WAT compiler.
const VALID_WASM: &[u8] = b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x05\x04\x01\x01\x01\x02\x07\x10\x02\x06memory\x02\0\x03run\0\0\x0a\x04\x01\x02\0\x0b";
static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

#[test]
fn publication_rejects_ledger_before_endpoint_or_device_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
        .args([
            "contract",
            "publish",
            "--ledger-hid-path",
            "unreachable-device",
            "--ledger-account",
            "0",
            "--ledger-expected-firmware-version",
            "1.0.0",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Ledger publication signing is not supported")
    );
    assert!(output.stdout.is_empty());
}

struct Fixture(PathBuf);

impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let sequence: u64 = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "sunrise-contract-validate-{}-{sequence}.wasm",
            std::process::id()
        ));
        let mut file: File = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, bytes).unwrap();
        Self(path)
    }

    fn run(&self, names: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
            .args(["contract", "validate", "--wasm"])
            .arg(&self.0)
            .args(["--entrypoints", names])
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ignored = fs::remove_file(&self.0);
    }
}

#[test]
fn binary_validates_without_endpoint_or_signer_and_reports_no_publication() {
    let fixture: Fixture = Fixture::new(VALID_WASM);
    let output: Output = fixture.run("run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "validation=structural_wasm\nprofile_version=1\nwasm_bytes={}\nentrypoint_count=1\npublished=false\n",
            VALID_WASM.len()
        )
    );
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read(&fixture.0).unwrap(), VALID_WASM);
}

#[test]
fn binary_rejects_malformed_text_and_wrong_entrypoints_without_success_output() {
    for bytes in [b"invalid".as_slice(), b"(module)".as_slice()] {
        let output: Output = Fixture::new(bytes).run("run");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .starts_with("error=")
        );
    }
    let fixture: Fixture = Fixture::new(VALID_WASM);
    for names in ["missing", "run,run", "run,"] {
        let output: Output = fixture.run(names);
        assert!(!output.status.success(), "{names}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn binary_rejects_oversized_file_and_network_or_signer_flags() {
    let fixture: Fixture = Fixture::new(VALID_WASM);
    File::options()
        .write(true)
        .open(&fixture.0)
        .unwrap()
        .set_len((MAX_CONTRACT_WASM_BYTES + 1) as u64)
        .unwrap();
    assert!(!fixture.run("run").status.success());
    for flag in ["--endpoint", "--seed-file", "--ledger-hid-path"] {
        let output: Output = Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
            .args(["contract", "validate", flag, "unused"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("unknown flag")
        );
    }
}

#[test]
fn contract_requires_explicit_supported_action_and_required_arguments() {
    for args in [
        vec!["contract"],
        vec!["contract", "publish"],
        vec!["contract", "validate"],
    ] {
        let output: Output = Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
