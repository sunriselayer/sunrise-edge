use std::process::Command;

#[test]
fn execution_commands_reject_ledger_before_network_or_device() {
    for action in ["instantiate", "call"] {
        let output = Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
            .args([
                "contract",
                action,
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
                .contains("Ledger local execution signing is not supported")
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn new_commands_reject_unknown_and_duplicate_flags_locally() {
    for action in ["instantiate", "call", "query-instance"] {
        for flags in [
            vec!["--unknown"],
            vec!["--endpoint", "127.0.0.1:1", "--endpoint", "127.0.0.1:2"],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
                .args(["contract", action])
                .args(flags)
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&output.stderr).contains("unknown contract action"));
        }
    }
}

#[test]
fn general_flags_are_explicit_and_preserve_ledger_preflight() {
    for action in ["instantiate", "call", "publish"] {
        let output = Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
            .args([
                "contract",
                action,
                "--general-calls",
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
        assert!(String::from_utf8_lossy(&output.stderr).contains("signing is not supported"));
        assert!(output.stdout.is_empty());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
        .args(["contract", "call", "--authorizations", "missing-file"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--authorizations requires --general-calls")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_sunrise-edge-cli"))
        .args(["contract", "publish", "--executable", "--general-calls"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("choose --executable or --general-calls")
    );
}
