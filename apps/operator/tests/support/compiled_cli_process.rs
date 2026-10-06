//! Storage-neutral locator for the actual separately compiled Rust CLI.
//! Required gates build this binary before running operator process tests.
#![allow(dead_code)]

use std::{env, ffi::OsStr, path::PathBuf, process::Command};

pub fn edge_cli_binary() -> PathBuf {
    let executable: PathBuf = env::current_exe().unwrap();
    let directory: &std::path::Path = executable.parent().unwrap().parent().unwrap();
    let name: String = format!("sunrise-edge-cli{}", env::consts::EXE_SUFFIX);
    let binary: PathBuf = directory.join(name);
    assert!(
        binary.is_file(),
        "build the actual sunrise-edge-cli before operator process acceptance: {}",
        binary.display()
    );
    binary
}

pub fn edge_cli_command<I, A>(args: I) -> Command
where
    I: IntoIterator<Item = A>,
    A: AsRef<OsStr>,
{
    let mut command: Command = Command::new(edge_cli_binary());
    command.args(args);
    command
}
