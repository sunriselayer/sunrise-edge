//! Locally pinned saved cut into a permanently inactive SQLite namespace.
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match sunrise_edge_operator::business_import::run(std::env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
