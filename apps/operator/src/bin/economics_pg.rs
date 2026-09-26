//! Explicit offline, single-namespace fee collection (DR-0149).
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match sunrise_edge_operator::economics::run(std::env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("economics_pg: {error}");
            ExitCode::FAILURE
        }
    }
}
