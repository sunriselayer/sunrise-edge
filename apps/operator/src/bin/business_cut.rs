//! Local pre-Seal candidate export and database-free saved verification.
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match sunrise_edge_operator::business_cut::run(std::env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
