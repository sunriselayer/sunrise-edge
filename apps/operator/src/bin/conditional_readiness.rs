//! Locally pinned inactive staging readiness, never active host composition.
#![forbid(unsafe_code)]
use std::process::ExitCode;
fn main() -> ExitCode {
    match sunrise_edge_operator::conditional_readiness::run(std::env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
