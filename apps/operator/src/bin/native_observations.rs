#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    match sunrise_edge_operator::native_observations::run(std::env::args_os().skip(1)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error.message());
            std::process::ExitCode::FAILURE
        }
    }
}
