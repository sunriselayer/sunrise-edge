#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    match sunrise_edge_operator::sqlite_source_host::run(std::env::args_os().skip(1)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sqlite-source-host: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
