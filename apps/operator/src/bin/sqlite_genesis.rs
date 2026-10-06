#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let result = sunrise_edge_operator::sqlite_genesis::run(std::env::args_os().skip(1));
    if let Ok(()) = result {
        return std::process::ExitCode::SUCCESS;
    }
    let Err(error) = &result else {
        return std::process::ExitCode::FAILURE;
    };
    eprintln!("sqlite-genesis: {error}");
    std::process::ExitCode::FAILURE
}
