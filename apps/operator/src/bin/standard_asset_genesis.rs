#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let result: Result<(), Box<dyn std::error::Error>> =
        sunrise_edge_operator::standard_asset_genesis::run(std::env::args_os().skip(1));
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("standard-asset-genesis: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
