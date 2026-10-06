//! Offline diagnostic entry point; no serving, signing or provider operation.
#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = sunrise_edge_operator::genesis_inspection::run(std::env::args_os().skip(1))
    {
        eprintln!("genesis inspection failed: {error}");
        std::process::exit(1);
    }
}
