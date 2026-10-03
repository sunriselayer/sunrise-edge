#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = sunrise_edge_operator::successor_host::run(std::env::args_os().skip(1)) {
        eprintln!("successor-host: {error}");
        std::process::exit(1);
    }
}
