#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = sunrise_edge_operator::ordered_seal::run(std::env::args_os().skip(1)) {
        eprintln!("ordered-seal: {error}");
        std::process::exit(1);
    }
}
