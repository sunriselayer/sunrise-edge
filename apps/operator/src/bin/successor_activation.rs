#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = sunrise_edge_operator::successor_activation::run(std::env::args_os().skip(1)) {
        eprintln!("successor-activation: {error}");
        std::process::exit(1);
    }
}
