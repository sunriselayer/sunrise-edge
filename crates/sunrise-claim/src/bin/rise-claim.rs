//! Build the RISE claim commitment from a frozen claims file.
//!
//! `rise-claim root claims.json` prints the Merkle root, the file sha256,
//! the snapshot time, and the custody total. Those values are what genesis
//! pins. This binary does not contact a chain.

use std::env;
use std::fs;
use std::process::ExitCode;

use sunrise_claim::{MerkleTree, ledger_sha256, rise_leaves};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("root"), Some(path)) => match print_root(&path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("rise-claim root: {path}: {err}");
                ExitCode::from(1)
            }
        },
        _ => {
            eprintln!("usage: rise-claim root <claims.json>");
            ExitCode::from(2)
        }
    }
}

fn print_root(path: &str) -> Result<(), String> {
    let raw = fs::read(path).map_err(|err| err.to_string())?;
    let (snapshot, leaves) = rise_leaves(&raw).map_err(|err| err.to_string())?;
    let tree =
        MerkleTree::new(&leaves).ok_or_else(|| "claims file has no rise rows".to_string())?;
    let total: u128 = leaves.iter().map(|leaf| leaf.amount as u128).sum();
    let hash = hex::encode(ledger_sha256(&raw));
    println!("root {}", hex::encode(tree.root()));
    println!("ledger_sha256 {hash}");
    println!("snapshot_unix {snapshot}");
    println!("leaves {}", leaves.len());
    println!("custody {total}");
    Ok(())
}
