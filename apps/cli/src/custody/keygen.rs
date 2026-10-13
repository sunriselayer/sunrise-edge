//! `custody keygen`: generates custody's own private Ed25519 key file.
//!
//! The generated seed is never printed or logged; only the derived public
//! key (the value an operator pastes into `publisher_public_key=` in the
//! custody config) is printed.

use std::ffi::OsString;
use std::path::Path;

use crate::args::{ParsedArgs, parse_flags, scalar};
use crate::error::CliError;
use crate::hex::encode_hex;

use super::keyfile;

const KEY_FILE: &str = "--key-file";

pub(super) fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let specs = vec![scalar(KEY_FILE)];
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let key_file = parsed.require(KEY_FILE)?;
    let signer = keyfile::generate(Path::new(key_file))?;
    println!("key_file={key_file}");
    println!("public_key={}", encode_hex(signer.address().as_bytes()));
    Ok(())
}
