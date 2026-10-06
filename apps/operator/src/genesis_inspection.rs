//! Pinned, offline original-genesis inspection with no signing or disk-store
//! authority. The defining installers validate in isolated disposable memory.
#![forbid(unsafe_code)]

mod input;
mod render;

use crate::original_genesis_install::validate_original_genesis_in_memory;
use input::Config;
use node_core::genesis::VerifiedGenesisRoot;
use std::{error::Error, ffi::OsString, io::Write};
use sunrise_edge_client::load_verified_genesis_root;

/// Runs only the closed `inspect` command, requiring independent public pins
/// and printing a descriptive summary after full generic installer validation.
/// It reads no private key and opens no disk-backed database or listener.
pub fn run(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut tokens = tokens.into_iter();
    if tokens.next().as_deref() != Some(std::ffi::OsStr::new("inspect")) {
        return Err("expected genesis-inspect inspect subcommand".into());
    }
    let config: Config = Config::parse(tokens)?;
    let root: VerifiedGenesisRoot = load_verified_genesis_root(
        &config.manifest,
        &config.resolver,
        config.expected_digest,
        &config.context,
    )?;
    if root.manifest().genesis_authority != config.authority {
        return Err(
            "manifest authority differs from independently expected genesis authority".into(),
        );
    }
    validate_original_genesis_in_memory(
        &root,
        config.validation_domain,
        config.validation_checkpoint,
        config.timeout_millis,
    )?;
    let summary: String = render::render(&root)?;
    let mut output: std::io::StdoutLock<'_> = std::io::stdout().lock();
    output.write_all(summary.as_bytes())?;
    output.flush()?;
    Ok(())
}
