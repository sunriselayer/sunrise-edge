//! Offline Standard Asset genesis authoring, not a network activation or key
//! ceremony. This preset composes the ordinary public contract and validators
//! from explicit inputs; the generic core remains the defining verifier.
#![forbid(unsafe_code)]

mod build;
mod input;

use crate::common::load_signing_key_file;
use crate::genesis_output::{FreshGenesisOutput, PublishedGenesis};
use crate::original_genesis_install::validate_original_genesis_in_memory;
use ed25519_zebra::{SigningKey, VerificationKey};
use input::{Allocation, Config, Validator};
use node_core::genesis::{
    GenesisManifest, VerifiedGenesisRoot, encode_genesis_manifest, genesis_manifest_commitment,
};
use protocol_types::Digest32;
use std::{error::Error, ffi::OsString, io::Write};

/// Runs the closed offline `author` command, publishing one fresh signed
/// manifest only after generic installer validation; never activates a network.
pub fn run(tokens: impl IntoIterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let mut tokens = tokens.into_iter();
    if tokens.next().as_deref() != Some(std::ffi::OsStr::new("author")) {
        return Err("expected standard-asset-genesis author subcommand".into());
    }
    let config: Config = Config::parse(tokens)?;
    let output: FreshGenesisOutput = FreshGenesisOutput::plan(
        &config.output,
        &[
            &config.key_file,
            &config.validators_file,
            &config.allocations_file,
        ],
    )?;
    let (validators, allocations): (Vec<Validator>, Vec<Allocation>) = config.tables()?;
    let key: SigningKey = load_signing_key_file(&config.key_file)?;
    let derived: [u8; 32] = VerificationKey::from(&key).into();
    if derived != config.authority {
        return Err("genesis key differs from independently expected genesis authority".into());
    }
    let manifest: GenesisManifest = build::build(&config, &validators, &allocations, &key)?;
    let bytes: Vec<u8> = encode_genesis_manifest(&manifest)?;
    let digest: Digest32 = genesis_manifest_commitment(&config.resolver, &manifest)?;
    let root: VerifiedGenesisRoot = VerifiedGenesisRoot::verify_bytes(
        &config.resolver,
        &bytes,
        digest.bytes(),
        &config.context,
    )?;
    // Signature self-consistency is insufficient. Full ordinary installation
    // verifies nested signatures, ABI, policy, object and bond constraints.
    validate_original_genesis_in_memory(
        &root,
        config.validation_domain,
        config.validation_checkpoint,
        config.timeout_millis,
    )?;
    let published: PublishedGenesis = output.publish(&bytes)?;
    published.ensure_attached()?;
    println!(
        "complete=true mode=author manifest_digest={} genesis_authority={}",
        hex(&digest.bytes()),
        hex(&derived)
    );
    std::io::stdout().flush()?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| format!("{byte:02x}"))
        .collect::<String>()
}
