//! Local contract tooling. Validation is structural, never execution authority.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;

use sunrise_edge_client::{
    MAX_CONTRACT_ENTRYPOINT_NAME_BYTES, MAX_CONTRACT_ENTRYPOINTS, MAX_CONTRACT_WASM_BYTES,
    ValidatedContractWasm, validate_contract_wasm,
};

use crate::args::{ArgsError, parse_flags, scalar};
use crate::error::CliError;

/// Dispatches local validation, authenticated publication, or verified query.
/// Only `validate` avoids signer, transport and node context construction.
pub fn run<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let action: OsString = args.next().ok_or(CliError::MissingContractAction)?;
    let action: &str = action.to_str().ok_or(ArgsError::NonUtf8Token)?;
    if action == "publish" || action == "query" {
        return super::publication::run(action, args);
    }
    if action != "validate" {
        return Err(CliError::UnknownContractAction(action.to_owned()));
    }
    let parsed = parse_flags(args, &[scalar("--wasm"), scalar("--entrypoints")])?;
    let path: &str = parsed.require("--wasm")?;
    let names: &str = parsed.require("--entrypoints")?;
    // Bound allocations before splitting caller-supplied text. Commas separate
    // names; whitespace is not trimmed, so the export name is never rewritten.
    const MAX_LIST_BYTES: usize =
        MAX_CONTRACT_ENTRYPOINTS * (MAX_CONTRACT_ENTRYPOINT_NAME_BYTES + 1);
    if names.len() > MAX_LIST_BYTES {
        return Err(CliError::ContractEntrypointListTooLarge);
    }
    let entrypoints: Vec<&str> = names.split(',').collect();
    let file: File = File::open(path).map_err(|source| CliError::WasmFileRead {
        path: path.to_owned(),
        source,
    })?;
    let mut bytes: Vec<u8> = Vec::new();
    // Reading one extra byte detects oversized files without trusting metadata
    // or loading the remainder. The verifier owns the actual size rejection.
    file.take((MAX_CONTRACT_WASM_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::WasmFileRead {
            path: path.to_owned(),
            source,
        })?;
    let validated: ValidatedContractWasm =
        validate_contract_wasm(&bytes, &entrypoints).map_err(CliError::ContractWasm)?;
    println!("validation=structural_wasm");
    println!("profile_version={}", validated.profile_version());
    println!("wasm_bytes={}", validated.wasm_bytes().len());
    println!("entrypoint_count={}", validated.entrypoints().len());
    println!("published=false");
    Ok(())
}
