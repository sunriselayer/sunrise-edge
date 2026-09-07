//! Immutable, non-executing local publication and verified readback.

use crate::{
    args::{ParsedArgs, parse_flags, scalar},
    error::CliError,
    hex::decode_hex_32,
    net::{connect_publication, tls_flag_specs},
    parse::parse_u64,
    seed::load_dev_seed,
    signer::{SignerSelection, parse_signer_selection, signer_flag_specs},
};
use std::{error::Error, ffi::OsString, fs::File, io::Read, path::Path};
use sunrise_edge_client::{
    ArtifactParts, CodeArtifact, ExpectedProtocolContext, LocalSigner, PackageOrigin,
    PublicationContext, RequestId, UnverifiedDependencyRef, build_signed_publication,
    local_publication_resolver,
};

fn failure(error: impl Error + 'static) -> CliError {
    CliError::Publication(Box::new(error))
}
fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

pub(super) fn run<I>(action: &str, args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut specs = vec![
        scalar("--endpoint"),
        scalar("--origin-seed"),
        scalar("--expected-chain-id"),
        scalar("--expected-protocol-version"),
        scalar("--expected-epoch"),
        scalar("--expected-hash-suite-id"),
        scalar("--expected-domain"),
    ];
    specs.extend(tls_flag_specs());
    if action == "publish" {
        specs.extend(signer_flag_specs());
        specs.extend([
            scalar("--wasm"),
            scalar("--abi"),
            scalar("--entrypoints"),
            scalar("--dependencies"),
            scalar("--request-id"),
            scalar("--nonce"),
        ]);
    } else {
        specs.extend([scalar("--publisher"), scalar("--dependency-ref-out")]);
    }
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    // Reject hardware signing before file access, device selection, or network I/O.
    let signer: Option<LocalSigner> = if action == "publish" {
        match parse_signer_selection(&parsed)? {
            SignerSelection::Local { seed_file } => Some(LocalSigner::from_seed(load_dev_seed(
                Path::new(&seed_file),
            )?)),
            SignerSelection::Ledger { .. } => {
                return Err(invalid("Ledger publication signing is not supported"));
            }
        }
    } else {
        None
    };
    let expected: ExpectedProtocolContext = super::transfer::parse_expected_context(&parsed)?;
    let resolver = local_publication_resolver(&expected)?;
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(failure)?;
    let semantics = sunrise_edge_client::local_publication_profile_semantics(&resolver, &context)
        .map_err(failure)?;
    let publisher: [u8; 32] = match &signer {
        Some(signer) => *signer.address().as_bytes(),
        None => decode_hex_32("--publisher", parsed.require("--publisher")?)?,
    };
    let origin: PackageOrigin = PackageOrigin::unverified(
        expected.chain_id().clone(),
        publisher,
        decode_hex_32("--origin-seed", parsed.require("--origin-seed")?)?,
    )
    .map_err(failure)?;
    let client = connect_publication(parsed.require("--endpoint")?, &parsed)?;
    // No signature is produced before independent locally expected context verification.
    if let Some(signer) = signer {
        client.query_verified_context(&expected)?;
        let names: &str = parsed.require("--entrypoints")?;
        if names.len()
            > sunrise_edge_client::MAX_CONTRACT_ENTRYPOINTS
                * (sunrise_edge_client::MAX_CONTRACT_ENTRYPOINT_NAME_BYTES + 1)
        {
            return Err(CliError::ContractEntrypointListTooLarge);
        }
        let exports: Vec<String> = names.split(',').map(str::to_owned).collect();
        let wasm: Vec<u8> = read_bounded(
            parsed.require("--wasm")?,
            sunrise_edge_client::MAX_CONTRACT_WASM_BYTES,
        )?;
        let abi: Vec<u8> = read_bounded(
            parsed.require("--abi")?,
            sunrise_edge_client::publication::MAX_ABI_DECLARATION_BYTES,
        )?;
        let mut dependencies: Vec<UnverifiedDependencyRef> = Vec::new();
        if let Some(paths) = parsed.get("--dependencies") {
            if paths.len() > 32 * 4096 {
                return Err(invalid("dependency file list is too large"));
            }
            for path in paths.split(',') {
                if dependencies.len() == 32 {
                    return Err(invalid("at most 32 dependency references are allowed"));
                }
                dependencies.push(
                    sunrise_edge_client::decode_dependency_ref(&read_bounded(path, 1024)?)
                        .map_err(failure)?,
                );
            }
        }
        let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
            context,
            origin,
            revision: 1,
            wasm_profile: 1,
            semantics,
            wasm,
            unverified_abi: abi,
            exports,
            unverified_dependencies: dependencies,
        })
        .map_err(failure)?;
        let request_id: RequestId = RequestId::new(decode_hex_32(
            "--request-id",
            parsed.require("--request-id")?,
        )?)?;
        // An explicit nonce permits exact replay of a previous immutable submission.
        let nonce: u64 = if let Some(value) = parsed.get("--nonce") {
            parse_u64("--nonce", value)?
        } else {
            let result = client.query_next_nonce(signer.address())?;
            if result.epoch() != expected.epoch() {
                return Err(CliError::EpochMismatch {
                    context_epoch: expected.epoch().get(),
                    nonce_epoch: result.epoch().get(),
                });
            }
            result.next_nonce()
        };
        let submission =
            build_signed_publication(&signer, &resolver, &expected, artifact, nonce, request_id)?;
        let result = client.submit_publication(&submission)?;
        println!("request_id={request_id}");
        println!("nonce={nonce}");
        println!("response_count={}", result.responses().len());
        println!("published=true");
    } else {
        match client.query_publication(&origin, &resolver, &expected, &semantics)? {
            Some(submission) => {
                let request = submission.request();
                if let Some(path) = parsed.get("--dependency-ref-out") {
                    use std::io::Write;
                    let reference = UnverifiedDependencyRef::new(
                        request.artifact().origin().clone(),
                        request.artifact().revision(),
                        request.artifact().context().clone(),
                        *request.artifact_digest(),
                    )
                    .map_err(failure)?;
                    let bytes = sunrise_edge_client::publication::encode_dependency_ref(&reference)
                        .map_err(failure)?;
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)
                        .map_err(failure)?;
                    file.write_all(&bytes).map_err(failure)?;
                }
                println!("published=true");
                println!("revision={}", request.artifact().revision());
                println!("wasm_bytes={}", request.artifact().wasm().len());
                println!("abi_bytes={}", request.artifact().unverified_abi().len());
                println!(
                    "dependency_count={}",
                    request.artifact().unverified_dependencies().len()
                );
                println!("nonce={}", request.nonce());
                println!("artifact_digest={}", request.artifact_digest());
            }
            None => println!("published=false"),
        }
    }
    Ok(())
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes: Vec<u8> = Vec::new();
    File::open(path)
        .map_err(failure)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() > maximum {
        return Err(invalid("publication input file exceeds its byte limit"));
    }
    Ok(bytes)
}
