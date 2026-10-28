//! Immutable, non-executing local publication and verified readback.

use crate::{
    args::{ParsedArgs, parse_flags, scalar, switch},
    custody::{CustodyTarget, request_signature},
    error::CliError,
    hex::decode_hex_32,
    net::{connect_publication, tls_flag_specs},
    parse::parse_u64,
    seed::load_dev_seed,
    signer::{SignerSelection, parse_signer_selection, signer_flag_specs},
};
use std::{error::Error, ffi::OsString, path::Path};
use sunrise_edge_client::{
    Address, ArtifactParts, CodeArtifact, Digest32, ExpectedProtocolContext, HashSuiteResolver,
    LocalSigner, PackageOrigin, PreparedPublication, PublicationContext, PublicationReview,
    RequestId, UnverifiedDependencyRef, local_publication_resolver,
};

/// The publication-signing identity: either the development-only in-memory
/// seed signer, or a pinned publication-only custody target (`crate::custody`).
/// Ledger publication signing is rejected earlier, before this is built.
enum PublishSigner {
    Local(Box<LocalSigner>),
    Custody(CustodyTarget),
}

impl PublishSigner {
    fn address(&self) -> Address {
        match self {
            Self::Local(signer) => signer.address(),
            Self::Custody(target) => Address::new(target.expected_public_key),
        }
    }
}

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::Publication(Box::new(error))
}
fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// Selects the structural WASM profile from mutually exclusive CLI flags.
/// Shared by `publish` and `preview` so the mapping exists exactly once.
fn selected_wasm_profile(parsed: &ParsedArgs) -> u32 {
    if parsed.is_present("--general-calls") {
        3
    } else if parsed.is_present("--executable") {
        2
    } else {
        1
    }
}

/// Computes the one profile semantics commitment matching
/// `selected_wasm_profile`'s choice, under the trusted resolver/context.
/// Shared by `publish` and `preview` so the profile/semantics pairing exists
/// exactly once rather than as two independently maintained copies.
fn semantics_for_selected_profile(
    parsed: &ParsedArgs,
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
) -> Result<Digest32, CliError> {
    if parsed.is_present("--general-calls") {
        sunrise_edge_client::local_execution::general_execution_semantics(resolver, context)
            .map_err(failure)
    } else if parsed.is_present("--executable") {
        sunrise_edge_client::local_execution::local_execution_semantics(resolver, context)
            .map_err(failure)
    } else {
        sunrise_edge_client::local_publication_profile_semantics(resolver, context).map_err(failure)
    }
}

/// Builds the exact `CodeArtifact` from already-resolved context/origin/
/// semantics plus the shared file-based construction flags (entrypoints,
/// wasm, abi, dependencies). Shared by `publish` (called after
/// `client.query_verified_context`) and `preview` (called with no client at
/// all, after the same context/origin/semantics construction); every bound
/// enforced here is `CodeArtifact`'s own existing bound, not a separate copy.
fn build_artifact_from_flags(
    parsed: &ParsedArgs,
    context: PublicationContext,
    origin: PackageOrigin,
    semantics: Digest32,
    wasm_profile: u32,
) -> Result<CodeArtifact, CliError> {
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
    if wasm_profile == 2 || wasm_profile == 3 {
        sunrise_edge_client::executable_abi::decode_executable_abi(&abi).map_err(failure)?;
    }
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
    CodeArtifact::new(ArtifactParts {
        context,
        origin,
        revision: 1,
        wasm_profile,
        semantics,
        wasm,
        unverified_abi: abi,
        exports,
        unverified_dependencies: dependencies,
    })
    .map_err(failure)
}

pub(super) fn run<I>(action: &str, args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    if action == "preview" {
        return run_preview(args);
    }
    let mut specs = vec![
        switch("--executable"),
        switch("--general-calls"),
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
    if parsed.is_present("--executable") && parsed.is_present("--general-calls") {
        return Err(invalid("choose --executable or --general-calls, not both"));
    }
    // Reject hardware signing before file access, device selection, or network I/O.
    let signer: Option<PublishSigner> = if action == "publish" {
        match parse_signer_selection(&parsed)? {
            SignerSelection::Local { seed_file } => Some(PublishSigner::Local(Box::new(
                LocalSigner::from_seed(load_dev_seed(Path::new(&seed_file))?),
            ))),
            SignerSelection::Ledger { .. } => {
                return Err(invalid("Ledger publication signing is not supported"));
            }
            SignerSelection::Custody {
                socket,
                custody_uid,
                expected_public_key,
            } => Some(PublishSigner::Custody(CustodyTarget {
                socket: std::path::PathBuf::from(socket),
                custody_uid,
                expected_public_key,
            })),
        }
    } else {
        None
    };
    let expected: ExpectedProtocolContext = super::standard_asset::parse_expected_context(&parsed)?;
    let resolver = local_publication_resolver(&expected)?;
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(failure)?;
    let semantics: Digest32 = semantics_for_selected_profile(&parsed, &resolver, &context)?;
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
        let wasm_profile: u32 = selected_wasm_profile(&parsed);
        let artifact: CodeArtifact =
            build_artifact_from_flags(&parsed, context, origin, semantics, wasm_profile)?;
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
        let prepared: PreparedPublication = PreparedPublication::prepare(
            signer.address(),
            &resolver,
            &expected,
            artifact,
            nonce,
            request_id,
        )?;
        let submission = match &signer {
            PublishSigner::Local(local_signer) => {
                prepared.sign_and_finalize_with(local_signer.as_ref())?
            }
            PublishSigner::Custody(target) => {
                let signature = request_signature(
                    target,
                    prepared.artifact(),
                    prepared.nonce(),
                    prepared.request_id(),
                )?;
                prepared.finalize(signature.to_vec())?
            }
        };
        let result = client.submit_publication(&submission)?;
        println!("request_id={request_id}");
        println!("nonce={nonce}");
        println!("response_count={}", result.responses().len());
        println!("published=true");
    } else {
        match client.query_publication(&origin, &resolver, &expected, &semantics)? {
            // DR-0126: a paid Publish record is queryable and clearly
            // labeled as such; it is never printed as if it were a legacy
            // submission. The client has already independently re-authenticated this exact
            // signed intent (context, signature, Publish kind, origin and
            // semantics) before returning it, so `published=true` here
            // reflects a verified record, not a raw server claim.
            Some(sunrise_edge_client::PublicationQueryResult::Paid(signed)) => {
                let request_id_hex: String = signed
                    .intent
                    .request_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                let artifact = match &signed.intent.application {
                    sunrise_edge_client::PaidApplication::Publish(artifact) => artifact,
                    _ => unreachable!("query_publication already rejects non-Publish paid records"),
                };
                if let Some(path) = parsed.get("--dependency-ref-out") {
                    use std::io::Write;
                    let digest = sunrise_edge_client::publication::artifact_commitment(
                        &resolver,
                        artifact.context(),
                        artifact,
                    )
                    .map_err(failure)?;
                    let reference = UnverifiedDependencyRef::new(
                        artifact.origin().clone(),
                        artifact.revision(),
                        artifact.context().clone(),
                        digest,
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
                println!("provenance=paid");
                println!("request_id={request_id_hex}");
                println!("revision={}", artifact.revision());
                println!("wasm_bytes={}", artifact.wasm().len());
                println!("abi_bytes={}", artifact.unverified_abi().len());
                println!(
                    "dependency_count={}",
                    artifact.unverified_dependencies().len()
                );
            }
            Some(sunrise_edge_client::PublicationQueryResult::Legacy(submission)) => {
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
                println!("provenance=legacy");
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

/// Bounded, non-authorizing local presentation of an exact publication.
///
/// Builds the SAME immutable [`PreparedPublication`] the `publish` action
/// signs (via the exact same [`build_artifact_from_flags`] helper), then
/// builds its complete bounded [`PublicationReview`] rendering before
/// printing anything. No signing seed is loaded, no signer or node is
/// contacted, no TLS/endpoint flags are accepted, and nothing is submitted;
/// `--nonce` is therefore required rather than queried from a node.
fn run_preview<I>(args: I) -> Result<(), CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let specs = vec![
        switch("--executable"),
        switch("--general-calls"),
        scalar("--origin-seed"),
        scalar("--expected-chain-id"),
        scalar("--expected-protocol-version"),
        scalar("--expected-epoch"),
        scalar("--expected-hash-suite-id"),
        scalar("--expected-domain"),
        scalar("--publisher"),
        scalar("--artifact-out"),
        scalar("--wasm"),
        scalar("--abi"),
        scalar("--entrypoints"),
        scalar("--dependencies"),
        scalar("--request-id"),
        scalar("--nonce"),
    ];
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    if parsed.is_present("--executable") && parsed.is_present("--general-calls") {
        return Err(invalid("choose --executable or --general-calls, not both"));
    }
    let expected: ExpectedProtocolContext = super::standard_asset::parse_expected_context(&parsed)?;
    let resolver = local_publication_resolver(&expected)?;
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(failure)?;
    let semantics: Digest32 = semantics_for_selected_profile(&parsed, &resolver, &context)?;
    let publisher: [u8; 32] = decode_hex_32("--publisher", parsed.require("--publisher")?)?;
    let origin: PackageOrigin = PackageOrigin::unverified(
        expected.chain_id().clone(),
        publisher,
        decode_hex_32("--origin-seed", parsed.require("--origin-seed")?)?,
    )
    .map_err(failure)?;
    let wasm_profile: u32 = selected_wasm_profile(&parsed);
    let artifact: CodeArtifact =
        build_artifact_from_flags(&parsed, context, origin, semantics, wasm_profile)?;
    let request_id: RequestId = RequestId::new(decode_hex_32(
        "--request-id",
        parsed.require("--request-id")?,
    )?)?;
    // Preview never contacts a node to allocate one; an explicit nonce is required.
    let nonce: u64 = parse_u64("--nonce", parsed.require("--nonce")?)?;
    let prepared: PreparedPublication = PreparedPublication::prepare(
        Address::new(publisher),
        &resolver,
        &expected,
        artifact,
        nonce,
        request_id,
    )?;
    let review: PublicationReview = PublicationReview::build(&prepared).map_err(failure)?;
    if let Some(path) = parsed.get("--artifact-out") {
        crate::custody::write_review_preimage(Path::new(path), review.artifact_bytes())?;
    }
    // The complete bounded output is built in full before the single print,
    // rather than interleaving work with partial `println!` calls.
    let mut output: String = String::from("preview=true\npublished=false\n");
    output.push_str(&review.render());
    print!("{output}");
    Ok(())
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, CliError> {
    let bytes: Vec<u8> = super::input_file::read_for_size_check(path, maximum).map_err(failure)?;
    if bytes.len() > maximum {
        return Err(invalid("publication input file exceeds its byte limit"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::Write,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn bounded_input_errors_keep_publication_classification() {
        let path: std::path::PathBuf = std::env::temp_dir().join(format!(
            "sunrise-publication-input-errors-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let path_text: &str = path.to_str().unwrap();
        let mut file: File = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"input").unwrap();
        drop(file);
        assert_eq!(read_bounded(path_text, 5).unwrap(), b"input");
        let oversized: CliError = read_bounded(path_text, 4).unwrap_err();
        assert!(matches!(
            oversized,
            CliError::Publication(inner)
                if inner.downcast_ref::<std::io::Error>().is_some_and(|source| {
                    source.kind() == std::io::ErrorKind::InvalidInput
                        && source.to_string() == "publication input file exceeds its byte limit"
                })
        ));
        std::fs::remove_file(&path).unwrap();
        let missing: CliError = read_bounded(path_text, 4).unwrap_err();
        assert!(matches!(
            missing,
            CliError::Publication(inner)
                if inner.downcast_ref::<std::io::Error>().is_some_and(|source| {
                    source.kind() == std::io::ErrorKind::NotFound
                })
        ));
    }
}
