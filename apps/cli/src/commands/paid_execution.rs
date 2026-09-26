//! Public paid contract Publish/Instantiate/Call workflow (DR-0126).

use crate::{
    args::{ParsedArgs, parse_flags, scalar},
    error::CliError,
    hex::decode_hex_32,
    net::{connect_paid_execution, tls_flag_specs},
    parse::parse_u64,
    seed::load_dev_seed,
    signer::{SignerSelection, parse_signer_selection, signer_flag_specs},
};
use std::{
    error::Error,
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    path::Path,
};
use sunrise_edge_client::paid_execution_client::build_signed_paid_execution;
use sunrise_edge_client::publication::MAX_ABI_DECLARATION_BYTES;
use sunrise_edge_client::{
    FeeSourceConsent, PaidApplication, PaidExecutionResult, PaidExecutionStatus,
    ReservationAccessKind, encode_paid_execution_result, encode_signed_paid_intent,
};
use sunrise_edge_client::{call::CallIntent, local_execution::*, *};

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}
fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}
pub(super) const MAX_INSTANCE_RECORD_BYTES: usize = 2048;

pub(super) fn validate_remote_instance(
    record: &InstanceRecord,
    remote: Option<&InstanceRecord>,
) -> Result<(), CliError> {
    if remote != Some(record) {
        return Err(invalid("remote instance differs from pinned instance file"));
    }
    Ok(())
}

pub(super) fn read(path: &str, maximum: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes: Vec<u8> = Vec::new();
    File::open(path)
        .map_err(failure)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() > maximum {
        return Err(invalid("canonical input file too large"));
    }
    Ok(bytes)
}
/// Reserves every requested artifact before the mutating POST. The signed
/// submission and deterministic derived reference are persisted before the
/// POST so they survive an uncertain response. A reserved file remains in
/// place on failure so recovery cannot overwrite an earlier operation.
#[allow(clippy::too_many_arguments)]
pub(super) fn submit_with_outputs(
    result_path: Option<&str>,
    submission_path: Option<&str>,
    derived_path: Option<&str>,
    submission: &[u8],
    derived: Option<&[u8]>,
    request_id: RequestId,
    nonce: u64,
    submit: impl FnOnce() -> Result<PaidExecutionResult, CliError>,
) -> Result<PaidExecutionResult, CliError> {
    let reserve = |path: &str| -> Result<File, CliError> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(failure)
    };
    let mut result_file: Option<File> = result_path.map(reserve).transpose()?;
    let mut submission_file: Option<File> = submission_path.map(reserve).transpose()?;
    let mut derived_file: Option<File> = derived_path.map(reserve).transpose()?;
    if let Some(file) = &mut submission_file {
        file.write_all(submission).map_err(failure)?;
        file.sync_all().map_err(failure)?;
    }
    if let (Some(file), Some(bytes)) = (&mut derived_file, derived) {
        file.write_all(bytes).map_err(failure)?;
        file.sync_all().map_err(failure)?;
    }
    println!("request_id={request_id}");
    println!("nonce={nonce}");
    let result: PaidExecutionResult = submit()?;
    let recovery = |error: &dyn Error| -> CliError {
        failure(std::io::Error::other(format!(
            "validated paid outcome received but output failed: {error}; request_id={request_id} nonce={nonce}; replay identical signed bytes with the same request ID and nonce; do not retry with a fresh nonce"
        )))
    };
    if let Some(file) = &mut result_file {
        let bytes: Vec<u8> =
            encode_paid_execution_result(&result).map_err(|error| recovery(&error))?;
        file.write_all(&bytes).map_err(|error| recovery(&error))?;
        file.sync_all().map_err(|error| recovery(&error))?;
    }
    Ok(result)
}

pub(super) fn run<I: IntoIterator<Item = OsString>>(action: &str, args: I) -> Result<(), CliError> {
    let mut specs = vec![
        scalar("--endpoint"),
        scalar("--expected-chain-id"),
        scalar("--expected-protocol-version"),
        scalar("--expected-epoch"),
        scalar("--expected-hash-suite-id"),
        scalar("--expected-domain"),
        scalar("--fee-source"),
        scalar("--fee-access"),
        scalar("--max-fee"),
        scalar("--refund-recipient"),
        scalar("--gas-limit"),
        scalar("--request-id"),
        scalar("--nonce"),
        scalar("--submission-out"),
        scalar("--result-out"),
        scalar("--authorizations"),
    ];
    specs.extend(tls_flag_specs());
    specs.extend(signer_flag_specs());
    specs.extend(super::fastvote_network::network_flag_specs());
    match action {
        "paid-publish" => specs.extend([
            scalar("--wasm"),
            scalar("--abi"),
            scalar("--entrypoints"),
            scalar("--origin-seed"),
            scalar("--dependencies"),
            scalar("--dependency-ref-out"),
        ]),
        "paid-instantiate" => specs.extend([
            scalar("--code-ref"),
            scalar("--instance-seed"),
            scalar("--args"),
            scalar("--type-args"),
            scalar("--instance-ref-out"),
        ]),
        "paid-call" => specs.extend([
            scalar("--instance-ref"),
            scalar("--entrypoint"),
            scalar("--access"),
            scalar("--args"),
            scalar("--type-args"),
        ]),
        _ => return Err(invalid("unknown paid contract action")),
    }
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    if action != "paid-call" && parsed.get("--authorizations").is_some() {
        return Err(invalid("--authorizations is supported only for paid-call"));
    }
    if action != "paid-call" && parsed.get("--fastvote-network").is_some() {
        return Err(invalid(
            "--fastvote-network is supported only for paid-call; paid-publish/paid-instantiate remain direct-only",
        ));
    }
    // Ledger clear signing is a separate deferred contract. Reject before
    // device access, file reads, policy queries, or submission.
    let signer: LocalSigner = match parse_signer_selection(&parsed)? {
        SignerSelection::Local { seed_file } => {
            LocalSigner::from_seed(load_dev_seed(Path::new(&seed_file))?)
        }
        SignerSelection::Ledger { .. } => {
            return Err(invalid("Ledger paid contract signing is not supported"));
        }
    };
    let expected: ExpectedProtocolContext = super::standard_asset::parse_expected_context(&parsed)?;
    let resolver: HashSuiteResolver = local_publication_resolver(&expected)?;
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(failure)?;
    // Endpoint-to-validator mapping is verified against the local genesis
    // pin *before* any fee/nonce query or signing, exactly like the local
    // expected-context check above.
    let network: Option<(
        Vec<FastVoteEndpoint<crate::net::CliTransport>>,
        FastPathCertifier,
    )> = if parsed.get("--fastvote-network").is_some() {
        Some(super::fastvote_network::load_endpoints_and_certifier(
            &parsed, &resolver, &context,
        )?)
    } else {
        None
    };
    let client = connect_paid_execution(parsed.require("--endpoint")?, &parsed)?;
    let fee_policy = client.query_paid_fee_policy(&resolver, &expected)?;
    let fee_source_id: ObjectId = ObjectId::new(decode_hex_32(
        "--fee-source",
        parsed.require("--fee-source")?,
    )?);
    let queried_source = client.query_object(fee_source_id)?;
    let source_ref: ObjectRef = current_inline_object_ref(&queried_source)
        .ok_or_else(|| invalid("fee source must be a current inline object"))?;
    let fee_access: ReservationAccessKind = match parsed.require("--fee-access")? {
        "write" => ReservationAccessKind::Write,
        "consume" => ReservationAccessKind::Consume,
        _ => return Err(invalid("--fee-access must be write or consume")),
    };
    let refund_recipient: [u8; 32] = match parsed.get("--refund-recipient") {
        Some(value) => decode_hex_32("--refund-recipient", value)?,
        None => *signer.address().as_bytes(),
    };
    let consent = FeeSourceConsent {
        source: source_ref,
        access: fee_access,
        max_fee: Amount::new(parse_u64("--max-fee", parsed.require("--max-fee")?)?),
        refund_recipient,
    };
    client.validate_paid_fee_source(&signer, &resolver, &expected, &fee_policy, &consent)?;
    let request_id: RequestId = RequestId::new(decode_hex_32(
        "--request-id",
        parsed.require("--request-id")?,
    )?)?;
    let nonce: u64 = match parsed.get("--nonce") {
        Some(value) => parse_u64("--nonce", value)?,
        None => {
            let value = client.query_next_nonce(signer.address())?;
            if value.epoch() != expected.epoch() {
                return Err(invalid("nonce epoch differs from expected context"));
            }
            value.next_nonce()
        }
    };
    let gas_limit: u64 = parse_u64("--gas-limit", parsed.require("--gas-limit")?)?;
    let authorizations = match parsed.get("--authorizations") {
        Some(path) => call_authorization::decode_call_authorizations(&read(
            path,
            call_authorization::MAX_CALL_AUTHORIZATION_BYTES,
        )?)
        .map_err(failure)?,
        None => Vec::new(),
    };
    let (application, instance_output): (PaidApplication, Option<InstanceRecord>) = match action {
        "paid-publish" => (
            PaidApplication::Publish(build_artifact(&parsed, &signer, &resolver, &context)?),
            None,
        ),
        "paid-instantiate" | "paid-call" => build_call_application(
            action, &parsed, &client, &signer, &resolver, &expected, &context, request_id, nonce,
            gas_limit,
        )?,
        _ => unreachable!(),
    };
    let signed = build_signed_paid_execution(
        &signer,
        &resolver,
        &expected,
        &fee_policy,
        consent,
        application,
        request_id,
        nonce,
        gas_limit,
        authorizations,
    )?;
    let signed_bytes: Vec<u8> = encode_signed_paid_intent(&signed).map_err(failure)?;
    let (derived_path, derived_bytes): (Option<&str>, Option<Vec<u8>>) =
        match &signed.intent.application {
            PaidApplication::Publish(artifact) => {
                let digest: Digest32 =
                    publication::artifact_commitment(&resolver, &context, artifact)
                        .map_err(failure)?;
                let reference: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
                    artifact.origin().clone(),
                    artifact.revision(),
                    artifact.context().clone(),
                    digest,
                )
                .map_err(failure)?;
                (
                    parsed.get("--dependency-ref-out"),
                    Some(publication::encode_dependency_ref(&reference).map_err(failure)?),
                )
            }
            PaidApplication::Instantiate(_) => (
                parsed.get("--instance-ref-out"),
                instance_output
                    .as_ref()
                    .map(encode_instance_record)
                    .transpose()
                    .map_err(failure)?,
            ),
            PaidApplication::Call(_) => (None, None),
        };
    let result: PaidExecutionResult = if let Some((endpoints, certifier)) = &network {
        super::fastvote_network::run_network_submit(
            &parsed, endpoints, certifier, &resolver, &signed,
        )?
    } else {
        submit_with_outputs(
            parsed.get("--result-out"),
            parsed.get("--submission-out"),
            derived_path,
            &signed_bytes,
            derived_bytes.as_deref(),
            request_id,
            nonce,
            || {
                client
                    .submit_paid_execution(&signed, &resolver)
                    .map_err(CliError::from)
            },
        )?
    };
    println!("paid_status={:?}", result.status);
    println!("gas_used={}", result.effects.gas_used);
    if let Some(charged) = &result.charged {
        println!("reserved_fee={}", charged.reserved.get());
        println!("actual_fee={}", charged.actual.get());
        println!("refund_fee={}", charged.refund.get());
    }
    if result.status != PaidExecutionStatus::Success {
        return Err(invalid(
            "paid contract execution rejected; replay identical signed bytes",
        ));
    }
    Ok(())
}

fn build_artifact(
    parsed: &ParsedArgs,
    signer: &LocalSigner,
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
) -> Result<CodeArtifact, CliError> {
    let names: &str = parsed.require("--entrypoints")?;
    if names.len() > MAX_CONTRACT_ENTRYPOINTS * (MAX_CONTRACT_ENTRYPOINT_NAME_BYTES + 1) {
        return Err(CliError::ContractEntrypointListTooLarge);
    }
    let exports: Vec<String> = names.split(',').map(str::to_owned).collect();
    let wasm: Vec<u8> = read(parsed.require("--wasm")?, MAX_CONTRACT_WASM_BYTES)?;
    let abi: Vec<u8> = read(parsed.require("--abi")?, MAX_ABI_DECLARATION_BYTES)?;
    executable_abi::decode_executable_abi(&abi).map_err(failure)?;
    let mut dependencies: Vec<UnverifiedDependencyRef> = Vec::new();
    if let Some(paths) = parsed.get("--dependencies") {
        if paths.len() > 32 * 4096 {
            return Err(invalid("dependency file list is too large"));
        }
        for path in paths.split(',') {
            if dependencies.len() == 32 {
                return Err(invalid("at most 32 dependency references are allowed"));
            }
            dependencies.push(decode_dependency_ref(&read(path, 1024)?).map_err(failure)?);
        }
    }
    CodeArtifact::new(ArtifactParts {
        context: context.clone(),
        origin: PackageOrigin::unverified(
            context.chain_id().clone(),
            *signer.address().as_bytes(),
            decode_hex_32("--origin-seed", parsed.require("--origin-seed")?)?,
        )
        .map_err(failure)?,
        revision: 1,
        wasm_profile: GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION,
        semantics: local_execution::generic_object_result_semantics(resolver, context)
            .map_err(failure)?,
        wasm,
        unverified_abi: abi,
        exports,
        unverified_dependencies: dependencies,
    })
    .map_err(failure)
}

#[allow(clippy::too_many_arguments)]
fn build_call_application<T: Transport>(
    action: &str,
    parsed: &ParsedArgs,
    client: &Client<T>,
    signer: &LocalSigner,
    resolver: &HashSuiteResolver,
    expected: &ExpectedProtocolContext,
    context: &PublicationContext,
    request_id: RequestId,
    nonce: u64,
    gas_limit: u64,
) -> Result<(PaidApplication, Option<InstanceRecord>), CliError> {
    let loaded: Option<InstanceRecord> = if action == "paid-call" {
        Some(
            decode_instance_record(&read(
                parsed.require("--instance-ref")?,
                MAX_INSTANCE_RECORD_BYTES,
            )?)
            .map_err(failure)?,
        )
    } else {
        None
    };
    let code: UnverifiedDependencyRef = match &loaded {
        Some(record) => record.code.clone(),
        None => {
            decode_dependency_ref(&read(parsed.require("--code-ref")?, 4096)?).map_err(failure)?
        }
    };
    let interface = client.query_paid_executable_interface(&code, resolver, expected)?;
    let initializer: String = interface
        .executable_abi(code.origin())
        .and_then(|metadata| metadata.initializer.clone())
        .ok_or_else(|| invalid("code has no initializer"))?;
    let instance: InstanceRecord = match loaded {
        Some(record) => {
            let remote: Option<InstanceRecord> =
                client.query_instance(record.creator, record.seed, resolver, expected)?;
            validate_remote_instance(&record, remote.as_ref())?;
            record
        }
        None => InstanceRecord {
            context: context.clone(),
            creator: *signer.address().as_bytes(),
            seed: decode_hex_32("--instance-seed", parsed.require("--instance-seed")?)?,
            code: code.clone(),
            revision: 1,
            initializer: initializer.clone(),
        },
    };
    let access: AccessManifest = if action == "paid-call" {
        decode_access_manifest(
            &read(parsed.require("--access")?, call::MAX_CALL_INTENT_BYTES)?,
            32,
        )
        .map_err(failure)?
    } else {
        AccessManifest::new()
    };
    let type_arguments = match parsed.get("--type-args") {
        Some(path) => package_types::decode_scoped_type_arguments(
            expected.chain_id(),
            &read(path, 32 * 1024)?,
        )
        .map_err(failure)?,
        None => Vec::new(),
    };
    let call = CallIntent {
        context: context.clone(),
        request_id: *request_id.as_bytes(),
        sender: *signer.address().as_bytes(),
        nonce,
        code,
        instance: instance_target(resolver, &instance).map_err(failure)?,
        entrypoint: if action == "paid-instantiate" {
            initializer
        } else {
            parsed.require("--entrypoint")?.to_owned()
        },
        type_arguments,
        access,
        arguments: read(parsed.require("--args")?, call::MAX_CALL_ARGUMENT_BYTES)?,
        gas_limit,
    };
    Ok(if action == "paid-instantiate" {
        (PaidApplication::Instantiate(call), Some(instance))
    } else {
        (PaidApplication::Call(call), None)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temporary_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "sunrise-paid-output-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn every_paid_output_is_reserved_before_submit() {
        let result_path = temporary_path("result");
        let submission_path = temporary_path("submission");
        let derived_path = temporary_path("derived");
        File::options()
            .write(true)
            .create_new(true)
            .open(&derived_path)
            .unwrap()
            .write_all(b"preserve")
            .unwrap();
        let called: Cell<bool> = Cell::new(false);
        let outcome = submit_with_outputs(
            result_path.to_str(),
            submission_path.to_str(),
            derived_path.to_str(),
            b"signed",
            Some(b"reference"),
            RequestId::new([3; 32]).unwrap(),
            7,
            || {
                called.set(true);
                Err(invalid("unexpected POST"))
            },
        );
        assert!(outcome.is_err());
        assert!(!called.get());
        assert_eq!(std::fs::read(&derived_path).unwrap(), b"preserve");
        assert_eq!(std::fs::read(&result_path).unwrap(), b"");
        assert_eq!(std::fs::read(&submission_path).unwrap(), b"");
        for path in [result_path, submission_path, derived_path] {
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn submission_and_derived_reference_survive_an_uncertain_post() {
        let result_path = temporary_path("uncertain-result");
        let submission_path = temporary_path("uncertain-submission");
        let derived_path = temporary_path("uncertain-derived");
        let outcome = submit_with_outputs(
            result_path.to_str(),
            submission_path.to_str(),
            derived_path.to_str(),
            b"signed",
            Some(b"reference"),
            RequestId::new([4; 32]).unwrap(),
            8,
            || Err(invalid("uncertain POST")),
        );
        assert!(outcome.is_err());
        assert_eq!(std::fs::read(&result_path).unwrap(), b"");
        assert_eq!(std::fs::read(&submission_path).unwrap(), b"signed");
        assert_eq!(std::fs::read(&derived_path).unwrap(), b"reference");
        for path in [result_path, submission_path, derived_path] {
            std::fs::remove_file(path).unwrap();
        }
    }
}
