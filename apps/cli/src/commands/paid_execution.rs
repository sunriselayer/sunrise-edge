//! Public paid contract Publish/Instantiate/Call workflow (DR-0126).

use crate::{
    args::{ParsedArgs, scalar},
    error::CliError,
    hex::decode_hex_32,
    net::{BudgetedTransport, OperationBudget, connect_paid_execution, tls_flag_specs},
    parse::parse_u64,
    seed::load_dev_seed,
    signer::{SignerSelection, parse_signer_selection, signer_flag_specs},
};
use std::{error::Error, ffi::OsString, fs::File, io::Write, path::Path};
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

/// Submits an already protected-signed canonical paid intent without opening
/// a local signer or custody socket. The configured endpoint/context and
/// installed fee policy are checked again before submission. This query is
/// an endpoint observation; admission still decides currentness atomically.
pub(super) fn run_signed_submit<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = vec![
        scalar("--endpoint"),
        scalar("--expected-chain-id"),
        scalar("--expected-protocol-version"),
        scalar("--expected-epoch"),
        scalar("--expected-hash-suite-id"),
        scalar("--expected-domain"),
        scalar("--signed-file"),
        scalar("--submission-out"),
        scalar("--result-out"),
        scalar("--dependency-ref-out"),
        scalar("--instance-ref-out"),
    ];
    specs.extend(tls_flag_specs());
    let (parsed, schedules) = super::hash_suite_pins::parse_pinned_flags(args, &specs)?;
    let expected = super::standard_asset::parse_expected_context(&parsed)?;
    let resolver = super::hash_suite_pins::publication_resolver(&expected, schedules)?;
    let context = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(failure)?;
    let signed_bytes = read(
        parsed.require("--signed-file")?,
        sunrise_edge_client::MAX_SIGNED_PAID_INTENT_BYTES,
    )?;
    execution::paid_execution::authenticate_paid_intent(&resolver, &context, &signed_bytes)
        .map_err(failure)?;
    let signed = sunrise_edge_client::decode_signed_paid_intent(&signed_bytes).map_err(failure)?;
    let derived = super::fastvote_network::recompute_derived_reference(
        &parsed,
        &resolver,
        &context,
        &signed.intent.application,
    )?;
    let request_id = RequestId::new(signed.intent.request_id).map_err(failure)?;
    let client = connect_paid_execution(parsed.require("--endpoint")?, &parsed)?;
    let policy = client.query_paid_fee_policy(&resolver, &expected)?;
    if signed.intent.fee_policy_digest
        != sunrise_edge_client::paid_fee_policy_digest(&resolver, &policy).map_err(failure)?
    {
        return Err(invalid("signed paid policy differs from installed policy"));
    }
    client.validate_paid_fee_source_for_owner(
        Address::new(signed.intent.sender),
        &resolver,
        &expected,
        &policy,
        &signed.intent.consent,
    )?;
    let result = submit_with_outputs(
        parsed.get("--result-out"),
        parsed.get("--submission-out"),
        derived.as_ref().map(|(path, _, _)| *path),
        &signed_bytes,
        derived.as_ref().map(|(_, _, bytes)| bytes.as_slice()),
        request_id,
        signed.intent.nonce,
        || {
            client
                .submit_paid_execution(&signed, &resolver)
                .map_err(CliError::from)
        },
    )?;
    println!(
        "paid_status={:?}\ngas_used={}",
        result.status, result.effects.gas_used
    );
    if result.status != PaidExecutionStatus::Success {
        return Err(invalid(
            "paid contract execution rejected; replay identical signed bytes",
        ));
    }
    Ok(())
}

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
    let bytes: Vec<u8> = super::input_file::read_for_size_check(path, maximum).map_err(failure)?;
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
        scalar("--unsigned-out"),
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
    let (parsed, schedules) = super::hash_suite_pins::parse_pinned_flags(args, &specs)?;
    // Budget/unsupported combinations are local errors, even when a seed or
    // other input is missing. The single instant starts before preparation.
    let budget: Option<OperationBudget> = if parsed.get("--fastvote-network").is_some() {
        let budget: OperationBudget = super::fastvote_network::parse_deadline(&parsed)?;
        Some(budget)
    } else {
        if super::fastvote_network::network_flag_specs()
            .iter()
            .any(|flag| parsed.get(flag.name).is_some())
        {
            return Err(invalid("FastVote flags require --fastvote-network"));
        }
        None
    };
    if action != "paid-call" && parsed.get("--authorizations").is_some() {
        return Err(invalid("--authorizations is supported only for paid-call"));
    }
    let unsigned_export = parsed.get("--unsigned-out").is_some();
    if unsigned_export {
        for name in [
            "--submission-out",
            "--result-out",
            "--dependency-ref-out",
            "--instance-ref-out",
            "--fastvote-signed-intent-out",
            "--fastvote-certificate-out",
            "--fastvote-availability-certificate-out",
        ] {
            if parsed.get(name).is_some() {
                return Err(invalid(
                    "unsigned custody preparation cannot reserve submission, result, certificate, or derived outputs",
                ));
            }
        }
    }
    if budget.is_some() {
        if unsigned_export {
            super::fastvote_network::validate_paid_unsigned_network_flags(&parsed)?;
        } else {
            super::fastvote_network::validate_paid_network_flags(&parsed)?;
        }
    }
    let signer_selection: SignerSelection = parse_signer_selection(&parsed)?;
    // A custody selection may only export a reviewed unsigned request. It
    // cannot sign or submit through this development command.
    if matches!(signer_selection, SignerSelection::Ledger { .. }) {
        return Err(invalid("Ledger paid contract signing is not supported"));
    }
    let custody_sender = match &signer_selection {
        SignerSelection::Custody {
            expected_public_key,
            ..
        } => {
            if !unsigned_export {
                return Err(invalid("custody paid preparation requires --unsigned-out"));
            }
            Some(Address::new(*expected_public_key))
        }
        _ => {
            if parsed.get("--unsigned-out").is_some() {
                return Err(invalid("--unsigned-out requires custody signer selection"));
            }
            None
        }
    };
    if let Some(path) = parsed.get("--unsigned-out") {
        crate::custody::check_review_preimage_destination(Path::new(path))?;
    }
    let load_signer = || -> Result<LocalSigner, CliError> {
        match &signer_selection {
            SignerSelection::Local { seed_file } => {
                Ok(LocalSigner::from_seed(load_dev_seed(Path::new(seed_file))?))
            }
            SignerSelection::Ledger { .. } => {
                Err(invalid("Ledger paid contract signing is not supported"))
            }
            SignerSelection::Custody { .. } => {
                Err(invalid("custody preparation uses public identity only"))
            }
        }
    };
    // Keep direct mode's existing local-input order. Network mode validates
    // the selected cohort peer before reading the signing seed.
    let direct_signer: Option<LocalSigner> = if budget.is_none() && custody_sender.is_none() {
        Some(load_signer()?)
    } else {
        None
    };
    let expected: ExpectedProtocolContext = super::standard_asset::parse_expected_context(&parsed)?;
    let resolver: HashSuiteResolver =
        super::hash_suite_pins::publication_resolver(&expected, schedules)?;
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
        sunrise_edge_client::VerifiedAdmissionProfile,
    )> = if parsed.get("--fastvote-network").is_some() {
        Some(super::fastvote_network::load_endpoints_and_profile(
            &parsed, &resolver, &context,
        )?)
    } else {
        None
    };
    if unsigned_export && let Some((_, _, admission)) = &network {
        let request_id = RequestId::new(decode_hex_32(
            "--request-id",
            parsed.require("--request-id")?,
        )?)?;
        super::fastvote_network::require_owned_lane(admission, request_id.as_bytes())?;
    }
    if let Some(budget) = budget {
        budget.ensure_live()?;
    }
    let signer: Option<LocalSigner> = match direct_signer {
        Some(signer) => Some(signer),
        None if custody_sender.is_none() => Some(load_signer()?),
        None => None,
    };
    let sender: Address = match (&signer, custody_sender) {
        (Some(signer), _) => signer.address(),
        (None, Some(sender)) => sender,
        (None, None) => return Err(invalid("paid sender missing")),
    };
    let direct_client: Option<Client<crate::net::CliTransport>> = if network.is_none() {
        Some(connect_paid_execution(
            parsed.require("--endpoint")?,
            &parsed,
        )?)
    } else {
        None
    };
    let preparation_client: &Client<crate::net::CliTransport> =
        if let Some((endpoints, _, _)) = &network {
            let selected: &str = parsed.require("--endpoint")?;
            super::fastvote_network::selected_preparation_client(endpoints, selected)?
        } else {
            direct_client
                .as_ref()
                .ok_or_else(|| invalid("direct client missing"))?
        };
    let client: Client<BudgetedTransport<'_, crate::net::CliTransport>> =
        Client::new(BudgetedTransport {
            inner: preparation_client.transport(),
            budget,
        });
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
        None => *sender.as_bytes(),
    };
    let consent = FeeSourceConsent {
        source: source_ref,
        access: fee_access,
        max_fee: Amount::new(parse_u64("--max-fee", parsed.require("--max-fee")?)?),
        refund_recipient,
    };
    client.validate_paid_fee_source_for_owner(
        sender,
        &resolver,
        &expected,
        &fee_policy,
        &consent,
    )?;
    let request_id: RequestId = RequestId::new(decode_hex_32(
        "--request-id",
        parsed.require("--request-id")?,
    )?)?;
    let nonce: u64 = match parsed.get("--nonce") {
        Some(value) => parse_u64("--nonce", value)?,
        None => {
            let value = client.query_next_nonce(sender)?;
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
            PaidApplication::Publish(build_artifact(&parsed, sender, &resolver, &context)?),
            None,
        ),
        "paid-instantiate" | "paid-call" => build_call_application(
            action, &parsed, &client, sender, &resolver, &expected, &context, request_id, nonce,
            gas_limit,
        )?,
        _ => unreachable!(),
    };
    if let Some(budget) = budget {
        budget.ensure_live()?;
    }
    let prepared: PreparedPaidExecution = PreparedPaidExecution::prepare(
        sender,
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
    if let Some(path) = parsed.get("--unsigned-out") {
        let review = sunrise_edge_client::PaidExecutionReview::build(&prepared).map_err(failure)?;
        print!("{}", review.text());
        crate::custody::write_review_preimage(Path::new(path), review.intent_bytes())?;
        println!("paid_unsigned_exported=true\nrequest_id={request_id}\nnonce={nonce}");
        return Ok(());
    }
    let signer = signer.ok_or_else(|| invalid("paid signer missing"))?;
    let signed = prepared.sign_and_finalize_with(&signer)?;
    let signed_bytes: Vec<u8> = encode_signed_paid_intent(&signed).map_err(failure)?;
    let (derived_path, derived_kind, derived_bytes): (Option<&str>, &'static str, Option<Vec<u8>>) =
        match &signed.intent.application {
            PaidApplication::Publish(artifact) => (
                parsed.get("--dependency-ref-out"),
                "dependency-ref",
                Some(dependency_reference_bytes(&resolver, &context, artifact)?),
            ),
            PaidApplication::Instantiate(_) => (
                parsed.get("--instance-ref-out"),
                "instance-ref",
                instance_output
                    .as_ref()
                    .map(encode_instance_record)
                    .transpose()
                    .map_err(failure)?,
            ),
            PaidApplication::Call(_) => (None, "unused", None),
        };
    let result: PaidExecutionResult = if let Some((endpoints, certifier, admission)) = &network {
        super::fastvote_network::run_network_submit(
            &parsed,
            endpoints,
            certifier,
            admission,
            expected.domain(),
            &resolver,
            &signed,
            derived_path
                .zip(derived_bytes.as_deref())
                .map(|(path, bytes)| (path, derived_kind, bytes)),
            budget.ok_or_else(|| invalid("network operation budget missing"))?,
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

/// Recomputes a `Publish` artifact's canonical dependency reference from
/// its own commitment, so any caller with the exact artifact and a locally
/// pinned context/resolver can derive the same bytes independently -- used
/// by the direct/network build path above and by
/// `fastvote_network::run_replay`'s offline reference recovery.
pub(super) fn dependency_reference_bytes(
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    artifact: &CodeArtifact,
) -> Result<Vec<u8>, CliError> {
    let digest: Digest32 =
        publication::artifact_commitment(resolver, context, artifact).map_err(failure)?;
    let reference: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        artifact.revision(),
        artifact.context().clone(),
        digest,
    )
    .map_err(failure)?;
    publication::encode_dependency_ref(&reference).map_err(failure)
}

fn build_artifact(
    parsed: &ParsedArgs,
    sender: Address,
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
            *sender.as_bytes(),
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
    sender: Address,
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
            creator: *sender.as_bytes(),
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
        sender: *sender.as_bytes(),
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

    /// Custody without an unsigned export destination must refuse before
    /// any signer file, peer, or device I/O.
    #[test]
    fn rejects_custody_signer_selection_before_any_io() {
        let error = run(
            "paid-call",
            vec![
                OsString::from("--custody-socket"),
                OsString::from("/nonexistent/custody.sock"),
                OsString::from("--custody-uid"),
                OsString::from("1001"),
                OsString::from("--custody-expected-public-key"),
                OsString::from("ab".repeat(32)),
            ],
        )
        .unwrap_err();
        assert!(matches!(error, CliError::LocalExecution(_)));
    }

    #[cfg(unix)]
    #[test]
    fn unsigned_fastvote_preflight_rejects_wrong_owned_lane_from_signed_genesis() {
        use crypto::SignatureSigner;
        let protocol = sunrise_edge_devnet::build_devnet_protocol_context(
            ChainId::new("paid-unsigned-fastvote-lane").unwrap(),
            Epoch::new(0),
        )
        .unwrap();
        let context = PublicationContext::new(
            protocol.chain_id().clone(),
            protocol.resolver().protocol_version(),
            protocol.epoch(),
        )
        .unwrap();
        let owner = LocalSigner::from_seed([0xA7; 32]);
        let fee_recipient = LocalSigner::from_seed([0xA8; 32]);
        let (mut manifest, _) = sunrise_edge_devnet::build_paid_genesis_manifest(
            protocol.resolver(),
            &context,
            &[sunrise_edge_devnet::DevOwner::new(
                *owner.address().as_bytes(),
            )],
            sunrise_edge_devnet::DevOwner::new(*fee_recipient.address().as_bytes()),
        )
        .unwrap();
        manifest.commitment_profile = CommitmentProfile::CausalAdmission;
        manifest.minimum_freeze_block_height = 1;
        let authority = LocalSigner::from_seed(sunrise_edge_devnet::DEVNET_PAID_GENESIS_SEED);
        manifest.signature = authority
            .sign_framed(&node_core::genesis::genesis_manifest_signing_frame(&manifest).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let bytes = node_core::genesis::encode_genesis_manifest(&manifest).unwrap();
        let digest =
            node_core::genesis::genesis_manifest_commitment(protocol.resolver(), &manifest)
                .unwrap();
        let root = sunrise_edge_client::VerifiedGenesisRoot::verify_bytes(
            protocol.resolver(),
            &bytes,
            digest.bytes(),
            &context,
        )
        .unwrap();
        let admission = root.admission_profile();
        assert!(
            super::super::fastvote_network::require_owned_lane(admission, &[0x81; 32]).is_err()
        );
        assert!(super::super::fastvote_network::require_owned_lane(admission, &[0x01; 32]).is_ok());

        // The unsigned CLI path must apply that same authenticated rule
        // before reading a fee source, signing, or creating an export file.
        use std::os::unix::fs::PermissionsExt;
        let dir = temporary_path("causal-unsigned");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let genesis_path = dir.join("genesis.bin");
        let network_path = dir.join("network.txt");
        let unsigned_path = dir.join("unsigned.bin");
        std::fs::write(&genesis_path, &bytes).unwrap();
        std::fs::write(
            &network_path,
            format!(
                "{} 127.0.0.1:1 - -\n",
                manifest.validator_set.validators[0].id
            ),
        )
        .unwrap();
        let error = run(
            "paid-call",
            vec![
                OsString::from("--endpoint"),
                OsString::from("127.0.0.1:1"),
                OsString::from("--expected-chain-id"),
                OsString::from(protocol.chain_id().as_str()),
                OsString::from("--expected-protocol-version"),
                OsString::from(protocol.resolver().protocol_version().get().to_string()),
                OsString::from("--expected-epoch"),
                OsString::from("0"),
                OsString::from("--expected-hash-suite-id"),
                OsString::from("1"),
                OsString::from("--expected-domain"),
                OsString::from(crate::hex::encode_hex(protocol.domain().as_bytes())),
                OsString::from("--request-id"),
                OsString::from("81".repeat(32)),
                OsString::from("--fastvote-network"),
                network_path.as_os_str().to_owned(),
                OsString::from("--fastvote-genesis-manifest"),
                genesis_path.as_os_str().to_owned(),
                OsString::from("--fastvote-expected-genesis-digest"),
                OsString::from(crate::hex::encode_hex(&digest.bytes())),
                OsString::from("--custody-socket"),
                OsString::from("/no-socket-is-opened"),
                OsString::from("--custody-uid"),
                OsString::from("1001"),
                OsString::from("--custody-expected-public-key"),
                OsString::from(owner.address().to_string()),
                OsString::from("--unsigned-out"),
                unsigned_path.as_os_str().to_owned(),
            ],
        )
        .unwrap_err();
        assert!(error.to_string().contains("wrong admission lane"));
        assert!(!unsigned_path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn signed_submit_rejects_malformed_saved_bytes_before_network_io() {
        let path = temporary_path("malformed-signed");
        std::fs::write(&path, b"not-a-signed-paid-intent").unwrap();
        let error = run_signed_submit(vec![
            OsString::from("--endpoint"),
            OsString::from("127.0.0.1:0"),
            OsString::from("--expected-chain-id"),
            OsString::from("paid-submit-test"),
            OsString::from("--expected-protocol-version"),
            OsString::from("7"),
            OsString::from("--expected-epoch"),
            OsString::from("0"),
            OsString::from("--expected-hash-suite-id"),
            OsString::from("1"),
            OsString::from("--expected-domain"),
            OsString::from("11".repeat(32)),
            OsString::from("--signed-file"),
            path.as_os_str().to_owned(),
        ])
        .unwrap_err();
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(error, CliError::LocalExecution(_)));
    }

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

    #[test]
    fn bounded_input_errors_keep_paid_execution_classification() {
        let path: std::path::PathBuf = temporary_path("input-errors");
        let path_text: &str = path.to_str().unwrap();
        let mut file: File = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"input").unwrap();
        drop(file);
        assert_eq!(read(path_text, 5).unwrap(), b"input");
        let oversized: CliError = read(path_text, 4).unwrap_err();
        assert!(matches!(
            oversized,
            CliError::LocalExecution(inner)
                if inner.downcast_ref::<std::io::Error>().is_some_and(|source| {
                    source.kind() == std::io::ErrorKind::InvalidInput
                        && source.to_string() == "canonical input file too large"
                })
        ));
        std::fs::remove_file(&path).unwrap();
        let missing: CliError = read(path_text, 4).unwrap_err();
        assert!(matches!(
            missing,
            CliError::LocalExecution(inner)
                if inner.downcast_ref::<std::io::Error>().is_some_and(|source| {
                    source.kind() == std::io::ErrorKind::NotFound
                })
        ));
    }
}
