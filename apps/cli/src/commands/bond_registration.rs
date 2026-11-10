//! Offline DR-0179 preparation. The predicted row is a claim, not VM proof.

use std::{error::Error, ffi::OsString, path::Path};

use sunrise_edge_client::{
    Address, AtomicityDomainId, ChainId,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, Epoch, ExpectedProtocolContext,
    HashSuiteResolver, HashSuiteSchedule, LocalSigner, ProtocolVersion, PublicationContext,
    RequestId, SignatureSchemeId,
    bond_registration::{
        BondRegistrationContent, BondRegistrationContext, BondRegistrationIntent, BondResourceId,
        FastPathBondRecord, MAX_BOND_REGISTRATION_ROW_BYTES, MAX_LOCAL_EXECUTION_INTENT_BYTES,
        PreparedLocalBondRegistration, PreparedSuccessorBondRegistration,
        decode_fastpath_bond_record, prepare_successor_bond_registration_for_public_key,
        preview_original_bond_registration_content, preview_successor_bond_registration_content,
    },
};

use crate::{
    args::{FlagSpec, ParsedArgs, scalar},
    custody::bond_inner::{BondInnerRequest, BondInnerTrust, PreparedBondInner},
    error::CliError,
    hex::{decode_hex_32, encode_hex},
    output::sanitize_line,
    parse::{parse_u32, parse_u64},
    seed::load_dev_seed,
};

use super::hash_suite_pins::parse_pinned_flags;
use super::network_artifacts::{ReservedArtifact, read_bounded, reserve_artifacts};

const HELP: &str = "Offline initial validator-bond registration preparation (no execution, membership, readiness or activation).\n\nRequired: --ordered-genesis-manifest FILE --ordered-expected-genesis-digest HEX --expected-chain-id CHAIN --expected-protocol-version N --expected-epoch N --domain HEX --suite epoch:id:transaction:object:effects:code:config:certificate --request-id HEX --signed-leg FILE --expected-bond-row FILE --seed-file FILE --out FILE.\n\nOne to 64 --suite entries form the explicit locally trusted schedule; algorithms 1 (SHA2-256) and 2 (SHA3-256) are supported. --seed-file is an existing private development seed file, not a production keystore. The generation-one row is a bounded caller prediction only: this command never executes the leg or proves source objects. The normal ordered handler executes the separately signed owned custody leg and rechecks its exact result. The actual key derives the new validator ID and may not reuse any genesis ID or key.\n\nThe output is an exact signed registration envelope, written through a fresh held file handle without overwrite. Wrap it using economics candidate-wrap --kind bond-registration with explicit request/context/checkpoint pins, then use the existing ordered submission/replay workflow.";
const PREVIEW_HELP: &str = "Offline, seed-free structural preview of an original or verified successor bond-registration claim. This command does not approve, sign, execute, register, or write an output artifact.\n\nRequired: --ordered-genesis-manifest FILE --ordered-expected-genesis-digest HEX --expected-chain-id CHAIN --expected-protocol-version N --expected-epoch N --domain HEX --suite epoch:id:transaction:object:effects:code:config:certificate --request-id HEX --signed-leg FILE --expected-bond-row FILE --expected-authorization-key HEX. Successor scope additionally requires the complete ordered successor archive pins and the exact verified e+1 context.\n\nOptional original-genesis-only semantic check: supply both --inner-source-coin FILE and --inner-source-key HEX. This rebuilds the manifest-pinned Standard Asset whole-Coin transfer and compares the exact signed leg and predicted row. The source file is a caller snapshot, not current-state proof or content approval. The supplied public key is a local review input, never a key selected by the leg or row. The full canonical signed leg, predicted row, unsigned outer intent and outer signing frame are printed as hex. The default structural view leaves generic leg semantics unreviewed.";

#[derive(Clone, Copy)]
enum Mode {
    DevelopmentSign,
    Preview,
}

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: impl Into<String>) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

const COMMON_FLAGS: &[FlagSpec] = &[
    scalar("--ordered-genesis-manifest"),
    scalar("--ordered-expected-genesis-digest"),
    scalar("--expected-chain-id"),
    scalar("--expected-protocol-version"),
    scalar("--expected-epoch"),
    scalar("--domain"),
    scalar("--request-id"),
    scalar("--signed-leg"),
    scalar("--expected-bond-row"),
];

pub(super) fn run<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    run_mode(args, Mode::DevelopmentSign)
}

pub(super) fn run_preview<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    run_mode(args, Mode::Preview)
}

fn run_mode<I: IntoIterator<Item = OsString>>(args: I, mode: Mode) -> Result<(), CliError> {
    let args: Vec<OsString> = args.into_iter().collect();
    if args.len() == 1 && args[0] == "--help" {
        println!(
            "{}",
            if matches!(mode, Mode::Preview) {
                PREVIEW_HELP
            } else {
                HELP
            }
        );
        return Ok(());
    }
    let mut flags: Vec<FlagSpec> = COMMON_FLAGS.to_vec();
    match mode {
        Mode::DevelopmentSign => flags.extend([scalar("--seed-file"), scalar("--out")]),
        Mode::Preview => flags.extend([
            scalar("--expected-authorization-key"),
            scalar("--inner-source-coin"),
            scalar("--inner-source-key"),
        ]),
    }
    flags.extend(super::successor_pins::successor_flag_specs(false));
    let (parsed, schedules): (ParsedArgs, Vec<HashSuiteSchedule>) =
        parse_pinned_flags(args, &flags)?;
    if schedules.is_empty() {
        return Err(invalid("one to 64 explicit --suite entries are required"));
    }
    // Parse every required flag and scalar pin before input I/O, output
    // reservation or signing. No unused transport/device flags are accepted.
    let manifest_path: &str = parsed.require("--ordered-genesis-manifest")?;
    let signed_leg_path: &str = parsed.require("--signed-leg")?;
    let predicted_row_path: &str = parsed.require("--expected-bond-row")?;
    let (seed_path, out_path, preview_key): (Option<&str>, Option<&str>, Option<[u8; 32]>) =
        match mode {
            Mode::DevelopmentSign => (
                Some(parsed.require("--seed-file")?),
                Some(parsed.require("--out")?),
                None,
            ),
            Mode::Preview => (
                None,
                None,
                Some(decode_hex_32(
                    "--expected-authorization-key",
                    parsed.require("--expected-authorization-key")?,
                )?),
            ),
        };
    let inner_source: Option<(&str, Address)> = if matches!(mode, Mode::Preview) {
        match (
            parsed.get("--inner-source-coin"),
            parsed.get("--inner-source-key"),
        ) {
            (None, None) => None,
            (Some(path), Some(key)) => Some((
                path,
                Address::new(decode_hex_32("--inner-source-key", key)?),
            )),
            _ => {
                return Err(invalid(
                    "original inner semantic check requires both source Coin and source key",
                ));
            }
        }
    } else {
        None
    };
    let request_id: [u8; 32] = decode_hex_32("--request-id", parsed.require("--request-id")?)?;
    let expected_digest: [u8; 32] = decode_hex_32(
        "--ordered-expected-genesis-digest",
        parsed.require("--ordered-expected-genesis-digest")?,
    )?;
    let chain_id: ChainId =
        ChainId::new(parsed.require("--expected-chain-id")?.to_string()).map_err(failure)?;
    let protocol_version: ProtocolVersion = ProtocolVersion::new(parse_u32(
        "--expected-protocol-version",
        parsed.require("--expected-protocol-version")?,
    )?);
    let epoch: Epoch = Epoch::new(parse_u64(
        "--expected-epoch",
        parsed.require("--expected-epoch")?,
    )?);
    let context: PublicationContext =
        PublicationContext::new(chain_id.clone(), protocol_version, epoch).map_err(failure)?;
    let domain: AtomicityDomainId =
        AtomicityDomainId::new(decode_hex_32("--domain", parsed.require("--domain")?)?)
            .map_err(failure)?;
    let resolver: HashSuiteResolver =
        HashSuiteResolver::new(chain_id, protocol_version, schedules).map_err(failure)?;
    let workflow: Option<sunrise_edge_client::SuccessorWorkflowAuthority> =
        super::successor_pins::load_successor_pins(
            &parsed,
            manifest_path,
            expected_digest,
            &resolver,
            &context,
            Some(domain),
        )?;
    let trusted: Option<BondRegistrationContext> = if workflow.is_none() {
        Some(
            BondRegistrationContext::load(
                Path::new(manifest_path),
                &resolver,
                expected_digest,
                &context,
                domain,
            )
            .map_err(failure)?,
        )
    } else {
        None
    };
    let leg: Vec<u8> = read_bounded(signed_leg_path, MAX_LOCAL_EXECUTION_INTENT_BYTES)?;
    let row_bytes: Vec<u8> = read_bounded(predicted_row_path, MAX_BOND_REGISTRATION_ROW_BYTES)?;
    let predicted_initial_row: FastPathBondRecord =
        decode_fastpath_bond_record(&row_bytes).map_err(failure)?;
    let signer: Option<LocalSigner> = match seed_path {
        Some(path) => Some(LocalSigner::from_seed(load_dev_seed(Path::new(path))?)),
        None => None,
    };
    let authorization_key: [u8; 32] = match (&signer, preview_key) {
        (Some(signer), None) => *signer.address().as_bytes(),
        (None, Some(key)) => key,
        _ => return Err(invalid("registration signing mode is incomplete")),
    };
    let (prepared, successor_prepared): (
        Option<PreparedLocalBondRegistration>,
        Option<PreparedSuccessorBondRegistration<'_>>,
    ) = match (&trusted, &workflow) {
        (Some(trusted), None) => (
            Some(
                trusted
                    .prepare_for_public_key(
                        authorization_key,
                        request_id,
                        leg,
                        predicted_initial_row,
                    )
                    .map_err(failure)?,
            ),
            None,
        ),
        (None, Some(workflow)) => (
            None,
            Some(
                prepare_successor_bond_registration_for_public_key(
                    workflow,
                    &context,
                    authorization_key,
                    request_id,
                    leg,
                    predicted_initial_row,
                )
                .map_err(failure)?,
            ),
        ),
        _ => return Err(invalid("registration authority composition is incomplete")),
    };
    if matches!(mode, Mode::Preview) {
        let recognized_inner: bool = match (inner_source, &prepared, &workflow) {
            (None, _, _) => false,
            (Some((path, source_key)), Some(prepared), None) => {
                check_original_inner_semantics(
                    path, source_key, prepared, &resolver, &context, domain,
                )?;
                true
            }
            (Some(_), _, _) => {
                return Err(invalid(
                    "inner Standard Asset semantic check is original-genesis only",
                ));
            }
        };
        let (intent, row, content, scope): (
            &BondRegistrationIntent,
            &FastPathBondRecord,
            BondRegistrationContent,
            &str,
        ) = match (&prepared, &successor_prepared) {
            (Some(prepared), None) => (
                prepared.intent(),
                prepared.predicted_initial_row(),
                preview_original_bond_registration_content(&resolver, prepared, &row_bytes)
                    .map_err(failure)?,
                "original",
            ),
            (None, Some(prepared)) => (
                prepared.intent(),
                prepared.predicted_initial_row(),
                preview_successor_bond_registration_content(
                    &resolver, prepared, &context, &row_bytes,
                )
                .map_err(failure)?,
                "successor",
            ),
            _ => return Err(invalid("registration preview preparation is incomplete")),
        };
        let report: String = render_preview(intent, row, &content, domain, scope, recognized_inner);
        print!("{report}");
        return Ok(());
    }
    let signer: LocalSigner = signer.ok_or_else(|| invalid("registration signer is missing"))?;
    let seed_path: &str = seed_path.ok_or_else(|| invalid("registration seed is missing"))?;
    let out_path: &str = out_path.ok_or_else(|| invalid("registration output is missing"))?;
    let mut outputs: Vec<ReservedArtifact> = reserve_artifacts(
        &[(out_path, "signed-bond-registration")],
        &[
            manifest_path,
            signed_leg_path,
            predicted_row_path,
            seed_path,
        ],
    )?;
    let mut output: ReservedArtifact = outputs
        .pop()
        .ok_or_else(|| invalid("registration output reservation is missing"))?;
    output.ensure_attached()?;
    let (validator, bytes): (sunrise_edge_client::ValidatorId, Vec<u8>) =
        match (prepared, successor_prepared) {
            (Some(prepared), None) => (
                prepared.validator_id(),
                prepared.sign_and_finalize_with(&signer).map_err(failure)?,
            ),
            (None, Some(prepared)) => (
                prepared.validator_id(),
                prepared.sign_and_finalize_with(&signer).map_err(failure)?,
            ),
            _ => return Err(invalid("registration preparation is incomplete")),
        };
    output.persist(&bytes)?;
    println!("preparation=structural_registration_claim");
    println!("executed=false");
    println!(
        "validator_id={}",
        crate::hex::encode_hex(validator.as_bytes())
    );
    println!("request_id={}", crate::hex::encode_hex(&request_id));
    println!("signed_registration_bytes={}", bytes.len());
    println!("out={}", crate::output::sanitize_line(out_path));
    Ok(())
}

/// Connects the existing exact inner and outer prepared owners without
/// granting either a signing endpoint. The source bytes remain a caller
/// snapshot, so this recognizes a bounded contract meaning, not live state.
fn check_original_inner_semantics(
    source_path: &str,
    source_key: Address,
    outer: &PreparedLocalBondRegistration,
    resolver: &HashSuiteResolver,
    context: &PublicationContext,
    domain: AtomicityDomainId,
) -> Result<(), CliError> {
    let source_bytes = read_bounded(
        source_path,
        sunrise_edge_client::MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
    )?;
    let signed_leg =
        sunrise_edge_client::local_execution::decode_signed_local_execution(&outer.intent().leg)
            .map_err(failure)?;
    let row = outer.predicted_initial_row();
    let expected = ExpectedProtocolContext::new(
        context.chain_id().clone(),
        context.protocol_version(),
        context.epoch(),
        resolver
            .suite_for_epoch(context.epoch())
            .map_err(failure)?
            .id,
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
        SignatureSchemeId::Ed25519.as_u16(),
        ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
        domain,
    )
    .map_err(failure)?;
    let trust = BondInnerTrust::new(expected, source_key, outer.genesis_root().clone())?;
    let request = BondInnerRequest {
        source_coin_bytes: source_bytes.clone(),
        validator_key: outer.intent().authorization_key,
        resource: BondResourceId::new(row.resource_domain, row.resource).map_err(failure)?,
        nonce: signed_leg.intent.call.nonce,
        request_id: RequestId::new(signed_leg.intent.call.request_id).map_err(failure)?,
        gas_limit: signed_leg.intent.call.gas_limit,
    };
    let inner: PreparedBondInner = trust.prepare(&request)?;
    if inner.prepared.intent() != &signed_leg.intent
        || inner.predicted_ref != row.custody_object
        || inner.amount != row.amount
    {
        return Err(invalid(
            "signed bond leg or predicted row differs from the manifest-pinned whole-Coin transfer",
        ));
    }
    Ok(())
}

/// This report is deliberately outside the signing path. The optional
/// original-genesis check recognizes only the pinned whole-Coin transfer;
/// nothing in this report is an approval or current-state proof.
fn render_preview(
    intent: &BondRegistrationIntent,
    row: &FastPathBondRecord,
    content: &BondRegistrationContent,
    domain: AtomicityDomainId,
    scope: &str,
    recognized_inner: bool,
) -> String {
    let mut lines: Vec<String> = vec![
        "preview=structural_bond_registration".to_string(),
        "approved=false".to_string(),
        "signed=false".to_string(),
        "executed=false".to_string(),
        format!(
            "leg_semantics={}",
            if recognized_inner {
                "manifest-pinned-original-standard-asset-whole-transfer"
            } else {
                "unreviewed"
            }
        ),
        format!("scope={scope}"),
        format!("ordered_domain={}", encode_hex(domain.as_bytes())),
        format!(
            "chain_id={}",
            sanitize_line(intent.context.chain_id().as_str())
        ),
        format!(
            "protocol_version={}",
            intent.context.protocol_version().get()
        ),
        format!("epoch={}", intent.context.epoch().get()),
        format!(
            "resource_chain_id={}",
            sanitize_line(intent.resource_context.chain_id().as_str())
        ),
        format!(
            "resource_protocol_version={}",
            intent.resource_context.protocol_version().get()
        ),
        format!("resource_epoch={}", intent.resource_context.epoch().get()),
        format!("request_id={}", encode_hex(&intent.request_id)),
        format!(
            "validator_id={}",
            encode_hex(intent.validator_id.as_bytes())
        ),
        format!(
            "authorization_key={}",
            encode_hex(&intent.authorization_key)
        ),
        format!("resource_domain={}", row.resource_domain),
        format!("resource={}", encode_hex(&row.resource)),
        format!("predicted_amount={}", row.amount),
        format!("predicted_required_minimum={}", row.required_minimum),
        format!("leg_sender={}", encode_hex(&content.leg_sender)),
        format!("leg_nonce={}", content.leg_nonce),
        format!("leg_gas_limit={}", content.leg_gas_limit),
        format!("leg_entrypoint={}", sanitize_line(&content.leg_entrypoint)),
        format!(
            "pinned_genesis_digest={}",
            encode_hex(&intent.pinned_genesis_digest.bytes())
        ),
        format!(
            "predicted_row_digest={}",
            encode_hex(&content.row_digest.bytes())
        ),
        format!(
            "outer_intent_digest={}",
            encode_hex(&content.intent_digest.bytes())
        ),
        format!("signed_leg_hex={}", encode_hex(&content.signed_leg)),
        format!("predicted_row_hex={}", encode_hex(&content.predicted_row)),
        format!("outer_intent_hex={}", encode_hex(&content.outer_intent)),
        format!("outer_frame_hex={}", encode_hex(&content.outer_frame)),
    ];
    if recognized_inner {
        lines.push("source_snapshot_unverified=true".to_string());
    }
    format!("{}\n", lines.join("\n"))
}
