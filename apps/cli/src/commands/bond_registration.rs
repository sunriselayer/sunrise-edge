//! Offline DR-0179 preparation. The predicted row is a claim, not VM proof.

use std::{error::Error, ffi::OsString, path::Path};

use sunrise_edge_client::{
    AtomicityDomainId, ChainId, Epoch, HashSuiteResolver, HashSuiteSchedule, LocalSigner,
    ProtocolVersion, PublicationContext,
    bond_registration::{
        BondRegistrationContext, FastPathBondRecord, MAX_BOND_REGISTRATION_ROW_BYTES,
        MAX_LOCAL_EXECUTION_INTENT_BYTES, PreparedLocalBondRegistration,
        PreparedSuccessorBondRegistration, decode_fastpath_bond_record,
        prepare_successor_bond_registration,
    },
};

use crate::{
    args::{FlagSpec, ParsedArgs, scalar},
    error::CliError,
    hex::decode_hex_32,
    parse::{parse_u32, parse_u64},
    seed::load_dev_seed,
};

use super::hash_suite_pins::parse_pinned_flags;
use super::network_artifacts::{ReservedArtifact, read_bounded, reserve_artifacts};

const HELP: &str = "Offline initial validator-bond registration preparation (no execution, membership, readiness or activation).\n\nRequired: --ordered-genesis-manifest FILE --ordered-expected-genesis-digest HEX --expected-chain-id CHAIN --expected-protocol-version N --expected-epoch N --domain HEX --suite epoch:id:transaction:object:effects:code:config:certificate --request-id HEX --signed-leg FILE --expected-bond-row FILE --seed-file FILE --out FILE.\n\nOne to 64 --suite entries form the explicit locally trusted schedule; algorithms 1 (SHA2-256) and 2 (SHA3-256) are supported. --seed-file is an existing private development seed file, not a production keystore. The generation-one row is a bounded caller prediction only: this command never executes the leg or proves source objects. The normal ordered handler executes the separately signed owned custody leg and rechecks its exact result. The actual key derives the new validator ID and may not reuse any genesis ID or key.\n\nThe output is an exact signed registration envelope, written through a fresh held file handle without overwrite. Wrap it using economics candidate-wrap --kind bond-registration with explicit request/context/checkpoint pins, then use the existing ordered submission/replay workflow.";

fn failure(error: impl Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: impl Into<String>) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

const FLAGS: &[FlagSpec] = &[
    scalar("--ordered-genesis-manifest"),
    scalar("--ordered-expected-genesis-digest"),
    scalar("--expected-chain-id"),
    scalar("--expected-protocol-version"),
    scalar("--expected-epoch"),
    scalar("--domain"),
    scalar("--request-id"),
    scalar("--signed-leg"),
    scalar("--expected-bond-row"),
    scalar("--seed-file"),
    scalar("--out"),
];

pub(super) fn run<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let args: Vec<OsString> = args.into_iter().collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("{HELP}");
        return Ok(());
    }
    let mut flags: Vec<FlagSpec> = FLAGS.to_vec();
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
    let seed_path: &str = parsed.require("--seed-file")?;
    let out_path: &str = parsed.require("--out")?;
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
    let signer: LocalSigner = LocalSigner::from_seed(load_dev_seed(Path::new(seed_path))?);
    let (prepared, successor_prepared): (
        Option<PreparedLocalBondRegistration>,
        Option<PreparedSuccessorBondRegistration<'_>>,
    ) = match (&trusted, &workflow) {
        (Some(trusted), None) => (
            Some(
                trusted
                    .prepare(&signer, request_id, leg, predicted_initial_row)
                    .map_err(failure)?,
            ),
            None,
        ),
        (None, Some(workflow)) => (
            None,
            Some(
                prepare_successor_bond_registration(
                    workflow,
                    &context,
                    &signer,
                    request_id,
                    leg,
                    predicted_initial_row,
                )
                .map_err(failure)?,
            ),
        ),
        _ => return Err(invalid("registration authority composition is incomplete")),
    };
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
        match (&prepared, &successor_prepared) {
            (Some(prepared), None) => (
                prepared.validator_id(),
                prepared.sign(&signer).map_err(failure)?,
            ),
            (None, Some(prepared)) => (
                prepared.validator_id(),
                prepared.sign(&signer, &context).map_err(failure)?,
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
