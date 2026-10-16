//! Explicit offline transfer custody commands; no peer supplies trust pins.

use super::{
    approvals::{self, ApprovalRecord},
    asset_transfer::{AssetTransferRequest, AssetTransferTrust},
    asset_wire,
    config::CustodyConfig,
    error::CustodyError,
    fsperm::read_private_file,
};
use crate::{
    args::{ParsedArgs, parse_flags, scalar},
    error::CliError,
    hex::decode_hex_32,
    parse::{parse_u32, parse_u64},
};
use std::{
    ffi::OsString,
    io::IsTerminal,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use sunrise_edge_client::{PublicationContext, VerifiedGenesisRoot};

const CONFIG: &str = "--config";
const GENESIS: &str = "--genesis-manifest-file";
const GENESIS_DIGEST: &str = "--genesis-digest";
const REQUEST: &str = "--request-file";
const OUT: &str = "--out";
const APPROVALS: &str = "--approvals-dir";

fn fail(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    fail(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

fn trust_specs() -> Vec<crate::args::FlagSpec> {
    vec![scalar(CONFIG), scalar(GENESIS), scalar(GENESIS_DIGEST)]
}

fn load_trust(parsed: &ParsedArgs, config: &CustodyConfig) -> Result<AssetTransferTrust, CliError> {
    let expected = config.expected_context()?;
    let resolver = sunrise_edge_client::local_publication_resolver(&expected)?;
    let context: PublicationContext = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(fail)?;
    let bytes: Vec<u8> = read_private_file(
        Path::new(parsed.require(GENESIS)?),
        0o600,
        0o700,
        sunrise_edge_client::MAX_GENESIS_MANIFEST_BYTES,
    )?;
    let digest: [u8; 32] = decode_hex_32(GENESIS_DIGEST, parsed.require(GENESIS_DIGEST)?)?;
    let root: VerifiedGenesisRoot =
        VerifiedGenesisRoot::verify_bytes(&resolver, &bytes, digest, &context).map_err(fail)?;
    AssetTransferTrust::new(config.clone(), root)
}

fn read_request(parsed: &ParsedArgs) -> Result<AssetTransferRequest, CliError> {
    let bytes: Vec<u8> = read_private_file(
        Path::new(parsed.require(REQUEST)?),
        0o600,
        0o700,
        asset_wire::MAX_REQUEST_BYTES,
    )?;
    asset_wire::decode(&bytes).map_err(|error| CustodyError::Wire(error).into())
}

pub(super) fn prepare<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    for name in [
        "--coin-file",
        "--fee-source-file",
        "--recipient",
        "--nonce",
        "--request-id",
        "--max-fee",
        "--gas-limit",
        OUT,
    ] {
        specs.push(scalar(name));
    }
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let output: &Path = Path::new(parsed.require(OUT)?);
    super::check_review_preimage_destination(output)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let trust: AssetTransferTrust = load_trust(&parsed, &config)?;
    let request = AssetTransferRequest {
        coin_bytes: read_private_file(
            Path::new(parsed.require("--coin-file")?),
            0o600,
            0o700,
            sunrise_edge_client::MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        )?,
        fee_bytes: read_private_file(
            Path::new(parsed.require("--fee-source-file")?),
            0o600,
            0o700,
            sunrise_edge_client::MAX_AUTHENTICATED_OBJECT_BODY_BYTES,
        )?,
        recipient: decode_hex_32("--recipient", parsed.require("--recipient")?)?,
        nonce: parse_u64("--nonce", parsed.require("--nonce")?)?,
        request_id: sunrise_edge_client::RequestId::new(decode_hex_32(
            "--request-id",
            parsed.require("--request-id")?,
        )?)?,
        max_fee: parse_u64("--max-fee", parsed.require("--max-fee")?)?,
        gas_limit: parse_u64("--gas-limit", parsed.require("--gas-limit")?)?,
    };
    let prepared = trust.prepare(&request)?;
    print!("{}", prepared.review);
    let bytes: Vec<u8> = asset_wire::encode(&request).map_err(CustodyError::Wire)?;
    super::write_review_preimage(output, &bytes)?;
    println!("transfer_request_exported=true");
    Ok(())
}

pub(super) fn approve<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([
        scalar(REQUEST),
        scalar(APPROVALS),
        scalar("--expires-in-seconds"),
    ]);
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let trust: AssetTransferTrust = load_trust(&parsed, &config)?;
    let request: AssetTransferRequest = read_request(&parsed)?;
    let approvals: &Path = Path::new(parsed.require(APPROVALS)?);
    if super::revoke::is_revoked(approvals, &request.request_id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    let transfer = trust.prepare(&request)?;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(CustodyError::ApproveRequiresTerminal.into());
    }
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyError::ClockBeforeEpoch)?
        .as_secs();
    let expires: u64 = parse_u64(
        "--expires-in-seconds",
        parsed.require("--expires-in-seconds")?,
    )?;
    let not_after: u64 = now
        .checked_add(expires)
        .ok_or(CustodyError::ExpiryOverflow)?;
    print!("{}", transfer.review);
    let confirmation: String = format!(
        "APPROVE-TRANSFER sender={} amount={} recipient={} fee_balance={} max_fee={} nonce={} request_id={} not_after={not_after}",
        config.publisher(),
        transfer.amount,
        crate::hex::encode_hex(&request.recipient),
        transfer.fee_balance,
        request.max_fee,
        request.nonce,
        request.request_id,
    );
    println!("Type exactly to approve:\n{confirmation}");
    if super::approve::read_bounded_confirmation_line(1024)? != confirmation {
        return Err(CustodyError::ApprovalConfirmationMismatch.into());
    }
    let record = ApprovalRecord {
        publisher: config.publisher(),
        not_after_unix_seconds: not_after,
        frame: transfer.prepared.signable_frame().to_vec(),
    };
    approvals::write_approval(approvals, &request.request_id, &record)?;
    println!(
        "approved_transfer=true\nrequest_id={}\nnot_after={not_after}",
        request.request_id
    );
    Ok(())
}

pub(super) fn serve<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    for flag in [
        "--key-file",
        "--socket",
        APPROVALS,
        "--max-connections",
        "--max-requests",
        "--total-deadline-secs",
    ] {
        specs.push(scalar(flag));
    }
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let bounds = super::server::ServeBounds::new(
        parse_u32("--max-connections", parsed.require("--max-connections")?)?,
        parse_u32("--max-requests", parsed.require("--max-requests")?)?,
        parse_u32(
            "--total-deadline-secs",
            parsed.require("--total-deadline-secs")?,
        )?,
    )?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    let trust: AssetTransferTrust = load_trust(&parsed, &config)?;
    let signer = super::keyfile::load_signer(Path::new(parsed.require("--key-file")?))?;
    let summary = super::server::run_transfer(
        config,
        signer,
        Path::new(parsed.require("--socket")?),
        Path::new(parsed.require(APPROVALS)?),
        bounds,
        trust,
    )?;
    println!(
        "connections_accepted={}\nrequests_handled={}\nrequests_signed={}\nrequests_refused={}",
        summary.connections_accepted,
        summary.requests_handled,
        summary.requests_signed,
        summary.requests_refused
    );
    Ok(())
}

pub(super) fn sign<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    let mut specs = trust_specs();
    specs.extend([scalar(REQUEST), scalar(OUT)]);
    specs.extend(crate::signer::signer_flag_specs());
    let parsed: ParsedArgs = parse_flags(args, &specs)?;
    let crate::signer::SignerSelection::Custody {
        socket,
        custody_uid,
        expected_public_key,
    } = crate::signer::parse_signer_selection(&parsed)?
    else {
        return Err(invalid(
            "sign-transfer requires the explicitly pinned custody signer",
        ));
    };
    let output: &Path = Path::new(parsed.require(OUT)?);
    super::check_review_preimage_destination(output)?;
    let config: CustodyConfig = CustodyConfig::load(Path::new(parsed.require(CONFIG)?))?;
    if config.publisher().as_bytes() != &expected_public_key {
        return Err(invalid("transfer sender differs from pinned custody key"));
    }
    let trust: AssetTransferTrust = load_trust(&parsed, &config)?;
    let request: AssetTransferRequest = read_request(&parsed)?;
    let transfer = trust.prepare(&request)?;
    let target = super::client::CustodyTarget {
        socket: socket.into(),
        custody_uid,
        expected_public_key,
    };
    let frame: Vec<u8> = asset_wire::encode(&request).map_err(CustodyError::Wire)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(CustodyError::Runtime)?;
    let signature: [u8; 64] =
        runtime.block_on(super::client::request_signature_async(&target, &frame))?;
    let signed = transfer.prepared.finalize(signature.to_vec())?;
    let bytes: Vec<u8> = sunrise_edge_client::encode_signed_paid_intent(&signed).map_err(fail)?;
    super::write_review_preimage(output, &bytes)?;
    println!(
        "signed_transfer_exported=true\nrequest_id={}",
        request.request_id
    );
    Ok(())
}
